using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace PCCheck.Engine
{
    public sealed partial class Scanner
    {
        sealed class JournalHit
        {
            public Signature Sig;
            public string Name;
            public long ParentRef;
            public DateTime? Time;
            public string Evidence;
        }

        /// <summary>Deleted, renamed and downloaded cheat files from the Recycle Bin and the NTFS change journal.</summary>
        string ScanDeleted()
        {
            ScanRecycleBin();
            DateTime? oldestCovered = null;
            var drives = DriveInfo.GetDrives().Where(IsFixedNtfs)
                .Where(d => options.ScanOtherDrives || d.Name.TrimEnd('\\').Equals(systemDrive, StringComparison.OrdinalIgnoreCase))
                .ToList();
            for (int i = 0; i < drives.Count && !cancelled; i++)
            {
                var covered = ScanJournal(drives[i], (double)i / drives.Count, 1.0 / drives.Count);
                if (covered.HasValue && (!oldestCovered.HasValue || covered.Value < oldestCovered.Value)) oldestCovered = covered;
            }

            int deleted = areaFindings.Count(f => f.Group == Groups.Cheat && (f.Evidence == Evidence.Deleted || f.Evidence == Evidence.Renamed));
            string cover = "";
            if (oldestCovered.HasValue)
            {
                int days = Math.Max(0, (int)(DateTime.Now - oldestCovered.Value).TotalDays);
                cover = days == 0 ? ", log covers today" : ", log covers " + days + (days == 1 ? " day" : " days");
            }
            if (!admin) return "Recycle Bin only (needs admin)";
            if (deleted == 0) return "No cheats deleted" + cover;
            return deleted + (deleted == 1 ? " cheat deleted or renamed" : " cheats deleted or renamed") + cover;
        }

        void ScanRecycleBin()
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                    string bin = Path.Combine(drive.Name, "$Recycle.Bin");
                    if (!Directory.Exists(bin)) continue;
                    foreach (var sidDir in Directory.GetDirectories(bin))
                    {
                        string[] infoFiles;
                        try { infoFiles = Directory.GetFiles(sidDir, "$I*"); }
                        catch { continue; }
                        foreach (var info in infoFiles)
                        {
                            try
                            {
                                var e = Parsers.ParseRecycleBinInfo(File.ReadAllBytes(info));
                                if (e == null || string.IsNullOrEmpty(e.OriginalPath)) continue;
                                string ext = Path.GetExtension(e.OriginalPath);
                                bool looksLikeFolder = string.IsNullOrEmpty(ext);
                                if (!looksLikeFolder && !Matcher.ScannedExtensions.Contains(ext)) continue;   // documents, photos etc. are never matched
                                var sig = looksLikeFolder ? matcher.MatchFolderName(Path.GetFileName(e.OriginalPath)) : matcher.MatchName(e.OriginalPath);
                                if (sig != null) Add(FromSignature(sig, Evidence.Deleted, e.OriginalPath, e.Deleted, "Recycle Bin"));
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }

        /// <summary>Reads the NTFS change journal (USN) for one drive. Returns the oldest time it covers.</summary>
        DateTime? ScanJournal(DriveInfo drive, double progressStart, double progressSpan)
        {
            if (!admin) return null;
            string letter = drive.Name.TrimEnd('\\');
            var hits = new Dictionary<string, JournalHit>(StringComparer.OrdinalIgnoreCase);
            var prefetchDeletes = new List<DateTime>();
            var robloxLogDeletes = new List<DateTime>();
            var jumpListDeletes = new List<DateTime>();
            int programDeletesThisWeek = 0;
            var weekAgo = DateTime.Now.AddDays(-7);
            DateTime? oldest = null;

            Microsoft.Win32.SafeHandles.SafeFileHandle volume;
            try { volume = Native.OpenVolume(letter); }
            catch (Exception ex) { notes.Add("Couldn't open drive " + letter + " change log: " + ex.Message); return null; }

            using (volume)
            {
                Native.UsnJournal journal;
                try { journal = Native.QueryJournal(volume); }
                catch (Exception ex) { notes.Add("Drive " + letter + " has no change log: " + ex.Message); return null; }

                var buffer = new byte[1 << 20];
                long usn = journal.FirstUsn;
                long span = Math.Max(1, journal.NextUsn - journal.FirstUsn);
                var sw = Stopwatch.StartNew();
                long records = 0;

                while (!cancelled && sw.Elapsed.TotalSeconds < options.JournalSeconds)
                {
                    int n = Native.ReadJournal(volume, journal.JournalId, usn, buffer);
                    if (n <= 8) break;
                    Breathe();
                    long next = BitConverter.ToInt64(buffer, 0);

                    foreach (var rec in Parsers.ParseUsnBuffer(buffer, n))
                    {
                        records++;
                        if (!oldest.HasValue && rec.Time.HasValue) oldest = rec.Time;

                        bool isDelete = (rec.Reason & Parsers.UsnReasonFileDelete) != 0;
                        bool isRename = (rec.Reason & Parsers.UsnReasonRenameOldName) != 0;
                        bool isCreate = (rec.Reason & Parsers.UsnReasonFileCreate) != 0;
                        if (!isDelete && !isRename && !isCreate) continue;

                        if (isDelete && rec.Time.HasValue)
                        {
                            if (rec.Name.EndsWith(".pf", StringComparison.OrdinalIgnoreCase)) prefetchDeletes.Add(rec.Time.Value);
                            else if (Parsers.IsRobloxLogName(rec.Name)) robloxLogDeletes.Add(rec.Time.Value);
                            else if (Parsers.IsJumpListName(rec.Name)) jumpListDeletes.Add(rec.Time.Value);
                            else if (rec.Time.Value > weekAgo && (rec.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || rec.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
                                programDeletesThisWeek++;
                        }

                        bool isFolder = (rec.Attributes & 0x10) != 0;
                        var sig = isFolder ? matcher.MatchFolderName(rec.Name) : matcher.MatchName(rec.Name);
                        if (sig == null) continue;
                        if (!isFolder && !Matcher.ScannedExtensions.Contains(Path.GetExtension(rec.Name))) continue;   // only programs, scripts and archives

                        string evidence = isDelete ? Evidence.Deleted : isRename ? Evidence.Renamed : Evidence.WasHere;
                        string key = evidence + "|" + rec.ParentRef + "|" + rec.Name;
                        JournalHit h;
                        if (!hits.TryGetValue(key, out h))
                        {
                            if (hits.Count >= 300) continue;
                            h = new JournalHit { Sig = sig, Name = rec.Name, ParentRef = rec.ParentRef, Evidence = evidence };
                            hits[key] = h;
                        }
                        if (rec.Time.HasValue && (!h.Time.HasValue || rec.Time.Value > h.Time.Value)) h.Time = rec.Time;
                    }

                    Tick("Reading drive " + letter + " change log", progressStart + progressSpan * Math.Min(1.0, (double)(next - journal.FirstUsn) / span));
                    if (next <= usn) break;
                    usn = next;
                }

                if (sw.Elapsed.TotalSeconds >= options.JournalSeconds)
                    notes.Add("Drive " + letter + " change log was only partly read (time limit).");

                // Turn hits into findings, finding each parent folder's current path.
                var parentCache = new Dictionary<long, string>();
                foreach (var h in hits.Values)
                {
                    string parent;
                    if (!parentCache.TryGetValue(h.ParentRef, out parent))
                    {
                        try { parent = Native.PathFromFileId(volume, h.ParentRef); } catch { parent = null; }
                        parentCache[h.ParentRef] = parent;
                    }
                    string path = parent != null ? Path.Combine(parent, h.Name) : letter + @"\(folder no longer exists)\" + h.Name;
                    var f = FromSignature(h.Sig, h.Evidence, path, h.Time, "Drive change log (USN)");
                    if (h.Evidence == Evidence.Renamed) f.Note = "Renamed from this name. Cheats are often renamed to avoid checks.";
                    Add(f);
                }

                // Prefetch wiped in one go?
                var burst = Parsers.FindBurst(prefetchDeletes, 25, TimeSpan.FromMinutes(10));
                if (burst.HasValue)
                {
                    Add(Simple("Prefetch files deleted in bulk", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, burst,
                        @"C:\Windows\Prefetch (" + prefetchDeletes.Count + " deletions in the log)", "Drive change log (USN)",
                        "Many program records were deleted within minutes. Windows sometimes trims old ones itself, so ask about it rather than treating it as proof."));
                }

                var logsBurst = Parsers.FindBurst(robloxLogDeletes, 8, TimeSpan.FromMinutes(10));
                if (logsBurst.HasValue)
                {
                    Add(Simple("Roblox logs deleted", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, logsBurst,
                        @"~\AppData\Local\Roblox\logs (" + robloxLogDeletes.Count + " log deletions)", "Drive change log (USN)",
                        "Several Roblox log files were deleted within minutes. These logs show when Roblox ran, so wiping them hides activity. Roblox also removes old logs by itself, a few at a time."));
                }
                var jumpBurst = Parsers.FindBurst(jumpListDeletes, 10, TimeSpan.FromMinutes(5));
                if (jumpBurst.HasValue)
                {
                    Add(Simple("Recent-files history wiped", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, jumpBurst,
                        "Jump lists (" + jumpListDeletes.Count + " deletions)", "Drive change log (USN)",
                        "Windows' per-program recent-file lists were deleted in bulk. Cleaners like CCleaner do this."));
                }
                if (programDeletesThisWeek > 0)
                {
                    Add(Simple(programDeletesThisWeek + " program files deleted this week", "Deleted files", Severity.Info, Evidence.Context, Groups.Tamper, DateTime.Now,
                        "Drive " + letter, "Drive change log (USN)",
                        "Count only. Names are never listed unless they match the cheat list. Installers and updates delete program files all the time."));
                }

                // Was the journal itself deleted and recreated recently?
                var created = Parsers.FromFileTime((long)journal.JournalId);
                var installed = WindowsInstallDate();
                if (created.HasValue && created.Value > DateTime.Now.AddDays(-14) && installed.HasValue && installed.Value < created.Value.AddDays(-1))
                {
                    Add(Simple("Drive change log was reset", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, created,
                        "Drive " + letter, "Drive change log (USN)",
                        "The change log was recreated after Windows was installed. Running 'fsutil usn deletejournal' does this to hide deleted files. Disk repairs can also cause it."));
                }
            }
            return oldest;
        }
    }
}
