using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace PCCheck.Engine
{
    /// <summary>
    /// Records that cleaners (CCleaner, BleachBit, PrivaZer and "PC check bypass" scripts) usually miss.
    /// Read-only, like everything else: files are opened for reading with sharing, and only matches are kept.
    /// </summary>
    public sealed partial class Scanner
    {
        readonly HashSet<string> extraRunKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Adds a program run to the list the behavior checks use (deleted during a game, disguised names).</summary>
        void AddRun(string path, DateTime time)
        {
            if (string.IsNullOrEmpty(path) || path.IndexOf('\\') < 0) return;
            if (extraRunKeys.Add(path + "|" + time.ToString("o"))) bamRuns.Add(Tuple.Create(path, time));
        }

        static byte[] ReadShared(string path, long maxBytes)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                long len = Math.Min(fs.Length, maxBytes);
                if (fs.Length > maxBytes) fs.Seek(fs.Length - maxBytes, SeekOrigin.Begin);   // keep the newest part
                var buf = new byte[len];
                int read = 0, n;
                while (read < len && (n = fs.Read(buf, read, (int)(len - read))) > 0) read += n;
                return buf;
            }
        }

        static IEnumerable<string> SplitLines(string text)
        {
            return text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        }

        /// <summary>
        /// Program Compatibility Assistant launch log (Windows 11 22H2+): every program started from Explorer,
        /// with its full path and time. Survives deleting the program and most cleaners.
        /// </summary>
        void ScanPcaLog()
        {
            string dir = Path.Combine(windowsDir, @"appcompat\pca");
            foreach (var name in new[] { "PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt" })
            {
                string file = Path.Combine(dir, name);
                try
                {
                    if (!File.Exists(file)) continue;
                    foreach (var line in SplitLines(TraceParsers.DecodeText(ReadShared(file, 16L << 20))))
                    {
                        var run = TraceParsers.ParsePcaLine(line);
                        if (run == null) continue;
                        if (run.Time.HasValue) AddRun(run.Path, run.Time.Value);
                        var sig = matcher.MatchName(run.Path);
                        if (sig == null) continue;
                        bool gone = false;
                        try { gone = !File.Exists(run.Path); } catch { }
                        var f = FromSignature(sig, Evidence.Ran, run.Path, run.Time, "Program launch log (PCA)");
                        if (gone) f.Note = (sig.Note == null ? "" : sig.Note + " ") + "The file is gone now, but Windows' program launch log still has it.";
                        Add(f);
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception ex) { notes.Add("Couldn't read " + name + ": " + ex.Message); }
            }
        }

        /// <summary>
        /// Windows Defender's support log (MPLog). Defender looks at programs as they start and as they're saved,
        /// and keeps this log for weeks. Cleaners and bypass scripts almost never touch it.
        /// </summary>
        void ScanDefenderSupportLog()
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Support");
            List<FileInfo> logs;
            try { logs = new DirectoryInfo(dir).EnumerateFiles("MPLog-*.log").OrderByDescending(f => f.LastWriteTime).Take(6).ToList(); }
            catch { return; }   // needs admin
            var deviceMap = Native.DeviceToDriveMap();
            int seconds = options.Depth == "quick" ? 5 : options.Depth == "thorough" ? 25 : 12;
            long budget = options.Depth == "quick" ? 24L << 20 : 96L << 20, used = 0;
            var sw = Stopwatch.StartNew();
            int hits = 0;
            foreach (var log in logs)
            {
                if (cancelled || used > budget || sw.Elapsed.TotalSeconds > seconds) break;
                try
                {
                    var bytes = ReadShared(log.FullName, Math.Min(48L << 20, budget - used + 1));
                    used += bytes.Length;
                    int lineNo = 0;
                    foreach (var line in SplitLines(TraceParsers.DecodeText(bytes)))
                    {
                        if ((++lineNo & 4095) == 0) { Breathe(); if (sw.Elapsed.TotalSeconds > seconds) break; }
                        foreach (var run in TraceParsers.MpLogRuns(line))
                        {
                            var sig = matcher.MatchName(run.Path);
                            if (sig == null || hits >= 40) continue;
                            string path = run.Path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) ? Parsers.ConvertDevicePath(run.Path, deviceMap) ?? run.Path : run.Path;
                            var f = FromSignature(sig, Evidence.WasHere, path, run.Time, "Windows Defender log");
                            f.Note = (sig.Note == null ? "" : sig.Note + " ") + "Windows Defender saw this file" +
                                     (run.Time.HasValue ? " on " + run.Time.Value.ToString("g") : "") + ". Defender keeps this log for weeks, even after the file is deleted.";
                            Add(f);
                            hits++;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception ex) { notes.Add("Couldn't read the Defender log: " + ex.Message); }
            }
        }

        /// <summary>
        /// Windows crash reports. A cheat that crashed leaves a folder named after it, and when Roblox crashes,
        /// Windows writes down every file loaded inside it, including injected cheat DLLs.
        /// </summary>
        void ScanCrashReports()
        {
            var roots = new List<string>();
            string common = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\WER");
            roots.Add(Path.Combine(common, "ReportArchive"));
            roots.Add(Path.Combine(common, "ReportQueue"));
            foreach (var p in profiles)
            {
                roots.Add(Path.Combine(p.Path, @"AppData\Local\Microsoft\Windows\WER\ReportArchive"));
                roots.Add(Path.Combine(p.Path, @"AppData\Local\Microsoft\Windows\WER\ReportQueue"));
            }
            int unusual = 0;
            var cutoff = DateTime.Now.AddDays(-90);
            foreach (var root in roots)
            {
                IEnumerable<DirectoryInfo> dirs;
                try { if (!Directory.Exists(root)) continue; dirs = new DirectoryInfo(root).EnumerateDirectories().ToList(); }
                catch { continue; }
                foreach (var d in dirs)
                {
                    string prog = TraceParsers.WerFolderProgram(d.Name);
                    if (prog == null) continue;
                    DateTime time;
                    try { time = d.LastWriteTime; } catch { continue; }
                    if (time < cutoff) continue;

                    var sig = matcher.MatchName(prog);
                    if (sig != null)
                    {
                        var f = FromSignature(sig, Evidence.Ran, prog, time, "Windows crash report");
                        f.Note = (sig.Note == null ? "" : sig.Note + " ") + "This program crashed on " + time.ToString("g") + " and Windows kept a crash report. Cleaners rarely remove these.";
                        Add(f);
                    }

                    if (!prog.StartsWith("RobloxPlayerBeta", StringComparison.OrdinalIgnoreCase) || unusual >= 10) continue;
                    try
                    {
                        string wer = Path.Combine(d.FullName, "Report.wer");
                        if (!File.Exists(wer)) continue;
                        var lines = SplitLines(TraceParsers.DecodeText(ReadShared(wer, 2L << 20)));
                        foreach (var module in TraceParsers.UnusualRobloxModules(lines))
                        {
                            if (unusual >= 10) break;
                            var msig = matcher.MatchName(module);
                            Finding f;
                            if (msig != null)
                            {
                                f = FromSignature(msig, Evidence.Ran, module, time, "Roblox crash report");
                                f.Note = (msig.Note == null ? "" : msig.Note + " ") + "This file was loaded inside Roblox when it crashed on " + time.ToString("g") + ".";
                            }
                            else
                            {
                                f = Simple("Unknown file loaded inside Roblox", "Injected file", Severity.Medium, Evidence.WasHere, Groups.Cheat, time, module, "Roblox crash report",
                                    "When Roblox crashed on " + time.ToString("g") + ", this file was loaded inside it. It isn't part of Roblox, Windows, or a known overlay (Discord, NVIDIA, Steam, OBS, Medal). Executors work by loading a file like this into Roblox. Ask what it is.");
                                f.RunTimes.Add(time);
                            }
                            Add(f);
                            unusual++;
                        }
                    }
                    catch { }
                }
            }
        }

        /// <summary>PowerShell history: commands that wipe exactly the records a PC check reads. Only matching lines are kept.</summary>
        void ScanShellHistory(List<string> found)
        {
            var kinds = new Dictionary<string, Tuple<string, DateTime?>>();
            foreach (var p in profiles)
            {
                string dir = Path.Combine(p.Path, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine");
                try
                {
                    if (!Directory.Exists(dir)) continue;
                    foreach (var file in Directory.EnumerateFiles(dir, "*history*.txt"))
                    {
                        DateTime? written = null;
                        try { written = File.GetLastWriteTime(file); } catch { }
                        foreach (var line in SplitLines(TraceParsers.DecodeText(ReadShared(file, 4L << 20))))
                        {
                            string kind = TraceParsers.CleanupCommand(line);
                            if (kind == null) continue;
                            string cmd = line.Trim();
                            if (cmd.Length > 160) cmd = cmd.Substring(0, 157) + "...";
                            kinds[kind] = Tuple.Create(cmd, written);   // keep the latest one of each kind
                        }
                    }
                }
                catch { }
            }
            foreach (var k in kinds)
            {
                Add(Simple(k.Key + " (typed command)", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, k.Value.Item2,
                    k.Value.Item1, "PowerShell history",
                    "This command was typed into PowerShell on this PC. It wipes records that PC checks read. The time shown is when the history was last written."));
            }
            if (kinds.Count > 0) found.Add("Cleanup commands typed");
        }

        /// <summary>Services and drivers installed in the last 90 days (event 7045), including ones deleted since.</summary>
        void ScanServiceInstalls(List<string> found)
        {
            const string last90Days = "TimeCreated[timediff(@SystemTime) <= 7776000000]";
            int personal = 0;
            try
            {
                ReadEvents("System", "*[System[(EventID=7045) and " + last90Days + "]]", 600, (time, id, data) =>
                {
                    string name, image;
                    data.TryGetValue("ServiceName", out name);
                    data.TryGetValue("ImagePath", out image);
                    string file = null;
                    try { file = string.IsNullOrEmpty(image) ? null : Path.GetFileName(image.Trim('"', ' ').Split('"')[0]); } catch { }
                    var sig = (string.IsNullOrEmpty(name) ? null : matcher.MatchName(name)) ?? (file == null ? null : matcher.MatchName(file));
                    if (sig != null)
                    {
                        var f = FromSignature(sig, Evidence.WasHere, image ?? name, time, "Service install log (7045)");
                        f.Note = (sig.Note == null ? "" : sig.Note + " ") + "Installed as a Windows service or driver named \"" + name + "\" on " + (time.HasValue ? time.Value.ToString("g") : "an unknown date") + ".";
                        if (time.HasValue) f.RunTimes.Add(time.Value);
                        Add(f);
                        return;
                    }
                    if (personal >= 5 || !TraceParsers.IsPersonalFolderDriver(image)) return;
                    personal++;
                    var d = Simple("Driver loaded from a personal folder", "Kernel driver", Severity.Medium, Evidence.WasHere, Groups.Cheat, time,
                        image, "Service install log (7045)",
                        "A kernel driver named \"" + name + "\" was loaded from a personal or temporary folder. Real drivers install under Windows or Program Files. External cheats and driver loaders (like kdmapper) do this. Ask what it was.");
                    if (time.HasValue) d.RunTimes.Add(time.Value);
                    Add(d);
                    if (!found.Contains("Driver from a personal folder")) found.Add("Driver from a personal folder");
                });
            }
            catch (Exception ex) { notes.Add("Service install log unavailable: " + ex.Message); }
        }
    }
}
