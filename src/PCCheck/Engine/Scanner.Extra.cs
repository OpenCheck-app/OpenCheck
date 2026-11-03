using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using Microsoft.Win32;

namespace PCCheck.Engine
{
    /// <summary>
    /// Places experienced manual PC checkers look that OpenCheck didn't read before: the Run box history,
    /// Windows Security's current settings, recent website lookups (DNS cache) and USB tools used with DMA cards.
    /// Read-only, and only matches are kept.
    /// </summary>
    public sealed partial class Scanner
    {
        /// <summary>Commands typed into the Run box (Win+R) and paths typed into Explorer's address bar.</summary>
        void ScanRunBox()
        {
            foreach (var sid in LoadedUserSids())
            {
                foreach (var sub in new[] { @"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", @"\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" })
                {
                    try
                    {
                        using (var key = Registry.Users.OpenSubKey(sid + sub))
                        {
                            if (key == null) continue;
                            string source = sub.EndsWith("RunMRU") ? "Run box (Win+R) history" : "Explorer address bar history";
                            foreach (var name in key.GetValueNames())
                            {
                                if (name.Equals("MRUList", StringComparison.OrdinalIgnoreCase)) continue;
                                string cmd = TraceParsers.RunBoxCommand(key.GetValue(name) as string);
                                if (cmd == null) continue;

                                var remote = TraceParsers.RemoteScriptRun(cmd);
                                if (remote != null) { ReportRemoteScript(remote, null, source); continue; }
                                string cleanup = TraceParsers.CleanupCommand(cmd);
                                if (cleanup != null)
                                {
                                    Add(Simple(cleanup + " (typed command)", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, null,
                                        cmd.Length > 160 ? cmd.Substring(0, 157) + "..." : cmd, source,
                                        "This command was typed into the " + (source.StartsWith("Run") ? "Run box" : "Explorer address bar") + " on this PC. It wipes records that PC checks read."));
                                    continue;
                                }
                                string target = TraceParsers.RunBoxTarget(cmd);
                                var sig = target == null ? null : matcher.MatchName(target);
                                if (sig == null) continue;
                                var f = FromSignature(sig, Evidence.Ran, target, null, source);
                                f.Note = (sig.Note == null ? "" : sig.Note + " ") + "This was typed into the " + (source.StartsWith("Run") ? "Run box" : "Explorer address bar") + " to open it.";
                                Add(f);
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        /// <summary>Windows Security switched off right now (real-time or tamper protection), when it's the only antivirus.</summary>
        int ScanDefenderStateNow()
        {
            bool realtimeOff = false, tamperOff = false, known = false;
            try
            {
                // Windows Security's own status report: the same thing the Windows Security app shows.
                using (var searcher = new ManagementObjectSearcher(new ManagementScope(@"root\Microsoft\Windows\Defender"), new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus")))
                    foreach (var o in searcher.Get())
                    {
                        known = true;
                        realtimeOff = Prop(o, "RealTimeProtectionEnabled").Equals("False", StringComparison.OrdinalIgnoreCase);
                        tamperOff = Prop(o, "IsTamperProtected").Equals("False", StringComparison.OrdinalIgnoreCase);
                    }
            }
            catch { return 0; }
            if (!known) return 0;

            bool otherAv = false;
            try
            {
                using (var searcher = new ManagementObjectSearcher(new ManagementScope(@"root\SecurityCenter2"), new ObjectQuery("SELECT displayName FROM AntiVirusProduct")))
                    foreach (var o in searcher.Get())
                    {
                        string name = Prop(o, "displayName");
                        if (name.Length > 0 && name.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) < 0) otherAv = true;
                    }
            }
            catch { otherAv = true; }   // can't tell: don't flag

            var off = TraceParsers.DefenderOffNow(realtimeOff, tamperOff, otherAv);
            if (off.Count == 0) return 0;
            Add(Simple("Windows Security is partly off right now", "Antivirus turned off", Severity.Medium, Evidence.Tamper, Groups.Tamper, DateTime.Now,
                string.Join(" and ", off) + " off", "Windows Security settings",
                "Windows Security is the only antivirus on this PC, and " + string.Join(" and ", off).ToLowerInvariant() + (off.Count == 1 ? " is" : " are") +
                " switched off. Executor guides tell people to do this so the cheat isn't removed. Ask why."));
            return 1;
        }

        /// <summary>USB tools used with DMA cards, from Windows' device list (kept after unplugging).</summary>
        void ScanDmaUsbTools(List<string> found)
        {
            bool serialNoted = false;
            try
            {
                using (var usb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB"))
                {
                    if (usb == null) return;
                    foreach (var dev in usb.GetSubKeyNames())
                    {
                        string label = TraceParsers.DmaUsbTool(dev);
                        bool serial = label == null && !serialNoted && TraceParsers.IsUsbSerialChip(dev);
                        if (label == null && !serial) continue;
                        string desc = null;
                        try
                        {
                            using (var d = usb.OpenSubKey(dev))
                            {
                                var inst = d == null ? null : d.GetSubKeyNames().FirstOrDefault();
                                if (inst != null)
                                    using (var i = d.OpenSubKey(inst))
                                        desc = i == null ? null : (i.GetValue("FriendlyName") as string ?? i.GetValue("DeviceDesc") as string);
                            }
                        }
                        catch { }
                        if (desc != null && desc.Contains(";")) desc = desc.Substring(desc.LastIndexOf(';') + 1);
                        string path = dev + (string.IsNullOrEmpty(desc) ? "" : " (" + desc + ")");
                        if (label != null)
                        {
                            Add(Simple(label + " was connected", "DMA", Severity.Medium, Evidence.WasHere, Groups.Hardware, null, path, "USB device history",
                                "Windows remembers this USB device was plugged into this PC. It's the kind of adapter used to flash or run DMA cheat cards (electronics hobbyists use it too). Ask what it was for."));
                            if (!found.Contains("DMA tool connected")) found.Add("DMA tool connected");
                        }
                        else
                        {
                            serialNoted = true;
                            Add(Simple("USB serial adapter was connected", "DMA", Severity.Info, Evidence.Context, Groups.Context, null, path, "USB device history",
                                "KMBox-style input boxes (used for DMA aimbots) connect through chips like this, but so do Arduinos and many other gadgets. Context only."));
                        }
                    }
                }
            }
            catch { }
        }
    
        /// <summary>
        /// Programs that ran from outside the usual install folders: their fingerprint is checked against known cheat
        /// builds, and their structure is checked for the shape of external cheat loaders (packed, unsigned, overlay,
        /// online), which catches loaders like Matcha's whatever they're named. Files are only read, never run.
        /// </summary>
        void CheckRanProgramFiles()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            long budget = 400L << 20, used = 0;
            int packedFound = 0;
            var paths = bamRuns.Where(r => TraceParsers.IsOutsideInstalledPlaces(r.Item1))
                               .GroupBy(r => r.Item1, StringComparer.OrdinalIgnoreCase)
                               .Select(g => new { Path = g.Key, Times = g.Select(x => x.Item2).Distinct().OrderByDescending(x => x).ToList() })
                               .OrderByDescending(x => x.Times.First()).Take(60).ToList();
            foreach (var p in paths)
            {
                if (cancelled || used > budget || sw.Elapsed.TotalSeconds > 20) break;
                byte[] bytes;
                try
                {
                    if (!System.IO.File.Exists(p.Path)) continue;
                    var info = new System.IO.FileInfo(p.Path);
                    if (info.Length > (64L << 20) || info.Length < 1024) continue;
                    bytes = ReadShared(p.Path, 64L << 20);
                    used += bytes.Length;
                }
                catch { continue; }
                Breathe();

                string sha;
                using (var h = System.Security.Cryptography.SHA256.Create()) sha = BitConverter.ToString(h.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
                string known;
                if (set.KnownBadSha256.TryGetValue(sha, out known))
                {
                    var k = Simple(known.Split('(')[0].Trim(), "Known cheat file", Severity.High, Evidence.Ran, Groups.Cheat, p.Times.First(), p.Path, "File fingerprint (SHA-256)",
                        "This exact file is a known cheat build: " + known + ". It matches by its contents, so renaming it doesn't help.");
                    k.IsCheat = true; k.Sha256 = sha;
                    foreach (var t in p.Times) k.RunTimes.Add(t);
                    Add(k);
                    continue;
                }
                if (matcher.MatchName(p.Path) != null || packedFound >= 8) continue;   // already reported by name

                var traits = TraceParsers.InspectPe(bytes);
                if (!traits.IsPe || traits.Packer == null) continue;
                if (Native.IsSigned(p.Path) == true) continue;   // signed by a publisher: not a cheat loader shape
                packedFound++;
                var parts = new List<string> { "packed with " + traits.Packer, "unsigned" };
                if (traits.Overlay) parts.Add("draws a DirectX overlay");
                if (traits.Online) parts.Add("connects online");
                bool external = traits.Overlay && traits.Online;
                var f = Simple(external ? "Program shaped like an external cheat ran" : "Packed, unsigned program ran", "Unknown loader", Severity.Medium, Evidence.Ran, Groups.Cheat,
                    p.Times.First(), p.Path, "Program file check",
                    "This program is " + string.Join(", ", parts) + ". " +
                    (external ? "That's exactly how external cheat loaders like Matcha are built: the code is hidden until it runs, then it draws an ESP menu over the game and logs in online. "
                              : "Cheat loaders hide their code like this so they can't be read. ") +
                    "Some legitimate tools are packed too, so ask what it is.");
                f.Sha256 = sha;
                foreach (var t in p.Times) f.RunTimes.Add(t);
                Add(f);
            }
        }
    }
}
