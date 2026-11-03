using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace PCCheck.Engine
{
    public sealed partial class Scanner
    {
        /// <summary>PCIe hardware IDs seen by the DMA check, used for the PC ID.</summary>
        readonly List<string> pciIds = new List<string>();

        /// <summary>USB drives that were plugged in, programs run from drives that aren't connected now, and sandbox or freeze tools.</summary>
        string ScanDevicesAndSandboxes()
        {
            var found = new List<string>();
            Tick("Reading USB drive history", 0.15);
            var usbTimes = ScanUsbHistory(found);
            Tick("Checking programs run from other drives", 0.45);
            ScanRemovableRuns(found, usbTimes);
            Tick("Checking for sandbox and freeze tools", 0.75);
            ScanSandboxes(found);
            return found.Count == 0 ? "No USB programs or sandboxes" : string.Join(", ", found);
        }

        List<DateTime> ScanUsbHistory(List<string> found)
        {
            var seen = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            var times = new List<DateTime>();
            try
            {
                ReadEvents("Microsoft-Windows-Kernel-PnP/Configuration",
                    "*[System[(EventID=400 or EventID=410) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]", 4000, (time, id, data) =>
                    {
                        string inst;
                        if (!time.HasValue || !data.TryGetValue("DeviceInstanceId", out inst)) return;
                        string name = Parsers.UsbStorageName(inst);
                        if (name == null) return;
                        times.Add(time.Value);
                        DateTime prev;
                        if (!seen.TryGetValue(name, out prev) || time.Value > prev) seen[name] = time.Value;
                    });
            }
            catch (Exception ex) { notes.Add("Couldn't read the USB device history: " + ex.Message); }

            foreach (var kv in seen.OrderByDescending(x => x.Value).Take(8))
            {
                var game = sessions.FirstOrDefault(x => kv.Value >= x.Start && kv.Value <= (x.End ?? x.Start));
                var f = Simple("USB drive plugged in", "USB drive", Severity.Info, Evidence.Context, Groups.Context, kv.Value, kv.Key, "Windows device history",
                    "Last connected " + kv.Value.ToString("g") + (game != null ? ", while Roblox place " + game.PlaceId + " was open" : "") +
                    ". Cheats can be run from a USB stick so fewer traces stay on the PC. Plugging one in is normal, so this is context only.");
                if (game != null) f.Games.Add(new GameLink { Session = game, How = "during" });
                Add(f);
            }
            if (seen.Count > 0) found.Add(seen.Count + (seen.Count == 1 ? " USB drive" : " USB drives"));
            return times;
        }

        /// <summary>
        /// BAM remembers the full path of programs that ran. A path on a drive that isn't connected now, or on a removable drive,
        /// usually means a USB stick or external drive.
        /// </summary>
        void ScanRemovableRuns(List<string> found, List<DateTime> usbTimes)
        {
            var removable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { foreach (var d in DriveInfo.GetDrives()) if (d.DriveType == DriveType.Removable) removable.Add(d.Name.Substring(0, 2)); } catch { }

            int listed = 0;
            foreach (var run in bamRuns.OrderByDescending(r => r.Item2))
            {
                if (listed >= 10 || run.Item2 < DateTime.Now.AddDays(-30)) break;
                string path = run.Item1;
                if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                bool notConnected = path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase);
                bool onRemovable = path.Length > 2 && path[1] == ':' && removable.Contains(path.Substring(0, 2));
                if (!notConnected && !onRemovable) continue;
                if (matcher.MatchName(path) != null) continue;   // already listed by name

                var game = sessions.FirstOrDefault(x => run.Item2 >= x.Start.AddMinutes(-5) && run.Item2 <= (x.End ?? x.Start).AddMinutes(5));
                var f = Simple(game != null ? "Program ran from a USB drive during a Roblox game" : "Program ran from a USB or external drive",
                    "USB program", game != null ? Severity.Medium : Severity.Info, Evidence.Ran, game != null ? Groups.Cheat : Groups.Context, run.Item2, path, "BAM",
                    (notConnected ? "This drive isn't connected now. " : "This is a removable drive. ") +
                    (game != null ? "It ran while Roblox place " + game.PlaceId + " was open. Running a cheat from a USB stick keeps it off the PC, so ask what this was."
                                  : "Listed so staff know programs were run from outside the PC."));
                f.RunTimes.Add(run.Item2);
                if (game != null) f.Games.Add(new GameLink { Session = game, How = "during" });
                Add(f);
                listed++;
                if (!found.Contains("programs from USB")) found.Add("programs from USB");
            }
        }

        /// <summary>Sandboxie's container folder (and anything cheat-like inside it), plus sandbox and freeze tools installed as services or drivers.</summary>
        void ScanSandboxes(List<string> found)
        {
            // Sandboxie keeps every file a boxed program creates under C:\Sandbox\<user>\<box>\...
            foreach (var root in new[] { systemDrive + @"\Sandbox" })
            {
                try
                {
                    if (!Directory.Exists(root)) continue;
                    Add(Simple("Sandboxie container folder", "Sandbox / freeze tool", Severity.Medium, Evidence.Found, Groups.Tamper, Directory.GetLastWriteTime(root), root, "Folder",
                        "Programs run inside Sandboxie keep their files here instead of on the real PC."));
                    if (!found.Contains("sandbox")) found.Add("sandbox");
                    int checkedFiles = 0;
                    foreach (var file in SafeFiles(root, 8))
                    {
                        if (++checkedFiles > 20000) break;
                        var sig = matcher.MatchName(file);
                        if (sig == null) continue;
                        var f = FromSignature(sig, Evidence.Found, file, File.GetLastWriteTime(file), "Inside Sandboxie");
                        f.Note = (sig.Note == null ? "" : sig.Note + " ") + "Found inside a Sandboxie box, where cheats are sometimes run to keep them off the real PC.";
                        Add(f);
                    }
                }
                catch { }
            }

            try
            {
                using (var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                {
                    if (services == null) return;
                    foreach (var name in services.GetSubKeyNames())
                    {
                        var sig = matcher.MatchName(name);
                        if (sig == null || (sig.Category ?? "").IndexOf("Sandbox", StringComparison.OrdinalIgnoreCase) < 0) continue;
                        var f = FromSignature(sig, Evidence.WasHere, name, null, "Installed driver or service");
                        f.Note = (sig.Note ?? "") + " Installed as a Windows service named \"" + name + "\".";
                        Add(f);
                        if (!found.Contains("sandbox")) found.Add("sandbox");
                    }
                }
            }
            catch { }
        }

        /// <summary>Walks a folder tree (read-only, skipping folders it can't open), up to a depth.</summary>
        static IEnumerable<string> SafeFiles(string root, int maxDepth)
        {
            var stack = new Stack<KeyValuePair<string, int>>();
            stack.Push(new KeyValuePair<string, int>(root, 0));
            while (stack.Count > 0)
            {
                var cur = stack.Pop();
                string[] files = new string[0], dirs = new string[0];
                try { files = Directory.GetFiles(cur.Key); } catch { }
                try { if (cur.Value < maxDepth) dirs = Directory.GetDirectories(cur.Key); } catch { }
                foreach (var f in files) yield return f;
                foreach (var d in dirs) stack.Push(new KeyValuePair<string, int>(d, cur.Value + 1));
            }
        }
    }
}
