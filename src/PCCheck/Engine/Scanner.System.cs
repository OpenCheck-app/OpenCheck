using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PCCheck.Engine
{
    public sealed partial class Scanner
    {
        static readonly Regex HackToolThreat = new Regex(@"hacktool|gamehack|injector|roblox|krnl|synapse|exploit|cheat", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>Threats Windows Defender caught, and antivirus exclusions that hide cheat folders.</summary>
        string ScanDefender()
        {
            int detections = 0;
            try
            {
                ReadEvents("Microsoft-Windows-Windows Defender/Operational", "*[System[(EventID=1116 or EventID=1117)]]", 1500, (time, id, data) =>
                {
                    string threat, rawPaths;
                    data.TryGetValue("Threat Name", out threat);
                    data.TryGetValue("Path", out rawPaths);
                    threat = threat ?? "";
                    foreach (var part in (rawPaths ?? "").Split(';'))
                    {
                        int marker = part.IndexOf(":_", StringComparison.Ordinal);
                        if (marker < 0 || !part.StartsWith("file", StringComparison.OrdinalIgnoreCase) && !part.StartsWith("containerfile", StringComparison.OrdinalIgnoreCase)) continue;
                        string path = part.Substring(marker + 2);
                        var sig = matcher.MatchName(path) ?? matcher.MatchFolderName(Path.GetFileName(path));
                        if (sig != null)
                        {
                            Add(FromSignature(sig, Evidence.Defender, path, time, "Windows Security: " + threat));
                            detections++;
                        }
                        else if (HackToolThreat.IsMatch(threat))
                        {
                            Add(Simple(Path.GetFileName(path), "Flagged as a hacking tool", Severity.Medium, Evidence.Defender, Groups.Cheat, time, path,
                                "Windows Security: " + threat, "Windows Security named this a hacking or game-cheat tool. The file name isn't on the cheat list."));
                            detections++;
                        }
                    }
                });
            }
            catch (Exception ex) { notes.Add("Windows Security history unavailable: " + ex.Message); }

            int exclusions = ScanDefenderExclusions();
            if (detections == 0 && exclusions == 0) return "No related threats";
            var parts = new List<string>();
            if (detections > 0) parts.Add(detections + (detections == 1 ? " related detection" : " related detections"));
            if (exclusions > 0) parts.Add(exclusions + (exclusions == 1 ? " risky exclusion" : " risky exclusions"));
            return string.Join(", ", parts);
        }

        int ScanDefenderExclusions()
        {
            int count = 0;
            foreach (var kind in new[] { "Paths", "Processes" })
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\" + kind))
                    {
                        if (key == null) continue;
                        foreach (var path in key.GetValueNames())
                        {
                            string leaf = Path.GetFileName(path.TrimEnd('\\'));
                            var sig = matcher.MatchName(path) ?? matcher.MatchFolderName(leaf);
                            if (sig != null)
                            {
                                var f = FromSignature(sig, Evidence.Excluded, path, null, "Defender exclusion");
                                f.Note = "This was added to Windows Security's exclusions so it won't be scanned. Executors usually ask users to do this.";
                                Add(f);
                                count++;
                            }
                            else if (path.TrimEnd('\\').Length <= 2)
                            {
                                Add(Simple("Whole drive hidden from antivirus", "Antivirus exclusion", Severity.Medium, Evidence.Excluded, Groups.Tamper, null, path, "Defender exclusion",
                                    "Windows Security is told to skip this entire drive."));
                                count++;
                            }
                            else if (Regex.IsMatch(path, @"\\(Downloads|Desktop|AppData|Temp|OneDrive)(\\|$)", RegexOptions.IgnoreCase))
                            {
                                Add(Simple("Antivirus exclusion in a user folder", "Antivirus exclusion", Severity.Medium, Evidence.Excluded, Groups.Tamper, null, path, "Defender exclusion",
                                    "Cheats are often kept in excluded folders so antivirus doesn't remove them. Some normal apps ask for this too."));
                                count++;
                            }
                        }
                    }
                }
                catch (Exception ex) { notes.Add("Couldn't read antivirus exclusions: " + ex.Message); break; }
            }
            return count;
        }

        /// <summary>Cleared event logs and clock changes in the last 90 days.</summary>
        string ScanLogs()
        {
            const string last90Days = "TimeCreated[timediff(@SystemTime) <= 7776000000]";
            var found = new List<string>();

            try
            {
                ReadEvents("Security", "*[System[(EventID=1102) and " + last90Days + "]]", 50, (time, id, data) =>
                {
                    Add(Simple("Security log cleared", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, time, "Event 1102, Security log", "Windows event log",
                        "Someone with admin rights wiped the Security event log."));
                    if (!found.Contains("Security log cleared")) found.Add("Security log cleared");
                });
            }
            catch (Exception ex) { notes.Add("Security log unavailable: " + ex.Message); }

            try
            {
                ReadEvents("System", "*[System[(EventID=104) and " + last90Days + "]]", 50, (time, id, data) =>
                {
                    string channel;
                    if (!data.TryGetValue("Channel", out channel) || string.IsNullOrEmpty(channel)) channel = "An event";
                    Add(Simple(channel + " log cleared", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, time, "Event 104, " + channel + " log", "Windows event log",
                        "An event log was wiped. Cleaners and some cheat tools do this to hide what ran."));
                    if (!found.Contains("Logs cleared")) found.Add("Logs cleared");
                });
            }
            catch (Exception ex) { notes.Add("System log unavailable: " + ex.Message); }

            try
            {
                int changes = 0;
                ReadEvents("Security", "*[System[(EventID=4616) and " + last90Days + "]]", 300, (time, id, data) =>
                {
                    if (changes >= 10) return;
                    string process, before, after;
                    data.TryGetValue("ProcessName", out process);
                    data.TryGetValue("PreviousTime", out before);
                    data.TryGetValue("NewTime", out after);
                    process = process ?? "";
                    if (process.EndsWith("svchost.exe", StringComparison.OrdinalIgnoreCase)) return;   // normal internet time sync
                    DateTime b, a;
                    if (!DateTime.TryParse(before, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out b) ||
                        !DateTime.TryParse(after, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out a)) return;
                    if (Math.Abs((a - b).TotalMinutes) < 10) return;
                    changes++;
                    Add(Simple("Clock was changed", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, time,
                        "From " + b.ToLocalTime().ToString("g") + " to " + a.ToLocalTime().ToString("g"),
                        "Windows event log (4616)",
                        "Changed by " + (process.Length > 0 ? Path.GetFileName(process) : "an unknown program") + ". Changing the clock can make file times look older or newer than they are."));
                    if (!found.Contains("Clock changed")) found.Add("Clock changed");
                });
            }
            catch { }

            Tick("Checking when Windows was reset", 0.5);
            DateTime? resetDate = ScanResets(found);
            Tick("Checking how far back the logs go", 0.7);
            ScanShortLogs(resetDate, found);
            Tick("Checking firewall rules", 0.85);
            ScanFirewall(found);

            if (!admin && found.Count == 0) return "Partial (needs admin)";
            return found.Count == 0 ? "Nothing unusual" : string.Join(", ", found);
        }

        /// <summary>When Windows was last installed or reset, telling resets apart from big Windows updates.</summary>
        DateTime? ScanResets(List<string> found)
        {
            DateTime? installed = WindowsInstallDate();
            DateTime? lastUpgrade = null;
            try
            {
                using (var setup = Registry.LocalMachine.OpenSubKey(@"SYSTEM\Setup"))
                {
                    if (setup != null)
                        foreach (var name in setup.GetSubKeyNames())
                        {
                            var t = Parsers.ParseSourceOsDate(name);
                            if (t.HasValue && (!lastUpgrade.HasValue || t.Value > lastUpgrade.Value)) lastUpgrade = t;
                        }
                }
            }
            catch { }

            // A big Windows update also rewrites the install date. If they match, it was an update, not a reset.
            bool installWasUpgrade = installed.HasValue && lastUpgrade.HasValue && Math.Abs((installed.Value - lastUpgrade.Value).TotalDays) < 2;
            DateTime? resetDate = installWasUpgrade ? null : installed;
            var week = DateTime.Now.AddDays(-7);

            if (resetDate.HasValue)
            {
                bool recent = resetDate.Value > week;
                Add(Simple(recent ? "PC was reset this week" : "Windows installed or last reset", "PC reset",
                    recent ? Severity.Medium : Severity.Info, recent ? Evidence.Reset : Evidence.Context, Groups.Tamper, resetDate,
                    "Windows install date", "Registry",
                    recent ? "Resetting Windows wipes most traces. Ask why it was reset right before the check."
                           : "When Windows was last installed fresh or reset. Shown for the timeline."));
                if (recent) found.Add("PC reset recently");
            }
            if (lastUpgrade.HasValue)
            {
                Add(Simple("Last big Windows update", "PC reset", Severity.Info, Evidence.Context, Groups.Context, lastUpgrade,
                    "Windows feature update", "Registry", "A normal Windows update. Not a reset."));
            }

            // When the Windows account doing the check was created.
            try
            {
                string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                DateTime created = Directory.GetCreationTime(profile);
                bool newAccount = created > week && (!resetDate.HasValue || created > resetDate.Value.AddDays(1));
                Add(Simple(newAccount ? "New Windows account" : "Windows account created", "PC reset",
                    newAccount ? Severity.Medium : Severity.Info, newAccount ? Evidence.Reset : Evidence.Context, Groups.Tamper, created,
                    "This Windows account", "User folder",
                    newAccount ? "This account is less than a week old. A fresh account has no history, so ask why it's new."
                               : "When the Windows account doing the check was created."));
                if (newAccount) found.Add("New account");
            }
            catch { }
            return resetDate;
        }

        /// <summary>Logs that start very recently on an older PC may have been cleared another way.</summary>
        void ScanShortLogs(DateTime? resetDate, List<string> found)
        {
            DateTime? installed = WindowsInstallDate();
            DateTime pcAge = resetDate ?? installed ?? DateTime.MinValue;
            if (pcAge > DateTime.Now.AddDays(-4)) return;   // a new PC naturally has short logs
            foreach (var channel in new[] { "System", "Security", "Application" })
            {
                try
                {
                    DateTime? oldest = OldestEvent(channel);
                    if (oldest.HasValue && oldest.Value > DateTime.Now.AddDays(-2))
                    {
                        Add(Simple(channel + " log is unusually short", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, oldest,
                            channel + " log starts " + oldest.Value.ToString("g"), "Windows event log",
                            "This PC is older than its log. The log may have been cleared, or its size was set very small."));
                        if (!found.Contains("Short logs")) found.Add("Short logs");
                    }
                }
                catch { }
            }
        }

        static DateTime? OldestEvent(string channel)
        {
            var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(channel, System.Diagnostics.Eventing.Reader.PathType.LogName, "*") { ReverseDirection = false };
            using (var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query))
            using (var first = reader.ReadEvent())
                return first == null ? null : first.TimeCreated;
        }

        /// <summary>Windows Firewall rules that block Roblox. Switching one on and off is a common lag switch.</summary>
        void ScanFirewall(List<string> found)
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"))
                {
                    if (key == null) return;
                    foreach (var valueName in key.GetValueNames())
                    {
                        string rule = key.GetValue(valueName) as string;
                        if (!Parsers.BlocksRoblox(rule)) continue;
                        bool active = string.Equals(Parsers.FirewallField(rule, "Active"), "TRUE", StringComparison.OrdinalIgnoreCase);
                        string ruleName = Parsers.FirewallField(rule, "Name") ?? valueName;
                        Add(Simple("Firewall rule blocks Roblox", "Lag switch", Severity.Medium, Evidence.LagSwitch, Groups.Cheat, null,
                            ruleName + (active ? " (on)" : " (off)") + ": " + Parsers.FirewallField(rule, "App"), "Windows Firewall",
                            "A rule that cuts Roblox's connection can be switched on and off to lag on purpose. Some network tools add rules like this for other reasons."));
                        if (!found.Contains("Roblox firewall rule")) found.Add("Roblox firewall rule");
                    }
                }
            }
            catch (Exception ex) { notes.Add("Couldn't read firewall rules: " + ex.Message); }
        }

        /// <summary>FastFlag files from Roblox and launchers like Bloxstrap or Fishstrap.</summary>
        string ScanFastFlags()
        {
            var files = new List<KeyValuePair<string, string>>();   // path, source
            foreach (var p in profiles)
            {
                string local = Path.Combine(p.Path, @"AppData\Local");
                AddFlagFilesUnder(files, Path.Combine(local, @"Roblox\Versions"), "Roblox");
                AddFlagFile(files, Path.Combine(local, @"Roblox\ClientSettings\ClientAppSettings.json"), "Roblox");
                try
                {
                    foreach (var dir in Directory.GetDirectories(local, "*strap"))
                    {
                        string name = Path.GetFileName(dir);
                        AddFlagFile(files, Path.Combine(dir, @"Modifications\ClientSettings\ClientAppSettings.json"), name);
                        // Bootstrappers are allowed. Unknown ones are still listed so moderators know what was used.
                        if (matcher.MatchName(name) == null)
                            Add(Simple(name, "Roblox bootstrapper (allowed)", Severity.Info, Evidence.Context, Groups.Context, Directory.GetLastWriteTime(dir), dir, "AppData",
                                "A Roblox launcher. Bootstrappers are normal; listed so moderators know which one is used."));
                    }
                }
                catch { }

                // FastFlag list files people download (names only, then read if they look like FastFlags).
                foreach (var sub in new[] { "Desktop", "Downloads", "Documents", @"OneDrive\Desktop", @"OneDrive\Documents" })
                    AddLooseFlagFiles(files, Path.Combine(p.Path, sub));

                // When Roblox was last opened, to help line up the timeline.
                try
                {
                    var logs = new DirectoryInfo(Path.Combine(local, @"Roblox\logs"));
                    if (logs.Exists)
                    {
                        var newest = logs.EnumerateFiles("*.log").OrderByDescending(f => f.LastWriteTime).FirstOrDefault();
                        if (newest != null)
                            Add(Simple("Roblox last used", "Roblox", Severity.Info, Evidence.Context, Groups.Context, newest.LastWriteTime,
                                logs.FullName, "Roblox logs", "Helps line up the timeline with the other findings."));
                    }
                }
                catch { }
            }
            foreach (var pf in ProgramFilesDirs())
                AddFlagFilesUnder(files, Path.Combine(pf, @"Roblox\Versions"), "Roblox");

            int unfair = 0, otherTotal = 0;
            foreach (var file in files)
            {
                try
                {
                    var info = new FileInfo(file.Key);
                    if (info.Length > 4 * 1024 * 1024) continue;
                    var flags = Json.Object(Json.Parse(File.ReadAllText(file.Key)));
                    int other;
                    var hits = Parsers.AnalyzeFastFlags(flags, set.FlagWords, out other);
                    foreach (var h in hits)
                    {
                        var f = Simple(h.Name, "FastFlag", Severity.Medium, Evidence.FastFlag, Groups.FastFlags, info.LastWriteTime, file.Key, file.Value,
                            "Set to " + h.Value + ". Its name contains \"" + h.Word + "\", which is used for unfair advantages like desync or bigger hitboxes. Roblox only honors an allowlist of FastFlags now, so it may have no effect, but it's worth asking about.");
                        Add(f);
                        unfair++;
                    }
                    if (other > 0)
                    {
                        otherTotal += other;
                        Add(Simple(other + " other FastFlags", "FastFlags (visual or performance)", Severity.Info, Evidence.Context, Groups.FastFlags, info.LastWriteTime, file.Key, file.Value,
                            "These don't match the unfair list. They're usually graphics or FPS tweaks."));
                    }
                }
                catch (Exception)
                {
                    Add(Simple("FastFlag file couldn't be read", "FastFlags", Severity.Info, Evidence.Context, Groups.FastFlags, null, file.Key, file.Value, "The file isn't valid JSON."));
                }
            }

            if (files.Count == 0) return "No FastFlag files";
            if (unfair == 0) return otherTotal > 0 ? "No unfair flags (" + otherTotal + " other)" : "No unfair flags";
            return unfair + (unfair == 1 ? " unfair flag" : " unfair flags");
        }

        void AddLooseFlagFiles(List<KeyValuePair<string, string>> files, string folder)
        {
            if (set.LooseFlagFileWords.Count == 0) return;
            try
            {
                if (!Directory.Exists(folder)) return;
                var candidates = Directory.GetFiles(folder, "*.json").ToList();
                foreach (var sub in Directory.GetDirectories(folder))
                {
                    try { candidates.AddRange(Directory.GetFiles(sub, "*.json")); } catch { }
                    if (candidates.Count > 2000) break;
                }
                foreach (var f in candidates)
                {
                    string n = SignatureSet.Clean(Path.GetFileNameWithoutExtension(f));
                    if (set.LooseFlagFileWords.Any(w => w.Length > 0 && n.Contains(w)))
                        AddFlagFile(files, f, "Loose file in " + Path.GetFileName(folder));
                }
            }
            catch { }
        }

        static void AddFlagFilesUnder(List<KeyValuePair<string, string>> files, string versionsDir, string source)
        {
            try
            {
                if (!Directory.Exists(versionsDir)) return;
                foreach (var v in Directory.GetDirectories(versionsDir))
                    AddFlagFile(files, Path.Combine(v, @"ClientSettings\ClientAppSettings.json"), source);
            }
            catch { }
        }

        static void AddFlagFile(List<KeyValuePair<string, string>> files, string path, string source)
        {
            try
            {
                if (File.Exists(path) && !files.Any(f => f.Key.Equals(path, StringComparison.OrdinalIgnoreCase)))
                    files.Add(new KeyValuePair<string, string>(path, source));
            }
            catch { }
        }
    }
}
