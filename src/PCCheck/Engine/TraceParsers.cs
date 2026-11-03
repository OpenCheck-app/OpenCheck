using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PCCheck.Engine
{
    /// <summary>A program path and when it ran, from a record that cleaners usually don't touch.</summary>
    public sealed class TraceRun
    {
        public string Path;
        public DateTime? Time;
    }

    /// <summary>
    /// Parsers for extra Windows records that survive most cleaners: the Program Compatibility Assistant
    /// launch log, Windows Defender's own support log, Windows crash reports, PowerShell history and
    /// service installs. All pure functions over text, so they can be tested without Windows.
    /// </summary>
    public static class TraceParsers
    {
        /// <summary>Text files Windows writes as UTF-16 (often without a BOM) or as UTF-8/ANSI.</summary>
        public static string DecodeText(byte[] data)
        {
            if (data == null || data.Length == 0) return "";
            if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE) return Encoding.Unicode.GetString(data, 2, data.Length - 2);
            if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) return Encoding.UTF8.GetString(data, 3, data.Length - 3);
            int sample = Math.Min(data.Length, 400), zeros = 0;
            for (int i = 1; i < sample; i += 2) if (data[i] == 0) zeros++;
            return zeros > sample / 4 ? Encoding.Unicode.GetString(data) : Encoding.UTF8.GetString(data);
        }

        static readonly string[] TimeFormats = { "yyyy-MM-dd HH:mm:ss.fff", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-ddTHH:mm:ss.fffZ", "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-ddTHH:mm:ss.fff" };

        static DateTime? ParseUtc(string s)
        {
            DateTime t;
            if (DateTime.TryParseExact((s ?? "").Trim(), TimeFormats, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out t))
                return t.ToLocalTime();
            return null;
        }

        static bool LooksLikeProgramPath(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 7) return false;
            bool rooted = (char.IsLetter(s[0]) && s[1] == ':' && s[2] == '\\') || s.StartsWith(@"\\", StringComparison.Ordinal);
            return rooted && (s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// One line of the Program Compatibility Assistant log (Windows 11 22H2 and later):
        /// PcaAppLaunchDic.txt is "path|time", PcaGeneralDb0.txt is "time|status|path|...". Times are UTC.
        /// </summary>
        public static TraceRun ParsePcaLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return null;
            var parts = line.Trim().Split('|');
            string path = parts.Select(p => p.Trim()).FirstOrDefault(LooksLikeProgramPath);
            if (path == null) return null;
            DateTime? time = null;
            foreach (var p in parts) { time = ParseUtc(p); if (time.HasValue) break; }
            return new TraceRun { Path = path, Time = time };
        }

        static readonly Regex MpLogPath = new Regex(@"(?:[A-Za-z]:\\|\\Device\\HarddiskVolume\d+\\)[^|<>""\r\n:*?]{1,240}?\.(?:exe|dll)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex MpLogImage = new Regex(@"ProcessImageName:\s*([^,\r\n]{1,120}?\.exe)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex LeadingTime = new Regex(@"^\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)", RegexOptions.Compiled);

        /// <summary>
        /// Program paths in one line of Windows Defender's support log (MPLog). Defender looks at every program
        /// that starts, and keeps this log for weeks. Cleaners don't touch it.
        /// </summary>
        public static List<TraceRun> MpLogRuns(string line)
        {
            var list = new List<TraceRun>();
            if (string.IsNullOrEmpty(line) || line.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) < 0 && line.IndexOf(".dll", StringComparison.OrdinalIgnoreCase) < 0) return list;
            DateTime? time = null;
            var tm = LeadingTime.Match(line);
            if (tm.Success)
            {
                DateTime t;
                if (DateTime.TryParse(tm.Groups[1].Value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t))
                    time = t.ToLocalTime();
            }
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match m in MpLogPath.Matches(line))
                if (seen.Add(m.Value)) list.Add(new TraceRun { Path = m.Value, Time = time });
            foreach (Match m in MpLogImage.Matches(line))
            {
                string name = m.Groups[1].Value.Trim();
                if (!seen.Any(s => s.EndsWith("\\" + name, StringComparison.OrdinalIgnoreCase)) && seen.Add(name))
                    list.Add(new TraceRun { Path = name, Time = time });
            }
            return list;
        }

        static readonly Regex WerFolder = new Regex(@"^(?:AppCrash|AppHang|BEX|BEX64|APPCRASH|Critical|NonCritical)_(.+?\.(?:exe|dll))_", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>The program name in a Windows crash report folder, like "AppCrash_Solara.exe_3f2a..._cab_1234".</summary>
        public static string WerFolderProgram(string folderName)
        {
            if (string.IsNullOrEmpty(folderName)) return null;
            var m = WerFolder.Match(folderName);
            return m.Success ? m.Groups[1].Value : null;
        }

        /// <summary>Folders where programs that legitimately load into games live (overlays, recorders, Roblox itself).</summary>
        static readonly string[] TrustedModulePlaces =
        {
            @"\windows\", @"\program files\", @"\program files (x86)\", @"\programdata\microsoft\", @"\programdata\nvidia",
            @"\appdata\local\roblox\", @"\appdata\local\bloxstrap\", @"\appdata\local\fishstrap\", @"\appdata\local\voidstrap\",
            @"\appdata\local\discord\", @"\appdata\local\discordptb\", @"\appdata\local\discordcanary\", @"\appdata\local\medal\",
            @"\appdata\local\overwolf\", @"\appdata\local\nvidia", @"\appdata\local\amd\", @"\appdata\local\microsoft\",
            @"\appdata\local\programs\microsoft vs code\", @"\appdata\roaming\microsoft\", @"\appdata\local\obs-studio\"
        };

        /// <summary>
        /// From a Windows crash report (Report.wer) of Roblox: the extra program files (DLLs) that were loaded inside Roblox
        /// from places no overlay or recorder uses. Cheats inject a DLL into Roblox, and when Roblox crashes Windows writes
        /// the full list down.
        /// </summary>
        public static List<string> UnusualRobloxModules(IEnumerable<string> reportLines)
        {
            var result = new List<string>();
            bool roblox = false;
            var modules = new List<string>();
            foreach (var raw in reportLines ?? Enumerable.Empty<string>())
            {
                string line = raw.Trim();
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq), value = line.Substring(eq + 1).Trim();
                if ((key.Equals("AppPath", StringComparison.OrdinalIgnoreCase) || key.Equals("AppName", StringComparison.OrdinalIgnoreCase) || key.StartsWith("Sig[0]", StringComparison.OrdinalIgnoreCase))
                    && value.IndexOf("RobloxPlayerBeta", StringComparison.OrdinalIgnoreCase) >= 0) roblox = true;
                if (key.StartsWith("LoadedModule[", StringComparison.OrdinalIgnoreCase)) modules.Add(value);
            }
            if (!roblox) return result;
            foreach (var m in modules)
            {
                string p = m.ToLowerInvariant();
                if (!p.EndsWith(".dll") && !p.EndsWith(".exe") && !p.EndsWith(".bin")) continue;
                if (p.Length < 4 || p[1] != ':') continue;
                if (TrustedModulePlaces.Any(t => p.Contains(t))) continue;
                if (!result.Contains(m, StringComparer.OrdinalIgnoreCase)) result.Add(m);
            }
            return result;
        }

        static readonly Tuple<Regex, string>[] CleanupCommands =
        {
            Tuple.Create(new Regex(@"\bfsutil(\.exe)?\s+usn\s+deletejournal\b", RegexOptions.IgnoreCase), "Deleted the drive change log"),
            Tuple.Create(new Regex(@"\bwevtutil(\.exe)?\s+(cl|clear-log)\b|\bClear-EventLog\b|\bRemove-EventLog\b|\bClear-WinEvent\b", RegexOptions.IgnoreCase), "Cleared event logs"),
            Tuple.Create(new Regex(@"\b(del|erase|rd|rmdir|rm|ri|Remove-Item)\b[^\r\n]*\\Prefetch\b", RegexOptions.IgnoreCase), "Deleted Prefetch"),
            Tuple.Create(new Regex(@"\b(reg(\.exe)?\s+delete|Remove-Item|Remove-ItemProperty|Clear-ItemProperty|ri|rp)\b[^\r\n]*\\(bam|UserAssist|AppCompatCache|MuiCache|Compatibility Assistant|BagMRU|RecentDocs)\b", RegexOptions.IgnoreCase), "Deleted program history from the registry"),
            Tuple.Create(new Regex(@"\bvssadmin(\.exe)?\s+delete\s+shadows\b|\bshadowcopy\s+delete\b", RegexOptions.IgnoreCase), "Deleted restore points"),
            Tuple.Create(new Regex(@"\b(del|erase|rd|rmdir|rm|ri|Remove-Item)\b[^\r\n]*\\Recent\b", RegexOptions.IgnoreCase), "Deleted recent-file history"),
            Tuple.Create(new Regex(@"\b(del|erase|rd|rmdir|rm|ri|Remove-Item)\b[^\r\n]*\\Roblox\\logs\b", RegexOptions.IgnoreCase), "Deleted Roblox logs"),
            Tuple.Create(new Regex(@"\b(del|erase|rd|rmdir|rm|ri|Remove-Item)\b[^\r\n]*\\appcompat\\pca\b", RegexOptions.IgnoreCase), "Deleted the program launch log"),
            Tuple.Create(new Regex(@"\bSet-MpPreference\b[^\r\n]*-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection)\s+\$?(true|1)\b|\bAdd-MpPreference\b[^\r\n]*-Exclusion", RegexOptions.IgnoreCase), "Changed antivirus settings"),
        };

        /// <summary>What a typed command does, if it's one of the commands used to wipe the records a PC check reads.</summary>
        public static string CleanupCommand(string line)
        {
            if (string.IsNullOrWhiteSpace(line) || line.Length > 2000) return null;
            foreach (var c in CleanupCommands) if (c.Item1.IsMatch(line)) return c.Item2;
            return null;
        }

        /// <summary>A driver file sitting in a user's own folders. Real drivers install under Windows or Program Files.</summary>
        public static bool IsPersonalFolderDriver(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;
            string p = imagePath.Trim('"', ' ').ToLowerInvariant();
            if (!p.EndsWith(".sys")) return false;
            return p.Contains(@"\users\") || p.Contains(@"\temp\") || p.Contains(@"\downloads\") || p.Contains(@"\desktop\");
        }
    }
}
