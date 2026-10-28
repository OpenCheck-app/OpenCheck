using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PCCheck.Engine
{
    public sealed class UserAssistEntry { public int RunCount; public DateTime? LastRun; }

    public sealed class RecycleEntry { public string OriginalPath; public DateTime? Deleted; public long Size; }

    public sealed class UsnRecord
    {
        public long FileRef;
        public long ParentRef;
        public long Usn;
        public DateTime? Time;
        public uint Reason;
        public uint Attributes;
        public string Name;
    }

    public sealed class PrefetchInfo { public int Version; public int RunCount; public List<DateTime> RunTimes = new List<DateTime>(); }

    public sealed class DeviceInstall { public DateTime Time; public string DeviceId; }

    public sealed class FlagHit { public string Name; public string Value; public string Word; }

    /// <summary>Pure parsing functions for Windows record formats. No file or registry access here, so they're easy to test.</summary>
    public static class Parsers
    {
        public const uint UsnReasonFileCreate = 0x00000100;
        public const uint UsnReasonFileDelete = 0x00000200;
        public const uint UsnReasonRenameOldName = 0x00001000;

        static readonly DateTime MinSane = new DateTime(2000, 1, 1);

        /// <summary>FILETIME (UTC ticks since 1601) to local time. Returns null for empty or impossible values.</summary>
        public static DateTime? FromFileTime(long fileTime)
        {
            if (fileTime <= 0) return null;
            try
            {
                var utc = DateTime.FromFileTimeUtc(fileTime);
                if (utc < MinSane || utc > DateTime.UtcNow.AddDays(2)) return null;
                return utc.ToLocalTime();
            }
            catch (ArgumentOutOfRangeException) { return null; }
        }

        public static string Rot13(string s)
        {
            if (s == null) return null;
            var chars = s.ToCharArray();
            for (int i = 0; i < chars.Length; i++)
            {
                char c = chars[i];
                if (c >= 'a' && c <= 'z') chars[i] = (char)('a' + (c - 'a' + 13) % 26);
                else if (c >= 'A' && c <= 'Z') chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            }
            return new string(chars);
        }

        /// <summary>UserAssist value data (Windows 7+, 72 bytes): run count at offset 4, last run FILETIME at offset 60.</summary>
        public static UserAssistEntry ParseUserAssist(byte[] data)
        {
            if (data == null || data.Length < 68) return null;
            return new UserAssistEntry
            {
                RunCount = Math.Max(0, BitConverter.ToInt32(data, 4)),
                LastRun = FromFileTime(BitConverter.ToInt64(data, 60))
            };
        }

        static readonly Dictionary<string, string> KnownFolders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "{6D809377-6AF0-444B-8957-A3773F02200E}", @"C:\Program Files" },
            { "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", @"C:\Program Files (x86)" },
            { "{F38BF404-1D43-42F2-9305-67DE0B28FC23}", @"C:\Windows" },
            { "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", @"C:\Windows\System32" },
            { "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", @"C:\Windows\SysWOW64" },
            { "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}", @"C:\ProgramData" },
            { "{374DE290-123F-4565-9164-39C4925E467B}", @"~\Downloads" },
            { "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", @"~\Desktop" },
            { "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", @"~\Documents" },
            { "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}", @"~\AppData\Local" },
            { "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}", @"~\AppData\Roaming" },
            { "{A520A1A4-1780-4FF6-BD18-167343C5AF16}", @"~\AppData\LocalLow" },
        };

        /// <summary>UserAssist paths start with a known-folder GUID. Turns "{6D80...}\Epic Games\x.exe" into "C:\Program Files\Epic Games\x.exe".</summary>
        public static string ExpandKnownFolder(string path)
        {
            if (string.IsNullOrEmpty(path) || path[0] != '{') return path;
            int end = path.IndexOf('}');
            if (end < 0) return path;
            string guid = path.Substring(0, end + 1);
            string folder;
            return KnownFolders.TryGetValue(guid, out folder) ? folder + path.Substring(end + 1) : path;
        }

        /// <summary>BAM stores "\Device\HarddiskVolume3\...". Converts it with a map of device -> drive letter.</summary>
        public static string ConvertDevicePath(string path, IDictionary<string, string> deviceToDrive)
        {
            if (string.IsNullOrEmpty(path) || !path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return path;
            foreach (var kv in deviceToDrive)
            {
                string dev = kv.Key.TrimEnd('\\');
                if (path.StartsWith(dev + @"\", StringComparison.OrdinalIgnoreCase))
                    return kv.Value.TrimEnd('\\') + path.Substring(dev.Length);
            }
            return path;
        }

        /// <summary>Recycle Bin $I file. Version 1 (Vista-8): fixed 520-byte path. Version 2 (Windows 10+): length-prefixed path.</summary>
        public static RecycleEntry ParseRecycleBinInfo(byte[] data)
        {
            if (data == null || data.Length < 24) return null;
            long version = BitConverter.ToInt64(data, 0);
            var e = new RecycleEntry
            {
                Size = BitConverter.ToInt64(data, 8),
                Deleted = FromFileTime(BitConverter.ToInt64(data, 16))
            };
            if (version == 1)
            {
                int len = Math.Min(520, data.Length - 24);
                e.OriginalPath = Encoding.Unicode.GetString(data, 24, len).TrimEnd('\0');
            }
            else if (version == 2 && data.Length >= 28)
            {
                int chars = BitConverter.ToInt32(data, 24);
                int bytes = Math.Min(chars * 2, data.Length - 28);
                if (bytes < 0) return null;
                e.OriginalPath = Encoding.Unicode.GetString(data, 28, bytes).TrimEnd('\0');
            }
            else return null;
            int nul = e.OriginalPath.IndexOf('\0');
            if (nul >= 0) e.OriginalPath = e.OriginalPath.Substring(0, nul);
            return e;
        }

        /// <summary>
        /// Reads USN_RECORD_V2 entries from a FSCTL_READ_USN_JOURNAL output buffer.
        /// The first 8 bytes of the buffer are the next USN and are skipped.
        /// </summary>
        public static List<UsnRecord> ParseUsnBuffer(byte[] buffer, int length)
        {
            var list = new List<UsnRecord>();
            int off = 8;
            while (off + 60 <= length)
            {
                int recLen = BitConverter.ToInt32(buffer, off);
                if (recLen < 60 || off + recLen > length) break;
                int major = BitConverter.ToUInt16(buffer, off + 4);
                if (major == 2)
                {
                    int nameLen = BitConverter.ToUInt16(buffer, off + 56);
                    int nameOff = BitConverter.ToUInt16(buffer, off + 58);
                    string name = (nameOff + nameLen <= recLen) ? Encoding.Unicode.GetString(buffer, off + nameOff, nameLen) : "";
                    list.Add(new UsnRecord
                    {
                        FileRef = BitConverter.ToInt64(buffer, off + 8),
                        ParentRef = BitConverter.ToInt64(buffer, off + 16),
                        Usn = BitConverter.ToInt64(buffer, off + 24),
                        Time = FromFileTime(BitConverter.ToInt64(buffer, off + 32)),
                        Reason = BitConverter.ToUInt32(buffer, off + 40),
                        Attributes = BitConverter.ToUInt32(buffer, off + 52),
                        Name = name
                    });
                }
                off += recLen;
            }
            return list;
        }

        /// <summary>Reads run times and run count from a decompressed Prefetch file (versions 17, 23, 26, 30, 31).</summary>
        public static PrefetchInfo ParsePrefetch(byte[] d)
        {
            if (d == null || d.Length < 0x9C) return null;
            if (d[4] != (byte)'S' || d[5] != (byte)'C' || d[6] != (byte)'C' || d[7] != (byte)'A') return null;
            var info = new PrefetchInfo { Version = BitConverter.ToInt32(d, 0) };
            switch (info.Version)
            {
                case 17:
                    AddTime(info, d, 0x78);
                    info.RunCount = BitConverter.ToInt32(d, 0x90);
                    break;
                case 23:
                    AddTime(info, d, 0x80);
                    info.RunCount = BitConverter.ToInt32(d, 0x98);
                    break;
                case 26:
                case 30:
                case 31:
                    if (d.Length < 0xD4) return info;
                    for (int i = 0; i < 8; i++) AddTime(info, d, 0x80 + i * 8);
                    int a = BitConverter.ToInt32(d, 0xD0), b = BitConverter.ToInt32(d, 0xC8);
                    info.RunCount = Plausible(a) ? a : Plausible(b) ? b : 0;
                    break;
            }
            info.RunTimes.Sort((x, y) => y.CompareTo(x));
            if (info.RunCount < info.RunTimes.Count) info.RunCount = info.RunTimes.Count;
            return info;
        }

        static bool Plausible(int n) { return n > 0 && n < 1000000; }

        static void AddTime(PrefetchInfo info, byte[] d, int offset)
        {
            if (offset + 8 > d.Length) return;
            var t = FromFileTime(BitConverter.ToInt64(d, offset));
            if (t.HasValue) info.RunTimes.Add(t.Value);
        }

        static readonly Regex SetupDevice = new Regex(@"^>>>\s+\[Device Install[^\]]*-\s*(?<id>[^\]]+)\]", RegexOptions.Compiled);
        static readonly Regex SetupStart = new Regex(@"^>>>\s+Section start (?<t>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", RegexOptions.Compiled);

        /// <summary>Finds device installs in C:\Windows\INF\setupapi.dev.log.</summary>
        public static List<DeviceInstall> ParseSetupApiLog(IEnumerable<string> lines)
        {
            var list = new List<DeviceInstall>();
            string pending = null;
            foreach (var line in lines)
            {
                var m = SetupDevice.Match(line);
                if (m.Success) { pending = m.Groups["id"].Value.Trim(); continue; }
                if (pending == null) continue;
                var s = SetupStart.Match(line);
                if (s.Success)
                {
                    DateTime t;
                    if (DateTime.TryParseExact(s.Groups["t"].Value, "yyyy/MM/dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out t))
                        list.Add(new DeviceInstall { Time = t, DeviceId = pending });
                    pending = null;
                }
            }
            return list;
        }

        static readonly Regex VendorRx = new Regex(@"VEN_([0-9A-Fa-f]{4})", RegexOptions.Compiled);

        public static string PciVendor(string deviceId)
        {
            if (string.IsNullOrEmpty(deviceId)) return null;
            var m = VendorRx.Match(deviceId);
            return m.Success ? m.Groups[1].Value.ToUpperInvariant() : null;
        }

        /// <summary>Flags FastFlags whose name contains a suspicious word. Returns hits; otherCount is the number of other flags.</summary>
        public static List<FlagHit> AnalyzeFastFlags(IDictionary<string, object> flags, IList<string> words, out int otherCount)
        {
            var hits = new List<FlagHit>();
            otherCount = 0;
            foreach (var kv in flags)
            {
                string word = words.FirstOrDefault(w => kv.Key.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0);
                if (word != null)
                    hits.Add(new FlagHit { Name = kv.Key, Value = kv.Value == null ? "null" : Convert.ToString(kv.Value, CultureInfo.InvariantCulture), Word = word });
                else
                    otherCount++;
            }
            return hits;
        }

        /// <summary>Times where at least `threshold` deletions happened within `window`. Used to spot Prefetch being wiped.</summary>
        public static DateTime? FindBurst(List<DateTime> times, int threshold, TimeSpan window)
        {
            if (times.Count < threshold) return null;
            var sorted = times.OrderBy(t => t).ToList();
            DateTime? latest = null;
            for (int i = 0; i + threshold - 1 < sorted.Count; i++)
                if (sorted[i + threshold - 1] - sorted[i] <= window) latest = sorted[i + threshold - 1];
            return latest;
        }

        /// <summary>Reads one field ("App", "Name", "Action"...) from a Windows Firewall rule string like "v2.30|Action=Block|App=C:\x.exe|".</summary>
        public static string FirewallField(string rule, string field)
        {
            if (string.IsNullOrEmpty(rule)) return null;
            foreach (var part in rule.Split('|'))
            {
                int eq = part.IndexOf('=');
                if (eq > 0 && part.Substring(0, eq).Equals(field, StringComparison.OrdinalIgnoreCase)) return part.Substring(eq + 1);
            }
            return null;
        }

        /// <summary>True when a firewall rule blocks a Roblox program (a common lag-switch trick).</summary>
        public static bool BlocksRoblox(string rule)
        {
            string action = FirewallField(rule, "Action"), app = FirewallField(rule, "App");
            return action != null && action.Equals("Block", StringComparison.OrdinalIgnoreCase)
                && app != null && app.IndexOf("roblox", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        static readonly Regex SourceOsDate = new Regex(@"Updated on (?<d>[0-9/]+ [0-9:]+)", RegexOptions.Compiled);

        /// <summary>Windows keeps "Source OS (Updated on 10/1/2024 12:00:00)" keys for big updates. Returns that date.</summary>
        public static DateTime? ParseSourceOsDate(string keyName)
        {
            if (string.IsNullOrEmpty(keyName)) return null;
            var m = SourceOsDate.Match(keyName);
            DateTime t;
            if (m.Success && DateTime.TryParse(m.Groups["d"].Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out t)) return t;
            return null;
        }

        /// <summary>Roblox log files look like "0.687.0.6870758_20251002T120000Z_Player_A1B2C_last.log".</summary>
        public static bool IsRobloxLogName(string name)
        {
            return !string.IsNullOrEmpty(name) && name.EndsWith(".log", StringComparison.OrdinalIgnoreCase)
                && name.IndexOf("_Player_", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>Jump lists ("recent files" per program) end in automaticDestinations-ms or customDestinations-ms.</summary>
        public static bool IsJumpListName(string name)
        {
            return !string.IsNullOrEmpty(name) && (name.EndsWith(".automaticDestinations-ms", StringComparison.OrdinalIgnoreCase)
                || name.EndsWith(".customDestinations-ms", StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>Removes characters that could break a Discord message or the report layout.</summary>
        public static string SafeName(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder();
            foreach (char c in s)
            {
                if (char.IsControl(c) || c == '`' || c == '@' || c == '*' || c == '_' || c == '~' || c == '|' || c == '<' || c == '>') continue;
                sb.Append(c);
                if (sb.Length >= max) break;
            }
            return sb.ToString().Trim();
        }
    }
}
