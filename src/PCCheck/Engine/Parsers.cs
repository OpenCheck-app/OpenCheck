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

    public sealed class ShimEntry { public string Path; public DateTime? Modified; }

    public sealed class PrefetchInfo { public int Version; public int RunCount; public List<DateTime> RunTimes = new List<DateTime>(); }

    public sealed class DeviceInstall { public DateTime Time; public string DeviceId; }

    public sealed class FlagHit { public string Name; public string Value; public string Word; }

    /// <summary>Pure parsing functions for Windows record formats. No file or registry access here, so they're easy to test.</summary>
    public static class Parsers
    {
        public const uint UsnReasonFileCreate = 0x00000100;
        public const uint UsnReasonFileDelete = 0x00000200;
        public const uint UsnReasonRenameOldName = 0x00001000;
        public const uint UsnReasonRenameNewName = 0x00002000;

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
        /// <summary>
        /// Reads Windows 8/10/11 AppCompatCache (ShimCache) data: a header, then "10ts" entries holding a program path
        /// and that file's last-modified time. Windows keeps these for a long time, even after the file is deleted.
        /// </summary>
        public static List<ShimEntry> ParseShimCache(byte[] data)
        {
            var list = new List<ShimEntry>();
            if (data == null || data.Length < 8) return list;
            int off = BitConverter.ToInt32(data, 0);   // header size (0x30, 0x34 or 0x80)
            if (off < 4 || off > data.Length) return list;
            while (off + 12 <= data.Length && list.Count < 4096)
            {
                if (data[off] != (byte)'1' || data[off + 1] != (byte)'0' || data[off + 2] != (byte)'t' || data[off + 3] != (byte)'s') break;
                int entrySize = BitConverter.ToInt32(data, off + 8);
                int body = off + 12;
                if (entrySize < 2 || body + entrySize > data.Length) break;
                int pathLen = BitConverter.ToUInt16(data, body);
                if (body + 2 + pathLen + 8 <= body + entrySize)
                {
                    string path = Encoding.Unicode.GetString(data, body + 2, pathLen);
                    var modified = FromFileTime(BitConverter.ToInt64(data, body + 2 + pathLen));
                    list.Add(new ShimEntry { Path = path, Modified = modified });
                }
                off = body + entrySize;
            }
            return list;
        }

        static readonly Regex RobloxJoin = new Regex(@"! Joining game '([0-9a-fA-F-]+)' place (\d+)", RegexOptions.Compiled);
        static readonly Regex RobloxUniverse = new Regex(@"game_join_loadtime:.*?placeid:(\d+).*?universeid:(\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>The ISO time at the start of a Roblox log line ("2026-10-28T21:14:05.123Z,..."), as local time.</summary>
        public static DateTime? RobloxLogTime(string line)
        {
            if (line == null || line.Length < 20 || line[4] != '-' || line[10] != 'T') return null;
            int end = line.IndexOf('Z');
            if (end < 19 || end > 32) return null;
            DateTime t;
            if (DateTime.TryParse(line.Substring(0, end + 1), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t))
                return DateTime.SpecifyKind(t, DateTimeKind.Utc).ToLocalTime();
            return null;
        }

        /// <summary>
        /// Finds game sessions in a Roblox log: "! Joining game ... place N" starts one, and
        /// "Time to disconnect replication data" (or leaving / the next join) ends it. Only place IDs and times are kept.
        /// </summary>
        public static List<RobloxSession> ParseRobloxLog(IEnumerable<string> lines, DateTime? fileEnd)
        {
            var list = new List<RobloxSession>();
            RobloxSession cur = null;
            DateTime? lastTime = null;
            foreach (var line in lines)
            {
                if (line == null) continue;
                bool join = line.IndexOf("! Joining game", StringComparison.Ordinal) >= 0;
                bool load = !join && line.IndexOf("game_join_loadtime", StringComparison.OrdinalIgnoreCase) >= 0;
                bool leave = !join && !load && (line.IndexOf("Time to disconnect replication data", StringComparison.Ordinal) >= 0
                                             || line.IndexOf("leaveUGCGameInternal", StringComparison.Ordinal) >= 0);
                if (!join && !load && !leave)
                {
                    if (cur != null && (line.IndexOf("kick", StringComparison.OrdinalIgnoreCase) >= 0 || line.IndexOf("268", StringComparison.Ordinal) >= 0 || line.IndexOf("client behavio", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        var kick = KickFromLogLine(line);
                        if (kick != null && cur.KickReason == null) { cur.KickReason = kick; cur.KickTime = RobloxLogTime(line) ?? cur.Start; }
                    }
                    continue;
                }
                var t = RobloxLogTime(line);
                if (t.HasValue) lastTime = t;
                if (join)
                {
                    var m = RobloxJoin.Match(line);
                    long place;
                    if (!m.Success || !t.HasValue || !long.TryParse(m.Groups[2].Value, out place)) continue;
                    if (cur != null && !cur.End.HasValue) { cur.End = t; }
                    cur = new RobloxSession { PlaceId = place, Start = t.Value };
                    list.Add(cur);
                }
                else if (load && cur != null)
                {
                    var m = RobloxUniverse.Match(line);
                    long place, universe;
                    if (m.Success && long.TryParse(m.Groups[1].Value, out place) && place == cur.PlaceId && long.TryParse(m.Groups[2].Value, out universe))
                        cur.UniverseId = universe;
                }
                else if (leave && cur != null && t.HasValue && !cur.End.HasValue)
                {
                    cur.End = t;
                }
            }
            if (cur != null && !cur.End.HasValue)
            {
                cur.NoLeave = true;
                var end = fileEnd ?? lastTime;
                if (end.HasValue && end.Value >= cur.Start) cur.End = end;
            }
            return list;
        }

        /// <summary>Roblox games that were open at time t (with 2 minutes of slack), or joined up to 20 minutes after it.</summary>
        public static List<GameLink> GamesAround(DateTime t, IList<RobloxSession> sessions)
        {
            var links = new List<GameLink>();
            var slack = TimeSpan.FromMinutes(2);
            foreach (var s in sessions)
            {
                var end = s.End ?? s.Start;
                if (t >= s.Start - slack && t <= end + slack) links.Add(new GameLink { Session = s, How = "during" });
            }
            if (links.Count == 0)
            {
                var next = sessions.Where(s => s.Start > t && s.Start <= t.AddMinutes(20)).OrderBy(s => s.Start).FirstOrDefault();
                if (next != null) links.Add(new GameLink { Session = next, How = "before" });
            }
            return links;
        }

        /// <summary>Program start times in [from, to] that no log file's (created, last written) span covers, with 5 minutes of slack.</summary>
        public static List<DateTime> UncoveredStarts(IEnumerable<DateTime> starts, IList<Tuple<DateTime, DateTime>> logSpans, DateTime from, DateTime to)
        {
            var slack = TimeSpan.FromMinutes(5);
            var result = new List<DateTime>();
            foreach (var t in starts.Distinct())
            {
                if (t < from || t > to) continue;
                bool covered = logSpans.Any(s => t >= s.Item1 - slack && t <= s.Item2 + slack);
                if (!covered) result.Add(t);
            }
            return result;
        }

        /// <summary>The VPN word a network adapter's name or description contains, or null. "VPN" alone must be a whole word.</summary>
        public static string VpnAdapterMatch(string name, string description, IEnumerable<string> words)
        {
            string text = ((name ?? "") + " | " + (description ?? ""));
            foreach (var w in words)
            {
                if (string.IsNullOrEmpty(w)) continue;
                if (w == "VPN")
                {
                    if (Regex.IsMatch(text, @"\bVPN\b", RegexOptions.IgnoreCase)) return w;
                }
                else if (text.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0) return w;
            }
            return null;
        }

        /// <summary>
        /// Network drops (disconnect, then reconnect within maxGap) that happened while a Roblox game was open.
        /// Lag switches, hardware switches and "disable adapter" macros all show up as short drops like these.
        /// </summary>
        public static List<Tuple<DateTime, RobloxSession>> DropsDuringGames(IList<Tuple<DateTime, bool>> events, IList<RobloxSession> sessions, TimeSpan maxGap)
        {
            var result = new List<Tuple<DateTime, RobloxSession>>();
            var ordered = events.OrderBy(e => e.Item1).ToList();
            for (int i = 0; i < ordered.Count; i++)
            {
                if (ordered[i].Item2) continue;                       // looking for a disconnect (false = disconnected)
                var down = ordered[i].Item1;
                var up = ordered.Skip(i + 1).FirstOrDefault(e => e.Item2);
                if (up == null || up.Item1 - down > maxGap) continue; // long outages are normal internet problems
                var s = sessions.FirstOrDefault(x => down >= x.Start && down <= (x.End ?? x.Start));
                if (s != null) result.Add(Tuple.Create(down, s));
            }
            return result;
        }

        /// <summary>
        /// Exploit-only functions found in a Roblox script's text. Real Roblox games can't call these, so finding them
        /// means the script was written for an executor. Returns the distinct markers found.
        /// </summary>
        public static List<string> ExploitMarkers(string text, IEnumerable<string> markers)
        {
            var found = new List<string>();
            if (string.IsNullOrEmpty(text)) return found;
            foreach (var m in markers)
                if (!string.IsNullOrEmpty(m) && text.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0 && !found.Contains(m)) found.Add(m);
            return found;
        }

        static readonly Regex LoadstringUrl = new Regex(@"loadstring\s*\(\s*game\s*:\s*HttpGet(?:Async)?\s*\(\s*[""']([^""']{8,300})[""']", RegexOptions.IgnoreCase);

        /// <summary>The first web address a script loads code from (loadstring(game:HttpGet("..."))). Text only; it is never visited.</summary>
        public static string LoadstringSource(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            var m = LoadstringUrl.Match(text);
            return m.Success ? m.Groups[1].Value : null;
        }

        static readonly string[] InstallerWords = { "setup", "install", "update", "unins", "vcredist", "vc_redist", "dxsetup", "dotnet", "ndp4", "windowsdesktop-runtime", "robloxplayerlauncher", "robloxplayerinstaller", "robloxstudio", "chromesetup", "discordsetup" };

        /// <summary>True for a program run from Downloads, Desktop, Documents or Temp that isn't an installer. Used for "deleted program ran during a game".</summary>
        public static bool IsLooseUserProgram(string path)
        {
            if (string.IsNullOrEmpty(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return false;
            string p = path.ToLowerInvariant();
            bool place = p.Contains(@"\downloads\") || p.Contains(@"\desktop\") || p.Contains(@"\documents\") || p.Contains(@"\appdata\local\temp\");
            if (!place) return false;
            string name = p.Substring(p.LastIndexOf('\\') + 1);
            return !InstallerWords.Any(w => name.Contains(w));
        }

        /// <summary>Website host names in a Zone.Identifier note (HostUrl= and ReferrerUrl= lines).</summary>
        public static List<string> ZoneHosts(string zone)
        {
            var hosts = new List<string>();
            if (string.IsNullOrEmpty(zone)) return hosts;
            foreach (var raw in zone.Split('\n'))
            {
                string line = raw.Trim();
                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq);
                if (!key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase) && !key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase)) continue;
                Uri u;
                if (Uri.TryCreate(line.Substring(eq + 1).Trim(), UriKind.Absolute, out u) && !string.IsNullOrEmpty(u.Host))
                {
                    string host = u.Host.ToLowerInvariant();
                    if (!hosts.Contains(host)) hosts.Add(host);
                }
            }
            return hosts;
        }

        /// <summary>The listed domain a host belongs to (exact or a subdomain of it), or null.</summary>
        public static string MatchDomain(string host, IEnumerable<string> domains)
        {
            if (string.IsNullOrEmpty(host)) return null;
            foreach (var d in domains)
            {
                if (string.IsNullOrEmpty(d)) continue;
                string dl = d.ToLowerInvariant();
                if (host == dl || host.EndsWith("." + dl, StringComparison.Ordinal)) return d;
            }
            return null;
        }

        static readonly Regex Kick268 = new Regex(@"unexpected client behavio(u)?r|(error code|reason)\s*:\s*268\b", RegexOptions.IgnoreCase);
        static readonly Regex KickByGame = new Regex(@"kicked from this experience\s*:\s*(.{1,160}?)\s*(\(error code|$)", RegexOptions.IgnoreCase);
        static readonly Regex CheatWords = new Regex(@"\b(exploit\w*|cheat\w*|hack\w*|inject\w*|executor|anti[- ]?cheat|speed ?hack\w*|fly ?hack\w*|noclip\w*|teleport ?hack\w*|tamper\w*|suspicious)\b", RegexOptions.IgnoreCase);

        /// <summary>Kick reason from a Roblox log line: "268" for Roblox's own anti-cheat, or the game's kick message, or null.</summary>
        public static string KickFromLogLine(string line)
        {
            if (string.IsNullOrEmpty(line)) return null;
            if (Kick268.IsMatch(line)) return "268";
            var m = KickByGame.Match(line);
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }

        /// <summary>True when a game's kick message talks about cheating.</summary>
        public static bool KickMentionsCheating(string reason)
        {
            return !string.IsNullOrEmpty(reason) && reason != "268" && CheatWords.IsMatch(reason);
        }

        static readonly HashSet<string> JunkSerials = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "", "0", "none", "default string", "to be filled by o.e.m", "system serial number", "not specified", "not applicable", "n/a", "123456789", "0123456789", "base board serial number", "chassis serial number" };

        /// <summary>True when a hardware serial is a real value, not a placeholder.</summary>
        public static bool IsRealSerial(string serial)
        {
            if (serial == null) return false;
            string s = serial.Trim().Trim('.');
            return s.Length >= 4 && !JunkSerials.Contains(s) && s.Distinct().Count() > 2;
        }

        /// <summary>
        /// A short ID for this PC: a SHA-256 of hardware serials (salted), cut to 12 characters as XXXX-XXXX-XXXX.
        /// It can't be turned back into the serials, but it's the same every time OpenCheck runs on the same PC.
        /// </summary>
        public static string PcId(IEnumerable<string> parts)
        {
            var real = parts.Where(IsRealSerial).Select(x => x.Trim().ToUpperInvariant()).ToList();
            if (real.Count == 0) return null;
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes("OpenCheck PC ID v1|" + string.Join("|", real)));
                string hex = BitConverter.ToString(hash).Replace("-", "").Substring(0, 12).ToUpperInvariant();
                return hex.Substring(0, 4) + "-" + hex.Substring(4, 4) + "-" + hex.Substring(8, 4);
            }
        }

        /// <summary>"USBSTOR\Disk&amp;Ven_SanDisk&amp;Prod_Cruzer_Blade&amp;Rev_1.00\4C53...&amp;0" becomes "SanDisk Cruzer Blade". Null if it isn't a USB storage device.</summary>
        public static string UsbStorageName(string deviceInstanceId)
        {
            if (string.IsNullOrEmpty(deviceInstanceId) || !deviceInstanceId.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase)) return null;
            string ven = null, prod = null;
            foreach (var part in deviceInstanceId.Split('\\')[1].Split('&'))
            {
                if (part.StartsWith("Ven_", StringComparison.OrdinalIgnoreCase)) ven = part.Substring(4).Replace('_', ' ').Trim();
                else if (part.StartsWith("Prod_", StringComparison.OrdinalIgnoreCase)) prod = part.Substring(5).Replace('_', ' ').Trim();
            }
            string name = ((ven ?? "") + " " + (prod ?? "")).Trim();
            return name.Length == 0 ? "USB drive" : name;
        }

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
