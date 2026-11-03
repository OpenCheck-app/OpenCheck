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

        /// <summary>A command typed into the Windows Run box (Win+R). Windows stores it with "\1" on the end.</summary>
        public static string RunBoxCommand(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            string v = value.Trim();
            if (v.EndsWith("\\1", StringComparison.Ordinal)) v = v.Substring(0, v.Length - 2);
            return v.Length == 0 ? null : v;
        }

        /// <summary>
        /// The program or file a Run-box command or typed path points at, for name matching
        /// ("C:\x\Solara.exe -arg" gives "C:\x\Solara.exe"; quoted paths are unquoted).
        /// </summary>
        public static string RunBoxTarget(string command)
        {
            if (string.IsNullOrEmpty(command)) return null;
            string c = command.Trim();
            if (c.StartsWith("\"", StringComparison.Ordinal))
            {
                int end = c.IndexOf('"', 1);
                return end > 1 ? c.Substring(1, end - 1) : c.Trim('"');
            }
            var m = Regex.Match(c, @"^.+?\.(exe|bat|cmd|lnk|ahk|lua)\b", RegexOptions.IgnoreCase);
            if (m.Success) return m.Value;
            int sp = c.IndexOf(' ');
            return sp > 0 ? c.Substring(0, sp) : c;
        }

        /// <summary>
        /// USB devices used with DMA cheats, by vendor and product ID from Windows' device list
        /// (kept after the device is unplugged). Returns a label, or null.
        /// </summary>
        public static string DmaUsbTool(string enumKeyName)
        {
            if (string.IsNullOrEmpty(enumKeyName)) return null;
            string k = enumKeyName.ToUpperInvariant();
            // WCH CH347: USB to UART + JTAG, the usual flasher for DMA card firmware.
            if (k.Contains("VID_1A86&PID_55DA") || k.Contains("VID_1A86&PID_55DB") || k.Contains("VID_1A86&PID_55DD") || k.Contains("VID_1A86&PID_55DE"))
                return "CH347 USB-to-JTAG adapter (DMA firmware flasher)";
            // FTDI FT601: the USB 3 link on Screamer-style DMA cards.
            if (k.Contains("VID_0403&PID_601F")) return "FT601 USB 3 bridge (used by DMA cards)";
            return null;
        }

        /// <summary>USB serial chips that KMBox-style input boxes use. Also common on Arduinos, so context only.</summary>
        public static bool IsUsbSerialChip(string enumKeyName)
        {
            if (string.IsNullOrEmpty(enumKeyName)) return false;
            string k = enumKeyName.ToUpperInvariant();
            return k.Contains("VID_1A86&PID_7523") || k.Contains("VID_1A86&PID_55D3") || k.Contains("VID_1A86&PID_55D4");
        }

        /// <summary>
        /// What's switched off in Windows Security right now, worth asking about. Real-time protection off is normal
        /// when another antivirus is installed, so it only counts when Defender is the only one.
        /// </summary>
        public static List<string> DefenderOffNow(bool realtimeOff, int? tamperProtection, bool otherAntivirus)
        {
            var list = new List<string>();
            if (otherAntivirus) return list;
            if (realtimeOff) list.Add("Real-time protection");
            if (tamperProtection.HasValue && tamperProtection.Value == 4) list.Add("Tamper protection");
            return list;
        }

        // ---------- Program file structure: packed, overlay, online (how external cheat loaders look) ----------

        public sealed class PeSection { public string Name; public uint VirtualSize; public uint RawSize; public uint RawOffset; public double Entropy; }

        public sealed class PeTraits
        {
            public bool IsPe;
            public string Packer;          // a named packer, "unknown protector", or null
            public bool Overlay;           // draws with DirectX on top of other windows
            public bool Online;            // downloads or logs in
            public List<string> Imports = new List<string>();
            public List<PeSection> Sections = new List<PeSection>();
        }

        static readonly string[] OverlayDlls = { "d3d11.dll", "d3d9.dll", "dxgi.dll", "d3dcompiler_43.dll", "d3dcompiler_47.dll", "opengl32.dll", "d3d12.dll" };
        static readonly string[] OnlineDlls = { "wininet.dll", "winhttp.dll", "ws2_32.dll", "urlmon.dll" };
        static readonly string[] StandardSections = { ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc", ".tls", ".idata", ".edata", ".bss", ".crt", ".gfids", ".00cfg", ".didat", "_rdata", ".xdata", ".sxdata", ".voltbl", ".fptable", ".retplne", ".gxfg", ".rodata", ".symtab", "cpadinfo", ".msvcjmc", ".stab", ".stabstr" };
        static readonly Tuple<string, string>[] NamedPackers =
        {
            Tuple.Create(".vmp", "VMProtect"), Tuple.Create(".themida", "Themida"), Tuple.Create(".winlice", "WinLicense"),
            Tuple.Create(".enigma", "Enigma Protector"), Tuple.Create("upx", "UPX"), Tuple.Create(".mpress", "MPRESS"),
            Tuple.Create(".aspack", "ASPack"), Tuple.Create(".petite", "Petite"), Tuple.Create(".obsidium", "Obsidium"), Tuple.Create(".boot", "Themida")
        };

        /// <summary>Entropy of up to 32 evenly spread 64 KB pieces of a range (encrypted data scores near 8).</summary>
        static double SampledEntropy(byte[] d, int start, int len)
        {
            if (len <= 0) return 0;
            const int piece = 64 * 1024, pieces = 32;
            if (len <= piece * pieces) return Entropy(d, start, len);
            var counts = new int[256];
            long total = 0;
            long step = len / pieces;
            for (int k = 0; k < pieces; k++)
            {
                int from = start + (int)(k * step);
                for (int i = from; i < from + piece && i < start + len; i++) { counts[d[i]]++; total++; }
            }
            return FromCounts(counts, total);
        }

        static double FromCounts(int[] counts, long total)
        {
            double e = 0;
            foreach (var c in counts) if (c > 0) { double p = (double)c / total; e -= p * Math.Log(p, 2); }
            return e;
        }

        static double Entropy(byte[] d, int start, int len)
        {
            if (len <= 0) return 0;
            var counts = new int[256];
            for (int i = start; i < start + len; i++) counts[d[i]]++;
            return FromCounts(counts, len);
        }

        /// <summary>
        /// Reads a Windows program's structure from its bytes: sections, imported DLLs, and from those,
        /// whether it's packed, draws an overlay, or goes online. Never runs anything.
        /// </summary>
        public static PeTraits InspectPe(byte[] d)
        {
            var t = new PeTraits();
            try
            {
                if (d == null || d.Length < 0x200 || d[0] != 'M' || d[1] != 'Z') return t;
                int pe = BitConverter.ToInt32(d, 0x3C);
                if (pe <= 0 || pe + 24 > d.Length || d[pe] != 'P' || d[pe + 1] != 'E') return t;
                t.IsPe = true;
                int nsec = BitConverter.ToUInt16(d, pe + 6), optSize = BitConverter.ToUInt16(d, pe + 20), opt = pe + 24;
                bool pe64 = BitConverter.ToUInt16(d, opt) == 0x20B;
                int dirs = opt + (pe64 ? 112 : 96);
                int secStart = opt + optSize;
                for (int k = 0; k < nsec && k < 40; k++)
                {
                    int o = secStart + 40 * k;
                    if (o + 40 > d.Length) break;
                    string name = Encoding.ASCII.GetString(d, o, 8).TrimEnd('\0');
                    uint vs = BitConverter.ToUInt32(d, o + 8), rs = BitConverter.ToUInt32(d, o + 16), rp = BitConverter.ToUInt32(d, o + 20);
                    var sec = new PeSection { Name = name, VirtualSize = vs, RawSize = rs, RawOffset = rp };
                    if (rs > 0 && rp < d.Length)
                        sec.Entropy = SampledEntropy(d, (int)rp, (int)Math.Min(rs, (uint)(d.Length - rp)));
                    t.Sections.Add(sec);
                }

                // Imported DLL names.
                uint importRva = BitConverter.ToUInt32(d, dirs + 8);
                Func<uint, int> off = rva =>
                {
                    foreach (var s in t.Sections)
                        if (rva >= 0 && s.RawSize > 0 && rva >= VirtualAddress(d, secStart, t.Sections.IndexOf(s)) && rva < VirtualAddress(d, secStart, t.Sections.IndexOf(s)) + Math.Max(s.VirtualSize, s.RawSize))
                            return (int)(s.RawOffset + rva - VirtualAddress(d, secStart, t.Sections.IndexOf(s)));
                    return -1;
                };
                int io = importRva == 0 ? -1 : off(importRva);
                for (int n = 0; io >= 0 && io + 20 <= d.Length && n < 200; n++, io += 20)
                {
                    uint nameRva = BitConverter.ToUInt32(d, io + 12);
                    if (nameRva == 0) break;
                    int no = off(nameRva);
                    if (no < 0 || no >= d.Length) continue;
                    int end = no;
                    while (end < d.Length && end - no < 128 && d[end] != 0) end++;
                    t.Imports.Add(Encoding.ASCII.GetString(d, no, end - no).ToLowerInvariant());
                }
            }
            catch { }
            t.Packer = PackedVerdict(t.Sections);
            t.Overlay = t.Imports.Any(i => OverlayDlls.Contains(i));
            t.Online = t.Imports.Any(i => OnlineDlls.Contains(i));
            return t;
        }

        static uint VirtualAddress(byte[] d, int secStart, int index)
        {
            return BitConverter.ToUInt32(d, secStart + 40 * index + 12);
        }

        /// <summary>
        /// Whether sections look packed: a known packer's section names, or the VMProtect/Themida shape
        /// (code sections empty on disk, everything inside one encrypted section, random section names).
        /// </summary>
        public static string PackedVerdict(IList<PeSection> sections)
        {
            if (sections == null || sections.Count == 0) return null;
            foreach (var s in sections)
                foreach (var p in NamedPackers)
                    if (s.Name.StartsWith(p.Item1, StringComparison.OrdinalIgnoreCase)) return p.Item2;
            var biggest = sections.OrderByDescending(s => s.RawSize).First();
            bool encrypted = biggest.RawSize >= 64 * 1024 && biggest.Entropy >= 7.4;
            // Code that isn't on disk at all: normal compilers never do this; protectors unpack it at run time.
            bool hollowCode = sections.Any(s => s.RawSize == 0 && s.VirtualSize >= 64 * 1024 && s.Name.Equals(".text", StringComparison.OrdinalIgnoreCase));
            bool hollow = hollowCode || sections.Any(s => s.RawSize == 0 && s.VirtualSize >= 64 * 1024 && (s.Name.Equals(".rdata", StringComparison.OrdinalIgnoreCase) || s.Name.Equals(".pdata", StringComparison.OrdinalIgnoreCase)));
            int odd = sections.Count(s => !StandardSections.Contains(s.Name.ToLowerInvariant()));
            if ((encrypted && (hollow || odd >= 2)) || (hollowCode && odd >= 2)) return "an unknown protector";
            return null;
        }

        static readonly string[] InstalledPlaces = { @"\windows\", @"\program files\", @"\program files (x86)\", @"\programdata\microsoft\", @"\appdata\local\microsoft\",
            @"\appdata\local\programs\", @"\appdata\roaming\microsoft\", @"\steamapps\", @"\windowsapps\", @"\appdata\local\roblox\", @"\appdata\local\discord", @"\appdata\local\packages\" };

        /// <summary>A program that ran from somewhere apps aren't normally installed (Downloads, Desktop, a folder the user made...).</summary>
        public static bool IsOutsideInstalledPlaces(string path)
        {
            if (string.IsNullOrEmpty(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return false;
            string p = path.ToLowerInvariant();
            if (p.Length < 4 || p[1] != ':') return false;
            return !InstalledPlaces.Any(x => p.Contains(x));
        }

        public sealed class RemoteScript { public string Host; public string Command; }

        static readonly Regex DownloadVerb = new Regex(@"\b(irm|iwr|invoke-restmethod|invoke-webrequest|curl(\.exe)?|wget|downloadstring|downloaddata|start-bitstransfer)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex RunVerb = new Regex(@"\b(iex|invoke-expression)\b|\[scriptblock\]::create", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex UrlHost = new Regex(@"https?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex BareHost = new Regex(@"\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)\s+(?:-uri\s+|-useb\s+|-usebasicparsing\s+)*['""]?([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// A command that downloads a script and runs it straight from memory ("irm site.com | iex" and its variants).
        /// Nothing is saved to disk, so this is how PowerShell cheats and loaders are started. Returns the site, or null.
        /// </summary>
        public static RemoteScript RemoteScriptRun(string text)
        {
            if (string.IsNullOrEmpty(text) || text.Length > 20000) return null;
            if (!DownloadVerb.IsMatch(text) || !RunVerb.IsMatch(text)) return null;
            var m = UrlHost.Match(text);
            string host = m.Success ? m.Groups[1].Value : null;
            if (host == null) { var b = BareHost.Match(text); if (b.Success) host = b.Groups[1].Value; }
            string cmd = text.Trim().Replace("\r", " ").Replace("\n", " ");
            if (cmd.Length > 160) cmd = cmd.Substring(0, 157) + "...";
            return new RemoteScript { Host = host == null ? null : host.ToLowerInvariant().TrimEnd('.'), Command = cmd };
        }

        /// <summary>"cheat", "installer" (a common, harmless one-line installer) or "unknown".</summary>
        public static string RemoteScriptKind(string host, IEnumerable<string> cheatSites, IEnumerable<string> installerSites)
        {
            if (string.IsNullOrEmpty(host)) return "unknown";
            if (Parsers.MatchDomain(host, cheatSites) != null) return "cheat";
            if (Parsers.MatchDomain(host, installerSites) != null) return "installer";
            return "unknown";
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
