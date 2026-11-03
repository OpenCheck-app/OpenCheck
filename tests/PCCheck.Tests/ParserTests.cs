using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PCCheck.Engine;
using Xunit;

namespace PCCheck.Tests
{
    public static class Repo
    {
        public static string Root
        {
            get
            {
                var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
                while (dir != null && !Directory.Exists(Path.Combine(dir.FullName, "src", "PCCheck"))) dir = dir.Parent;
                if (dir == null) throw new InvalidOperationException("Repository root not found");
                return dir.FullName;
            }
        }

        public static SignatureSet Signatures()
        {
            return SignatureSet.Parse(File.ReadAllText(Path.Combine(Root, "src", "PCCheck", "signatures.json")));
        }
    }

    public class MatcherTests
    {
        readonly Matcher m = new Matcher(Repo.Signatures());

        [Theory]
        [InlineData(@"C:\ProgramData\Solara\Solara.exe", "Solara")]
        [InlineData("SOLARAV3.DLL", "Solara")]
        [InlineData("POTASSIUM.EXE-1A2B3C4D.pf", "Potassium")]
        [InlineData(@"C:\Users\x\Downloads\DownloadR2\VolcanoUI.exe", "Volcano")]
        [InlineData("Volcano (1).exe", "Volcano")]
        [InlineData("Wave.exe", "Wave")]
        [InlineData("WaveBootstrapper.exe", "Wave")]
        [InlineData("Xeno.exe", "Xeno")]
        [InlineData("Synapse Z.exe", "Synapse")]
        [InlineData("Matcha.exe", "Matcha")]
        [InlineData("cheatengine-x86_64-SSE4-AVX2.exe", "Cheat Engine")]
        [InlineData("Extreme Injector v3.exe", "Extreme Injector")]
        [InlineData("HD-Player.exe", "Android emulator")]
        [InlineData("Bloxstrap.exe", "Roblox bootstrapper")]
        public void Matches_known_cheat_names(string file, string expected)
        {
            var sig = m.MatchName(file);
            Assert.NotNull(sig);
            Assert.Equal(expected, sig.Name);
        }

        [Theory]
        [InlineData("WaveBrowser.exe")]           // adware, not the Wave executor
        [InlineData("Waves MaxxAudio.exe")]
        [InlineData("chrome.exe")]
        [InlineData("RobloxPlayerBeta.exe")]
        [InlineData("Discord.exe")]
        [InlineData("velocityraptor.exe")]
        [InlineData("severeweather.exe")]
        [InlineData("explorer.exe")]
        [InlineData("a.exe")]
        public void Ignores_normal_programs(string file)
        {
            Assert.Null(m.MatchName(file));
        }

        [Fact]
        public void Folder_names_only_match_distinctive_names()
        {
            Assert.NotNull(m.MatchFolderName("Solara"));
            Assert.NotNull(m.MatchFolderName("Potassium"));
            Assert.Null(m.MatchFolderName("Wave"));     // strict names never match folders
            Assert.Null(m.MatchFolderName("Zenith"));
            Assert.Null(m.MatchFolderName("Bloxstrap")); // allowed tools don't get flagged
        }

        [Fact]
        public void Detects_executor_folder_layout()
        {
            Assert.NotNull(m.MatchLayout(new HashSet<string> { "workspace", "autoexec", "bin" }));
            Assert.Null(m.MatchLayout(new HashSet<string> { "workspace", "src", "bin" }));
        }

        [Theory]
        [InlineData(@"C:\Users\alex\Downloads\x.exe", @"~\Downloads\x.exe")]
        [InlineData(@"c:\users\Some Name\AppData\Local\Potassium", @"~\AppData\Local\Potassium")]
        [InlineData(@"C:\ProgramData\Solara", @"C:\ProgramData\Solara")]
        public void Hides_the_windows_user_name(string input, string expected)
        {
            Assert.Equal(expected, Matcher.MaskUser(input));
        }

        [Fact]
        public void Signature_list_is_well_formed()
        {
            var set = Repo.Signatures();
            Assert.True(set.Items.Count >= 30);
            Assert.Equal(set.Items.Count, set.Items.Select(s => s.Name).Distinct().Count());
            Assert.All(set.Items, s => Assert.True(s.Tokens.Count > 0 || s.Folders.Count > 0, s.Name));
            Assert.All(set.Items.SelectMany(s => s.Tokens), t => Assert.True(t.Length >= 3, t));
            Assert.NotEmpty(set.FlagWords);
            Assert.NotEmpty(set.DmaVendors);
        }
    }

    public class ParserTests
    {
        [Fact]
        public void Rot13_round_trips()
        {
            Assert.Equal("{6Q809377-6NS0-444O-8957-N3773S02200R}\\Rcvp Tnzrf\\Cbgnffvhz.rkr",
                Parsers.Rot13(@"{6D809377-6AF0-444B-8957-A3773F02200E}\Epic Games\Potassium.exe"));
            Assert.Equal("Potassium.exe", Parsers.Rot13(Parsers.Rot13("Potassium.exe")));
        }

        [Fact]
        public void Reads_user_assist_data()
        {
            var data = new byte[72];
            BitConverter.GetBytes(7).CopyTo(data, 4);
            var when = new DateTime(2026, 10, 24, 16, 1, 0, DateTimeKind.Utc);
            BitConverter.GetBytes(when.ToFileTimeUtc()).CopyTo(data, 60);
            var e = Parsers.ParseUserAssist(data);
            Assert.Equal(7, e.RunCount);
            Assert.Equal(when.ToLocalTime(), e.LastRun);
            Assert.Null(Parsers.ParseUserAssist(new byte[16]));
        }

        [Fact]
        public void Expands_known_folder_guids()
        {
            Assert.Equal(@"C:\Program Files\Epic Games\x\Potassium.exe",
                Parsers.ExpandKnownFolder(@"{6D809377-6AF0-444B-8957-A3773F02200E}\Epic Games\x\Potassium.exe"));
            Assert.Equal(@"C:\plain\path.exe", Parsers.ExpandKnownFolder(@"C:\plain\path.exe"));
        }

        [Fact]
        public void Converts_device_paths()
        {
            var map = new Dictionary<string, string> { { @"\Device\HarddiskVolume3", "C:" }, { @"\Device\HarddiskVolume30", "D:" } };
            Assert.Equal(@"C:\Users\x\Wave.exe", Parsers.ConvertDevicePath(@"\Device\HarddiskVolume3\Users\x\Wave.exe", map));
            Assert.Equal(@"D:\Games\a.exe", Parsers.ConvertDevicePath(@"\Device\HarddiskVolume30\Games\a.exe", map));
            Assert.Equal("Microsoft.Windows.Explorer", Parsers.ConvertDevicePath("Microsoft.Windows.Explorer", map));
        }

        [Fact]
        public void Reads_recycle_bin_v2()
        {
            string path = @"C:\Users\x\Desktop\Solara.exe";
            var when = new DateTime(2026, 10, 20, 12, 0, 0, DateTimeKind.Utc);
            var ms = new MemoryStream();
            var w = new BinaryWriter(ms);
            w.Write(2L); w.Write(12345L); w.Write(when.ToFileTimeUtc());
            w.Write(path.Length + 1); w.Write(Encoding.Unicode.GetBytes(path + "\0"));
            var e = Parsers.ParseRecycleBinInfo(ms.ToArray());
            Assert.Equal(path, e.OriginalPath);
            Assert.Equal(12345L, e.Size);
            Assert.Equal(when.ToLocalTime(), e.Deleted);
        }

        [Fact]
        public void Reads_recycle_bin_v1()
        {
            string path = @"C:\old\krnl.exe";
            var data = new byte[24 + 520];
            BitConverter.GetBytes(1L).CopyTo(data, 0);
            Encoding.Unicode.GetBytes(path).CopyTo(data, 24);
            Assert.Equal(path, Parsers.ParseRecycleBinInfo(data).OriginalPath);
        }

        static byte[] UsnRecord(string name, uint reason, DateTime utc, long parent)
        {
            var nameBytes = Encoding.Unicode.GetBytes(name);
            int len = (60 + nameBytes.Length + 7) & ~7;
            var r = new byte[len];
            BitConverter.GetBytes(len).CopyTo(r, 0);
            BitConverter.GetBytes((ushort)2).CopyTo(r, 4);
            BitConverter.GetBytes(111L).CopyTo(r, 8);
            BitConverter.GetBytes(parent).CopyTo(r, 16);
            BitConverter.GetBytes(999L).CopyTo(r, 24);
            BitConverter.GetBytes(utc.ToFileTimeUtc()).CopyTo(r, 32);
            BitConverter.GetBytes(reason).CopyTo(r, 40);
            BitConverter.GetBytes((ushort)nameBytes.Length).CopyTo(r, 56);
            BitConverter.GetBytes((ushort)60).CopyTo(r, 58);
            nameBytes.CopyTo(r, 60);
            return r;
        }

        [Fact]
        public void Reads_usn_journal_records()
        {
            var t = new DateTime(2026, 10, 24, 21, 42, 0, DateTimeKind.Utc);
            var buf = new List<byte>(BitConverter.GetBytes(5000L));
            buf.AddRange(UsnRecord("wave.exe", Parsers.UsnReasonFileDelete, t, 42));
            buf.AddRange(UsnRecord("notes.txt", Parsers.UsnReasonFileCreate, t, 43));
            var arr = buf.ToArray();
            var recs = Parsers.ParseUsnBuffer(arr, arr.Length);
            Assert.Equal(2, recs.Count);
            Assert.Equal("wave.exe", recs[0].Name);
            Assert.Equal(42, recs[0].ParentRef);
            Assert.Equal(Parsers.UsnReasonFileDelete, recs[0].Reason);
            Assert.Equal(t.ToLocalTime(), recs[0].Time);
            Assert.Equal("notes.txt", recs[1].Name);
        }

        [Fact]
        public void Usn_parser_survives_garbage()
        {
            var junk = new byte[200];
            new Random(1).NextBytes(junk);
            Parsers.ParseUsnBuffer(junk, junk.Length);   // must not throw
            Assert.Empty(Parsers.ParseUsnBuffer(new byte[8], 8));
        }

        [Fact]
        public void Reads_prefetch_v30()
        {
            var d = new byte[0x100];
            BitConverter.GetBytes(30).CopyTo(d, 0);
            Encoding.ASCII.GetBytes("SCCA").CopyTo(d, 4);
            var t1 = new DateTime(2026, 10, 24, 13, 27, 0, DateTimeKind.Utc);
            var t2 = t1.AddDays(-2);
            BitConverter.GetBytes(t2.ToFileTimeUtc()).CopyTo(d, 0x88);
            BitConverter.GetBytes(t1.ToFileTimeUtc()).CopyTo(d, 0x80);
            BitConverter.GetBytes(7).CopyTo(d, 0xD0);
            var info = Parsers.ParsePrefetch(d);
            Assert.Equal(30, info.Version);
            Assert.Equal(7, info.RunCount);
            Assert.Equal(t1.ToLocalTime(), info.RunTimes[0]);
            Assert.Equal(2, info.RunTimes.Count);
            Assert.Null(Parsers.ParsePrefetch(new byte[0x100]));
        }

        [Fact]
        public void Reads_setupapi_log()
        {
            var lines = new[]
            {
                ">>>  [Device Install (Hardware initiated) - PCI\\VEN_10EE&DEV_0666&SUBSYS_000710EE&REV_02\\4&1a2b3c&0&0008]",
                ">>>  Section start 2026/10/24 13:27:01.123",
                "     some detail",
                "<<<  Section end 2026/10/24 13:27:03.000",
                ">>>  [Device Install (Hardware initiated) - USB\\VID_046D&PID_C52B\\5&2]",
                ">>>  Section start 2026/10/25 09:00:00.000",
            };
            var list = Parsers.ParseSetupApiLog(lines);
            Assert.Equal(2, list.Count);
            Assert.StartsWith(@"PCI\VEN_10EE", list[0].DeviceId);
            Assert.Equal(new DateTime(2026, 10, 24, 13, 27, 1), list[0].Time);
            Assert.Equal("10EE", Parsers.PciVendor(list[0].DeviceId));
            Assert.Null(Parsers.PciVendor("USB\\VID_046D"));
        }

        [Fact]
        public void Flags_unfair_fast_flags_only()
        {
            var flags = new Dictionary<string, object>
            {
                { "DFIntS2PhysicsSenderRate", 1 },
                { "DFIntMaxMissedWorldStepsRemembered", 1000 },
                { "FFlagDebugGraphicsPreferD3D11", true },
                { "DFIntTaskSchedulerTargetFps", 240 },
            };
            int other;
            var hits = Parsers.AnalyzeFastFlags(flags, Repo.Signatures().FlagWords, out other);
            Assert.Equal(2, hits.Count);
            Assert.Equal(2, other);
            Assert.Contains(hits, h => h.Name == "DFIntS2PhysicsSenderRate" && h.Value == "1");
        }

        [Fact]
        public void Finds_bulk_deletions()
        {
            var start = new DateTime(2026, 10, 24, 21, 0, 0);
            var times = Enumerable.Range(0, 30).Select(i => start.AddSeconds(i * 5)).ToList();
            Assert.NotNull(Parsers.FindBurst(times, 25, TimeSpan.FromMinutes(10)));
            var spread = Enumerable.Range(0, 30).Select(i => start.AddHours(i)).ToList();
            Assert.Null(Parsers.FindBurst(spread, 25, TimeSpan.FromMinutes(10)));
        }

        [Fact]
        public void Safe_name_strips_discord_formatting_and_mentions()
        {
            Assert.Equal("everyone", Parsers.SafeName("@everyone", 40));
            Assert.Equal("builderman", Parsers.SafeName("**builder`man**", 40));
            Assert.Equal(5, Parsers.SafeName("abcdefghij", 5).Length);
        }

        [Fact]
        public void Rejects_impossible_file_times()
        {
            Assert.Null(Parsers.FromFileTime(0));
            Assert.Null(Parsers.FromFileTime(-5));
            Assert.Null(Parsers.FromFileTime(DateTime.UtcNow.AddYears(5).ToFileTimeUtc()));
            Assert.NotNull(Parsers.FromFileTime(DateTime.UtcNow.AddDays(-1).ToFileTimeUtc()));
        }
    }

    public class ReportTests
    {
        static Finding F(string name, Severity sev, bool cheat, string evidence = "Found on this PC", string path = @"C:\x\a.exe")
        {
            return new Finding { Name = name, Category = "Internal executor", Severity = sev, IsCheat = cheat, Evidence = evidence, Group = cheat ? Groups.Cheat : Groups.Tamper, Path = path, Time = DateTime.Now };
        }

        [Fact]
        public void Verdict_rules()
        {
            Assert.Equal("clean", Report.DecideVerdict(new Finding[0]));
            Assert.Equal("clean", Report.DecideVerdict(new[] { F("Bloxstrap", Severity.Info, false) }));
            Assert.Equal("review", Report.DecideVerdict(new[] { F("Log cleared", Severity.Medium, false) }));
            Assert.Equal("flag", Report.DecideVerdict(new[] { F("Potassium", Severity.Medium, true, "Ran on this PC") }));
        }

        [Fact]
        public void Merges_program_history_by_file_name()
        {
            var a = F("Potassium", Severity.Medium, true, "Ran on this PC", "POTASSIUM.EXE");
            a.Sources.Add("Prefetch"); a.RunCount = 7;
            var b = F("Potassium", Severity.Medium, true, "Ran on this PC", @"C:\Program Files\Epic Games\x\Potassium.exe");
            b.Sources.Add("BAM");
            Assert.Equal(a.MergeKey, b.MergeKey);
            a.MergeFrom(b);
            Assert.Equal(@"C:\Program Files\Epic Games\x\Potassium.exe", a.Path);
            Assert.Equal(new[] { "BAM", "Prefetch" }, a.Sources.ToArray());
            Assert.Equal(7, a.RunCount);
        }

        static Report Big(int n)
        {
            var r = new Report { Verdict = "flag", Who = "tester", Pc = "Windows 11", AppVersion = "1.0.0", AppSha256 = new string('a', 64), ListVersion = "x", Started = DateTime.Now.AddMinutes(-1), Finished = DateTime.Now, Admin = true };
            for (int i = 0; i < n; i++) r.Findings.Add(F("Cheat " + i, Severity.High, true, "Found on this PC", @"C:\Very\Long\Path\Number\" + i + @"\with\many\folders\cheat.exe"));
            return r;
        }

        [Fact]
        public void Discord_text_fits_in_one_message()
        {
            string text = ReportWriter.BuildDiscordText(Big(200));
            Assert.True(text.Length <= 2000, "length " + text.Length);
            Assert.Contains("more in the saved report file", text);
            Assert.StartsWith("**OpenCheck: FLAGGED**", text);
        }

        [Fact]
        public void Html_report_escapes_file_names()
        {
            var r = Big(0);
            r.Findings.Add(F("<script>alert(1)</script>", Severity.High, true));
            string html = ReportWriter.BuildHtml(r);
            Assert.DoesNotContain("<script>", html);
            Assert.Contains("&lt;script&gt;", html);
        }

        [Fact]
        public void Text_report_lists_everything()
        {
            string text = ReportWriter.BuildText(Big(50));
            Assert.Contains("Cheat 49", text);
            Assert.Contains("App SHA-256", text);
        }
    }
}

namespace PCCheck.Tests
{
    public class NewDetectionTests
    {
        readonly Matcher m = new Matcher(Repo.Signatures());

        [Theory]
        [InlineData("Delta Executor.exe", "Delta")]
        [InlineData("Roblox Executor v2.exe", "Generic executor")]
        [InlineData("InfiniteYield.lua", "Exploit script")]
        [InlineData("FFlag Injector.exe", "FastFlag editor / injector")]
        [InlineData("OP AutoClicker.exe", "Auto clicker")]
        [InlineData("AutoHotkey64.exe", "AutoHotkey")]
        [InlineData("TinyTask.exe", "Macro recorder")]
        [InlineData("clumsy.exe", "Clumsy (lag switch)")]
        [InlineData("NetLimiter.exe", "NetLimiter")]
        [InlineData("WinDivert64.sys", "WinDivert")]
        [InlineData("Voidstrap.exe", "Roblox bootstrapper")]
        [InlineData("Fishstrap.exe", "Roblox bootstrapper")]
        [InlineData("Matrix.exe", "Matrix Hub")]
        [InlineData("Matrix External.exe", "Matrix Hub")]
        [InlineData("Matrix Hub.exe", "Matrix Hub")]
        [InlineData("newui.exe", "Matrix Hub")]
        [InlineData("NEWUI.EXE-1A2B3C4D.pf", "Matrix Hub")]
        [InlineData("newuimatrix.exe", "Matrix Hub")]
        [InlineData("olduimatrix.exe", "Matrix Hub")]
        [InlineData("newui (1).exe", "Matrix Hub")]
        [InlineData("Matrix_Hub_v2.exe", "Matrix Hub")]
        [InlineData("MatrixHubLoader.exe", "Matrix Hub")]
        [InlineData("matrix-external-3.1.exe", "Matrix Hub")]
        [InlineData("MATRIX.EXE-1A2B3C4D.pf", "Matrix Hub")]
        [InlineData("MatrixV2.exe", "Matrix Hub")]
        [InlineData("DX9WARE V2.exe", "DX9WARE")]
        [InlineData("Photon.exe", "Photon")]
        [InlineData("Melatonin.exe", "Melatonin")]
        [InlineData("Lumen External.exe", "Lumen")]
        [InlineData("Madius.exe", "Madius")]
        [InlineData("Isaeva.exe", "Isaeva")]
        [InlineData("Cosmic Executor.exe", "Cosmic")]
        [InlineData("WRDApi.dll", "WeAreDevs / exploit API")]
        [InlineData("Roblox Hack.exe", "Generic executor")]
        [InlineData("Severe Hub.exe", "Severe")]
        [InlineData("Volt.exe", "Volt")]
        [InlineData("VoltLoader.exe", "Volt")]
        [InlineData("Vector.cc.exe", "Vector")]
        [InlineData("Vector External.exe", "Vector")]
        [InlineData("Isaeva.exe", "Isaeva")]
        [InlineData("Serotonin.exe", "Serotonin")]
        [InlineData("Potassium.exe", "Potassium")]
        [InlineData("RiftHub.lua", "Exploit script")]
        [InlineData("Yabujin.lua", "Exploit script")]
        [InlineData("Lunor Hub.lua", "Exploit script")]
        [InlineData("Faded Yart.lua", "Exploit script")]
        [InlineData("divine.land loader.exe", "Cheat store loader")]
        [InlineData("Predator CS2.exe", "Predator")]
        [InlineData("NordVPN.exe", "VPN app")]
        [InlineData("ProtonVPN.Client.exe", "VPN app")]
        [InlineData("warp-svc.exe", "VPN app")]
        [InlineData("ExitLag.exe", "Game ping booster")]
        [InlineData("WTFast.exe", "Game ping booster")]
        [InlineData("NetCut.exe", "Network cutting tool")]
        [InlineData("lag switch.ahk", "Lag switch tool")]
        [InlineData("LagMacro.ahk", "Lag switch tool")]
        [InlineData("SandboxiePlus.exe", "Sandbox or freeze tool")]
        [InlineData("DeepFreeze.exe", "Sandbox or freeze tool")]
        [InlineData("ShadowDefender.exe", "Sandbox or freeze tool")]
        [InlineData("Matcha External.exe", "Matcha")]
        public void Detects_new_categories(string file, string expected)
        {
            var sig = m.MatchName(file);
            Assert.NotNull(sig);
            Assert.Equal(expected, sig.Name);
        }

        [Theory]
        [InlineData("Delta.exe")]          // git-delta, not the executor
        [InlineData("codex.exe")]          // a coding tool
        [InlineData("Electron.exe")]
        [InlineData("lghub.exe")]
        [InlineData("RobloxPlayerInstaller.exe")]
        [InlineData("feature-flags.json")]
        [InlineData("Microsoft.Build.Tasks.Executor.dll")]
        [InlineData("MatrixScreensaver.exe")]
        [InlineData("PhotonEngine.dll")]
        [InlineData("Photoshop.exe")]
        [InlineData("AxisCameraStation.exe")]
        [InlineData("LumenRender.dll")]
        [InlineData("CosmicTweaks.exe")]
        [InlineData("RealtekAudio.exe")]
        [InlineData("MatrixMultiply.dll")]
        [InlineData("NewUIDemo.exe")]
        [InlineData("renewui.exe")]
        [InlineData("Wavelength.exe")]
        [InlineData("Severeweatheralerts.exe")]
        [InlineData("vector.exe")]
        [InlineData("Volta.exe")]
        [InlineData("PredatorSense.exe")]
        [InlineData("TekkitLauncher.exe")]
        [InlineData("Ignite.exe")]
        [InlineData("svchost.exe")]
        [InlineData("RasMan.dll")]
        [InlineData("chrome.exe")]
        [InlineData("Matrices.dll")]
        public void New_rules_do_not_flag_normal_apps(string file)
        {
            Assert.Null(m.MatchName(file));
        }

        [Fact]
        public void Bootstrappers_are_context_only()
        {
            var sig = m.MatchName("Bloxstrap.exe");
            Assert.Equal(Severity.Info, sig.Severity);
        }

        [Fact]
        public void Reads_firewall_rules()
        {
            string block = "v2.30|Action=Block|Active=TRUE|Dir=Out|App=C:\\Users\\x\\AppData\\Local\\Roblox\\Versions\\v1\\RobloxPlayerBeta.exe|Name=lag|";
            string allow = "v2.30|Action=Allow|Active=TRUE|Dir=In|App=C:\\Program Files\\Steam\\steam.exe|Name=Steam|";
            Assert.True(Parsers.BlocksRoblox(block));
            Assert.False(Parsers.BlocksRoblox(allow));
            Assert.Equal("lag", Parsers.FirewallField(block, "Name"));
            Assert.Equal("TRUE", Parsers.FirewallField(block, "active"));
            Assert.False(Parsers.BlocksRoblox(null));
        }

        [Fact]
        public void Reads_windows_update_dates()
        {
            var t = Parsers.ParseSourceOsDate("Source OS (Updated on 10/1/2024 13:05:22)");
            Assert.Equal(new DateTime(2024, 10, 1, 13, 5, 22), t);
            Assert.Null(Parsers.ParseSourceOsDate("Status"));
        }

        [Fact]
        public void Recognizes_roblox_logs_and_jump_lists()
        {
            Assert.True(Parsers.IsRobloxLogName("0.687.0.6870758_20251002T120000Z_Player_A1B2C_last.log"));
            Assert.False(Parsers.IsRobloxLogName("setup.log"));
            Assert.True(Parsers.IsJumpListName("5f7b5f1e01b83767.automaticDestinations-ms"));
            Assert.False(Parsers.IsJumpListName("notes.txt"));
        }
    }

    public class ShimCacheTests
    {
        static byte[] Entry(string path, long fileTime)
        {
            var p = System.Text.Encoding.Unicode.GetBytes(path);
            var body = new List<byte>();
            body.AddRange(BitConverter.GetBytes((ushort)p.Length));
            body.AddRange(p);
            body.AddRange(BitConverter.GetBytes(fileTime));
            body.AddRange(BitConverter.GetBytes(0));   // no extra data
            var e = new List<byte>();
            e.AddRange(System.Text.Encoding.ASCII.GetBytes("10ts"));
            e.AddRange(BitConverter.GetBytes(0));
            e.AddRange(BitConverter.GetBytes(body.Count));
            e.AddRange(body);
            return e.ToArray();
        }

        [Fact]
        public void Reads_paths_and_dates()
        {
            long ft = new DateTime(2026, 3, 1, 12, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
            var data = new List<byte>();
            data.AddRange(BitConverter.GetBytes(0x34));
            data.AddRange(new byte[0x34 - 4]);
            data.AddRange(Entry(@"C:\Users\a\Downloads\Solara.exe", ft));
            data.AddRange(Entry(@"\??\C:\Windows\notepad.exe", ft));
            var list = Parsers.ParseShimCache(data.ToArray());
            Assert.Equal(2, list.Count);
            Assert.Equal(@"C:\Users\a\Downloads\Solara.exe", list[0].Path);
            Assert.True(list[0].Modified.HasValue);
            Assert.Equal(2026, list[0].Modified.Value.Year);
        }

        [Fact]
        public void Bad_data_is_ignored()
        {
            Assert.Empty(Parsers.ParseShimCache(null));
            Assert.Empty(Parsers.ParseShimCache(new byte[] { 1, 2, 3 }));
            var junk = new byte[200]; junk[0] = 0x34;
            Assert.Empty(Parsers.ParseShimCache(junk));
        }
    }

    public class RobloxLogTests
    {
        static readonly string[] Log =
        {
            "2026-10-28T21:00:01.100Z,0.1,1a2b,6 [FLog::Output] Settings Date header was Wed, 28 Oct 2026",
            "2026-10-28T21:02:05.123Z,12.3,1a2b,6 [FLog::Output] ! Joining game 'aa11bb22-cc33-dd44-ee55-ff6677889900' place 920587237 at 128.116.1.1",
            "2026-10-28T21:02:20.000Z,27.3,1a2b,6 [FLog::GameJoinLoadTime] Report game_join_loadtime: placeid:920587237, loadtime:15, universeid:383310974, joinattemptid:x",
            "2026-10-28T21:40:00.000Z,99.0,1a2b,6 [FLog::Network] Time to disconnect replication data: {{1.0}}",
            "2026-10-28T21:45:00.000Z,99.5,1a2b,6 [FLog::Output] ! Joining game '11111111-2222-3333-4444-555555555555' place 2753915549 at 128.116.1.2",
        };

        [Fact]
        public void Finds_sessions_with_place_universe_and_times()
        {
            var end = new DateTime(2026, 10, 28, 22, 10, 0, DateTimeKind.Utc).ToLocalTime();
            var list = Parsers.ParseRobloxLog(Log, end);
            Assert.Equal(2, list.Count);
            Assert.Equal(920587237L, list[0].PlaceId);
            Assert.Equal(383310974L, list[0].UniverseId);
            Assert.Equal(new DateTime(2026, 10, 28, 21, 2, 5, DateTimeKind.Utc).ToLocalTime(), list[0].Start.AddMilliseconds(-list[0].Start.Millisecond));
            Assert.Equal(new DateTime(2026, 10, 28, 21, 40, 0, DateTimeKind.Utc).ToLocalTime(), list[0].End.Value);
            Assert.Equal(2753915549L, list[1].PlaceId);
            Assert.True(list[1].NoLeave);
            Assert.Equal(end, list[1].End.Value);
        }

        [Fact]
        public void Links_cheat_run_times_to_games()
        {
            var list = Parsers.ParseRobloxLog(Log, null);
            var during = new DateTime(2026, 10, 28, 21, 15, 0, DateTimeKind.Utc).ToLocalTime();
            var links = Parsers.GamesAround(during, list);
            Assert.Single(links);
            Assert.Equal("during", links[0].How);
            Assert.Equal(920587237L, links[0].Session.PlaceId);

            var before = new DateTime(2026, 10, 28, 20, 55, 0, DateTimeKind.Utc).ToLocalTime();
            links = Parsers.GamesAround(before, list);
            Assert.Single(links);
            Assert.Equal("before", links[0].How);

            var unrelated = new DateTime(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc).ToLocalTime();
            Assert.Empty(Parsers.GamesAround(unrelated, list));
        }

        [Fact]
        public void Ignores_junk_lines()
        {
            Assert.Empty(Parsers.ParseRobloxLog(new[] { "", "hello", "! Joining game 'x' place abc", null }, null));
            Assert.Null(Parsers.RobloxLogTime("not a time"));
        }
    }

    public class MissingLogTests
    {
        [Fact]
        public void Finds_roblox_starts_with_no_log()
        {
            var now = new DateTime(2026, 11, 2, 12, 0, 0);
            var starts = new[] { now.AddHours(-30), now.AddHours(-20), now.AddHours(-5), now.AddDays(-9) };
            var spans = new List<Tuple<DateTime, DateTime>> { Tuple.Create(now.AddHours(-5).AddSeconds(3), now.AddHours(-4)) };
            var missing = Parsers.UncoveredStarts(starts, spans, now.AddDays(-3), now.AddMinutes(-10));
            Assert.Equal(2, missing.Count);                       // -30h and -20h have no log; -5h is covered; -9 days is too old
            Assert.DoesNotContain(now.AddHours(-5), missing);
        }
    }

    public class NetworkTests
    {
        static readonly string[] Words = { "WireGuard", "NordLynx", "TAP-Windows", "ExitLag", "VPN" };

        [Theory]
        [InlineData("NordLynx", "NordLynx Tunnel", "NordLynx")]
        [InlineData("Ethernet 3", "TAP-Windows Adapter V9", "TAP-Windows")]
        [InlineData("vpn0", "Some Corp VPN Adapter", "VPN")]
        [InlineData("ExitLag", "ExitLag Tap Adapter", "ExitLag")]
        public void Finds_vpn_adapters(string name, string description, string expected)
        {
            Assert.Equal(expected, Parsers.VpnAdapterMatch(name, description, Words));
        }

        [Theory]
        [InlineData("Ethernet", "Realtek PCIe GbE Family Controller")]
        [InlineData("Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz")]
        [InlineData("Local Area Connection* 1", "WAN Miniport (IKEv2)")]
        [InlineData("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter")]
        [InlineData("Ethernet 2", "Advpnet Controller")]
        public void Normal_adapters_are_not_vpns(string name, string description)
        {
            Assert.Null(Parsers.VpnAdapterMatch(name, description, Words));
        }

        [Fact]
        public void Counts_short_drops_only_during_games()
        {
            var t0 = new DateTime(2026, 11, 1, 20, 0, 0);
            var sessions = new List<RobloxSession> { new RobloxSession { PlaceId = 84448037861644, Start = t0, End = t0.AddHours(1) } };
            var ev = new List<Tuple<DateTime, bool>>
            {
                Tuple.Create(t0.AddMinutes(10), false), Tuple.Create(t0.AddMinutes(10).AddSeconds(20), true),   // short drop in game
                Tuple.Create(t0.AddMinutes(30), false), Tuple.Create(t0.AddMinutes(30).AddSeconds(5), true),    // short drop in game
                Tuple.Create(t0.AddMinutes(50), false), Tuple.Create(t0.AddMinutes(58), true),                  // 8-minute outage: ignored
                Tuple.Create(t0.AddHours(3), false), Tuple.Create(t0.AddHours(3).AddSeconds(10), true),         // not during a game
            };
            var drops = Parsers.DropsDuringGames(ev, sessions, TimeSpan.FromMinutes(3));
            Assert.Equal(2, drops.Count);
            Assert.All(drops, d => Assert.Equal(84448037861644L, d.Item2.PlaceId));
        }
    }

    public class ScriptTests
    {
        static readonly string[] Strong = { "identifyexecutor(", "hookfunction(", "fireclickdetector(" };
        static readonly string[] Weak = { "getgenv(", "Drawing.new(", "loadstring(game:HttpGet", "setreadonly(" };

        [Fact]
        public void Finds_exploit_scripts()
        {
            string hub = "getgenv().Aimbot = true\nlocal esp = Drawing.new(\"Square\")\nloadstring(game:HttpGet(\"https://example.invalid/hub.lua\"))()";
            Assert.True(Parsers.ExploitMarkers(hub, Weak).Count >= 2);
            Assert.Equal("https://example.invalid/hub.lua", Parsers.LoadstringSource(hub));
            Assert.Single(Parsers.ExploitMarkers("print(identifyexecutor())", Strong));
        }

        [Fact]
        public void Normal_lua_is_not_flagged()
        {
            string roblox = "local Players = game:GetService(\"Players\")\nPlayers.PlayerAdded:Connect(function(p) print(p.Name) end)";
            string neovim = "local lines = vim.fn.readfile(path)\nvim.fn.writefile(lines, path)\nvim.keymap.set('n', '<leader>w', ':w<CR>')";
            string wow = "hooksecurefunc(\"ChatFrame_OnEvent\", function() end)";
            foreach (var text in new[] { roblox, neovim, wow })
            {
                Assert.Empty(Parsers.ExploitMarkers(text, Strong));
                Assert.True(Parsers.ExploitMarkers(text, Weak).Count < 2);
            }
            Assert.Null(Parsers.LoadstringSource(roblox));
        }

        [Theory]
        [InlineData(@"C:\Users\a\Downloads\x7f2k.exe", true)]
        [InlineData(@"C:\Users\a\Desktop\New folder\loader.exe", true)]
        [InlineData(@"C:\Users\a\AppData\Local\Temp\abc\run.exe", true)]
        [InlineData(@"C:\Users\a\Downloads\DiscordSetup.exe", false)]
        [InlineData(@"C:\Users\a\Downloads\RobloxPlayerInstaller.exe", false)]
        [InlineData(@"C:\Program Files\Roblox\RobloxPlayerBeta.exe", false)]
        [InlineData(@"C:\Users\a\Downloads\notes.txt", false)]
        public void Loose_programs(string path, bool expected)
        {
            Assert.Equal(expected, Parsers.IsLooseUserProgram(path));
        }
    }

    public class BehaviorTests
    {
        [Fact]
        public void Reads_download_source()
        {
            string zone = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://work.ink/abc\r\nHostUrl=https://cdn.wearedevs.net/files/thing.zip\r\n";
            var hosts = Parsers.ZoneHosts(zone);
            Assert.Contains("cdn.wearedevs.net", hosts);
            Assert.Contains("work.ink", hosts);
            Assert.Equal("wearedevs.net", Parsers.MatchDomain("cdn.wearedevs.net", new[] { "wearedevs.net" }));
            Assert.Null(Parsers.MatchDomain("notwearedevs.net", new[] { "wearedevs.net" }));
            Assert.Null(Parsers.MatchDomain("github.com", new[] { "wearedevs.net", "work.ink" }));
            Assert.Empty(Parsers.ZoneHosts(null));
            Assert.Empty(Parsers.ZoneHosts("[ZoneTransfer]\r\nZoneId=3\r\n"));
        }

        [Fact]
        public void Reads_kicks_from_roblox_logs()
        {
            Assert.Equal("268", Parsers.KickFromLogLine("2026-11-01T20:10:00.000Z,1,a,6 [FLog::Output] Disconnection Notification. Reason: You have been kicked due to unexpected client behavior. (Error Code: 268)"));
            Assert.Equal("Exploiting detected", Parsers.KickFromLogLine("2026-11-01T20:10:00.000Z,1,a,6 [FLog::Output] You were kicked from this experience: Exploiting detected (Error Code: 267)"));
            Assert.Null(Parsers.KickFromLogLine("2026-11-01T20:10:00.000Z,1,a,6 [FLog::Output] Settings loaded"));
            Assert.True(Parsers.KickMentionsCheating("Exploiting detected"));
            Assert.False(Parsers.KickMentionsCheating("Server is restarting for an update"));
            Assert.False(Parsers.KickMentionsCheating("The butterfly event has ended"));
            Assert.True(Parsers.KickMentionsCheating("Anti-Cheat: fly hacking"));
            Assert.False(Parsers.KickMentionsCheating("268"));
        }

        [Fact]
        public void Kick_is_attached_to_its_game()
        {
            var log = new[]
            {
                "2026-11-01T20:00:00.000Z,1,a,6 [FLog::Output] ! Joining game 'aa11bb22-cc33-dd44-ee55-ff6677889900' place 84448037861644 at 1.1.1.1",
                "2026-11-01T20:10:00.000Z,1,a,6 [FLog::Output] Disconnection Notification. Reason: You have been kicked due to unexpected client behavior. (Error Code: 268)",
            };
            var list = Parsers.ParseRobloxLog(log, null);
            Assert.Single(list);
            Assert.Equal("268", list[0].KickReason);
            Assert.True(list[0].KickTime.HasValue);
        }
    }

    public class DeviceTests
    {
        [Fact]
        public void Pc_id_comes_from_hardware_models_not_serials()
        {
            var pc = new[]
            {
                @"PCI\VEN_10DE&DEV_2484&SUBSYS_146710DE&REV_A1\4&2B3F1C9&0&0008",
                @"PCI\VEN_8086&DEV_7AF0&SUBSYS_00748086&REV_11\3&11583659&0&A3",
                @"PCI\VEN_10EC&DEV_8125&SUBSYS_7D251462&REV_05\4&1A2B3C&0&00E4",
                @"USB\VID_046D&PID_C52B\5&2A5B9&0&2"
            };
            var a = Parsers.PcIdFromHardware(pc);
            var sameHardwareOtherSlots = pc.Select(x => x.Replace("&0&0008", "&0&0010")).Reverse().ToArray();
            Assert.Matches("^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$", a);
            Assert.Equal(a, Parsers.PcIdFromHardware(sameHardwareOtherSlots));
            Assert.NotEqual(a, Parsers.PcIdFromHardware(pc.Take(2).Concat(new[] { @"PCI\VEN_1022&DEV_1480&SUBSYS_7C371462&REV_00\3&2411E6FE&0&00" })));
            Assert.Null(Parsers.PcIdFromHardware(pc.Take(2)));
        }

        [Theory]
        [InlineData(@"USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001231122118365&0", "SanDisk Cruzer Blade")]
        [InlineData(@"USBSTOR\Disk&Ven_&Prod_USB_DISK_3.0&Rev_PMAP\070B3A1&0", "USB DISK 3.0")]
        [InlineData(@"USB\VID_046D&PID_C52B\5&2A5B9&0&2", null)]
        [InlineData(@"HID\VID_046D&PID_C52B&MI_00\7&1", null)]
        public void Names_usb_drives(string id, string expected)
        {
            Assert.Equal(expected, Parsers.UsbStorageName(id));
        }
    }

    public class MatrixRegressionTests
    {
        readonly Matcher m = new Matcher(Repo.Signatures());

        // Missed on a real PC (Nov 2026): Matrix Hub's loader is newui.exe and the program files are
        // newuimatrix.exe / olduimatrix.exe, which the old "starts with matrix" rule never matched.
        [Fact]
        public void Matrix_folder_is_found_even_if_every_program_is_renamed()
        {
            var folder = new HashSet<string> { "x7f2k.exe", "version.dat", "mcache.dat", "_license.dat" };
            var hit = m.MatchFileLayout(folder);
            Assert.NotNull(hit);
            Assert.Equal("Matrix Hub", hit.Name);
            Assert.Null(m.MatchFileLayout(new HashSet<string> { "version.dat", "settings.dat", "readme.txt" }));
            Assert.Null(m.MatchFileLayout(new HashSet<string> { "_license.dat" }));
        }

        [Fact]
        public void Matrix_loader_fingerprint_is_known()
        {
            Assert.True(Repo.Signatures().KnownBadSha256.ContainsKey("74e704b51c1c1d2ffd2c58d2c10026d88c5a50134c9989b87c98db315f341400"));
        }
    }
}
