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
}
