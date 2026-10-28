using System.Collections.Generic;
using PCCheck.Engine;
using Xunit;

namespace PCCheck.Tests
{
    public class ScanOptionsTests
    {
        [Fact]
        public void Defaults_are_standard_with_everything_on()
        {
            var o = ScanOptions.FromJson(null);
            Assert.Equal("Standard", o.DepthName);
            Assert.True(o.OtherDrives);
            Assert.True(o.HashMatches);
            Assert.False(o.LowCpu);
            Assert.Equal("Standard", o.Summary);
        }

        [Fact]
        public void Reads_settings_from_the_ui()
        {
            var o = ScanOptions.FromJson(new Dictionary<string, object>
            {
                { "depth", "thorough" }, { "lowCpu", true }, { "otherDrives", false }, { "hashMatches", false }
            });
            Assert.Equal("Thorough", o.DepthName);
            Assert.True(o.LowCpu);
            Assert.False(o.ScanOtherDrives);
            Assert.Equal("Thorough, Windows drive only, low CPU, no fingerprints", o.Summary);
            Assert.True(o.FileSeconds > new ScanOptions().FileSeconds);
        }

        [Fact]
        public void Unknown_depth_falls_back_to_standard()
        {
            var o = ScanOptions.FromJson(new Dictionary<string, object> { { "depth", "ultra" } });
            Assert.Equal("Standard", o.DepthName);
        }

        [Fact]
        public void Quick_only_checks_the_windows_drive()
        {
            var o = ScanOptions.FromJson(new Dictionary<string, object> { { "depth", "quick" } });
            Assert.False(o.ScanOtherDrives);
            Assert.True(o.FileSeconds < new ScanOptions().FileSeconds);
            Assert.Equal(-1, o.DepthBonus);
        }

        [Fact]
        public void Report_shows_the_scan_mode()
        {
            var r = new Report { Verdict = "clean", Pc = "Windows 11", AppVersion = "1.0.0", ListVersion = "x", Mode = "Quick, low CPU", Started = System.DateTime.Now, Finished = System.DateTime.Now };
            Assert.Contains("Quick, low CPU", ReportWriter.BuildText(r));
            Assert.Contains("Quick, low CPU scan", ReportWriter.BuildDiscordText(r));
        }
    }
}
