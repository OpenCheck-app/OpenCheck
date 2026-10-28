using System;
using System.Collections.Generic;

namespace PCCheck.Engine
{
    /// <summary>Performance settings chosen in the Settings panel. They change how deep and how fast the check runs, never what it's allowed to do.</summary>
    public sealed class ScanOptions
    {
        public string Depth = "standard";   // quick, standard, thorough
        public bool LowCpu;
        public bool OtherDrives = true;
        public bool HashMatches = true;

        public string DepthName
        {
            get { return Depth == "quick" ? "Quick" : Depth == "thorough" ? "Thorough" : "Standard"; }
        }

        /// <summary>Time limit for walking file and folder names.</summary>
        public int FileSeconds
        {
            get { return Depth == "quick" ? 30 : Depth == "thorough" ? 180 : 75; }
        }

        /// <summary>Added to every folder depth limit (Quick looks less deep, Thorough looks deeper).</summary>
        public int DepthBonus
        {
            get { return Depth == "quick" ? -1 : Depth == "thorough" ? 2 : 0; }
        }

        /// <summary>Time limit for reading each drive's change log.</summary>
        public int JournalSeconds
        {
            get { return Depth == "quick" ? 15 : Depth == "thorough" ? 90 : 35; }
        }

        /// <summary>Quick checks only the Windows drive. Otherwise it follows the "Check other drives" switch.</summary>
        public bool ScanOtherDrives
        {
            get { return OtherDrives && Depth != "quick"; }
        }

        public string Summary
        {
            get
            {
                var parts = new List<string> { DepthName };
                if (!ScanOtherDrives) parts.Add("Windows drive only");
                if (LowCpu) parts.Add("low CPU");
                if (!HashMatches) parts.Add("no fingerprints");
                return string.Join(", ", parts);
            }
        }

        public static ScanOptions FromJson(Dictionary<string, object> d)
        {
            var o = new ScanOptions();
            if (d == null) return o;
            string depth = (Json.Str(d, "depth") ?? "").ToLowerInvariant();
            if (depth == "quick" || depth == "standard" || depth == "thorough") o.Depth = depth;
            if (d.ContainsKey("lowCpu")) o.LowCpu = Json.Bool(d, "lowCpu");
            if (d.ContainsKey("otherDrives")) o.OtherDrives = Json.Bool(d, "otherDrives");
            if (d.ContainsKey("hashMatches")) o.HashMatches = Json.Bool(d, "hashMatches");
            return o;
        }
    }
}
