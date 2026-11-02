using System;
using System.Collections.Generic;
using System.Linq;

namespace PCCheck.Engine
{
    public enum Severity { Info = 0, Medium = 1, High = 2 }

    /// <summary>Evidence wording shown in the UI and reports.</summary>
    public static class Evidence
    {
        public const string Found = "Found on this PC";
        public const string Running = "Running right now";
        public const string Ran = "Ran on this PC";
        public const string Deleted = "Deleted";
        public const string Renamed = "Renamed";
        public const string WasHere = "Was on this PC";
        public const string Defender = "Caught by Windows Security";
        public const string Excluded = "Hidden from antivirus";
        public const string Tamper = "Possible tampering";
        public const string FastFlag = "Unfair FastFlag";
        public const string LagSwitch = "Possible lag switch";
        public const string Vpn = "VPN";
        public const string Reset = "PC reset";
        public const string Context = "Context";
    }

    public static class Groups
    {
        public const string Cheat = "cheat";
        public const string Tamper = "tamper";
        public const string FastFlags = "fflags";
        public const string Hardware = "hw";
        public const string Context = "context";
        public const string Network = "net";
    }

    public sealed class Finding
    {
        public string Name;
        public string Category;
        public Severity Severity;
        public string Evidence;
        public string Group;
        public DateTime? Time;
        public string Path;
        public readonly SortedSet<string> Sources = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        public int RunCount;
        /// <summary>Every run time we know of (Prefetch keeps up to 8). Time is the latest one.</summary>
        public readonly SortedSet<DateTime> RunTimes = new SortedSet<DateTime>();
        /// <summary>Roblox games that were open when this ran (from Roblox's own logs).</summary>
        public readonly List<GameLink> Games = new List<GameLink>();
        public string Sha256;
        public string Note;
        /// <summary>True when the finding matched a high-severity cheat signature.</summary>
        public bool IsCheat;

        /// <summary>
        /// Findings with the same key are combined into one row. Program history is keyed by file name, so
        /// Prefetch ("POTASSIUM.EXE") and BAM ("C:\...\Potassium.exe") end up on the same row with both sources.
        /// </summary>
        public string MergeKey
        {
            get
            {
                string p = Path ?? "";
                if (Evidence == PCCheck.Engine.Evidence.Ran)
                {
                    int slash = p.LastIndexOf('\\');
                    if (slash >= 0) p = p.Substring(slash + 1);
                }
                return (Evidence + "|" + Name + "|" + p).ToLowerInvariant();
            }
        }

        public void MergeFrom(Finding other)
        {
            // Prefer a full path over a bare file name.
            if (other.Path != null && other.Path.IndexOf('\\') >= 0 && (Path == null || Path.IndexOf('\\') < 0)) Path = other.Path;
            foreach (var s in other.Sources) Sources.Add(s);
            if (other.Time.HasValue && (!Time.HasValue || other.Time.Value > Time.Value)) Time = other.Time;
            if (other.RunCount > RunCount) RunCount = other.RunCount;
            foreach (var t in other.RunTimes) RunTimes.Add(t);
            if (Sha256 == null) Sha256 = other.Sha256;
            if (Note == null) Note = other.Note;
            if (other.Severity > Severity) Severity = other.Severity;
            IsCheat = IsCheat || other.IsCheat;
        }
    }

    /// <summary>One Roblox game session, read from Roblox's own log files.</summary>
    public sealed class RobloxSession
    {
        public long PlaceId;
        public long UniverseId;
        public DateTime Start;
        public DateTime? End;
        /// <summary>True when the log has no leave line (Roblox closed or is still open).</summary>
        public bool NoLeave;
        public string LogFile;
    }

    /// <summary>A Roblox game that was open when a cheat ran.</summary>
    public sealed class GameLink
    {
        public RobloxSession Session;
        /// <summary>"during": the cheat ran while this game was open. "before": it ran shortly before the game was joined.</summary>
        public string How;
    }

    public sealed class Report
    {
        public List<RobloxSession> Sessions = new List<RobloxSession>();
        public string Verdict;          // flag, review, clean
        public string Who;
        public string Pc;
        public string AppVersion;
        public string AppSha256;
        public string ListVersion;
        /// <summary>Scan depth and performance settings used, e.g. "Standard" or "Quick, low CPU".</summary>
        public string Mode = "Standard";
        public DateTime Started;
        public DateTime Finished;
        public bool Admin;
        public List<Finding> Findings = new List<Finding>();
        public List<string> Notes = new List<string>();

        public static string DecideVerdict(IEnumerable<Finding> findings)
        {
            var list = findings.ToList();
            if (list.Any(f => f.IsCheat)) return "flag";
            if (list.Any(f => f.Severity >= Severity.Medium)) return "review";
            return "clean";
        }
    }
}
