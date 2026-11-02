using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace PCCheck.Engine
{
    public sealed partial class Scanner
    {
        readonly List<RobloxSession> sessions = new List<RobloxSession>();

        /// <summary>
        /// Roblox game sessions from Roblox's own log files (place ID, join and leave times only).
        /// Used to show which game was open when a cheat ran. Nothing else from the logs is kept.
        /// </summary>
        string ScanRobloxGames()
        {
            var files = new List<FileInfo>();
            foreach (var p in profiles)
            {
                foreach (var dir in new[] { @"AppData\Local\Roblox\logs", @"AppData\Local\Roblox\logs\archive" })
                {
                    try
                    {
                        var di = new DirectoryInfo(Path.Combine(p.Path, dir));
                        if (di.Exists) files.AddRange(di.EnumerateFiles("*.log"));
                    }
                    catch { }
                }
            }

            var cutoff = DateTime.Now.AddDays(-60);
            var recent = files.Where(f => { try { return f.LastWriteTime > cutoff; } catch { return false; } })
                              .OrderByDescending(f => f.LastWriteTime).Take(150).ToList();
            var sw = Stopwatch.StartNew();
            int seconds = options.Depth == "quick" ? 8 : options.Depth == "thorough" ? 40 : 20;
            long budget = 600L << 20, read = 0;
            int done = 0;

            foreach (var f in recent)
            {
                if (cancelled || sw.Elapsed.TotalSeconds > seconds || read > budget) break;
                try
                {
                    if (f.Length > 200L << 20) continue;
                    read += f.Length;
                    using (var fs = new FileStream(f.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (var reader = new StreamReader(fs, Encoding.UTF8))
                    {
                        foreach (var s in Parsers.ParseRobloxLog(Lines(reader), f.LastWriteTime))
                        {
                            s.LogFile = f.Name;
                            sessions.Add(s);
                        }
                    }
                }
                catch { }
                done++;
                if (done % 5 == 0) { Breathe(); Tick("Reading Roblox logs", (double)done / Math.Max(1, recent.Count)); }
            }
            if (done < recent.Count) notes.Add("Only the newest " + done + " of " + recent.Count + " Roblox logs were read (time limit).");

            sessions.Sort((a, b) => b.Start.CompareTo(a.Start));
            CheckMissingRobloxLogs(files);
            if (files.Count > 0 && recent.Count == 0)
                notes.Add("Roblox is installed but has no logs from the last 60 days.");

            if (sessions.Count == 0)
            {
                var newest = files.OrderByDescending(f => f.LastWriteTime).FirstOrDefault();
                if (newest != null)
                    Add(Simple("Roblox last used", "Roblox", Severity.Info, Evidence.Context, Groups.Context, newest.LastWriteTime,
                        newest.DirectoryName, "Roblox logs", "No game joins were found in the logs, but this is when Roblox last wrote one."));
                return files.Count == 0 ? "No Roblox logs found" : "No games in the logs";
            }
            var oldest = sessions[sessions.Count - 1].Start;
            int days = Math.Max(1, (int)Math.Ceiling((DateTime.Now - oldest).TotalDays));
            var latest = sessions[0];
            Add(Simple("Last Roblox game", "Roblox", Severity.Info, Evidence.Context, Groups.Context, latest.Start,
                "Place " + latest.PlaceId + " (roblox.com/games/" + latest.PlaceId + ")", "Roblox logs",
                "Joined " + latest.Start.ToString("g") + (latest.End.HasValue ? ", left " + latest.End.Value.ToString("t") : "") +
                ". " + sessions.Count + " game sessions found in the last " + days + (days == 1 ? " day." : " days.")));
            return sessions.Count + (sessions.Count == 1 ? " game session" : " game sessions") + ", last " + days + (days == 1 ? " day" : " days");
        }

        /// <summary>
        /// Prefetch says when Roblox started. Every start makes a new Roblox log, so a recent start with no log
        /// covering it means the logs were deleted. Only file times are compared here.
        /// </summary>
        void CheckMissingRobloxLogs(List<FileInfo> logFiles)
        {
            if (!admin) return;
            var starts = new List<DateTime>();
            try
            {
                foreach (var pf in Directory.EnumerateFiles(Path.Combine(windowsDir, "Prefetch"), "ROBLOXPLAYERBETA.EXE-*.pf"))
                {
                    try
                    {
                        var info = Parsers.ParsePrefetch(Native.DecompressPrefetch(File.ReadAllBytes(pf)));
                        if (info != null) starts.AddRange(info.RunTimes);
                    }
                    catch { }
                }
            }
            catch { return; }

            var spans = new List<Tuple<DateTime, DateTime>>();
            foreach (var f in logFiles)
            {
                try { spans.Add(Tuple.Create(f.CreationTime, f.LastWriteTime)); } catch { }
            }
            var missing = Parsers.UncoveredStarts(starts, spans, DateTime.Now.AddDays(-3), DateTime.Now.AddMinutes(-10));
            if (missing.Count >= 2 || (missing.Count == 1 && spans.Count == 0))
            {
                Add(Simple("Roblox logs deleted", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, missing.Max(),
                    @"~\AppData\Local\Roblox\logs", "Prefetch + Roblox logs",
                    "Roblox started " + missing.Count + (missing.Count == 1 ? " time" : " times") + " in the last 3 days with no Roblox log left for " +
                    (missing.Count == 1 ? "it" : "those starts") + " (latest " + missing.Max().ToString("g") + "). Roblox writes a log every time it opens, so these were most likely deleted to hide which games were played."));
            }
        }

        static IEnumerable<string> Lines(StreamReader reader)
        {
            string line;
            while ((line = reader.ReadLine()) != null) yield return line;
        }

        /// <summary>After every check: line up each cheat's run times with the Roblox games open at the time.</summary>
        void LinkGames()
        {
            if (sessions.Count == 0) return;
            foreach (var f in findings.Values)
            {
                if (f.Group != Groups.Cheat) continue;
                var times = new SortedSet<DateTime>(f.RunTimes);
                if (f.Evidence == Evidence.Running) times.Add(DateTime.Now);
                if (times.Count == 0) continue;

                var seen = new HashSet<RobloxSession>();
                foreach (var t in times.Reverse())
                {
                    foreach (var link in Parsers.GamesAround(t, sessions))
                    {
                        if (f.Games.Count >= 6 || !seen.Add(link.Session)) continue;
                        f.Games.Add(link);
                    }
                }
            }
        }
    }
}
