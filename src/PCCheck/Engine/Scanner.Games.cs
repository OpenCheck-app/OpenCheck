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
            ReportKicks();
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

        /// <summary>
        /// A program run from Downloads, Desktop, Documents or Temp while a Roblox game was open, and deleted since.
        /// This catches renamed or brand-new loaders that no name list knows about.
        /// </summary>
        /// <summary>Windows system program names run from personal folders, where the real ones never are.</summary>
        void CheckDisguisedPrograms()
        {
            int added = 0;
            foreach (var run in bamRuns.OrderByDescending(r => r.Item2))
            {
                if (added >= 10) break;
                if (!Parsers.IsDisguisedAsWindows(run.Item1)) continue;
                var game = sessions.FirstOrDefault(s => run.Item2 >= s.Start.AddMinutes(-5) && run.Item2 <= (s.End ?? s.Start).AddMinutes(5));
                var f = Simple("Program disguised as a Windows file", "Disguised program", Severity.Medium, Evidence.Ran, Groups.Cheat, run.Item2, run.Item1, "BAM",
                    "This has the name of a Windows system program, but ran from a personal folder, where the real one never is. Cheats and loaders rename themselves like this to blend in." +
                    (game != null ? " It ran while Roblox place " + game.PlaceId + " was open." : ""));
                f.RunTimes.Add(run.Item2);
                if (game != null) f.Games.Add(new GameLink { Session = game, How = "during" });
                Add(f);
                added++;
            }
        }

        void CheckDeletedRunsDuringGames()
        {
            if (sessions.Count == 0 || bamRuns.Count == 0) return;
            var slack = TimeSpan.FromMinutes(5);
            int added = 0;
            foreach (var run in bamRuns.OrderByDescending(r => r.Item2))
            {
                if (added >= 10) break;
                if (!Parsers.IsLooseUserProgram(run.Item1)) continue;
                if (matcher.MatchName(run.Item1) != null) continue;   // already reported by name
                bool exists = true;
                try { exists = File.Exists(run.Item1); } catch { }
                if (exists) continue;
                var game = sessions.FirstOrDefault(s => run.Item2 >= s.Start - slack && run.Item2 <= (s.End ?? s.Start) + slack);
                if (game == null) continue;
                var f = Simple("Deleted program ran during a Roblox game", "Unknown program", Severity.Medium, Evidence.Deleted, Groups.Cheat, run.Item2, run.Item1, "BAM + Roblox logs",
                    "This program was run from a personal folder while Roblox place " + game.PlaceId + " was open, and it has been deleted since. Renamed cheat loaders are used exactly like this. It could also be something harmless, so ask what it was.");
                f.RunTimes.Add(run.Item2);
                f.Games.Add(new GameLink { Session = game, How = "during" });
                Add(f);
                added++;
            }
        }

        /// <summary>Kicks recorded in Roblox's logs: Roblox's own anti-cheat (error 268), and games kicking the player for cheating.</summary>
        void ReportKicks()
        {
            var roblox = sessions.Where(x => x.KickReason == "268").ToList();
            if (roblox.Count > 0)
            {
                var last = roblox.OrderByDescending(x => x.KickTime ?? x.Start).First();
                var f = Simple("Kicked by Roblox's anti-cheat", "Roblox anti-cheat", Severity.Medium, Evidence.Tamper, Groups.Cheat, last.KickTime ?? last.Start,
                    "Error 268 in place " + last.PlaceId + (roblox.Count > 1 ? " (" + roblox.Count + " times)" : ""), "Roblox logs",
                    "Roblox kicked this account for \"unexpected client behavior\" (error 268). Roblox's anti-cheat shows this when it detects an executor or a modified client.");
                f.Games.Add(new GameLink { Session = last, How = "during" });
                Add(f);
            }
            foreach (var s in sessions.Where(x => x.KickReason != null && x.KickReason != "268").Take(10))
            {
                bool cheating = Parsers.KickMentionsCheating(s.KickReason);
                var f = Simple(cheating ? "Kicked by a game's anti-cheat" : "Kicked from a game", "Game kick", cheating ? Severity.Medium : Severity.Info,
                    cheating ? Evidence.Tamper : Evidence.Context, cheating ? Groups.Cheat : Groups.Context, s.KickTime ?? s.Start,
                    "Place " + s.PlaceId + ": \"" + s.KickReason + "\"", "Roblox logs",
                    cheating ? "The game kicked this player with a message about cheating or exploiting." : "The game kicked this player. Listed for context.");
                f.Games.Add(new GameLink { Session = s, How = "during" });
                Add(f);
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
