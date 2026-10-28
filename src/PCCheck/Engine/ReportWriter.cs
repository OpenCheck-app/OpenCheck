using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace PCCheck.Engine
{
    /// <summary>Turns a report into text for Discord, a .txt file, an .html file, and data for the UI.</summary>
    public static class ReportWriter
    {
        public const int DiscordLimit = 1990;

        static string VerdictWord(string v)
        {
            return v == "flag" ? "FLAGGED" : v == "review" ? "NEEDS REVIEW" : "CLEAN";
        }

        static string SevTag(Severity s)
        {
            return s == Severity.High ? "[HIGH]" : s == Severity.Medium ? "[MED] " : "[INFO]";
        }

        static string Time(DateTime? t)
        {
            return t.HasValue ? t.Value.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : "time unknown";
        }

        /// <summary>Findings in the order a moderator should read them: strongest evidence first, then newest.</summary>
        public static List<Finding> Ordered(Report r)
        {
            return r.Findings
                .OrderByDescending(f => f.IsCheat)
                .ThenByDescending(f => f.Severity)
                .ThenByDescending(f => f.Time ?? DateTime.MinValue)
                .ToList();
        }

        static string Ticks(string s) { return (s ?? "").Replace("`", "'"); }

        /// <summary>Discord-ready text. Kept under Discord's 2000 character limit; the full list is in the saved file.</summary>
        public static string BuildDiscordText(Report r)
        {
            var head = new StringBuilder();
            head.AppendLine("**OpenCheck: " + VerdictWord(r.Verdict) + "**");
            if (!string.IsNullOrEmpty(r.Who)) head.AppendLine("Checked: " + r.Who);
            head.AppendLine(r.Pc + " | " + Time(r.Finished) + " | " + r.Mode + " scan | admin: " + (r.Admin ? "yes" : "no"));
            head.AppendLine("App v" + r.AppVersion + ", SHA-256 `" + Short(r.AppSha256) + "`");
            head.AppendLine();

            var lines = new List<string>();
            foreach (var f in Ordered(r).Where(f => f.Severity != Severity.Info))
            {
                var sb = new StringBuilder();
                sb.Append(SevTag(f.Severity).Trim()).Append(' ').Append("**").Append(Ticks(f.Name)).Append("** (").Append(f.Category).Append(") ")
                  .Append(f.Evidence).Append(", ").Append(Time(f.Time));
                if (f.RunCount > 1) sb.Append(", ").Append(f.RunCount).Append(" runs");
                sb.AppendLine();
                if (!string.IsNullOrEmpty(f.Path)) sb.Append('`').Append(Ticks(f.Path)).Append('`').AppendLine();
                lines.Add(sb.ToString());
            }
            if (lines.Count == 0) lines.Add("Nothing on the cheat list was found.\n");

            var body = new StringBuilder(head.ToString());
            int shown = 0;
            foreach (var line in lines)
            {
                string tail = "...and " + (lines.Count - shown) + " more in the saved report file.";
                if (body.Length + line.Length + tail.Length > DiscordLimit)
                {
                    body.Append(tail);
                    return body.ToString();
                }
                body.Append(line);
                shown++;
            }
            return body.ToString().TrimEnd();
        }

        static string Short(string hash)
        {
            if (string.IsNullOrEmpty(hash)) return "unknown";
            return hash.Length > 16 ? hash.Substring(0, 16) + "..." : hash;
        }

        public static string BuildText(Report r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("OPENCHECK: " + VerdictWord(r.Verdict));
            sb.AppendLine(new string('=', 60));
            if (!string.IsNullOrEmpty(r.Who)) sb.AppendLine("Checked:     " + r.Who);
            sb.AppendLine("PC:          " + r.Pc);
            sb.AppendLine("Started:     " + Time(r.Started));
            sb.AppendLine("Finished:    " + Time(r.Finished) + " (" + (int)(r.Finished - r.Started).TotalSeconds + " s)");
            sb.AppendLine("Admin:       " + (r.Admin ? "Yes" : "No, partial check"));
            sb.AppendLine("Scan:        " + r.Mode);
            sb.AppendLine("App:         v" + r.AppVersion + ", cheat list " + r.ListVersion);
            sb.AppendLine("App SHA-256: " + (r.AppSha256 ?? "unknown"));
            sb.AppendLine("             Compare this with the official release to confirm the app wasn't modified.");
            sb.AppendLine();

            var ordered = Ordered(r);
            if (ordered.Count == 0) sb.AppendLine("Nothing on the cheat list was found.");
            foreach (var f in ordered)
            {
                sb.AppendLine(SevTag(f.Severity) + " " + f.Name + " (" + f.Category + ")");
                sb.AppendLine("       " + f.Evidence + ", " + Time(f.Time) + (f.RunCount > 1 ? ", " + f.RunCount + " runs" : ""));
                if (!string.IsNullOrEmpty(f.Path)) sb.AppendLine("       " + f.Path);
                if (f.Sources.Count > 0) sb.AppendLine("       Seen in: " + string.Join(", ", f.Sources));
                if (!string.IsNullOrEmpty(f.Sha256)) sb.AppendLine("       SHA-256: " + f.Sha256);
                if (!string.IsNullOrEmpty(f.Note)) sb.AppendLine("       Note: " + f.Note);
                sb.AppendLine();
            }

            if (r.Notes.Count > 0)
            {
                sb.AppendLine("Limits of this check");
                sb.AppendLine(new string('-', 60));
                foreach (var n in r.Notes) sb.AppendLine("- " + n);
                sb.AppendLine();
            }
            sb.AppendLine("A match is evidence, not proof. Names can be renamed and innocent files can share a name.");
            sb.AppendLine("A moderator should make the final call.");
            sb.AppendLine("OpenCheck is open source and is not affiliated with Roblox Corporation.");
            return sb.ToString();
        }

        public static string BuildHtml(Report r)
        {
            Func<string, string> h = s => WebUtility.HtmlEncode(s ?? "");
            string color = r.Verdict == "flag" ? "#C8362F" : r.Verdict == "review" ? "#A86E06" : "#178A5A";
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.Append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">");
            sb.Append("<title>OpenCheck: ").Append(h(VerdictWord(r.Verdict))).Append("</title><style>");
            sb.Append("body{font:15px/1.5 'Segoe UI',system-ui,sans-serif;color:#172033;background:#EDF0F4;margin:0;padding:32px 16px}");
            sb.Append("main{max-width:860px;margin:auto;background:#fff;border:1px solid #DCE1E8;border-radius:12px;padding:32px}");
            sb.Append("h1{font-size:40px;margin:0 0 4px;color:").Append(color).Append("}dl{display:grid;grid-template-columns:130px 1fr;gap:4px 12px;color:#5E6779;font-size:14px}dd{margin:0;color:#172033;word-break:break-all}");
            sb.Append(".f{border-left:4px solid #4A6280;padding:10px 14px;margin:12px 0;background:#F5F7FA;border-radius:6px}.High{border-color:#C8362F}.Medium{border-color:#A86E06}");
            sb.Append(".f b{font-size:16px}.f span{color:#5E6779}.p{font:13px Consolas,monospace;color:#5E6779;word-break:break-all}small{color:#5E6779}</style></head><body><main>");
            sb.Append("<h1>").Append(h(VerdictWord(r.Verdict))).Append("</h1><dl>");
            if (!string.IsNullOrEmpty(r.Who)) sb.Append("<dt>Checked</dt><dd>").Append(h(r.Who)).Append("</dd>");
            sb.Append("<dt>PC</dt><dd>").Append(h(r.Pc)).Append("</dd>");
            sb.Append("<dt>Finished</dt><dd>").Append(h(Time(r.Finished))).Append("</dd>");
            sb.Append("<dt>Admin</dt><dd>").Append(r.Admin ? "Yes" : "No, partial check").Append("</dd>");
            sb.Append("<dt>Scan</dt><dd>").Append(h(r.Mode)).Append("</dd>");
            sb.Append("<dt>App</dt><dd>v").Append(h(r.AppVersion)).Append(", cheat list ").Append(h(r.ListVersion)).Append("</dd>");
            sb.Append("<dt>App SHA-256</dt><dd>").Append(h(r.AppSha256 ?? "unknown")).Append("</dd></dl>");
            var ordered = Ordered(r);
            if (ordered.Count == 0) sb.Append("<p>Nothing on the cheat list was found.</p>");
            foreach (var f in ordered)
            {
                sb.Append("<div class=\"f ").Append(f.Severity).Append("\"><b>").Append(h(f.Name)).Append("</b> <span>").Append(h(f.Category)).Append(" &middot; ")
                  .Append(h(f.Evidence)).Append(" &middot; ").Append(h(Time(f.Time)));
                if (f.RunCount > 1) sb.Append(" &middot; ").Append(f.RunCount).Append(" runs");
                sb.Append("</span>");
                if (!string.IsNullOrEmpty(f.Path)) sb.Append("<div class=\"p\">").Append(h(f.Path)).Append("</div>");
                if (f.Sources.Count > 0) sb.Append("<small>Seen in: ").Append(h(string.Join(", ", f.Sources))).Append("</small><br>");
                if (!string.IsNullOrEmpty(f.Sha256)) sb.Append("<small class=\"p\">SHA-256: ").Append(h(f.Sha256)).Append("</small><br>");
                if (!string.IsNullOrEmpty(f.Note)) sb.Append("<small>").Append(h(f.Note)).Append("</small>");
                sb.Append("</div>");
            }
            if (r.Notes.Count > 0)
            {
                sb.Append("<h3>Limits of this check</h3><ul>");
                foreach (var n in r.Notes) sb.Append("<li>").Append(h(n)).Append("</li>");
                sb.Append("</ul>");
            }
            sb.Append("<p><small>A match is evidence, not proof. A moderator should make the final call. OpenCheck is open source and is not affiliated with Roblox Corporation.</small></p></main></body></html>");
            return sb.ToString();
        }

        /// <summary>The ONLY place this app writes files: the report, to the Desktop. Returns the .txt file name.</summary>
        public static string SaveToDesktop(Report r)
        {
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string who = Parsers.SafeName(r.Who, 30);
            foreach (char c in Path.GetInvalidFileNameChars()) who = who.Replace(c.ToString(), "");
            string baseName = "OpenCheck" + (who.Length > 0 ? " - " + who : "") + " - " + r.Finished.ToString("yyyy-MM-dd HHmm", CultureInfo.InvariantCulture);
            string txt = Path.Combine(desktop, baseName + ".txt");
            string html = Path.Combine(desktop, baseName + ".html");
            File.WriteAllText(txt, BuildText(r), new UTF8Encoding(false));
            File.WriteAllText(html, BuildHtml(r), new UTF8Encoding(false));
            return Path.GetFileName(txt);
        }

        /// <summary>Plain data for the UI.</summary>
        public static Dictionary<string, object> ToUi(Report r)
        {
            return new Dictionary<string, object>
            {
                { "verdict", r.Verdict },
                { "who", r.Who },
                { "pc", r.Pc },
                { "finished", r.Finished.ToString("o", CultureInfo.InvariantCulture) },
                { "seconds", (int)Math.Round((r.Finished - r.Started).TotalSeconds) },
                { "admin", r.Admin },
                { "mode", r.Mode },
                { "findings", r.Findings.Select(f => (object)new Dictionary<string, object>
                    {
                        { "name", f.Name },
                        { "category", f.Category },
                        { "severity", f.Severity == Severity.High ? "high" : f.Severity == Severity.Medium ? "medium" : "info" },
                        { "evidence", f.Evidence },
                        { "group", f.Group },
                        { "time", f.Time.HasValue ? f.Time.Value.ToString("o", CultureInfo.InvariantCulture) : null },
                        { "path", f.Path },
                        { "sources", f.Sources.ToArray() },
                        { "runCount", f.RunCount },
                        { "sha256", f.Sha256 },
                        { "note", f.Note },
                        { "cheat", f.IsCheat }
                    }).ToArray() }
            };
        }
    }
}
