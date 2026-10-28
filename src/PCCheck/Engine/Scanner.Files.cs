using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PCCheck.Engine
{
    public sealed partial class Scanner
    {
        static readonly HashSet<string> SkipAnywhere = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "$recycle.bin", "system volume information", "winsxs", "node_modules", ".git", "$windows.~bt", "$windows.~ws", "$winreagent" };

        // Folders at the drive root that are scanned separately (or are Windows itself).
        static readonly HashSet<string> SkipAtRoot = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "windows", "users", "program files", "program files (x86)", "programdata", "recovery", "msocache", "perflogs" };

        const long MaxHashBytes = 150L * 1024 * 1024;

        /// <summary>Looks at file and folder NAMES in user folders, ProgramData and Program Files. Contents are only read to fingerprint (hash) a file that already matched.</summary>
        string ScanFiles()
        {
            var roots = new List<KeyValuePair<string, int>>();
            foreach (var p in profiles)
            {
                foreach (var sub in new[] { "Desktop", "Downloads", "Documents", @"AppData\Local", @"AppData\Roaming", @"AppData\LocalLow" })
                    roots.Add(new KeyValuePair<string, int>(Path.Combine(p.Path, sub), Depth(sub.StartsWith("AppData") ? 4 : 5)));
                try
                {
                    foreach (var od in Directory.GetDirectories(p.Path, "OneDrive*"))
                        roots.Add(new KeyValuePair<string, int>(od, Depth(5)));
                }
                catch { }
            }
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            roots.Add(new KeyValuePair<string, int>(programData, Depth(3)));
            foreach (var pf in ProgramFilesDirs()) roots.Add(new KeyValuePair<string, int>(pf, Depth(2)));
            roots.Add(new KeyValuePair<string, int>(systemDrive + "\\", Depth(2)));
            if (options.ScanOtherDrives)
            {
                foreach (var d in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (d.DriveType == DriveType.Fixed && d.IsReady && !d.Name.TrimEnd('\\').Equals(systemDrive, StringComparison.OrdinalIgnoreCase))
                            roots.Add(new KeyValuePair<string, int>(d.Name, Depth(2)));
                    }
                    catch { }
                }
            }

            bool hashUnknown = set.KnownBadSha256.Count > 0;
            var sw = Stopwatch.StartNew();
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            long names = 0;
            bool outOfTime = false;
            int rootIndex = 0;

            foreach (var root in roots)
            {
                rootIndex++;
                if (outOfTime || cancelled) break;
                if (!Directory.Exists(root.Key)) continue;
                var stack = new Stack<KeyValuePair<string, int>>();
                stack.Push(new KeyValuePair<string, int>(root.Key, 0));
                bool isDriveRoot = root.Key.Length <= 3;

                while (stack.Count > 0)
                {
                    if (sw.Elapsed.TotalSeconds > options.FileSeconds || cancelled) { outOfTime = true; break; }
                    var item = stack.Pop();
                    string dir = item.Key;
                    int depth = item.Value;
                    if (!visited.Add(dir.TrimEnd('\\'))) continue;

                    var childDirs = new List<string>();
                    var childNames = new HashSet<string>(StringComparer.Ordinal);
                    try
                    {
                        foreach (var e in new DirectoryInfo(dir).EnumerateFileSystemInfos())
                        {
                            names++;
                            if (names % 2000 == 0) Breathe();
                            if (names % 4000 == 0)
                                Tick("Checked " + names.ToString("N0") + " names", (double)rootIndex / roots.Count);

                            if ((e.Attributes & FileAttributes.Directory) != 0)
                            {
                                childNames.Add(e.Name.ToLowerInvariant());
                                if ((e.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                                if (SkipAnywhere.Contains(e.Name)) continue;
                                if (isDriveRoot && depth == 0 && SkipAtRoot.Contains(e.Name)) continue;

                                var folderSig = matcher.MatchFolderName(e.Name);
                                if (folderSig != null)
                                    Add(FromSignature(folderSig, Evidence.Found, e.FullName, e.LastWriteTime, "Folder"));

                                if (depth < root.Value) childDirs.Add(e.FullName);
                            }
                            else
                            {
                                string ext = Path.GetExtension(e.Name);
                                if (!Matcher.ScannedExtensions.Contains(ext)) continue;
                                var sig = matcher.MatchName(e.Name);
                                bool isBinary = ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);
                                long length = 0;
                                try { length = ((FileInfo)e).Length; } catch { }

                                if (sig != null)
                                {
                                    var f = FromSignature(sig, Evidence.Found, e.FullName, e.LastWriteTime, "File");
                                    if (options.HashMatches && isBinary && length < MaxHashBytes) f.Sha256 = SafeHash(e.FullName);
                                    Add(f);
                                }
                                else if (hashUnknown && isBinary && length < 60L * 1024 * 1024 &&
                                         (e.FullName.IndexOf(@"\Downloads\", StringComparison.OrdinalIgnoreCase) >= 0 || e.FullName.IndexOf(@"\Desktop\", StringComparison.OrdinalIgnoreCase) >= 0))
                                {
                                    string hash = SafeHash(e.FullName);
                                    string known;
                                    if (hash != null && set.KnownBadSha256.TryGetValue(hash, out known))
                                    {
                                        var f = Simple(known, "Known cheat file (renamed)", Severity.High, Evidence.Found, Groups.Cheat, e.LastWriteTime, e.FullName, "Fingerprint match", "The file name was changed, but its fingerprint matches a known cheat.");
                                        f.IsCheat = true;
                                        f.Sha256 = hash;
                                        Add(f);
                                    }
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                    catch (System.Security.SecurityException) { }

                    var layout = matcher.MatchLayout(childNames);
                    if (layout != null)
                    {
                        DateTime? t = null;
                        try { t = Directory.GetLastWriteTime(dir); } catch { }
                        var f = Simple("Executor workspace", "Executor files", Severity.High, Evidence.Found, Groups.Cheat, t, dir,
                            "Folder layout: " + string.Join(" + ", layout),
                            "Executors keep scripts in these folders. They are often left behind after the executor itself is deleted.");
                        f.IsCheat = true;
                        Add(f);
                    }

                    foreach (var c in childDirs) stack.Push(new KeyValuePair<string, int>(c, depth + 1));
                }
            }

            // Known install folders from the list (checked even if the walk above ran out of time).
            foreach (var sig in set.Items)
            {
                foreach (var template in sig.Folders)
                {
                    foreach (var path in ExpandForProfiles(template))
                    {
                        try
                        {
                            if (Directory.Exists(path))
                                Add(FromSignature(sig, Evidence.Found, path, Directory.GetLastWriteTime(path), "Known install folder"));
                        }
                        catch { }
                    }
                }
            }

            if (outOfTime) notes.Add("The file scan hit its time limit after " + names.ToString("N0") + " names. Some deep folders were skipped.");
            int hits = areaFindings.Count(f => f.Severity >= Severity.Medium);
            return hits == 0
                ? "Nothing found in " + names.ToString("N0") + " names"
                : hits + (hits == 1 ? " match" : " matches") + " in " + names.ToString("N0") + " names";
        }

        /// <summary>Folder depth limit adjusted for the chosen scan depth (never below 1).</summary>
        int Depth(int normal)
        {
            return Math.Max(1, normal + options.DepthBonus);
        }

        static IEnumerable<string> ProgramFilesDirs()
        {
            var list = new List<string>();
            string a = Environment.GetEnvironmentVariable("ProgramW6432");
            string b = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string c = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            foreach (var p in new[] { a, b, c })
                if (!string.IsNullOrEmpty(p) && !list.Contains(p, StringComparer.OrdinalIgnoreCase)) list.Add(p);
            return list;
        }

        /// <summary>Expands %LocalAppData% and friends for every user profile on the PC.</summary>
        IEnumerable<string> ExpandForProfiles(string template)
        {
            var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var pfDirs = ProgramFilesDirs().ToList();
            string pf64 = pfDirs.Count > 0 ? pfDirs[0] : @"C:\Program Files";
            string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

            foreach (var p in profiles)
            {
                string s = template;
                s = ReplaceVar(s, "%ProgramFiles(x86)%", pf86);
                s = ReplaceVar(s, "%ProgramFiles%", pf64);
                s = ReplaceVar(s, "%ProgramData%", programData);
                s = ReplaceVar(s, "%LocalAppData%", Path.Combine(p.Path, @"AppData\Local"));
                s = ReplaceVar(s, "%AppData%", Path.Combine(p.Path, @"AppData\Roaming"));
                s = ReplaceVar(s, "%UserProfile%", p.Path);
                if (s.IndexOf('%') < 0) results.Add(s);
            }
            return results;
        }

        static string ReplaceVar(string s, string variable, string value)
        {
            if (string.IsNullOrEmpty(value)) return s;
            return Regex.Replace(s, Regex.Escape(variable), value.Replace("$", "$$"), RegexOptions.IgnoreCase);
        }
    }
}
