using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml.Linq;
using Microsoft.Win32;

namespace PCCheck.Engine
{
    public sealed class ProgressUpdate
    {
        public string Area;
        public string State;    // running, ok, hit, warn
        public string Detail;
        public double Percent;
    }

    public sealed class UserProfile
    {
        public string Sid;
        public string Path;
    }

    /// <summary>
    /// Runs every check in order. Everything here READS ONLY: no file, registry key or setting is changed,
    /// and nothing is sent over the network.
    /// </summary>
    public sealed partial class Scanner
    {
        readonly Matcher matcher;
        readonly SignatureSet set;
        readonly ScanOptions options;
        readonly Action<ProgressUpdate> onProgress;
        readonly Dictionary<string, Finding> findings = new Dictionary<string, Finding>();
        readonly List<Finding> areaFindings = new List<Finding>();
        readonly List<string> notes = new List<string>();
        readonly List<UserProfile> profiles;
        readonly bool admin;
        readonly string windowsDir;
        readonly string systemDrive;
        string currentArea;
        double areaStartPercent, areaEndPercent;
        volatile bool cancelled;

        public Scanner(SignatureSet set, ScanOptions options, Action<ProgressUpdate> onProgress)
        {
            this.set = set;
            this.options = options ?? new ScanOptions();
            this.matcher = new Matcher(set);
            this.onProgress = onProgress ?? (p => { });
            this.admin = IsAdmin();
            this.windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            this.systemDrive = Path.GetPathRoot(windowsDir).TrimEnd('\\');
            this.profiles = FindProfiles();
        }

        public void Cancel() { cancelled = true; }

        delegate string AreaFn();

        public Report Run(string who)
        {
            var report = new Report
            {
                Who = Parsers.SafeName(who, 40),
                Started = DateTime.Now,
                Admin = admin,
                ListVersion = set.Version,
                AppVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString(3),
                AppSha256 = SafeHash(Assembly.GetExecutingAssembly().Location),
                Pc = WindowsName(),
                Mode = options.Summary
            };

            if (options.LowCpu)
            {
                // Low CPU mode: let games and other apps go first.
                try { Thread.CurrentThread.Priority = ThreadPriority.BelowNormal; } catch { }
                try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
            }

            var areas = new List<Tuple<string, double, AreaFn>>
            {
                Tuple.Create("files", 30.0, (AreaFn)ScanFiles),
                Tuple.Create("exec", 14.0, (AreaFn)ScanProgramHistory),
                Tuple.Create("deleted", 22.0, (AreaFn)ScanDeleted),
                Tuple.Create("defender", 6.0, (AreaFn)ScanDefender),
                Tuple.Create("logs", 6.0, (AreaFn)ScanLogs),
                Tuple.Create("fflags", 4.0, (AreaFn)ScanFastFlags),
                Tuple.Create("vm", 6.0, (AreaFn)ScanVirtualMachines),
                Tuple.Create("dma", 8.0, (AreaFn)ScanDma),
                Tuple.Create("running", 4.0, (AreaFn)ScanRunning),
            };
            double total = areas.Sum(a => a.Item2), done = 0;

            foreach (var area in areas)
            {
                if (cancelled) break;
                currentArea = area.Item1;
                areaStartPercent = done / total * 100;
                areaEndPercent = (done + area.Item2) / total * 100;
                areaFindings.Clear();
                Progress("running", "Checking", areaStartPercent);

                string detail;
                bool failed = false;
                try { detail = area.Item3(); }
                catch (Exception ex)
                {
                    failed = true;
                    detail = "Couldn't finish this step";
                    notes.Add(area.Item1 + ": " + ex.GetType().Name + ": " + ex.Message);
                }

                done += area.Item2;
                string state = areaFindings.Any(f => f.IsCheat) ? "hit"
                             : (failed || areaFindings.Any(f => f.Severity >= Severity.Medium)) ? "warn"
                             : "ok";
                Progress(state, detail, done / total * 100);
            }

            report.Findings = findings.Values.ToList();
            report.Notes = notes;
            if (!admin) notes.Add("Not run as administrator, so Prefetch, the drive change log and the Security log could not be read.");
            report.Verdict = Report.DecideVerdict(report.Findings);
            report.Finished = DateTime.Now;
            return report;
        }

        // ---------- shared helpers ----------

        /// <summary>In Low CPU mode, give other programs a moment every so often.</summary>
        void Breathe()
        {
            if (options.LowCpu) Thread.Sleep(2);
        }

        void Progress(string state, string detail, double percent)
        {
            onProgress(new ProgressUpdate { Area = currentArea, State = state, Detail = detail, Percent = percent });
        }

        /// <summary>Progress inside an area (0..1 of that area).</summary>
        void Tick(string detail, double fraction)
        {
            fraction = Math.Max(0, Math.Min(1, fraction));
            Progress("running", detail, areaStartPercent + (areaEndPercent - areaStartPercent) * fraction);
        }

        void Add(Finding f)
        {
            f.Path = Matcher.MaskUser(f.Path);
            string key = f.MergeKey;
            Finding existing;
            if (findings.TryGetValue(key, out existing))
            {
                existing.MergeFrom(f);
                if (!areaFindings.Contains(existing)) areaFindings.Add(existing);
            }
            else
            {
                findings[key] = f;
                areaFindings.Add(f);
            }
        }

        /// <summary>Builds a finding from a cheat-list match.</summary>
        Finding FromSignature(Signature sig, string evidence, string path, DateTime? time, string source)
        {
            var sev = sig.Severity;
            bool strongEvidence = evidence == Evidence.Found || evidence == Evidence.Running || evidence == Evidence.Excluded;
            if (sev == Severity.High && !strongEvidence) sev = Severity.Medium;

            string group;
            string cat = sig.Category ?? "";
            if (sig.Severity == Severity.Info) group = Groups.Context;
            else if (cat.IndexOf("Virtual", StringComparison.OrdinalIgnoreCase) >= 0 || cat.IndexOf("Emulator", StringComparison.OrdinalIgnoreCase) >= 0 || cat == "DMA") group = Groups.Hardware;
            else if (cat.IndexOf("cleaner", StringComparison.OrdinalIgnoreCase) >= 0) group = Groups.Tamper;
            else group = Groups.Cheat;

            var f = new Finding
            {
                Name = sig.Name,
                Category = sig.Category,
                Severity = sev,
                Evidence = evidence,
                Group = group,
                Time = time,
                Path = path,
                Note = sig.Note,
                IsCheat = sig.Severity == Severity.High
            };
            if (!string.IsNullOrEmpty(source)) f.Sources.Add(source);
            return f;
        }

        Finding Simple(string name, string category, Severity sev, string evidence, string group, DateTime? time, string path, string source, string note)
        {
            var f = new Finding { Name = name, Category = category, Severity = sev, Evidence = evidence, Group = group, Time = time, Path = path, Note = note };
            if (!string.IsNullOrEmpty(source)) f.Sources.Add(source);
            return f;
        }

        static bool IsAdmin()
        {
            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        static List<UserProfile> FindProfiles()
        {
            var list = new List<UserProfile>();
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                {
                    if (key != null)
                    {
                        foreach (var sid in key.GetSubKeyNames())
                        {
                            if (!sid.StartsWith("S-1-5-21-")) continue;
                            using (var sk = key.OpenSubKey(sid))
                            {
                                var path = sk == null ? null : sk.GetValue("ProfileImagePath") as string;
                                if (!string.IsNullOrEmpty(path))
                                {
                                    path = Environment.ExpandEnvironmentVariables(path);
                                    if (Directory.Exists(path)) list.Add(new UserProfile { Sid = sid, Path = path });
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            if (list.Count == 0)
                list.Add(new UserProfile { Sid = null, Path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) });
            return list;
        }

        /// <summary>User hives that are loaded right now (signed-in users).</summary>
        static List<string> LoadedUserSids()
        {
            try
            {
                return Registry.Users.GetSubKeyNames()
                    .Where(s => s.StartsWith("S-1-5-21-") && !s.EndsWith("_Classes"))
                    .ToList();
            }
            catch { return new List<string>(); }
        }

        static string WindowsName()
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    string name = k.GetValue("ProductName") as string ?? "Windows";
                    string ver = k.GetValue("DisplayVersion") as string ?? "";
                    int build;
                    if (int.TryParse(k.GetValue("CurrentBuild") as string, out build) && build >= 22000)
                        name = name.Replace("Windows 10", "Windows 11");
                    return (name + " " + ver).Trim();
                }
            }
            catch { return "Windows"; }
        }

        static DateTime? WindowsInstallDate()
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    object v = k.GetValue("InstallDate");
                    if (v is int) return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds((uint)(int)v).ToLocalTime();
                }
            }
            catch { }
            return null;
        }

        static string SafeHash(string path)
        {
            try
            {
                using (var sha = SHA256.Create())
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
            }
            catch { return null; }
        }

        static IEnumerable<ManagementBaseObject> Wmi(string query)
        {
            var results = new List<ManagementBaseObject>();
            try
            {
                using (var searcher = new ManagementObjectSearcher(query))
                    foreach (var o in searcher.Get()) results.Add(o);
            }
            catch { }
            return results;
        }

        static string Prop(ManagementBaseObject o, string name)
        {
            try { var v = o[name]; return v == null ? "" : Convert.ToString(v); }
            catch { return ""; }
        }

        static readonly XNamespace EventNs = "http://schemas.microsoft.com/win/2004/08/events/event";

        /// <summary>Reads event log entries (newest first) and hands each one's data fields to the callback.</summary>
        static void ReadEvents(string channel, string xpath, int max, Action<DateTime?, int, Dictionary<string, string>> each)
        {
            var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(channel, System.Diagnostics.Eventing.Reader.PathType.LogName, xpath) { ReverseDirection = true };
            using (var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query))
            {
                int n = 0;
                System.Diagnostics.Eventing.Reader.EventRecord rec;
                while (n < max && (rec = reader.ReadEvent()) != null)
                {
                    using (rec)
                    {
                        n++;
                        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        try
                        {
                            var doc = XDocument.Parse(rec.ToXml());
                            foreach (var d in doc.Descendants(EventNs + "Data"))
                            {
                                var nameAttr = d.Attribute("Name");
                                if (nameAttr != null) data[nameAttr.Value] = d.Value;
                            }
                            // Some events (like 104) keep fields under UserData in their own namespace.
                            foreach (var e in doc.Descendants().Where(x => x.Name.LocalName == "Channel" && !x.HasElements))
                                data["Channel"] = e.Value;
                        }
                        catch { }
                        each(rec.TimeCreated, rec.Id, data);
                    }
                }
            }
        }

        static bool IsFixedNtfs(DriveInfo d)
        {
            try { return d.DriveType == DriveType.Fixed && d.IsReady && d.DriveFormat == "NTFS"; }
            catch { return false; }
        }
    }
}
