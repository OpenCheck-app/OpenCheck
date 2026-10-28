using System;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace PCCheck.Engine
{
    public sealed partial class Scanner
    {
        /// <summary>Windows' own records of programs that ran: Prefetch, BAM, UserAssist, MuiCache, Compatibility Assistant and Recent files.</summary>
        string ScanProgramHistory()
        {
            ScanPrefetch();
            Tick("Reading BAM", 0.4);
            ScanBam();
            Tick("Reading UserAssist", 0.6);
            foreach (var sid in LoadedUserSids())
            {
                ScanUserAssist(sid);
                ScanRegistryPathNames(Registry.Users, sid + @"_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", "MuiCache", true);
                ScanRegistryPathNames(Registry.Users, sid + @"\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", "Compatibility Assistant", false);
                ScanRegistryPathNames(Registry.Users, sid + @"\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "Compatibility settings", false);
            }
            ScanRegistryPathNames(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", "Compatibility settings", false);
            Tick("Reading recent files", 0.9);
            ScanRecentShortcuts();

            var ran = areaFindings.Where(f => f.Evidence == Evidence.Ran && f.Group == Groups.Cheat).ToList();
            if (ran.Count == 0) return admin ? "No cheats in program history" : "No cheats found (partial, needs admin)";
            int runs = ran.Sum(f => Math.Max(1, f.RunCount));
            return ran.Count + (ran.Count == 1 ? " program, " : " programs, ") + runs + (runs == 1 ? " run" : " runs");
        }

        void ScanPrefetch()
        {
            string dir = Path.Combine(windowsDir, "Prefetch");
            int count = 0;
            bool readable = true;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.pf"))
                {
                    count++;
                    string fileName = Path.GetFileName(file);
                    var sig = matcher.MatchName(fileName);
                    if (sig == null) continue;

                    DateTime? last = null;
                    int runs = 0;
                    try { last = File.GetLastWriteTime(file); } catch { }
                    try
                    {
                        var raw = File.ReadAllBytes(file);
                        var plain = Native.DecompressPrefetch(raw);
                        var info = Parsers.ParsePrefetch(plain);
                        if (info != null)
                        {
                            runs = info.RunCount;
                            if (info.RunTimes.Count > 0) last = info.RunTimes[0];
                        }
                    }
                    catch { }

                    int dash = fileName.LastIndexOf('-');
                    string exe = dash > 0 ? fileName.Substring(0, dash) : fileName;
                    var f = FromSignature(sig, Evidence.Ran, exe, last, "Prefetch");
                    f.RunCount = runs;
                    Add(f);
                }
            }
            catch (UnauthorizedAccessException) { readable = false; }
            catch (DirectoryNotFoundException) { }
            catch (IOException) { }

            // Signs that Prefetch was switched off or wiped.
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"))
                {
                    object v = k == null ? null : k.GetValue("EnablePrefetcher");
                    if (v is int && (int)v == 0)
                    {
                        Add(Simple("Prefetch is turned off", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, null,
                            @"HKLM\...\PrefetchParameters\EnablePrefetcher = 0", "Registry",
                            "Windows records programs in Prefetch by default. Turning it off hides what ran."));
                        return;
                    }
                }
            }
            catch { }

            if (admin && readable && count < 20 && Directory.Exists(dir))
            {
                DateTime? newest = null;
                try { newest = Directory.GetLastWriteTime(dir); } catch { }
                Add(Simple("Prefetch folder is almost empty", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, newest,
                    @"C:\Windows\Prefetch (" + count + " files)", "Prefetch",
                    "A PC in normal use usually has hundreds of Prefetch files. It may have been cleared."));
            }
        }

        void ScanBam()
        {
            var deviceMap = Native.DeviceToDriveMap();
            foreach (var basePath in new[] { @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", @"SYSTEM\CurrentControlSet\Services\bam\UserSettings" })
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(basePath))
                    {
                        if (key == null) continue;
                        foreach (var sid in key.GetSubKeyNames())
                        {
                            using (var sk = key.OpenSubKey(sid))
                            {
                                if (sk == null) continue;
                                foreach (var valueName in sk.GetValueNames())
                                {
                                    var sig = matcher.MatchName(valueName);
                                    if (sig == null) continue;
                                    var data = sk.GetValue(valueName) as byte[];
                                    DateTime? t = data != null && data.Length >= 8 ? Parsers.FromFileTime(BitConverter.ToInt64(data, 0)) : null;
                                    Add(FromSignature(sig, Evidence.Ran, Parsers.ConvertDevicePath(valueName, deviceMap), t, "BAM"));
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }

        void ScanUserAssist(string sid)
        {
            try
            {
                using (var ua = Registry.Users.OpenSubKey(sid + @"\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"))
                {
                    if (ua == null) return;
                    foreach (var guid in ua.GetSubKeyNames())
                    {
                        using (var count = ua.OpenSubKey(guid + @"\Count"))
                        {
                            if (count == null) continue;
                            foreach (var encoded in count.GetValueNames())
                            {
                                string name = Parsers.Rot13(encoded);
                                var sig = matcher.MatchName(name);
                                if (sig == null) continue;
                                var entry = Parsers.ParseUserAssist(count.GetValue(encoded) as byte[]);
                                var f = FromSignature(sig, Evidence.Ran, Parsers.ExpandKnownFolder(name), entry == null ? null : entry.LastRun, "UserAssist");
                                f.RunCount = entry == null ? 0 : entry.RunCount;
                                Add(f);
                            }
                        }
                    }
                }
            }
            catch { }
        }

        /// <summary>Registry keys whose value NAMES are program paths (MuiCache, Compatibility Assistant, Layers).</summary>
        void ScanRegistryPathNames(RegistryKey hive, string path, string source, bool muiCache)
        {
            try
            {
                using (var key = hive.OpenSubKey(path))
                {
                    if (key == null) return;
                    foreach (var valueName in key.GetValueNames())
                    {
                        string p = valueName;
                        if (muiCache)
                        {
                            int i = p.LastIndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                            if (i < 0) continue;
                            p = p.Substring(0, i + 4);
                        }
                        var sig = matcher.MatchName(p);
                        if (sig != null) Add(FromSignature(sig, Evidence.Ran, p, null, source));
                    }
                }
            }
            catch { }
        }

        void ScanRecentShortcuts()
        {
            foreach (var p in profiles)
            {
                string dir = Path.Combine(p.Path, @"AppData\Roaming\Microsoft\Windows\Recent");
                try
                {
                    foreach (var lnk in Directory.EnumerateFiles(dir, "*.lnk"))
                    {
                        var sig = matcher.MatchName(Path.GetFileName(lnk));
                        if (sig == null) continue;
                        string target = Path.GetFileNameWithoutExtension(lnk);
                        Add(FromSignature(sig, Evidence.Ran, target, File.GetLastWriteTime(lnk), "Recent files"));
                    }
                }
                catch { }
            }
        }
    }
}
