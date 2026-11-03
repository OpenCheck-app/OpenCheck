using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using Microsoft.Win32;

namespace PCCheck.Engine
{
    /// <summary>
    /// Places experienced manual PC checkers look that OpenCheck didn't read before: the Run box history,
    /// Windows Security's current settings, recent website lookups (DNS cache) and USB tools used with DMA cards.
    /// Read-only, and only matches are kept.
    /// </summary>
    public sealed partial class Scanner
    {
        /// <summary>Commands typed into the Run box (Win+R) and paths typed into Explorer's address bar.</summary>
        void ScanRunBox()
        {
            foreach (var sid in LoadedUserSids())
            {
                foreach (var sub in new[] { @"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", @"\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" })
                {
                    try
                    {
                        using (var key = Registry.Users.OpenSubKey(sid + sub))
                        {
                            if (key == null) continue;
                            string source = sub.EndsWith("RunMRU") ? "Run box (Win+R) history" : "Explorer address bar history";
                            foreach (var name in key.GetValueNames())
                            {
                                if (name.Equals("MRUList", StringComparison.OrdinalIgnoreCase)) continue;
                                string cmd = TraceParsers.RunBoxCommand(key.GetValue(name) as string);
                                if (cmd == null) continue;

                                string cleanup = TraceParsers.CleanupCommand(cmd);
                                if (cleanup != null)
                                {
                                    Add(Simple(cleanup + " (typed command)", "Tampering", Severity.Medium, Evidence.Tamper, Groups.Tamper, null,
                                        cmd.Length > 160 ? cmd.Substring(0, 157) + "..." : cmd, source,
                                        "This command was typed into the " + (source.StartsWith("Run") ? "Run box" : "Explorer address bar") + " on this PC. It wipes records that PC checks read."));
                                    continue;
                                }
                                string target = TraceParsers.RunBoxTarget(cmd);
                                var sig = target == null ? null : matcher.MatchName(target);
                                if (sig == null) continue;
                                var f = FromSignature(sig, Evidence.Ran, target, null, source);
                                f.Note = (sig.Note == null ? "" : sig.Note + " ") + "This was typed into the " + (source.StartsWith("Run") ? "Run box" : "Explorer address bar") + " to open it.";
                                Add(f);
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        /// <summary>Windows Security switched off right now (real-time or tamper protection), when it's the only antivirus.</summary>
        int ScanDefenderStateNow()
        {
            bool realtimeOff = false;
            int? tamper = null;
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"))
                    if (k != null && k.GetValue("DisableRealtimeMonitoring") is int && (int)k.GetValue("DisableRealtimeMonitoring") == 1) realtimeOff = true;
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"))
                    if (k != null && k.GetValue("DisableRealtimeMonitoring") is int && (int)k.GetValue("DisableRealtimeMonitoring") == 1) realtimeOff = true;
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Features"))
                    if (k != null && k.GetValue("TamperProtection") is int) tamper = (int)k.GetValue("TamperProtection");
            }
            catch { return 0; }

            bool otherAv = false;
            try
            {
                using (var searcher = new ManagementObjectSearcher(new ManagementScope(@"root\SecurityCenter2"), new ObjectQuery("SELECT displayName FROM AntiVirusProduct")))
                    foreach (var o in searcher.Get())
                    {
                        string name = Prop(o, "displayName");
                        if (name.Length > 0 && name.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) < 0) otherAv = true;
                    }
            }
            catch { otherAv = true; }   // can't tell: don't flag

            var off = TraceParsers.DefenderOffNow(realtimeOff, tamper, otherAv);
            if (off.Count == 0) return 0;
            Add(Simple("Windows Security is partly off right now", "Antivirus turned off", Severity.Medium, Evidence.Tamper, Groups.Tamper, DateTime.Now,
                string.Join(" and ", off) + " off", "Windows Security settings",
                "Windows Security is the only antivirus on this PC, and " + string.Join(" and ", off).ToLowerInvariant() + (off.Count == 1 ? " is" : " are") +
                " switched off. Executor guides tell people to do this so the cheat isn't removed. Ask why."));
            return 1;
        }

        /// <summary>Cheat and script-key websites in Windows' DNS cache: looked up in the last few hours (the cache clears at restart).</summary>
        void ScanDnsCache(List<string> found)
        {
            var hosts = Native.CachedHostNames();
            int cheat = 0, key = 0;
            foreach (var host in hosts)
            {
                string site = Parsers.MatchDomain(host, set.CheatSites);
                if (site != null && cheat < 8)
                {
                    cheat++;
                    Add(Simple("Cheat website visited recently", "Cheat website", Severity.Medium, Evidence.WasHere, Groups.Cheat, null, host, "DNS cache",
                        "This PC looked up " + site + " in the last few hours (Windows forgets these at restart). It's a Roblox executor or script site. Only cheat sites are listed; no other browsing is read."));
                    continue;
                }
                site = Parsers.MatchDomain(host, set.KeySites);
                if (site != null && key < 3)
                {
                    key++;
                    Add(Simple("Script key site visited recently", "Cheat website", Severity.Info, Evidence.Context, Groups.Context, null, host, "DNS cache",
                        "Executor keys usually go through sites like " + site + ", but other things use them too. Context only."));
                }
            }
            if (cheat > 0) found.Add("Cheat site visited recently");
        }

        /// <summary>USB tools used with DMA cards, from Windows' device list (kept after unplugging).</summary>
        void ScanDmaUsbTools(List<string> found)
        {
            bool serialNoted = false;
            try
            {
                using (var usb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB"))
                {
                    if (usb == null) return;
                    foreach (var dev in usb.GetSubKeyNames())
                    {
                        string label = TraceParsers.DmaUsbTool(dev);
                        bool serial = label == null && !serialNoted && TraceParsers.IsUsbSerialChip(dev);
                        if (label == null && !serial) continue;
                        string desc = null;
                        try
                        {
                            using (var d = usb.OpenSubKey(dev))
                            {
                                var inst = d == null ? null : d.GetSubKeyNames().FirstOrDefault();
                                if (inst != null)
                                    using (var i = d.OpenSubKey(inst))
                                        desc = i == null ? null : (i.GetValue("FriendlyName") as string ?? i.GetValue("DeviceDesc") as string);
                            }
                        }
                        catch { }
                        if (desc != null && desc.Contains(";")) desc = desc.Substring(desc.LastIndexOf(';') + 1);
                        string path = dev + (string.IsNullOrEmpty(desc) ? "" : " (" + desc + ")");
                        if (label != null)
                        {
                            Add(Simple(label + " was connected", "DMA", Severity.Medium, Evidence.WasHere, Groups.Hardware, null, path, "USB device history",
                                "Windows remembers this USB device was plugged into this PC. It's the kind of adapter used to flash or run DMA cheat cards (electronics hobbyists use it too). Ask what it was for."));
                            if (!found.Contains("DMA tool connected")) found.Add("DMA tool connected");
                        }
                        else
                        {
                            serialNoted = true;
                            Add(Simple("USB serial adapter was connected", "DMA", Severity.Info, Evidence.Context, Groups.Context, null, path, "USB device history",
                                "KMBox-style input boxes (used for DMA aimbots) connect through chips like this, but so do Arduinos and many other gadgets. Context only."));
                        }
                    }
                }
            }
            catch { }
        }
    }
}
