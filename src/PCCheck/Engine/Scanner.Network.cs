using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using Microsoft.Win32;

namespace PCCheck.Engine
{
    public sealed partial class Scanner
    {
        /// <summary>
        /// Lag switches and VPNs. Reads only local information: network adapter names, installed drivers,
        /// firewall rules and their history, and the times the network connected or disconnected.
        /// Nothing is sent and no connection is made.
        /// </summary>
        string ScanNetwork()
        {
            var found = new List<string>();
            Tick("Checking network adapters", 0.1);
            ScanAdapters(found);
            Tick("Checking network drivers", 0.3);
            ScanNetworkDrivers(found);
            Tick("Reading firewall history", 0.55);
            ScanFirewallHistory(found);
            Tick("Checking for network drops during games", 0.8);
            ScanDropsDuringGames(found);
            Tick("Checking recent cheat site lookups", 0.95);
            ScanDnsCache(found);
            return found.Count == 0 ? "No lag switch or VPN found" : string.Join(", ", found);
        }

        void ScanAdapters(List<string> found)
        {
            NetworkInterface[] adapters;
            try { adapters = NetworkInterface.GetAllNetworkInterfaces(); }
            catch (Exception ex) { notes.Add("Couldn't list network adapters: " + ex.Message); return; }

            foreach (var a in adapters)
            {
                string word;
                try { word = Parsers.VpnAdapterMatch(a.Name, a.Description, set.VpnAdapters); } catch { continue; }
                if (word == null) continue;
                bool up = false;
                try { up = a.OperationalStatus == OperationalStatus.Up; } catch { }
                string label = a.Description + (a.Name != a.Description ? " (" + a.Name + ")" : "");
                if (up)
                {
                    Add(Simple("VPN connected right now", "VPN", Severity.Medium, Evidence.Vpn, Groups.Network, DateTime.Now, label, "Network adapters",
                        "A VPN or game ping booster was connected while the check ran. VPNs are legal, but they change the player's connection and can be used to dodge IP bans. Ask about it if your rules care."));
                    if (!found.Contains("VPN connected")) found.Add("VPN connected");
                }
                else
                {
                    Add(Simple("VPN adapter installed", "VPN", Severity.Info, Evidence.Context, Groups.Network, null, label, "Network adapters",
                        "A VPN or game ping booster is installed but wasn't connected during the check."));
                    if (!found.Contains("VPN installed") && !found.Contains("VPN connected")) found.Add("VPN installed");
                }
            }
        }

        /// <summary>Drivers and services that can hold back or drop traffic (WinDivert, NetLimiter and similar), matched by name only.</summary>
        void ScanNetworkDrivers(List<string> found)
        {
            try
            {
                using (var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                {
                    if (services == null) return;
                    foreach (var name in services.GetSubKeyNames())
                    {
                        string image = null;
                        try
                        {
                            using (var k = services.OpenSubKey(name))
                                image = k == null ? null : k.GetValue("ImagePath") as string;
                        }
                        catch { }
                        string fileName = null;
                        try { fileName = string.IsNullOrEmpty(image) ? null : Path.GetFileName(image.Trim('"').Split(new[] { ".sys", ".exe", ".SYS", ".EXE" }, StringSplitOptions.None)[0]); } catch { }

                        var sig = matcher.MatchName(name) ?? (fileName == null ? null : matcher.MatchName(fileName));
                        if (sig == null) continue;
                        string cat = sig.Category ?? "";
                        bool network = cat.IndexOf("Lag", StringComparison.OrdinalIgnoreCase) >= 0
                                    || cat.IndexOf("VPN", StringComparison.OrdinalIgnoreCase) >= 0
                                    || cat.IndexOf("ping booster", StringComparison.OrdinalIgnoreCase) >= 0;
                        if (!network) continue;
                        var f = FromSignature(sig, Evidence.WasHere, image ?? name, null, "Installed driver or service");
                        f.Note = (sig.Note ?? "") + (sig.Note == null ? "" : " ") + "Installed as a Windows driver or service named \"" + name + "\".";
                        Add(f);
                        string tag = cat.IndexOf("Lag", StringComparison.OrdinalIgnoreCase) >= 0 ? "lag tool driver" : "VPN driver";
                        if (!found.Contains(tag)) found.Add(tag);
                    }
                }
            }
            catch (Exception ex) { notes.Add("Couldn't read installed drivers: " + ex.Message); }
        }

        /// <summary>
        /// Windows Firewall's own log of rule changes. A rule for Roblox being added and removed again and again
        /// is how most "firewall lag switch" macros work, even if the rule is gone by the time of the check.
        /// </summary>
        void ScanFirewallHistory(List<string> found)
        {
            var changes = new List<DateTime>();
            string example = null;
            try
            {
                ReadEvents("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                    "*[System[(EventID=2004 or EventID=2005 or EventID=2006 or EventID=2097 or EventID=2099 or EventID=2052) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]",
                    5000, (time, id, data) =>
                    {
                        bool roblox = data.Values.Any(v => v != null && v.IndexOf("roblox", StringComparison.OrdinalIgnoreCase) >= 0);
                        if (!roblox || !time.HasValue) return;
                        changes.Add(time.Value);
                        if (example == null)
                        {
                            string rule;
                            if (data.TryGetValue("RuleName", out rule) && !string.IsNullOrEmpty(rule)) example = rule;
                        }
                    });
            }
            catch (Exception ex) { notes.Add("Couldn't read the firewall history: " + ex.Message); return; }

            if (changes.Count == 0) return;
            changes.Sort();
            var latest = changes[changes.Count - 1];
            bool repeated = changes.Count >= 4;
            Add(Simple(repeated ? "Roblox firewall rule switched on and off" : "Roblox firewall rule changed", "Lag switch", Severity.Medium, Evidence.LagSwitch, Groups.Cheat, latest,
                (example ?? "Windows Firewall rule for Roblox") + " (" + changes.Count + (changes.Count == 1 ? " change" : " changes") + " in 30 days)", "Windows Firewall history",
                repeated
                    ? "A firewall rule for Roblox was added, changed or removed " + changes.Count + " times. Lag-switch macros do exactly this to cut Roblox's connection for a moment."
                    : "A firewall rule for Roblox was added, changed or removed. Some installers do this once, so ask about it rather than treating it as proof."));
            if (!found.Contains("firewall changes")) found.Add("firewall changes");
        }

        /// <summary>
        /// Short internet drops while a Roblox game was open. A lag switch (software, a macro that turns the adapter off,
        /// or a physical switch on the cable) shows up here as disconnect-then-reconnect within a couple of minutes.
        /// </summary>
        void ScanDropsDuringGames(List<string> found)
        {
            if (sessions.Count == 0) return;
            var events = new List<Tuple<DateTime, bool>>();
            try
            {
                ReadEvents("Microsoft-Windows-NetworkProfile/Operational",
                    "*[System[(EventID=10000 or EventID=10001) and TimeCreated[timediff(@SystemTime) <= 1209600000]]]",
                    5000, (time, id, data) => { if (time.HasValue) events.Add(Tuple.Create(time.Value, id == 10000)); });
            }
            catch (Exception ex) { notes.Add("Couldn't read the network connection history: " + ex.Message); return; }

            var drops = Parsers.DropsDuringGames(events, sessions, TimeSpan.FromMinutes(3));
            if (drops.Count < 3) return;   // the odd Wi-Fi hiccup is normal
            var places = drops.Select(d => d.Item2.PlaceId).Distinct().Take(3).Select(p => "place " + p);
            Add(Simple("Internet cut out " + drops.Count + " times during Roblox games", "Lag switch", Severity.Medium, Evidence.LagSwitch, Groups.Network, drops.Max(d => d.Item1),
                string.Join(", ", places), "Network history + Roblox logs",
                "The connection dropped and came back within a few minutes " + drops.Count + " times while Roblox games were open (last 14 days). Lag switches, macros that turn the network off and physical switches on the cable all look like this. Weak Wi-Fi can too, so ask about it and compare with VODs."));
            if (!found.Contains("drops during games")) found.Add("drops during games");
        }
    }
}
