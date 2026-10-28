using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.ServiceProcess;

namespace PCCheck.Engine
{
    public sealed partial class Scanner
    {
        static readonly string[] VmMarkers = { "vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "parallels", "bochs", "innotek", "bhyve" };

        static readonly Dictionary<string, string> VmServices = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "VMAuthdService", "VMware" }, { "VMnetDHCP", "VMware" }, { "vmx86", "VMware" },
            { "VBoxSDS", "VirtualBox" }, { "VBoxSup", "VirtualBox" }, { "VBoxDrv", "VirtualBox" },
            { "vmms", "Hyper-V" },
        };

        /// <summary>Is this PC a virtual machine, and is VM software installed?</summary>
        string ScanVirtualMachines()
        {
            string vmName = null, vmWhere = null;

            foreach (var o in Wmi("SELECT Manufacturer, Model FROM Win32_ComputerSystem"))
            {
                string man = Prop(o, "Manufacturer"), model = Prop(o, "Model");
                if (model.Equals("Virtual Machine", StringComparison.OrdinalIgnoreCase) && man.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0) { vmName = "Hyper-V"; vmWhere = "system model"; }
                else { var m = VmMarker(man + " " + model); if (m != null) { vmName = m; vmWhere = "system model"; } }
            }
            if (vmName == null)
                foreach (var o in Wmi("SELECT Manufacturer, SMBIOSBIOSVersion, SerialNumber FROM Win32_BIOS"))
                { var m = VmMarker(Prop(o, "Manufacturer") + " " + Prop(o, "SMBIOSBIOSVersion") + " " + Prop(o, "SerialNumber")); if (m != null) { vmName = m; vmWhere = "BIOS"; } }
            if (vmName == null)
                foreach (var o in Wmi("SELECT Manufacturer, Product FROM Win32_BaseBoard"))
                { var m = VmMarker(Prop(o, "Manufacturer") + " " + Prop(o, "Product")); if (m != null) { vmName = m; vmWhere = "motherboard"; } }
            if (vmName == null)
                foreach (var o in Wmi("SELECT Model FROM Win32_DiskDrive"))
                { var m = VmMarker(Prop(o, "Model")); if (m != null) { vmName = m; vmWhere = "disk"; } }
            if (vmName == null && Environment.UserName.Equals("WDAGUtilityAccount", StringComparison.OrdinalIgnoreCase))
            { vmName = "Windows Sandbox"; vmWhere = "user account"; }

            if (vmName != null)
            {
                Add(Simple("Running inside a virtual machine", "Virtual machine", Severity.High, Evidence.Tamper, Groups.Hardware, DateTime.Now,
                    vmName + " (" + vmWhere + ")", "Hardware info",
                    "This check is running in a VM, so it can't see the real PC. Ask for the check to be run on the real PC."));
            }

            // VM software installed on this (real) PC.
            var installed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var s in ServiceController.GetServices().Concat(ServiceController.GetDevices()))
                {
                    using (s)
                    {
                        string product;
                        if (VmServices.TryGetValue(s.ServiceName, out product)) installed.Add(product);
                    }
                }
            }
            catch { }

            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    string mac = ni.GetPhysicalAddress().ToString();
                    if (mac.Length != 12) continue;
                    string vendor;
                    if (!set.VmMacPrefixes.TryGetValue(mac.Substring(0, 6), out vendor)) continue;
                    // Windows' own Hyper-V switch (used by WSL, Docker, Sandbox) is normal on a real PC.
                    if (vendor == "Hyper-V" && ni.Name.StartsWith("vEthernet", StringComparison.OrdinalIgnoreCase)) continue;
                    if (vmName == null) installed.Add(vendor);
                }
            }
            catch { }

            foreach (var product in installed)
                Add(Simple(product + " is installed", "Virtual machine software", Severity.Info, Evidence.Context, Groups.Hardware, null,
                    product, "Services and network adapters", "Installed, not necessarily used. Program history shows whether it ran recently."));

            if (vmName != null) return "Running inside " + vmName;
            return installed.Count == 0 ? "Real PC, no VM software" : "Real PC, " + string.Join(", ", installed) + " installed";
        }

        static string VmMarker(string text)
        {
            string t = (text ?? "").ToLowerInvariant();
            foreach (var m in VmMarkers)
                if (t.IndexOf(m, StringComparison.Ordinal) >= 0)
                    return m == "vbox" || m == "innotek" ? "VirtualBox" : m == "kvm" || m == "qemu" ? "QEMU/KVM" : char.ToUpperInvariant(m[0]) + m.Substring(1);
            return null;
        }

        /// <summary>PCIe devices and recent hardware installs that could be a DMA card.</summary>
        string ScanDma()
        {
            int pciCount = 0, suspicious = 0;
            foreach (var o in Wmi("SELECT Name, PNPDeviceID, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'PCI%'"))
            {
                pciCount++;
                string id = Prop(o, "PNPDeviceID"), name = Prop(o, "Name");
                string vendor = Parsers.PciVendor(id), vendorName;
                if (vendor != null && set.DmaVendors.TryGetValue(vendor, out vendorName))
                {
                    suspicious++;
                    Add(Simple(vendorName + " PCIe device", "DMA", Severity.Medium, Evidence.Found, Groups.Hardware, null, id, "Device Manager: " + name,
                        "FPGA boards like this are used by DMA cheats. Some are legitimate (capture cards, dev boards), so ask what it is."));
                }
                else if (Prop(o, "ConfigManagerErrorCode") != "0" && Prop(o, "ConfigManagerErrorCode") != "")
                {
                    Add(Simple("PCIe device without a working driver", "DMA", Severity.Info, Evidence.Context, Groups.Hardware, null, id, "Device Manager: " + name,
                        "Common after a fresh Windows install. A DMA card with custom firmware can also show up like this."));
                }
            }

            Tick("Reading hardware install history", 0.5);
            try
            {
                string log = Path.Combine(windowsDir, @"INF\setupapi.dev.log");
                if (File.Exists(log))
                {
                    List<DeviceInstall> installs;
                    using (var fs = new FileStream(log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (var reader = new StreamReader(fs))
                        installs = Parsers.ParseSetupApiLog(ReadLines(reader));

                    var cutoff = DateTime.Now.AddDays(-30);
                    var recent = installs.Where(i => i.Time > cutoff && i.DeviceId.StartsWith(@"PCI\", StringComparison.OrdinalIgnoreCase))
                                         .GroupBy(i => i.DeviceId, StringComparer.OrdinalIgnoreCase)
                                         .Select(g => g.OrderByDescending(i => i.Time).First())
                                         .OrderByDescending(i => i.Time)
                                         .ToList();
                    int shown = 0;
                    foreach (var i in recent)
                    {
                        string vendorName;
                        string vendor = Parsers.PciVendor(i.DeviceId);
                        if (vendor != null && set.DmaVendors.TryGetValue(vendor, out vendorName))
                        {
                            suspicious++;
                            Add(Simple(vendorName + " device was connected", "DMA", Severity.Medium, Evidence.WasHere, Groups.Hardware, i.Time, i.DeviceId, "Hardware install log",
                                "An FPGA PCIe device was installed recently. DMA cheat cards often use these chips."));
                        }
                        else if (shown < 5)
                        {
                            shown++;
                            Add(Simple("New PCIe device installed", "Hardware", Severity.Info, Evidence.Context, Groups.Hardware, i.Time, i.DeviceId, "Hardware install log",
                                "Usually a normal hardware or driver change. Listed for the timeline."));
                        }
                    }
                }
            }
            catch (Exception ex) { notes.Add("Hardware install log unavailable: " + ex.Message); }

            try
            {
                var dmaProtection = Native.KernelDmaProtectionOn();
                if (dmaProtection == false)
                    Add(Simple("Kernel DMA Protection is off", "DMA", Severity.Info, Evidence.Context, Groups.Hardware, null, "Windows security setting", "System information",
                        "Many PCs have this off. It only matters alongside other DMA signs."));
            }
            catch { }

            if (suspicious > 0) return suspicious + (suspicious == 1 ? " suspicious device" : " suspicious devices");
            return pciCount > 0 ? pciCount + " PCIe devices, none suspicious" : "No suspicious devices";
        }

        static IEnumerable<string> ReadLines(StreamReader reader)
        {
            string line;
            while ((line = reader.ReadLine()) != null) yield return line;
        }

        /// <summary>Cheat programs open right now.</summary>
        string ScanRunning()
        {
            int self = Process.GetCurrentProcess().Id;
            int running = 0;
            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    try
                    {
                        if (p.Id == self) continue;
                        var sig = matcher.MatchName(p.ProcessName + ".exe");
                        if (sig == null) continue;
                        string path = p.ProcessName + ".exe";
                        DateTime? started = null;
                        try { path = p.MainModule.FileName; } catch { }
                        try { started = p.StartTime; } catch { }
                        Add(FromSignature(sig, Evidence.Running, path, started, "Running process"));
                        if (sig.Severity >= Severity.Medium) running++;
                    }
                    catch { }
                }
            }
            return running == 0 ? "Nothing running" : running + " running now";
        }
    }
}
