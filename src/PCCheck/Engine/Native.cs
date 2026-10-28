using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PCCheck.Engine
{
    /// <summary>
    /// The few Windows functions .NET doesn't wrap. Every handle here is opened for READING only.
    /// </summary>
    internal static class Native
    {
        const uint GENERIC_READ = 0x80000000;
        const uint FILE_SHARE_READ_WRITE_DELETE = 0x7;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
        const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[] inBuf, int inSize, byte[] outBuf, int outSize, out int returned, IntPtr overlapped);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint QueryDosDeviceW(string deviceName, StringBuilder target, int max);

        [StructLayout(LayoutKind.Explicit, Size = 24)]
        struct FILE_ID_DESCRIPTOR
        {
            [FieldOffset(0)] public uint dwSize;
            [FieldOffset(4)] public int Type;
            [FieldOffset(8)] public long FileId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern SafeFileHandle OpenFileById(SafeFileHandle volumeHint, ref FILE_ID_DESCRIPTOR id, uint access, uint share, IntPtr security, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);

        [DllImport("ntdll.dll")]
        static extern uint RtlGetCompressionWorkSpaceSize(ushort format, out uint bufferWorkSpaceSize, out uint fragmentWorkSpaceSize);

        [DllImport("ntdll.dll")]
        static extern uint RtlDecompressBufferEx(ushort format, byte[] uncompressed, int uncompressedSize, byte[] compressed, int compressedSize, out int finalSize, byte[] workSpace);

        [DllImport("ntdll.dll")]
        static extern int NtQuerySystemInformation(int infoClass, byte[] info, int length, out int returnLength);

        /// <summary>Maps "\Device\HarddiskVolume3" to "C:" for every drive letter.</summary>
        public static Dictionary<string, string> DeviceToDriveMap()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var drive in DriveInfo.GetDrives())
            {
                string letter = drive.Name.TrimEnd('\\');
                var sb = new StringBuilder(512);
                if (QueryDosDeviceW(letter, sb, sb.Capacity) != 0)
                {
                    string dev = sb.ToString();
                    if (!map.ContainsKey(dev)) map[dev] = letter;
                }
            }
            return map;
        }

        /// <summary>Windows 10/11 compress Prefetch files ("MAM" header). Returns the plain bytes, or the input if it wasn't compressed.</summary>
        public static byte[] DecompressPrefetch(byte[] file)
        {
            if (file.Length < 8 || file[0] != (byte)'M' || file[1] != (byte)'A' || file[2] != (byte)'M') return file;
            ushort format = (ushort)(file[3] & 0x0F);
            bool hasChecksum = (file[3] & 0xF0) != 0;
            int size = BitConverter.ToInt32(file, 4);
            int start = hasChecksum ? 12 : 8;
            if (size <= 0 || size > 64 * 1024 * 1024 || start >= file.Length) return null;

            uint wsSize, fragSize;
            if (RtlGetCompressionWorkSpaceSize(format, out wsSize, out fragSize) != 0) return null;
            var workspace = new byte[wsSize];
            var input = new byte[file.Length - start];
            Buffer.BlockCopy(file, start, input, 0, input.Length);
            var output = new byte[size];
            int final;
            if (RtlDecompressBufferEx(format, output, size, input, input.Length, out final, workspace) != 0) return null;
            return output;
        }

        public sealed class UsnJournal
        {
            public ulong JournalId;
            public long FirstUsn;
            public long NextUsn;
        }

        /// <summary>Opens a volume (like "C:") read-only. Needs admin.</summary>
        public static SafeFileHandle OpenVolume(string driveLetter)
        {
            var h = CreateFileW(@"\\.\" + driveLetter.TrimEnd('\\'), GENERIC_READ, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            return h;
        }

        public static UsnJournal QueryJournal(SafeFileHandle volume)
        {
            var output = new byte[80];
            int returned;
            if (!DeviceIoControl(volume, FSCTL_QUERY_USN_JOURNAL, null, 0, output, output.Length, out returned, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return new UsnJournal
            {
                JournalId = BitConverter.ToUInt64(output, 0),
                FirstUsn = BitConverter.ToInt64(output, 8),
                NextUsn = BitConverter.ToInt64(output, 16)
            };
        }

        /// <summary>Reads one chunk of the change journal. Returns bytes in buffer (0 when finished).</summary>
        public static int ReadJournal(SafeFileHandle volume, ulong journalId, long startUsn, byte[] buffer)
        {
            var input = new byte[40];
            Buffer.BlockCopy(BitConverter.GetBytes(startUsn), 0, input, 0, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(0xFFFFFFFFu), 0, input, 8, 4);   // all reasons
            // ReturnOnlyOnClose = 0, Timeout = 0, BytesToWaitFor = 0
            Buffer.BlockCopy(BitConverter.GetBytes(journalId), 0, input, 32, 8);
            int returned;
            if (!DeviceIoControl(volume, FSCTL_READ_USN_JOURNAL, input, input.Length, buffer, buffer.Length, out returned, IntPtr.Zero))
                return 0;
            return returned;
        }

        /// <summary>Gets the current path of a folder from its file ID (used for deleted files' parent folders). Null if it no longer exists.</summary>
        public static string PathFromFileId(SafeFileHandle volume, long fileId)
        {
            var desc = new FILE_ID_DESCRIPTOR { dwSize = 24, Type = 0, FileId = fileId };
            using (var h = OpenFileById(volume, ref desc, 0, FILE_SHARE_READ_WRITE_DELETE, IntPtr.Zero, FILE_FLAG_BACKUP_SEMANTICS))
            {
                if (h.IsInvalid) return null;
                var sb = new StringBuilder(1024);
                uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
                if (n == 0 || n >= sb.Capacity) return null;
                string p = sb.ToString();
                return p.StartsWith(@"\\?\") ? p.Substring(4) : p;
            }
        }

        /// <summary>Kernel DMA Protection status. Null if Windows doesn't report it.</summary>
        public static bool? KernelDmaProtectionOn()
        {
            const int SystemDmaProtectionInformation = 169;
            var buf = new byte[2];
            int ret;
            int status = NtQuerySystemInformation(SystemDmaProtectionInformation, buf, buf.Length, out ret);
            if (status != 0) return null;
            return buf[1] != 0;   // DmaProtectionsInUse
        }
    }
}
