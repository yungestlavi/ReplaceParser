using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SSForensic.Forensics
{
    /// <summary>
    /// NTFS USN Journal reader via DeviceIoControl. Exposes ALL reason flags
    /// so the analyzer can identify replaces, renames, stream changes, etc.
    /// </summary>
    public class UsnJournalReader
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFileHandle CreateFile(
            string fileName, uint desiredAccess, uint shareMode,
            IntPtr securityAttributes, uint creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ  = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING    = 3;

        private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900F4;
        private const uint FSCTL_READ_USN_JOURNAL  = 0x000900BB;

        // Full USN reason flag set
        public const uint USN_REASON_DATA_OVERWRITE        = 0x00000001;
        public const uint USN_REASON_DATA_EXTEND           = 0x00000002;
        public const uint USN_REASON_DATA_TRUNCATION       = 0x00000004;
        public const uint USN_REASON_NAMED_DATA_OVERWRITE  = 0x00000010;
        public const uint USN_REASON_NAMED_DATA_EXTEND     = 0x00000020;
        public const uint USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040;
        public const uint USN_REASON_FILE_CREATE           = 0x00000100;
        public const uint USN_REASON_FILE_DELETE           = 0x00000200;
        public const uint USN_REASON_EA_CHANGE             = 0x00000400;
        public const uint USN_REASON_SECURITY_CHANGE       = 0x00000800;
        public const uint USN_REASON_RENAME_OLD_NAME       = 0x00001000;
        public const uint USN_REASON_RENAME_NEW_NAME       = 0x00002000;
        public const uint USN_REASON_INDEXABLE_CHANGE      = 0x00004000;
        public const uint USN_REASON_BASIC_INFO_CHANGE     = 0x00008000;
        public const uint USN_REASON_HARD_LINK_CHANGE      = 0x00010000;
        public const uint USN_REASON_COMPRESSION_CHANGE    = 0x00020000;
        public const uint USN_REASON_ENCRYPTION_CHANGE     = 0x00040000;
        public const uint USN_REASON_OBJECT_ID_CHANGE      = 0x00080000;
        public const uint USN_REASON_REPARSE_POINT_CHANGE  = 0x00100000;
        public const uint USN_REASON_STREAM_CHANGE         = 0x00200000;
        public const uint USN_REASON_TRANSACTED_CHANGE     = 0x00400000;
        public const uint USN_REASON_INTEGRITY_CHANGE      = 0x00800000;
        public const uint USN_REASON_CLOSE                 = 0x80000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct USN_JOURNAL_DATA_V0
        {
            public long UsnJournalID;
            public long FirstUsn;
            public long NextUsn;
            public long LowestValidUsn;
            public long MaxUsn;
            public long MaximumSize;
            public long AllocationDelta;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct READ_USN_JOURNAL_DATA_V0
        {
            public long StartUsn;
            public uint ReasonMask;
            public uint ReturnOnlyOnClose;
            public ulong Timeout;
            public ulong BytesToWaitFor;
            public long UsnJournalID;
        }

        public class UsnRecord
        {
            public long Usn { get; set; }
            public ulong FileReferenceNumber { get; set; }
            public ulong ParentFileReferenceNumber { get; set; }
            public DateTime Timestamp { get; set; }
            public uint Reason { get; set; }
            public string FileName { get; set; } = string.Empty;
            public uint FileAttributes { get; set; }

            /// <summary>
            /// True if this record indicates the file has been replaced or its content
            /// substantially rewritten. We treat the union of these reasons as "replace":
            /// FILE_CREATE, DATA_OVERWRITE, DATA_TRUNCATION, NAMED_DATA_OVERWRITE,
            /// NAMED_DATA_TRUNCATION, RENAME_NEW_NAME, RENAME_OLD_NAME, STREAM_CHANGE.
            /// </summary>
            public bool IsReplace =>
                (Reason & (USN_REASON_FILE_CREATE
                         | USN_REASON_DATA_OVERWRITE
                         | USN_REASON_DATA_TRUNCATION
                         | USN_REASON_NAMED_DATA_OVERWRITE
                         | USN_REASON_NAMED_DATA_TRUNCATION
                         | USN_REASON_RENAME_NEW_NAME
                         | USN_REASON_RENAME_OLD_NAME
                         | USN_REASON_STREAM_CHANGE)) != 0;

            public string ReasonString
            {
                get
                {
                    var p = new List<string>();
                    if ((Reason & USN_REASON_DATA_OVERWRITE)        != 0) p.Add("DATA_OVERWRITE");
                    if ((Reason & USN_REASON_DATA_EXTEND)           != 0) p.Add("DATA_EXTEND");
                    if ((Reason & USN_REASON_DATA_TRUNCATION)       != 0) p.Add("DATA_TRUNCATION");
                    if ((Reason & USN_REASON_NAMED_DATA_OVERWRITE)  != 0) p.Add("NAMED_DATA_OVERWRITE");
                    if ((Reason & USN_REASON_NAMED_DATA_EXTEND)     != 0) p.Add("NAMED_DATA_EXTEND");
                    if ((Reason & USN_REASON_NAMED_DATA_TRUNCATION) != 0) p.Add("NAMED_DATA_TRUNCATION");
                    if ((Reason & USN_REASON_FILE_CREATE)           != 0) p.Add("FILE_CREATE");
                    if ((Reason & USN_REASON_FILE_DELETE)           != 0) p.Add("FILE_DELETE");
                    if ((Reason & USN_REASON_EA_CHANGE)             != 0) p.Add("EA_CHANGE");
                    if ((Reason & USN_REASON_SECURITY_CHANGE)       != 0) p.Add("SECURITY_CHANGE");
                    if ((Reason & USN_REASON_RENAME_OLD_NAME)       != 0) p.Add("RENAME_OLD");
                    if ((Reason & USN_REASON_RENAME_NEW_NAME)       != 0) p.Add("RENAME_NEW");
                    if ((Reason & USN_REASON_INDEXABLE_CHANGE)      != 0) p.Add("INDEXABLE_CHANGE");
                    if ((Reason & USN_REASON_BASIC_INFO_CHANGE)     != 0) p.Add("BASIC_INFO_CHANGE");
                    if ((Reason & USN_REASON_HARD_LINK_CHANGE)      != 0) p.Add("HARD_LINK_CHANGE");
                    if ((Reason & USN_REASON_COMPRESSION_CHANGE)    != 0) p.Add("COMPRESSION_CHANGE");
                    if ((Reason & USN_REASON_ENCRYPTION_CHANGE)     != 0) p.Add("ENCRYPTION_CHANGE");
                    if ((Reason & USN_REASON_OBJECT_ID_CHANGE)      != 0) p.Add("OBJECT_ID_CHANGE");
                    if ((Reason & USN_REASON_REPARSE_POINT_CHANGE)  != 0) p.Add("REPARSE_POINT_CHANGE");
                    if ((Reason & USN_REASON_STREAM_CHANGE)         != 0) p.Add("STREAM_CHANGE");
                    if ((Reason & USN_REASON_TRANSACTED_CHANGE)     != 0) p.Add("TRANSACTED_CHANGE");
                    if ((Reason & USN_REASON_INTEGRITY_CHANGE)      != 0) p.Add("INTEGRITY_CHANGE");
                    if ((Reason & USN_REASON_CLOSE)                 != 0) p.Add("CLOSE");
                    return string.Join("|", p);
                }
            }
        }

        public IEnumerable<UsnRecord> ReadJournal(string driveLetter)
        {
            string volumePath = $@"\\.\{driveLetter}:";
            using var handle = CreateFile(
                volumePath, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

            if (handle.IsInvalid)
                throw new IOException($"Cannot open {volumePath}. Run as admin. Win32: {Marshal.GetLastWin32Error()}");

            var journalData = new USN_JOURNAL_DATA_V0();
            int journalSize = Marshal.SizeOf(journalData);
            IntPtr journalPtr = Marshal.AllocHGlobal(journalSize);

            try
            {
                if (!DeviceIoControl(handle, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0,
                                      journalPtr, (uint)journalSize, out _, IntPtr.Zero))
                    throw new IOException($"FSCTL_QUERY_USN_JOURNAL failed: {Marshal.GetLastWin32Error()}");
                journalData = Marshal.PtrToStructure<USN_JOURNAL_DATA_V0>(journalPtr);
            }
            finally { Marshal.FreeHGlobal(journalPtr); }

            var readData = new READ_USN_JOURNAL_DATA_V0
            {
                StartUsn = 0,
                ReasonMask = 0xFFFFFFFF,
                ReturnOnlyOnClose = 0,
                Timeout = 0,
                BytesToWaitFor = 0,
                UsnJournalID = journalData.UsnJournalID
            };

            const int bufferSize = 1024 * 1024;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            int readDataSize = Marshal.SizeOf(readData);
            IntPtr readDataPtr = Marshal.AllocHGlobal(readDataSize);

            try
            {
                while (true)
                {
                    Marshal.StructureToPtr(readData, readDataPtr, false);
                    bool ok = DeviceIoControl(handle, FSCTL_READ_USN_JOURNAL,
                        readDataPtr, (uint)readDataSize,
                        buffer, bufferSize,
                        out uint bytesRead, IntPtr.Zero);

                    if (!ok || bytesRead < 8) yield break;

                    long nextUsn = Marshal.ReadInt64(buffer);
                    int offset = 8;

                    while (offset < bytesRead)
                    {
                        IntPtr recordPtr = IntPtr.Add(buffer, offset);
                        int recordLength = Marshal.ReadInt32(recordPtr);
                        if (recordLength <= 0) break;

                        var rec = ParseRecord(recordPtr);
                        if (rec != null) yield return rec;

                        offset += recordLength;
                    }

                    if (nextUsn == readData.StartUsn) yield break;
                    readData.StartUsn = nextUsn;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
                Marshal.FreeHGlobal(readDataPtr);
            }
        }

        private static UsnRecord? ParseRecord(IntPtr recordPtr)
        {
            int recordLength = Marshal.ReadInt32(recordPtr, 0);
            ushort majorVersion = (ushort)Marshal.ReadInt16(recordPtr, 4);
            if (majorVersion != 2) return null;

            ulong fileRef = (ulong)Marshal.ReadInt64(recordPtr, 8);
            ulong parentRef = (ulong)Marshal.ReadInt64(recordPtr, 16);
            long usn = Marshal.ReadInt64(recordPtr, 24);
            long timestamp = Marshal.ReadInt64(recordPtr, 32);
            uint reason = (uint)Marshal.ReadInt32(recordPtr, 40);
            uint fileAttr = (uint)Marshal.ReadInt32(recordPtr, 52);
            ushort fileNameLength = (ushort)Marshal.ReadInt16(recordPtr, 56);
            ushort fileNameOffset = (ushort)Marshal.ReadInt16(recordPtr, 58);

            string fileName = Marshal.PtrToStringUni(
                IntPtr.Add(recordPtr, fileNameOffset),
                fileNameLength / 2);

            return new UsnRecord
            {
                Usn = usn,
                FileReferenceNumber = fileRef,
                ParentFileReferenceNumber = parentRef,
                Timestamp = DateTime.FromFileTimeUtc(timestamp),
                Reason = reason,
                FileName = fileName,
                FileAttributes = fileAttr
            };
        }
    }
}
