using System;
using System.Collections.Generic;

namespace SSForensic.Models
{
    /// <summary>
    /// How the replace was performed, detected by matching USN reason sequences.
    /// </summary>
    public enum ReplaceType
    {
        Unknown,
        Explorer,   // File renamed over target via Windows Explorer (Rename Old/New pattern)
        Type,       // Typed-overwrite or echo-replace (Data Extend + Truncation only)
        Copy,       // Copy-paste overwrite (Data Overwrite + Extend + Truncation ± Security/BasicInfo)
        Hex         // Hex-editor or raw binary write (no standard overwrite sequence, Data Overwrite alone or anomalous)
    }

    /// <summary>
    /// Classification of the file's trust level (sets row color).
    /// </summary>
    public enum FileTrust
    {
        Unknown,
        Cheat,        // blue   - matches a cheat YARA rule or known-bad hash
        Legit,        // green  - Authenticode signed and trusted
        Unsigned,     // orange - no Authenticode signature
        ExtSpoofed    // purple - declared extension does not match real magic bytes
    }

    /// <summary>
    /// Where a piece of forensic evidence was sourced from.
    /// </summary>
    public enum EvidenceSource
    {
        UsnJournal,
        Prefetch,
        EventLog,
        Dps,          // Diagnostic Policy Service
        SysMain,      // SuperFetch / amcache-style data
        PcaSvc,       // Program Compatibility Assistant
        DiagTrack,    // Connected User Experiences & Telemetry
        DcomLaunch,
        Amcache,
        FileSystem
    }

    /// <summary>
    /// A single piece of evidence about a file event.
    /// </summary>
    public class ForensicEvidence
    {
        public EvidenceSource Source { get; set; }
        public DateTime Timestamp { get; set; }
        public string Description { get; set; } = string.Empty;
        public string RawData { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents a detected file replace operation.
    /// One row in the main grid corresponds to one ReplaceRecord.
    /// </summary>
    public class ReplaceRecord
    {
        // Original file
        public string OriginalFileName { get; set; } = string.Empty;
        public string OriginalPath { get; set; } = string.Empty;
        public string OriginalHash { get; set; } = string.Empty;
        public DateTime? OriginalCreated { get; set; }
        public DateTime? OriginalLastModified { get; set; }
        public DateTime? OriginalLastAccessed { get; set; }
        public FileTrust OriginalTrust { get; set; } = FileTrust.Unknown;
        public string OriginalSigner { get; set; } = string.Empty;

        // Replacement file (the file that replaced the original)
        public string ReplacementFileName { get; set; } = string.Empty;
        public string ReplacementPath { get; set; } = string.Empty;
        public string ReplacementHash { get; set; } = string.Empty;
        public DateTime? ReplacementCreated { get; set; }
        public DateTime? ReplacementLastModified { get; set; }
        public DateTime? ReplacementLastAccessed { get; set; }
        public FileTrust ReplacementTrust { get; set; } = FileTrust.Unknown;
        public string ReplacementSigner { get; set; } = string.Empty;

        // When the replace happened (best estimate from evidence)
        public DateTime? ReplaceTimestamp { get; set; }

        // Was javaw.exe / java.exe running at the time?
        public bool JavaInstanceActive { get; set; }

        // Is the declared file extension spoofed (magic bytes differ)?
        public bool ExtensionSpoofed { get; set; }
        public string DeclaredExtension { get; set; } = string.Empty;
        public string DetectedFormat { get; set; } = string.Empty;

        // YARA rule hits
        public List<string> YaraMatches { get; set; } = new();

        // Supporting evidence
        public List<ForensicEvidence> Evidence { get; set; } = new();

        // Full per-file USN change history (every journal entry for this file's
        // NTFS reference number) - powers the JournalTrace-style detail window.
        public List<UsnEvent> UsnHistory { get; set; } = new();

        // How the replace was performed (pattern-matched from USN reason sequence)
        public ReplaceType DetectedReplaceType { get; set; } = ReplaceType.Unknown;

        /// <summary>Human-readable label shown in the Type column.</summary>
        public string ReplaceTypeLabel => DetectedReplaceType switch
        {
            ReplaceType.Explorer => "Explorer",
            ReplaceType.Type     => "Type",
            ReplaceType.Copy     => "Copy",
            ReplaceType.Hex      => "HEX",
            _                    => "Unknown"
        };

        // The NTFS file reference number this record was grouped by.
        public ulong FileReferenceNumber { get; set; }

        // Extended digital-signature verification (Authenticode + X509 chain + WinTrust)
        public string SignatureVerdict { get; set; } = string.Empty;
        public string SignatureDetails { get; set; } = string.Empty;
        public bool SignatureChainTrusted { get; set; }
        public bool SignatureTimeValid { get; set; }
        public bool SignatureAuthenticodeValid { get; set; }

        // Computed: which color the row should be tagged with for the UI
        public string PrimaryFlag
        {
            get
            {
                if (JavaInstanceActive) return "REPLACE_DURING_JAVA";
                return OriginalTrust switch
                {
                    FileTrust.Cheat => "ORIGINAL_CHEAT",
                    FileTrust.Legit => "ORIGINAL_LEGIT",
                    FileTrust.Unsigned => "ORIGINAL_UNSIGNED",
                    FileTrust.ExtSpoofed => "EXT_SPOOFED",
                    _ => "UNKNOWN"
                };
            }
        }
    }

    /// <summary>
    /// A single NTFS USN journal entry for a file, mirroring the columns shown in
    /// JournalTrace-style detail views: USN, Name, Date, Reason, Directory (parent FRN).
    /// </summary>
    public class UsnEvent
    {
        public long Usn { get; set; }
        public string Name { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string Reason { get; set; } = string.Empty;
        public ulong FileReferenceNumber { get; set; }
        public ulong ParentFileReferenceNumber { get; set; }

        // Convenience for binding: the "Directory" column shows the parent reference number.
        public string Directory => ParentFileReferenceNumber.ToString();
    }

    /// <summary>
    /// Snapshot of a process that was running at a given moment in time
    /// (reconstructed from PcaSvc / DiagTrack / Sysmain / EventLog).
    /// </summary>
    public class ProcessSnapshot
    {
        public string ProcessName { get; set; } = string.Empty;
        public string ImagePath { get; set; } = string.Empty;
        public int Pid { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? EndTime { get; set; }

        public bool IsJava => ProcessName.Equals("java.exe", StringComparison.OrdinalIgnoreCase)
                           || ProcessName.Equals("javaw.exe", StringComparison.OrdinalIgnoreCase);

        public bool Contains(DateTime t)
        {
            if (t < StartTime) return false;
            if (EndTime.HasValue && t > EndTime.Value) return false;
            return true;
        }
    }
}
