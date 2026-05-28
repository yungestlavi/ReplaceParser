using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using SSForensic.Forensics;
using SSForensic.Models;

namespace SSForensic.Services
{
    public class ForensicAnalyzer
    {
        private readonly UsnJournalReader _usn = new();
        private readonly YaraEngine _yara;

        public HashSet<string> EnabledExtensions { get; set; } = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".jar", ".dll", ".py", ".bat"
        };

        // Master switch for the modified-extension detector. When on, the multi-signal
        // scoring system below decides whether a strange extension is a disguised executable.
        public bool DetectSuspiciousExtensions { get; set; } = false;

        private static readonly HashSet<string> WellKnownExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".com", ".drv", ".efi",
            ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
            ".jar", ".class", ".jmod", ".war", ".ear",
            ".py", ".pyc", ".pyo", ".pyd", ".pyw",
            ".lua", ".rb", ".pl", ".sh", ".so",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt", ".ods", ".odp",
            ".txt", ".md", ".csv", ".log", ".ini", ".cfg", ".conf", ".json", ".xml", ".yaml", ".yml",
            ".toml", ".env", ".reg",
            ".html", ".htm", ".css", ".sass", ".scss", ".ts", ".tsx", ".jsx", ".vue", ".php", ".asp", ".aspx",
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tiff", ".tif", ".svg", ".heic", ".heif",
            ".psd", ".ai", ".eps", ".raw", ".cr2", ".nef", ".arw",
            ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".wma", ".opus",
            ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpg", ".mpeg", ".3gp",
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".tgz",
            ".ttf", ".otf", ".woff", ".woff2", ".eot",
            ".msi", ".msu", ".msp", ".appx", ".msix", ".nupkg",
            ".db", ".sqlite", ".sqlite3", ".dat", ".bin", ".sav", ".bak",
            ".mca", ".mcr", ".nbt", ".schematic", ".litematic",
            ".dmg", ".pkg",
            ".lnk", ".url", ".tmp", ".temp", ".cache", ".pid", ".lock"
        };

        // IDEA 1: hard blacklist of pure OS / app-internal artifact extensions.
        private static readonly HashSet<string> SystemArtifactExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".pf", ".ldb", ".log1", ".log2", ".blf", ".regtrans-ms",
            ".toc", ".tbres", ".customdestinations-ms", ".automaticdestinations-ms",
            ".etl", ".dmp", ".mdmp", ".tmp", ".temp", ".old", ".partial", ".crdownload",
            ".db-wal", ".db-shm", ".db-journal", ".sqlite-wal", ".sqlite-shm",
            ".manifest", ".cat", ".mui", ".nls", ".pri", ".jfm", ".chk", ".idx", ".bak"
        };

        private static readonly string[] WindowsFilenamePrefixes =
        {
            "api-ms-win-", "ext-ms-win-", "Microsoft.", "System.",
            "vcruntime", "msvcp", "mscor", "ucrtbase", "ntdll", "kernel32",
            "Windows.", "Microsoft-Windows-", "wpf", "WindowsBase",
            "PresentationCore", "PresentationFramework", "ReachFramework",
            "d3d", "dx", "Cabinet", "winmm", "uxtheme", "advapi32",
            "user32", "gdi32", "comctl32", "comdlg32", "shell32", "ws2_",
            "rpcrt4", "iphlpapi", "crypt32", "bcrypt", "ncrypt",
            "vulkan", "vk_", "nv", "ig", "atig", "amdvlk",
            "cowork-svc", "chrome-native-host", "chrome_", "msedge",
            "GoogleUpdate", "EpicGames", "EpicWebHelper", "Discord",
            "Update", "Squirrel", "elevation_service", "notification_helper"
        };

        private static readonly string[] SystemProcessNames =
        {
            "svchost", "dllhost", "wmiprvse", "taskhostw", "taskhost",
            "backgroundtaskhost", "runtimebroker", "dwm", "csrss", "wininit",
            "services", "lsass", "smss", "conhost", "fontdrvhost", "sihost",
            "ctfmon", "searchindexer", "searchprotocolhost", "searchfilterhost",
            "dotnet", "mscorsvw", "ngen", "trustedinstaller", "tiworker",
            "wuauclt", "usocoreworker", "mousocoreworker", "compattelrunner",
            "rundll32", "consent", "audiodg", "spoolsv",
            "claude", "explorer", "startmenuexperiencehost", "shellexperiencehost",
            "applicationframehost", "systemsettings", "textinputhost"
        };

        private static readonly string[] AutomatedPathMarkers =
        {
            @"\AppData\Local\Google\", @"\AppData\Local\Microsoft\",
            @"\AppData\Local\Microsoft\Edge", @"\AppData\Local\Discord\",
            @"\AppData\Local\Programs\", @"\AppData\Local\SquirrelTemp",
            @"\AppData\Local\Temp\", @"\AppData\Roaming\Spotify\",
            @"\AppData\Local\EpicGamesLauncher", @"Epic Games\Epic Online",
            @"Epic Games\Launcher", @"\Google\Chrome\Application\",
            @"\Microsoft\EdgeUpdate", @"\Microsoft\EdgeWebView",
            @"\Package Cache\", @"\NVIDIA Corporation\", @"\AMD\", @"\Intel\",
            @"\WindowsApps\", @"\Common Files\microsoft shared",
            @"\dotnet\", @"\Steam\steamapps\downloading",
            @"\AppData\LocalLow\", @"\AppData\Local\Packages\",
            @"\AppData\Local\Razer\", @"\AppData\Roaming\discord\",
            @"\AppData\Local\CrashDumps\", @"\AppData\Local\ConnectedDevicesPlatform\",
            @"\AppData\Local\Comms\", @"\AppData\Local\PlaceholderTileLogoFolder"
        };

        private static readonly string[] WindowsSystemRoots =
        {
            @"C:\Windows\",
            @"C:\Program Files\WindowsApps",
            @"C:\Program Files\Common Files\microsoft shared",
            @"C:\Program Files (x86)\Common Files\microsoft shared",
            @"C:\Program Files\Windows Defender",
            @"C:\Program Files (x86)\Windows Defender",
            @"C:\Program Files\Microsoft\",
            @"C:\Program Files (x86)\Microsoft\",
            @"C:\ProgramData\Microsoft\",
            @"C:\ProgramData\Package Cache\",
            @"C:\$WinREAgent\", @"C:\$Windows.~BT\", @"C:\$Windows.~WS\"
        };

        private static readonly string[] UserActionFolders =
        {
            @"\Desktop", @"\Downloads", @"\Documents", @"\Music",
            @"\Videos", @"\Pictures", @"\OneDrive\Desktop", @"\OneDrive\Documents",
            @"\Saved Games", @"\source\repos", @"\Projects"
        };

        private static readonly string[] TrustedSignerKeywords =
        {
            "Microsoft", "Windows", "Google LLC", "Mozilla", "Adobe",
            "Intel", "NVIDIA", "AMD", "Apple", "Valve", "Discord",
            "Spotify", "JetBrains", "GitHub", "Realtek", "Logitech",
            "Razer", "ASUS", "Dell", "HP Inc", "Lenovo", "Acer",
            "Steam", "Epic Games", "EA Games", "Riot Games", "Ubisoft",
            "Activision", "Blizzard", "Roblox", "Battle.net",
            "OBS Studio", "Notepad++", "VideoLAN", "7-Zip",
            "Brave Software", "Opera Norway", "TeamSpeak"
        };

        private static readonly string[] McClientFolders =
        {
            @"\AppData\Roaming\.minecraft\", @"\AppData\Roaming\.minecraft\libraries\",
            @"\AppData\Roaming\.minecraft\versions\", @"\AppData\Roaming\.minecraft\mods\",
            @"\AppData\Local\.lunarclient\", @"\.lunarclient\offline\",
            @"\.lunarclient\jre\", @"\.lunarclient\textures\",
            @"\AppData\Roaming\ModrinthApp\", @"\AppData\Roaming\com.modrinth.theseus\",
            @"\AppData\Roaming\PrismLauncher\", @"\AppData\Roaming\.feather\",
            @"\AppData\Roaming\.minecraft\badlion\", @"\Badlion Client\",
            @"\AppData\Local\Programs\lunarclient\", @"\AppData\Local\Programs\Modrinth App\"
        };

        private static readonly string[] McLegitNamePrefixes =
        {
            "optifine", "fabric-", "forge-", "quilt-", "sodium", "lithium", "iris",
            "starlight", "lwjgl", "asm-", "guava-", "gson-", "log4j-", "netty-",
            "authlib", "brigadier", "datafixerupper", "fastutil", "icu4j",
            "jopt-simple", "commons-", "slf4j-", "oshi-", "jna-",
            "text2speech", "javabridge", "patchy", "blocklist"
        };

        public event Action<string>? StatusUpdate;
        public event Action<int>? ProgressUpdate;

        // IDEA 3: if Sysmon FileCreate (event 11) or Security 4663 auditing is available,
        // we map filename -> writing process. Built once per analysis.
        private Dictionary<string, string> _fileWriterMap = new(StringComparer.OrdinalIgnoreCase);

        public ForensicAnalyzer(YaraEngine yara) => _yara = yara;

        public static DateTime GetLastBootTimeUtc()
        {
            try { return DateTime.UtcNow.AddMilliseconds(-Environment.TickCount64); }
            catch { return DateTime.UtcNow.AddDays(-1); }
        }

        public async Task<List<ReplaceRecord>> AnalyzeAsync(string driveLetter, CancellationToken ct)
            => await Task.Run(() => Analyze(driveLetter, ct), ct);

        public List<ReplaceRecord> Analyze(string driveLetter, CancellationToken ct)
        {
            var sinceUtc = GetLastBootTimeUtc();
            var sw = Stopwatch.StartNew();
            StatusUpdate?.Invoke($"Last boot: {sinceUtc:u} — scanning since system start...");

            // IDEA 3: build writer map (best-effort, silent if auditing not enabled)
            _fileWriterMap = BuildFileWriterMap(sinceUtc);
            if (_fileWriterMap.Count > 0)
                StatusUpdate?.Invoke($"Process-write audit available: {_fileWriterMap.Count} file→process links.");

            StatusUpdate?.Invoke($"Reading USN journal on {driveLetter}: ...");
            var allRelevant = new List<UsnJournalReader.UsnRecord>();
            int totalUsn = 0, skippedSystem = 0;
            try
            {
                foreach (var rec in _usn.ReadJournal(driveLetter))
                {
                    totalUsn++;
                    if (rec.Timestamp < sinceUtc) continue;

                    string ext = Path.GetExtension(rec.FileName);

                    if (SystemArtifactExtensions.Contains(ext)) { skippedSystem++; continue; }
                    if (IsSystemProcessArtifact(rec.FileName)) { skippedSystem++; continue; }

                    bool inEnabled = EnabledExtensions.Contains(ext);
                    bool isUnknownExt = !string.IsNullOrEmpty(ext) && !WellKnownExtensions.Contains(ext);

                    if (!inEnabled && !(DetectSuspiciousExtensions && isUnknownExt)) continue;
                    if (LooksLikeWindowsComponentByName(rec.FileName)) { skippedSystem++; continue; }

                    allRelevant.Add(rec);
                    if (totalUsn % 50000 == 0)
                        StatusUpdate?.Invoke($"USN: {totalUsn} scanned, {allRelevant.Count} kept, {skippedSystem} system skipped...");
                    ct.ThrowIfCancellationRequested();
                }
            }
            catch (Exception ex) { StatusUpdate?.Invoke($"USN read failed: {ex.Message}"); }

            var candidateUsn = allRelevant.Where(r => r.IsReplace).ToList();
            StatusUpdate?.Invoke($"USN: {totalUsn} total, {candidateUsn.Count} replace candidates [{sw.Elapsed.TotalSeconds:F1}s]");

            var batchTimestamps = candidateUsn
                .GroupBy(r => new DateTime(r.Timestamp.Year, r.Timestamp.Month, r.Timestamp.Day,
                                           r.Timestamp.Hour, r.Timestamp.Minute, r.Timestamp.Second, DateTimeKind.Utc))
                .Where(g => g.Select(x => x.FileReferenceNumber).Distinct().Count() >= 4)
                .Select(g => g.Key)
                .ToHashSet();

            var renameMap = BuildRenameMap(allRelevant);

            StatusUpdate?.Invoke("Building filesystem index...");
            var wantedNames = candidateUsn.Select(r => r.FileName)
                                          .Concat(renameMap.Values.SelectMany(v => new[] { v.OldName, v.NewName }))
                                          .Where(n => !string.IsNullOrEmpty(n))
                                          .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var multiIndex = BuildMultiFileIndex(wantedNames, ct);
            var fileIndex = multiIndex.ToDictionary(kv => kv.Key, kv => kv.Value.First(), StringComparer.OrdinalIgnoreCase);
            StatusUpdate?.Invoke($"Indexed {fileIndex.Count} files [{sw.Elapsed.TotalSeconds:F1}s]");

            var groups = candidateUsn.GroupBy(r => r.FileReferenceNumber).ToList();
            StatusUpdate?.Invoke($"Building {groups.Count} records...");
            var bag = new ConcurrentBag<ReplaceRecord>();
            int done = 0, dropped = 0;

            Parallel.ForEach(groups, new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount,
                CancellationToken = ct
            }, group =>
            {
                var ordered = group.OrderBy(r => r.Timestamp).ToList();
                var rec = BuildReplaceRecord(group.Key, ordered, fileIndex, multiIndex, renameMap);
                if (rec == null) return;

                if (IsKnownWindowsPath(rec.ReplacementPath) || IsKnownWindowsPath(rec.OriginalPath)) { Interlocked.Increment(ref dropped); return; }
                if (rec.ReplacementTrust == FileTrust.Legit && IsTrustedSigner(rec.ReplacementSigner)) { Interlocked.Increment(ref dropped); return; }

                bool isCheatLike = rec.ReplacementTrust == FileTrust.Cheat;

                if (!isCheatLike && IsLegitMinecraftClientFile(rec)) { Interlocked.Increment(ref dropped); return; }
                if (!isCheatLike && IsLikelyAutomatedReplace(rec, batchTimestamps)) { Interlocked.Increment(ref dropped); return; }

                bag.Add(rec);
                int d = Interlocked.Increment(ref done);
                if (d % 50 == 0) ProgressUpdate?.Invoke((int)(100.0 * d / groups.Count));
            });

            ProgressUpdate?.Invoke(100);
            var results = bag.OrderByDescending(r => r.ReplaceTimestamp).ToList();
            StatusUpdate?.Invoke($"DONE: {results.Count} user-action records ({dropped} system/auto filtered) in {sw.Elapsed.TotalSeconds:F1}s.");
            return results;
        }

        // ============================================================
        //  MULTI-SIGNAL SPOOF SCORING (combines ideas 2,3,4,5)
        // ============================================================
        /// <summary>
        /// Decides whether a file with a non-standard extension is a disguised executable
        /// placed by the user, vs. legitimate system/app churn. Returns (isSpoofed, reason).
        /// A score >= 3 is required to flag.
        /// </summary>
        private (bool spoofed, string reason) ScoreModifiedExtension(
            string filePath, string declaredExt, bool magicSaysExecutable, string detectedFmt)
        {
            int score = 0;
            var reasons = new List<string>();

            // --- IDEA 2: executable content under a non-executable extension is the
            // strongest single signal. Worth 3 by itself (immediate flag). ---
            bool extClaimsExecutable = declaredExt is ".exe" or ".dll" or ".jar" or ".class"
                                                    or ".sys" or ".so" or ".com" or ".scr" or ".ocx";
            if (magicSaysExecutable && !extClaimsExecutable)
            {
                score += 3;
                reasons.Add($"executable content ({detectedFmt}) hidden under '{declaredExt}'");
            }

            // --- IDEA 4: location. User folders raise suspicion, AppData/ProgramData lower it. ---
            bool inUserFolder = false, inSystemArea = false;
            if (!string.IsNullOrEmpty(filePath) && !filePath.StartsWith("("))
            {
                if (filePath.IndexOf(@"\AppData\", StringComparison.OrdinalIgnoreCase) >= 0
                 || filePath.IndexOf(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) >= 0)
                    inSystemArea = true;
                foreach (var f in UserActionFolders)
                    if (filePath.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0) { inUserFolder = true; break; }
            }
            if (inUserFolder) { score += 2; reasons.Add("in user folder"); }
            if (inSystemArea) { score -= 3; reasons.Add("inside AppData/ProgramData (system area)"); }

            // --- IDEA 3: writer process. Explorer/cmd/powershell = human; service = automatic. ---
            string writer = GetWriterProcess(filePath);
            if (!string.IsNullOrEmpty(writer))
            {
                string w = writer.ToLowerInvariant();
                bool humanWriter = w.Contains("explorer") || w.Contains("cmd.exe")
                                 || w.Contains("powershell") || w.Contains("pwsh")
                                 || w.Contains("7zfm") || w.Contains("winrar")
                                 || w.Contains("totalcmd") || w.Contains("filezilla");
                bool serviceWriter = SystemProcessNames.Any(p => w.Contains(p))
                                  || w.Contains("chrome") || w.Contains("msedge")
                                  || w.Contains("msmpeng") || w.Contains("update");
                if (humanWriter) { score += 3; reasons.Add($"written by user process ({writer})"); }
                if (serviceWriter) { score -= 4; reasons.Add($"written by system/app process ({writer})"); }
            }

            // --- IDEA 5: size + entropy. Tiny files and pure-noise blobs are not disguised exes. ---
            try
            {
                if (File.Exists(filePath))
                {
                    var fi = new FileInfo(filePath);
                    if (fi.Length < 4096) { score -= 2; reasons.Add("tiny file (<4KB)"); }
                    else if (fi.Length > 50 * 1024) { score += 1; reasons.Add("program-sized"); }

                    double entropy = SampleEntropy(filePath);
                    // Very high entropy (>7.5) without exec magic = compressed/encrypted data, not a disguised exe
                    if (entropy > 7.5 && !magicSaysExecutable) { score -= 2; reasons.Add($"high-entropy data ({entropy:F1})"); }
                }
            }
            catch { }

            bool flag = score >= 3;
            return (flag, string.Join("; ", reasons));
        }

        /// <summary>Shannon entropy on a 64KB sample. 0=uniform, 8=random.</summary>
        private static double SampleEntropy(string filePath)
        {
            try
            {
                using var fs = File.OpenRead(filePath);
                int n = (int)Math.Min(65536, fs.Length);
                if (n == 0) return 0;
                var buf = new byte[n];
                fs.Read(buf, 0, n);
                var counts = new int[256];
                foreach (var b in buf) counts[b]++;
                double e = 0;
                foreach (var c in counts)
                {
                    if (c == 0) continue;
                    double p = (double)c / n;
                    e -= p * Math.Log2(p);
                }
                return e;
            }
            catch { return 0; }
        }

        private string GetWriterProcess(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || _fileWriterMap.Count == 0) return "";
            string name = Path.GetFileName(filePath);
            return _fileWriterMap.TryGetValue(name, out var p) ? p : "";
        }

        /// <summary>
        /// IDEA 3: best-effort map of filename -> writing process from Sysmon Event 11
        /// (FileCreate) or Security 4663. Returns empty if neither channel is available.
        /// </summary>
        private Dictionary<string, string> BuildFileWriterMap(DateTime sinceUtc)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            // Sysmon Event 11
            TryReadWriterChannel("Microsoft-Windows-Sysmon/Operational", 11, sinceUtc, map,
                                 imageIdx: 3, targetIdx: 4);
            // Security 4663 (object access - requires SACL auditing; often off, hence best-effort)
            if (map.Count == 0)
                TryReadWriterChannel("Security", 4663, sinceUtc, map, imageIdx: 11, targetIdx: 6);
            return map;
        }

        private void TryReadWriterChannel(string channel, int eventId, DateTime sinceUtc,
                                          Dictionary<string, string> map, int imageIdx, int targetIdx)
        {
            try
            {
                string iso = sinceUtc.ToString("yyyy-MM-ddTHH:mm:ss.000Z");
                string xpath = $"*[System[EventID={eventId} and TimeCreated[@SystemTime>='{iso}']]]";
                var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                    channel, System.Diagnostics.Eventing.Reader.PathType.LogName, xpath);
                using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
                System.Diagnostics.Eventing.Reader.EventRecord? rec;
                int read = 0;
                while ((rec = reader.ReadEvent()) != null && read < 20000)
                {
                    read++;
                    try
                    {
                        var props = rec.Properties;
                        if (props.Count > Math.Max(imageIdx, targetIdx))
                        {
                            string image = props[imageIdx].Value?.ToString() ?? "";
                            string target = props[targetIdx].Value?.ToString() ?? "";
                            if (!string.IsNullOrEmpty(target))
                            {
                                string fn = Path.GetFileName(target);
                                if (!map.ContainsKey(fn)) map[fn] = Path.GetFileName(image);
                            }
                        }
                    }
                    catch { }
                    rec.Dispose();
                }
            }
            catch { /* channel unavailable / auditing off -> silent */ }
        }

        private static bool IsSystemProcessArtifact(string fileName)
        {
            string lower = fileName.ToLowerInvariant();
            foreach (var proc in SystemProcessNames)
            {
                if (lower.StartsWith(proc + ".exe", StringComparison.OrdinalIgnoreCase)) return true;
                if (lower.StartsWith(proc + "-", StringComparison.OrdinalIgnoreCase)) return true;
                if (lower.Equals(proc + ".exe", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static bool IsLegitMinecraftClientFile(ReplaceRecord rec)
        {
            string path = rec.ReplacementPath ?? "";
            if (string.IsNullOrEmpty(path) || path.StartsWith("(")) return false;

            bool inClientFolder = false;
            foreach (var f in McClientFolders)
                if (path.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0) { inClientFolder = true; break; }
            if (!inClientFolder) return false;

            if (path.IndexOf(@"\libraries\", StringComparison.OrdinalIgnoreCase) >= 0
             || path.IndexOf(@"\versions\", StringComparison.OrdinalIgnoreCase) >= 0
             || path.IndexOf(@"\jre\", StringComparison.OrdinalIgnoreCase) >= 0
             || path.IndexOf(@"\offline\", StringComparison.OrdinalIgnoreCase) >= 0
             || path.IndexOf(@"\textures\", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;

            string name = rec.ReplacementFileName?.ToLowerInvariant() ?? "";
            foreach (var p in McLegitNamePrefixes)
                if (name.StartsWith(p, StringComparison.OrdinalIgnoreCase)) return true;

            return false;
        }

        private static bool IsLikelyAutomatedReplace(ReplaceRecord rec, HashSet<DateTime> batchTimestamps)
        {
            foreach (var marker in AutomatedPathMarkers)
            {
                if (rec.ReplacementPath.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0) return true;
                if (rec.OriginalPath.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            if (rec.ReplaceTimestamp.HasValue)
            {
                var t = rec.ReplaceTimestamp.Value;
                var sec = new DateTime(t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second, DateTimeKind.Utc);
                if (batchTimestamps.Contains(sec)) return true;
            }
            if (HasVersionFolder(rec.ReplacementPath) || HasVersionFolder(rec.OriginalPath)) return true;

            bool pathsMissing = rec.ReplacementPath.StartsWith("(") && rec.OriginalPath.StartsWith("(");
            if (pathsMissing) return true;

            return false;
        }

        private static bool HasVersionFolder(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            foreach (var seg in path.Split('\\'))
            {
                int dots = 0; bool ok = seg.Length > 0;
                foreach (char c in seg) { if (c == '.') dots++; else if (!char.IsDigit(c)) { ok = false; break; } }
                if (ok && dots >= 2) return true;
            }
            return false;
        }

        private class RenameInfo { public string OldName = ""; public string NewName = ""; public DateTime Timestamp; }

        private static Dictionary<ulong, RenameInfo> BuildRenameMap(List<UsnJournalReader.UsnRecord> all)
        {
            var map = new Dictionary<ulong, RenameInfo>();
            var byFrn = all.Where(r => (r.Reason & (UsnJournalReader.USN_REASON_RENAME_OLD_NAME
                                                  | UsnJournalReader.USN_REASON_RENAME_NEW_NAME)) != 0)
                           .GroupBy(r => r.FileReferenceNumber);
            foreach (var g in byFrn)
            {
                var ordered = g.OrderBy(r => r.Timestamp).ToList();
                string? oldName = null, newName = null; DateTime ts = DateTime.MinValue;
                foreach (var r in ordered)
                {
                    if ((r.Reason & UsnJournalReader.USN_REASON_RENAME_OLD_NAME) != 0) { oldName = r.FileName; ts = r.Timestamp; }
                    if ((r.Reason & UsnJournalReader.USN_REASON_RENAME_NEW_NAME) != 0) { newName = r.FileName; if (ts == DateTime.MinValue) ts = r.Timestamp; }
                }
                if (oldName != null && newName != null && !oldName.Equals(newName, StringComparison.OrdinalIgnoreCase))
                    map[g.Key] = new RenameInfo { OldName = oldName, NewName = newName, Timestamp = ts };
            }
            return map;
        }

        private static bool LooksLikeWindowsComponentByName(string fileName)
        {
            foreach (var prefix in WindowsFilenamePrefixes)
                if (fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static bool IsKnownWindowsPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            foreach (var root in WindowsSystemRoots)
                if (path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static bool IsTrustedSigner(string signer)
        {
            if (string.IsNullOrEmpty(signer)) return false;
            foreach (var kw in TrustedSignerKeywords)
                if (signer.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        private Dictionary<string, List<string>> BuildMultiFileIndex(HashSet<string> wantedNames, CancellationToken ct)
        {
            var index = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, path) in EnumerateMatches(wantedNames, ct))
            {
                if (!index.TryGetValue(name, out var list)) { list = new List<string>(); index[name] = list; }
                if (!list.Contains(path, StringComparer.OrdinalIgnoreCase)) list.Add(path);
            }
            return index;
        }

        private IEnumerable<(string name, string path)> EnumerateMatches(HashSet<string> wantedNames, CancellationToken ct)
        {
            var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            }.Where(r => !string.IsNullOrEmpty(r) && Directory.Exists(r))
             .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

            var budget = Stopwatch.StartNew();
            var maxBudget = TimeSpan.FromSeconds(30);
            foreach (var root in roots)
            {
                if (budget.Elapsed > maxBudget) break;
                foreach (var hit in WalkDir(root, wantedNames, budget, maxBudget, ct)) yield return hit;
            }
        }

        private IEnumerable<(string name, string path)> WalkDir(string dir, HashSet<string> wantedNames,
                              Stopwatch budget, TimeSpan maxBudget, CancellationToken ct)
        {
            if (budget.Elapsed > maxBudget || ct.IsCancellationRequested) yield break;
            if (IsKnownWindowsPath(dir)) yield break;

            string[] files;
            try { files = Directory.GetFiles(dir); } catch { yield break; }
            foreach (var f in files)
            {
                string name = Path.GetFileName(f);
                if (wantedNames.Contains(name)) yield return (name, f);
            }

            string[] subdirs;
            try { subdirs = Directory.GetDirectories(dir); } catch { yield break; }
            foreach (var sub in subdirs)
            {
                string subName = Path.GetFileName(sub);
                if (subName.Equals("WinSxS", StringComparison.OrdinalIgnoreCase)) continue;
                if (subName.Equals("Installer", StringComparison.OrdinalIgnoreCase)) continue;
                if (subName.Equals("assembly", StringComparison.OrdinalIgnoreCase)) continue;
                if (subName.Equals("WindowsApps", StringComparison.OrdinalIgnoreCase)) continue;
                if (subName.Equals("servicing", StringComparison.OrdinalIgnoreCase)) continue;
                if (subName.StartsWith("$", StringComparison.Ordinal)) continue;
                foreach (var hit in WalkDir(sub, wantedNames, budget, maxBudget, ct)) yield return hit;
            }
        }

        private ReplaceRecord? BuildReplaceRecord(
            ulong frn,
            List<UsnJournalReader.UsnRecord> events,
            Dictionary<string, string> fileIndex,
            Dictionary<string, List<string>> multiIndex,
            Dictionary<ulong, RenameInfo> renameMap)
        {
            string filename = events.Last().FileName;
            if (renameMap.TryGetValue(frn, out var ren)) filename = ren.NewName;

            var paths = multiIndex.TryGetValue(filename, out var pl) ? pl : new List<string>();
            string originalPath = "(file moved or deleted)";
            string replacementPath = "(file moved or deleted)";

            if (paths.Count >= 2)
            {
                var infos = paths.Select(p =>
                {
                    try { var fi = new FileInfo(p); return new { Path = p, Created = fi.CreationTimeUtc, Exists = fi.Exists }; }
                    catch { return new { Path = p, Created = DateTime.MaxValue, Exists = false }; }
                }).Where(i => i.Exists).ToList();

                if (infos.Count >= 2)
                {
                    originalPath = infos.OrderBy(i => i.Created).First().Path;
                    replacementPath = infos.OrderByDescending(i => i.Created).First().Path;
                }
                else if (infos.Count == 1) originalPath = replacementPath = infos[0].Path;
            }
            else if (paths.Count == 1) originalPath = replacementPath = paths[0];
            else if (fileIndex.TryGetValue(filename, out var single)) originalPath = replacementPath = single;

            var record = new ReplaceRecord
            {
                OriginalFileName = filename,
                ReplacementFileName = filename,
                OriginalPath = originalPath,
                ReplacementPath = replacementPath,
                ReplaceTimestamp = events.Last().Timestamp,
                DeclaredExtension = Path.GetExtension(filename)
            };

            string? canonical = File.Exists(replacementPath) ? replacementPath
                              : File.Exists(originalPath) ? originalPath : null;

            if (canonical != null && File.Exists(canonical))
            {
                try
                {
                    if (File.Exists(originalPath))
                    {
                        var fo = new FileInfo(originalPath);
                        record.OriginalCreated = fo.CreationTimeUtc;
                        record.OriginalLastModified = fo.LastWriteTimeUtc;
                        record.OriginalLastAccessed = fo.LastAccessTimeUtc;
                    }
                    if (File.Exists(replacementPath))
                    {
                        var fr = new FileInfo(replacementPath);
                        record.ReplacementCreated = fr.CreationTimeUtc;
                        record.ReplacementLastModified = fr.LastWriteTimeUtc;
                        record.ReplacementLastAccessed = fr.LastAccessTimeUtc;
                    }
                }
                catch { }

                record.ReplacementHash = FileHasher.Sha256(canonical);
                record.OriginalHash = record.ReplacementHash;

                var (detectedFmt, magicSaysExe) = DetectExecutableMagic(canonical);
                record.DetectedFormat = detectedFmt;

                // === MULTI-SIGNAL SPOOF DECISION ===
                bool unknownExt = DetectSuspiciousExtensions
                               && !string.IsNullOrEmpty(record.DeclaredExtension)
                               && !WellKnownExtensions.Contains(record.DeclaredExtension);
                // Magic mismatch on a *standard* exec extension (e.g. .exe that isn't PE) - keep simple
                bool magicMismatch = MagicMismatch(record.DeclaredExtension, detectedFmt);

                bool spoofed = false;
                if (magicMismatch)
                {
                    spoofed = true; // a declared .exe/.jar that isn't really one is always suspicious
                }
                else if (unknownExt)
                {
                    var (s, reason) = ScoreModifiedExtension(canonical, record.DeclaredExtension, magicSaysExe, detectedFmt);
                    spoofed = s;
                    if (s) record.DetectedFormat = $"{detectedFmt} [{reason}]";
                }
                record.ExtensionSpoofed = spoofed;

                // === DEEP DIGITAL-SIGNATURE VERIFICATION ===
                var sig = SignatureVerifier.Verify(canonical);
                string signerLabel = !string.IsNullOrEmpty(sig.SignerName)
                    ? sig.SignerName
                    : (sig.IsSigned ? "(signed, signer unknown)" : "");
                record.ReplacementSigner = signerLabel;
                record.OriginalSigner = signerLabel;
                record.SignatureVerdict = sig.Verdict;
                record.SignatureDetails = sig.Summary();
                record.SignatureChainTrusted = sig.IsChainTrusted;
                record.SignatureTimeValid = sig.IsTimeValid;
                record.SignatureAuthenticodeValid = sig.IsAuthenticodeValid;

                bool signed = sig.IsSigned && (sig.IsAuthenticodeValid || sig.IsChainTrusted);
                bool fullyValid = sig.IsAuthenticodeValid && sig.IsChainTrusted && sig.IsTimeValid;

                var yara = _yara.Scan(canonical);
                record.YaraMatches = yara.Matches;

                if (yara.IsCheat) { record.ReplacementTrust = FileTrust.Cheat; record.OriginalTrust = FileTrust.Cheat; }
                else if (record.ExtensionSpoofed) { record.ReplacementTrust = FileTrust.ExtSpoofed; record.OriginalTrust = FileTrust.ExtSpoofed; }
                else if (signed && fullyValid) { record.ReplacementTrust = FileTrust.Legit; record.OriginalTrust = FileTrust.Legit; }
                else { record.ReplacementTrust = FileTrust.Unsigned; record.OriginalTrust = FileTrust.Unsigned; }
            }
            else
            {
                // File not on disk: we cannot read magic/size/entropy, so we CANNOT confirm a
                // disguised executable. To avoid false flags we do NOT mark these as spoofed.
                record.ReplacementTrust = FileTrust.Unsigned;
                record.OriginalTrust = FileTrust.Unsigned;
                record.ReplacementSigner = "(file not on disk)";
                record.OriginalSigner = record.ReplacementSigner;
            }

            foreach (var ev in events.OrderBy(e => e.Timestamp))
            {
                record.Evidence.Add(new ForensicEvidence
                {
                    Source = EvidenceSource.UsnJournal,
                    Timestamp = ev.Timestamp,
                    Description = $"[{ev.ReasonString}] {ev.FileName}",
                    RawData = $"USN={ev.Usn} FRN={ev.FileReferenceNumber} Reason=0x{ev.Reason:X8}"
                });
            }
            return record;
        }

        /// <summary>Reads magic bytes. Returns (formatLabel, isExecutableContent).</summary>
        private static (string fmt, bool isExe) DetectExecutableMagic(string filePath)
        {
            byte[] hdr;
            try
            {
                using var fs = File.OpenRead(filePath);
                hdr = new byte[Math.Min(16, fs.Length)];
                fs.Read(hdr, 0, hdr.Length);
            }
            catch { return ("UNREADABLE", false); }
            if (hdr.Length < 2) return ("EMPTY", false);

            bool isPE = hdr[0] == 0x4D && hdr[1] == 0x5A;
            bool isZip = hdr.Length >= 4 && hdr[0] == 0x50 && hdr[1] == 0x4B && hdr[2] == 0x03 && hdr[3] == 0x04;
            bool isClass = hdr.Length >= 4 && hdr[0] == 0xCA && hdr[1] == 0xFE && hdr[2] == 0xBA && hdr[3] == 0xBE;
            bool isElf = hdr.Length >= 4 && hdr[0] == 0x7F && hdr[1] == 0x45 && hdr[2] == 0x4C && hdr[3] == 0x46;
            bool isDex = hdr.Length >= 4 && hdr[0] == 0x64 && hdr[1] == 0x65 && hdr[2] == 0x78 && hdr[3] == 0x0A;

            if (isPE) return ("PE", true);
            if (isClass) return ("CLASS", true);
            if (isElf) return ("ELF", true);
            if (isDex) return ("DEX", true);
            if (isZip) return ("ZIP/JAR", false);   // zip alone isn't necessarily executable
            return ("BINARY", false);
        }

        /// <summary>A declared executable extension whose magic bytes don't match.</summary>
        private static bool MagicMismatch(string declaredExt, string detectedFmt)
        {
            string ext = (declaredExt ?? "").ToLowerInvariant();
            return ext switch
            {
                ".exe" or ".dll" or ".sys" or ".ocx" or ".cpl" or ".scr" => detectedFmt != "PE",
                ".jar" or ".war" => detectedFmt != "ZIP/JAR",
                ".class" => detectedFmt != "CLASS",
                _ => false
            };
        }
    }
}