using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SSForensic.Models;
using SSForensic.Services;

namespace SSForensic.ViewModels
{
    public partial class ExtensionToggle : ObservableObject
    {
        [ObservableProperty] private string extension = "";
        [ObservableProperty] private bool isEnabled = true;
    }

    public partial class MainViewModel : ObservableObject
    {
        private readonly YaraEngine _yara = new();
        private readonly ForensicAnalyzer _analyzer;
        private CancellationTokenSource? _cts;

        public ObservableCollection<ReplaceRecord> Records { get; } = new();
        public ObservableCollection<ForensicEvidence> SelectedEvidence { get; } = new();
        public ObservableCollection<ExtensionToggle> Extensions { get; } = new();

        [ObservableProperty] private string statusText = "Ready. Click Run to scan files modified since last boot.";
        [ObservableProperty] private string driveLetter = "C";
        [ObservableProperty] private int progressValue;
        [ObservableProperty] private bool isAnalyzing;
        [ObservableProperty] private bool hasRun;          // controls background opacity
        [ObservableProperty] private ReplaceRecord? selectedRecord;
        [ObservableProperty] private string searchText = "";
        [ObservableProperty] private string activeFilter = "ALL";
        [ObservableProperty] private string lastBootInfo = "";

        [ObservableProperty] private bool detectSuspiciousExt;   // default false

        [ObservableProperty] private string updateStatusText = "";
        [ObservableProperty] private bool isCheckingUpdate;

        [ObservableProperty] private int totalRecords;
        [ObservableProperty] private int renameReplaces;
        [ObservableProperty] private int cheatHits;
        [ObservableProperty] private int spoofedHits;
        [ObservableProperty] private int unsignedHits;
        [ObservableProperty] private int legitHits;

        public MainViewModel()
        {
            _analyzer = new ForensicAnalyzer(_yara);
            _analyzer.StatusUpdate += s => StatusText = s;
            _analyzer.ProgressUpdate += p => ProgressValue = p;

            foreach (var ext in new[] { ".exe", ".jar", ".dll", ".py", ".bat",
                                        ".ps1", ".vbs", ".js", ".class", ".pyc",
                                        ".cmd", ".lua", ".sys" })
            {
                bool defaultOn = new[] { ".exe", ".jar", ".dll", ".py", ".bat" }.Contains(ext);
                Extensions.Add(new ExtensionToggle { Extension = ext, IsEnabled = defaultOn });
            }

            // Anything below can touch the filesystem / OS and must never crash the
            // constructor, otherwise the whole window fails to load (XamlParseException).
            try { _yara.LoadRulesAuto(); }
            catch (Exception ex) { StatusText = "Rule load warning: " + ex.Message; }

            try
            {
                var boot = ForensicAnalyzer.GetLastBootTimeUtc();
                LastBootInfo = $"Last boot (UTC): {boot:u}";
            }
            catch { LastBootInfo = "Last boot: unknown"; }

            // Auto-start the analysis once the app is idle and the window is up.
            // BeginInvoke at Background priority guarantees the UI has rendered first,
            // and the whole thing is guarded so a failure can never take down startup.
            try
            {
                System.Windows.Application.Current?.Dispatcher.BeginInvoke(
                    System.Windows.Threading.DispatcherPriority.Background,
                    new Action(() =>
                    {
                        try
                        {
                            if (RunAnalysisCommand.CanExecute(null))
                                RunAnalysisCommand.Execute(null);
                        }
                        catch (Exception ex) { StatusText = "Auto-start failed: " + ex.Message; }
                    }));
            }
            catch { /* if no dispatcher yet, the user can still press Parse again */ }
        }

        partial void OnSelectedRecordChanged(ReplaceRecord? value)
        {
            SelectedEvidence.Clear();
            if (value == null) return;
            foreach (var e in value.Evidence.OrderBy(e => e.Timestamp))
                SelectedEvidence.Add(e);
        }

        partial void OnSearchTextChanged(string value) => ReapplyFilters();
        partial void OnActiveFilterChanged(string value) => ReapplyFilters();

        [RelayCommand]
        private async Task RunAnalysisAsync()
        {
            if (IsAnalyzing) return;
            IsAnalyzing = true;
            HasRun = true;     // dim the background for readability after first run
            ProgressValue = 0;
            Records.Clear();
            SelectedEvidence.Clear();
            _cts = new CancellationTokenSource();

            try
            {
                _analyzer.EnabledExtensions = new HashSet<string>(
                    Extensions.Where(e => e.IsEnabled).Select(e => e.Extension),
                    StringComparer.OrdinalIgnoreCase);
                _analyzer.DetectSuspiciousExtensions = DetectSuspiciousExt;

                StatusText = "Parsing Prefetch...";
                var results = await _analyzer.AnalyzeAsync(DriveLetter, _cts.Token);
                ApplyFilters(results);
                UpdateStats(results);
            }
            catch (OperationCanceledException) { StatusText = "Analysis cancelled."; }
            catch (Exception ex) { StatusText = $"Error: {ex.Message}"; }
            finally { IsAnalyzing = false; }
        }

        [RelayCommand] private void Cancel() => _cts?.Cancel();
        [RelayCommand] private void SetFilter(string filter) => ActiveFilter = filter ?? "ALL";
        [RelayCommand] private void ClearSearch() => SearchText = "";

        [RelayCommand]
        private void OpenServices()
        {
            var win = new Views.ServicesWindow
            {
                Owner = System.Windows.Application.Current?.MainWindow
            };
            win.Show();
        }

        [RelayCommand]
        private async Task CheckUpdatesAsync()
        {
            if (IsCheckingUpdate) return;
            IsCheckingUpdate = true;
            UpdateStatusText = "Checking for updates...";
            try
            {
                var info = await UpdateChecker.CheckAsync();

                if (!string.IsNullOrEmpty(info.Error))
                {
                    UpdateStatusText = "Update check failed: " + info.Error;
                    System.Windows.MessageBox.Show(info.Error, "Update check failed",
                        System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                    return;
                }

                if (!info.IsUpdateAvailable)
                {
                    UpdateStatusText = $"You are up to date (v{info.CurrentVersion}).";
                    System.Windows.MessageBox.Show(
                        $"You are running the latest version (v{info.CurrentVersion}).",
                        "Replace Parser - up to date",
                        System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
                    return;
                }

                UpdateStatusText = $"Update available: v{info.LatestVersion} (current v{info.CurrentVersion}).";

                string notes = string.IsNullOrWhiteSpace(info.ReleaseNotes) ? "(no release notes)" : info.ReleaseNotes;
                if (notes.Length > 600) notes = notes.Substring(0, 600) + "...";

                var choice = System.Windows.MessageBox.Show(
                    $"A new version is available.\n\n" +
                    $"Current:  v{info.CurrentVersion}\n" +
                    $"Latest:   v{info.LatestVersion}\n\n" +
                    $"Release notes:\n{notes}\n\n" +
                    $"Download and install it now? The application will close, update, and restart.",
                    "Replace Parser - update available",
                    System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question);

                if (choice != System.Windows.MessageBoxResult.Yes) return;

                if (string.IsNullOrEmpty(info.AssetDownloadUrl))
                {
                    System.Windows.MessageBox.Show(
                        "The latest release does not include a downloadable .zip asset.\n" +
                        "Please download it manually from GitHub.",
                        "Replace Parser - no asset",
                        System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                    return;
                }

                UpdateStatusText = "Downloading update...";
                var progress = new Progress<int>(p => UpdateStatusText = $"Downloading update... {p}%");
                await UpdateChecker.DownloadAndInstallAsync(info, progress);

                UpdateStatusText = "Update staged - the app will now close to apply it.";
                System.Windows.Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                UpdateStatusText = "Update error: " + ex.Message;
                System.Windows.MessageBox.Show(ex.ToString(), "Update error",
                    System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
            finally
            {
                IsCheckingUpdate = false;
            }
        }

        private List<ReplaceRecord>? _lastResults;
        private void ApplyFilters(List<ReplaceRecord> results)
        {
            _lastResults = results;
            ReapplyFilters();
        }

        private void ReapplyFilters()
        {
            if (_lastResults == null) return;
            Records.Clear();
            string search = (SearchText ?? "").Trim();
            bool hasSearch = search.Length > 0;

            foreach (var r in _lastResults)
            {
                switch (ActiveFilter)
                {
                    case "RENAMES": if (!r.Evidence.Any(e => e.Description.Contains("RENAME"))) continue; break;
                    case "CHEATS": if (r.ReplacementTrust != FileTrust.Cheat) continue; break;
                    case "SPOOFED": if (!r.ExtensionSpoofed) continue; break;
                    case "UNSIGNED": if (r.ReplacementTrust != FileTrust.Unsigned) continue; break;
                    case "LEGIT": if (r.ReplacementTrust != FileTrust.Legit) continue; break;
                }

                if (hasSearch)
                {
                    bool m = (r.ReplacementFileName?.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0)
                          || (r.ReplacementPath?.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0)
                          || (r.OriginalPath?.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!m) continue;
                }
                Records.Add(r);
            }
        }

        private void UpdateStats(List<ReplaceRecord> results)
        {
            TotalRecords = results.Count;
            RenameReplaces = results.Count(r => r.Evidence.Any(e => e.Description.Contains("RENAME")));
            CheatHits = results.Count(r => r.ReplacementTrust == FileTrust.Cheat);
            SpoofedHits = results.Count(r => r.ExtensionSpoofed);
            UnsignedHits = results.Count(r => r.ReplacementTrust == FileTrust.Unsigned);
            LegitHits = results.Count(r => r.ReplacementTrust == FileTrust.Legit);
        }
    }
}