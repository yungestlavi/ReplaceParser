using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SSForensic.ViewModels
{
    /// <summary>
    /// Status of a single Windows service relevant to SS forensics.
    /// A stopped / disabled forensic service is suspicious because a cheater
    /// may stop it to erase the artefacts it would otherwise leave behind.
    /// </summary>
    public partial class ServiceStatusItem : ObservableObject
    {
        [ObservableProperty] private string shortName = "";
        [ObservableProperty] private string displayName = "";
        [ObservableProperty] private string description = "";
        [ObservableProperty] private string statusText = "Unknown";
        [ObservableProperty] private string startType = "";
        [ObservableProperty] private string startTimeText = "";   // when the host process started
        [ObservableProperty] private string extraInfo = "";       // deep diagnostics (e.g. SysMain)
        [ObservableProperty] private bool hasExtraInfo;
        [ObservableProperty] private string healthColor = "#9E9E9E"; // grey default

        // GREEN  = running normally
        // ORANGE = paused / start-pending / stop-pending (tampered / transitional)
        // RED    = stopped / not installed (forensic blind spot)
        public void Apply(ServiceControllerStatus? status, bool installed, string startMode)
        {
            StartType = startMode;

            if (!installed)
            {
                StatusText = "Not installed";
                HealthColor = "#E53935"; // red
                return;
            }

            switch (status)
            {
                case ServiceControllerStatus.Running:
                    StatusText = "Running";
                    HealthColor = "#43A047"; // green
                    break;
                case ServiceControllerStatus.Paused:
                    StatusText = "Paused";
                    HealthColor = "#FB8C00"; // orange
                    break;
                case ServiceControllerStatus.StartPending:
                    StatusText = "Start pending";
                    HealthColor = "#FB8C00";
                    break;
                case ServiceControllerStatus.StopPending:
                    StatusText = "Stop pending";
                    HealthColor = "#FB8C00";
                    break;
                case ServiceControllerStatus.PausePending:
                    StatusText = "Pause pending";
                    HealthColor = "#FB8C00";
                    break;
                case ServiceControllerStatus.ContinuePending:
                    StatusText = "Continue pending";
                    HealthColor = "#FB8C00";
                    break;
                case ServiceControllerStatus.Stopped:
                    StatusText = "Stopped";
                    HealthColor = "#E53935"; // red
                    break;
                default:
                    StatusText = status?.ToString() ?? "Unknown";
                    HealthColor = "#9E9E9E";
                    break;
            }
        }
    }

    public partial class ServicesViewModel : ObservableObject
    {
        // (short name, friendly label, why it matters for SS)
        private static readonly (string Name, string Label, string Why)[] Monitored =
        {
            ("SysMain",    "SysMain (SuperFetch)",        "Builds the prefetch / Amcache trail of every executed binary."),
            ("PcaSvc",     "Program Compatibility Asst.", "Logs which programs ran and from where (PCA store)."),
            ("DPS",        "Diagnostic Policy Service",   "Feeds PCA / SRUM execution telemetry."),
            ("DcomLaunch", "DCOM Server Process Launcher", "Core launcher; stopping it usually breaks the whole box."),
            ("PlugPlay",   "Plug and Play",               "Tracks USB / device insertion used to side-load cheats."),
            ("Schedule",   "Task Scheduler",              "Persistence point; cheats often hide as scheduled tasks."),
            ("BAM",        "Background Activity Moderator", "Records last-run time + full path of every executable per user."),
            ("DiagTrack",  "Conn. User Exp. & Telemetry", "SRUM / timeline of process execution."),
            ("Appinfo",    "Application Information",     "Handles elevation (UAC); required to run elevated cheats."),
            ("EventLog",   "Windows Event Log",           "If stopped, security / system events stop being recorded."),
        };

        public ObservableCollection<ServiceStatusItem> Services { get; } = new();

        [ObservableProperty] private string summary = "Querying services...";
        [ObservableProperty] private bool isRefreshing;

        public ServicesViewModel()
        {
            foreach (var m in Monitored)
                Services.Add(new ServiceStatusItem
                {
                    ShortName = m.Name,
                    DisplayName = m.Label,
                    Description = m.Why
                });

            _ = RefreshAsync();
        }

        [RelayCommand]
        private async Task RefreshAsync()
        {
            if (IsRefreshing) return;
            IsRefreshing = true;
            Summary = "Querying services...";
            try
            {
                await Task.Run(QueryAll);

                int red = Services.Count(s => s.HealthColor == "#E53935");
                int orange = Services.Count(s => s.HealthColor == "#FB8C00");
                int green = Services.Count(s => s.HealthColor == "#43A047");

                Summary = red > 0
                    ? $"{red} service(s) STOPPED / missing - possible anti-forensic tampering."
                    : orange > 0
                        ? $"{orange} service(s) in a transitional state - re-check."
                        : $"All {green} forensic services running normally.";
            }
            catch (Exception ex)
            {
                Summary = "Error querying services: " + ex.Message;
            }
            finally
            {
                IsRefreshing = false;
            }
        }

        private void QueryAll()
        {
            ServiceController[] all;
            try { all = ServiceController.GetServices(); }
            catch { all = Array.Empty<ServiceController>(); }

            // Map service short-name -> host process id (PID) via WMI in one shot.
            var pidByService = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, ProcessId, State FROM Win32_Service");
                foreach (ManagementObject mo in searcher.Get())
                {
                    string name = (mo["Name"] as string) ?? "";
                    int pid = 0;
                    try { pid = Convert.ToInt32(mo["ProcessId"]); } catch { }
                    if (!string.IsNullOrEmpty(name) && pid > 0)
                        pidByService[name] = pid;
                }
            }
            catch { /* WMI not available -> start times simply stay blank */ }

            foreach (var item in Services)
            {
                var sc = all.FirstOrDefault(s =>
                    string.Equals(s.ServiceName, item.ShortName, StringComparison.OrdinalIgnoreCase));

                if (sc == null)
                {
                    Ui(() =>
                    {
                        item.Apply(null, installed: false, startMode: "");
                        item.StartTimeText = "";
                        item.ExtraInfo = "";
                        item.HasExtraInfo = false;
                    });
                    continue;
                }

                ServiceControllerStatus? status = null;
                string startMode = "";
                try { status = sc.Status; } catch { }
                try { startMode = sc.StartType.ToString(); } catch { }

                // Resolve host-process start time (the closest honest proxy for
                // "when the service started"). Services share svchost hosts, so this
                // is the start time of the hosting process, which we label as such.
                string startTime = "";
                int hostPid = pidByService.TryGetValue(item.ShortName, out var p) ? p : 0;
                if (hostPid > 0)
                {
                    try
                    {
                        using var proc = Process.GetProcessById(hostPid);
                        startTime = proc.StartTime.ToString("yyyy-MM-dd HH:mm:ss");
                    }
                    catch { startTime = ""; }
                }

                // SysMain gets an extra, honest host-process health probe.
                string extra = "";
                if (string.Equals(item.ShortName, "SysMain", StringComparison.OrdinalIgnoreCase))
                    extra = ProbeSysMainHost(hostPid);

                var s = status;
                var sm = startMode;
                var st = startTime;
                var ex = extra;
                Ui(() =>
                {
                    item.Apply(s, installed: true, startMode: sm);
                    item.StartTimeText = st;
                    item.ExtraInfo = ex;
                    item.HasExtraInfo = !string.IsNullOrEmpty(ex);

                    // If the SysMain host looks frozen, downgrade the colour to orange
                    // even when the SCM still reports "Running".
                    if (!string.IsNullOrEmpty(ex) &&
                        ex.IndexOf("not responding", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        item.HealthColor == "#43A047")
                    {
                        item.HealthColor = "#FB8C00";
                        item.StatusText = "Running (host not responding)";
                    }
                });
            }
        }

        /// <summary>
        /// Honest, user-mode health probe of the svchost process that hosts SysMain.
        /// We cannot inspect individual kernel threads or sechost.dll internals from
        /// user mode, so instead we report what is actually observable: that the host
        /// process exists, how many threads it has, whether any of those threads are in
        /// a Wait/suspended state, and whether the process reports as responding. A
        /// SysMain whose host is frozen or whose threads are all suspended will not be
        /// updating the prefetch/SuperFetch trail, which is the forensic concern.
        /// </summary>
        private static string ProbeSysMainHost(int hostPid)
        {
            if (hostPid <= 0)
                return "Host process not found (SysMain may be stopped or hosted elsewhere).";

            try
            {
                using var proc = Process.GetProcessById(hostPid);

                int threadCount = proc.Threads.Count;
                int waiting = 0;
                int suspended = 0;
                foreach (ProcessThread t in proc.Threads)
                {
                    try
                    {
                        if (t.ThreadState == System.Diagnostics.ThreadState.Wait)
                        {
                            waiting++;
                            if (t.WaitReason == ThreadWaitReason.Suspended)
                                suspended++;
                        }
                    }
                    catch { /* per-thread query can fail; ignore */ }
                }

                bool responding = true;
                try { responding = proc.Responding; } catch { }

                // sechost.dll is loaded by svchost hosts; confirming it is mapped is a
                // sanity check that the standard service host stack is intact.
                bool sechostLoaded = false;
                try
                {
                    foreach (ProcessModule m in proc.Modules)
                    {
                        if (string.Equals(m.ModuleName, "sechost.dll", StringComparison.OrdinalIgnoreCase))
                        {
                            sechostLoaded = true;
                            break;
                        }
                    }
                }
                catch { /* module enumeration needs matching bitness/rights; ignore on failure */ }

                var parts = new List<string>
                {
                    $"host PID {hostPid}",
                    $"{threadCount} threads",
                };
                if (suspended > 0) parts.Add($"{suspended} suspended");
                parts.Add(responding ? "responding" : "not responding");
                parts.Add(sechostLoaded ? "sechost.dll mapped" : "sechost.dll not visible");

                if (suspended == threadCount && threadCount > 0)
                    parts.Add("ALL THREADS SUSPENDED - SysMain likely frozen");

                return string.Join(", ", parts);
            }
            catch (Exception ex)
            {
                return "Host probe failed: " + ex.Message;
            }
        }

        private static void Ui(Action a)
        {
            var disp = System.Windows.Application.Current?.Dispatcher;
            if (disp != null && !disp.CheckAccess()) disp.Invoke(a);
            else a();
        }
    }
}
