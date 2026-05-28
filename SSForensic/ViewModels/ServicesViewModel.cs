using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
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

            foreach (var item in Services)
            {
                var sc = all.FirstOrDefault(s =>
                    string.Equals(s.ServiceName, item.ShortName, StringComparison.OrdinalIgnoreCase));

                if (sc == null)
                {
                    Ui(() => item.Apply(null, installed: false, startMode: ""));
                    continue;
                }

                ServiceControllerStatus? status = null;
                string startMode = "";
                try { status = sc.Status; } catch { }
                try { startMode = sc.StartType.ToString(); } catch { }

                var s = status;
                var sm = startMode;
                Ui(() => item.Apply(s, installed: true, startMode: sm));
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
