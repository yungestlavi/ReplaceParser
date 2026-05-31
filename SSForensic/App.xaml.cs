using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace SSForensic
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
                LogCrash("AppDomain.UnhandledException", args.ExceptionObject as Exception);

            DispatcherUnhandledException += (s, args) =>
            {
                // If a required assembly / runtime piece is missing, point the user to the .NET download.
                if (args.Exception is FileNotFoundException or BadImageFormatException
                    or TypeLoadException or DllNotFoundException)
                {
                    var result = MessageBox.Show(
                        "This tool needs the .NET 8 Desktop Runtime (x64) and a required component is missing.\n\n" +
                        "Click OK to open the official Microsoft download page.",
                        "Replace Parser - .NET runtime required",
                        MessageBoxButton.OKCancel, MessageBoxImage.Warning);
                    if (result == MessageBoxResult.OK)
                        OpenDotNetDownload();
                    args.Handled = true;
                    Shutdown();
                    return;
                }

                LogCrash("Dispatcher.UnhandledException", args.Exception);
                args.Handled = true;
            };

            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, args) =>
            {
                LogCrash("TaskScheduler.UnobservedTaskException", args.Exception);
                args.SetObserved();
            };

            try
            {
                base.OnStartup(e);
            }
            catch (Exception ex)
            {
                LogCrash("OnStartup (window construction)", ex);
                Shutdown();
            }
        }

        private static void OpenDotNetDownload()
        {
            try
            {
                // Direct link to the .NET 8 Desktop Runtime download page.
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "https://dotnet.microsoft.com/en-us/download/dotnet/8.0/runtime?cid=getdotnetcore",
                    UseShellExecute = true
                });
            }
            catch { }
        }

        private static void LogCrash(string where, Exception? ex)
        {
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash.log");
                string msg = $"=== {DateTime.Now:u} === {where}\n{ex}\n\n";
                File.AppendAllText(path, msg);
                MessageBox.Show(ex?.ToString() ?? "(null exception)", "SSForensic Crash",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch { }
        }
    }
}
