using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SSForensic.Services
{
    /// <summary>
    /// Result of an update probe against GitHub Releases.
    /// </summary>
    public class UpdateInfo
    {
        public bool IsUpdateAvailable { get; set; }
        public string CurrentVersion { get; set; } = "";
        public string LatestVersion { get; set; } = "";
        public string ReleaseUrl { get; set; } = "";
        public string AssetDownloadUrl { get; set; } = "";
        public string AssetName { get; set; } = "";
        public long AssetSize { get; set; }
        public string ReleaseNotes { get; set; } = "";
        public string Error { get; set; } = "";
    }

    /// <summary>
    /// Checks the project's GitHub Releases for a newer build, downloads the asset
    /// and stages a self-update via a small generated batch script.
    /// </summary>
    public static class UpdateChecker
    {
        // Repo hard-coded by request.
        private const string Owner = "yungestlavi";
        private const string Repo  = "ReplaceParser";

        // GitHub asks for a UA; anything stable is fine.
        private const string UserAgent = "ReplaceParser-Updater";

        /// <summary>
        /// Calls the GitHub API and reports whether a newer release is available.
        /// </summary>
        public static async Task<UpdateInfo> CheckAsync()
        {
            var info = new UpdateInfo
            {
                CurrentVersion = GetCurrentVersion()
            };

            try
            {
                using var http = new HttpClient();
                http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
                http.DefaultRequestHeaders.Accept.Add(
                    new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
                http.Timeout = TimeSpan.FromSeconds(20);

                string url = $"https://api.github.com/repos/{Owner}/{Repo}/releases/latest";
                using var resp = await http.GetAsync(url);

                if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    info.Error = "No release published yet on GitHub.";
                    return info;
                }
                resp.EnsureSuccessStatusCode();

                string json = await resp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                string tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
                info.LatestVersion = NormalizeTag(tag);
                info.ReleaseUrl    = root.TryGetProperty("html_url", out var hu) ? hu.GetString() ?? "" : "";
                info.ReleaseNotes  = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";

                // Pick the .zip asset (we publish a self-contained zip per release).
                if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
                {
                    JsonElement? chosen = null;
                    foreach (var a in assets.EnumerateArray())
                    {
                        var name = a.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                        if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                        {
                            chosen = a;
                            break;
                        }
                    }
                    if (chosen.HasValue)
                    {
                        info.AssetName        = chosen.Value.GetProperty("name").GetString() ?? "";
                        info.AssetDownloadUrl = chosen.Value.GetProperty("browser_download_url").GetString() ?? "";
                        if (chosen.Value.TryGetProperty("size", out var sz)) info.AssetSize = sz.GetInt64();
                    }
                }

                info.IsUpdateAvailable = CompareVersions(info.LatestVersion, info.CurrentVersion) > 0;
            }
            catch (Exception ex)
            {
                info.Error = ex.Message;
            }

            return info;
        }

        /// <summary>
        /// Downloads the release asset, generates a self-elevating updater script,
        /// launches it, and exits so the script can overwrite the running files.
        /// </summary>
        public static async Task<bool> DownloadAndInstallAsync(UpdateInfo info, IProgress<int>? progress = null)
        {
            if (string.IsNullOrEmpty(info.AssetDownloadUrl))
                throw new InvalidOperationException("No downloadable asset attached to the latest release.");

            string tempDir = Path.Combine(Path.GetTempPath(), "ReplaceParser_Update_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            string zipPath = Path.Combine(tempDir, info.AssetName.Length > 0 ? info.AssetName : "update.zip");

            // --- 1) Download the asset with progress reporting ---
            using (var http = new HttpClient())
            {
                http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
                http.Timeout = TimeSpan.FromMinutes(10);

                using var resp = await http.GetAsync(info.AssetDownloadUrl, HttpCompletionOption.ResponseHeadersRead);
                resp.EnsureSuccessStatusCode();

                long total = resp.Content.Headers.ContentLength ?? info.AssetSize;
                using var src = await resp.Content.ReadAsStreamAsync();
                using var dst = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None);

                byte[] buf = new byte[81920];
                long done = 0;
                int read;
                while ((read = await src.ReadAsync(buf, 0, buf.Length)) > 0)
                {
                    await dst.WriteAsync(buf, 0, read);
                    done += read;
                    if (total > 0)
                        progress?.Report((int)(done * 100 / total));
                }
            }

            // --- 2) Extract zip to a staging folder next to it ---
            string extractDir = Path.Combine(tempDir, "extracted");
            System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, extractDir);

            // --- 3) Build the updater .bat that swaps files and restarts the app ---
            string installDir = AppContext.BaseDirectory.TrimEnd('\\');
            string exePath    = Process.GetCurrentProcess().MainModule?.FileName ?? Path.Combine(installDir, "SSForensic.exe");
            int    pid        = Environment.ProcessId;

            string batPath = Path.Combine(tempDir, "apply_update.bat");
            string bat = BuildUpdaterScript(pid, extractDir, installDir, exePath, tempDir);
            File.WriteAllText(batPath, bat, new UTF8Encoding(false));

            // --- 4) Launch the updater detached and exit our process ---
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c \"\"{batPath}\"\"",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true
            };
            Process.Start(psi);
            return true;
        }

        /// <summary>
        /// The updater script must wait for our process to die, copy the new files
        /// over the install directory, restart the app, and clean up after itself.
        /// </summary>
        private static string BuildUpdaterScript(int pid, string newFilesDir, string installDir, string exePath, string tempDir)
        {
            // A few notes on the script:
            //  - We loop on tasklist until our PID is gone (rather than taskkill so we don't kill ourselves
            //    if something goes wrong with PID detection on a slow machine).
            //  - We robocopy /MIR to mirror the staged folder onto the install folder; /XO would skip
            //    overwriting same-timestamp files, which we don't want.
            //  - The script deletes its own temp directory only after relaunching the app.
            var sb = new StringBuilder();
            sb.AppendLine("@echo off");
            sb.AppendLine("setlocal");
            sb.AppendLine("title Replace Parser Updater");
            sb.AppendLine();
            sb.AppendLine(":wait_exit");
            sb.AppendLine($"tasklist /FI \"PID eq {pid}\" 2>NUL | find /I \"{pid}\" >NUL");
            sb.AppendLine("if not errorlevel 1 (");
            sb.AppendLine("    timeout /t 1 /nobreak >NUL");
            sb.AppendLine("    goto wait_exit");
            sb.AppendLine(")");
            sb.AppendLine();
            sb.AppendLine("rem Give the OS a moment to release file locks.");
            sb.AppendLine("timeout /t 1 /nobreak >NUL");
            sb.AppendLine();
            sb.AppendLine($"robocopy \"{newFilesDir}\" \"{installDir}\" /E /COPY:DAT /R:3 /W:2 /NFL /NDL /NJH /NJS /NP >NUL");
            sb.AppendLine();
            sb.AppendLine($"start \"\" \"{exePath}\"");
            sb.AppendLine();
            sb.AppendLine("rem Self-delete the temp dir (best-effort).");
            sb.AppendLine($"rmdir /S /Q \"{tempDir}\" 2>NUL");
            sb.AppendLine("exit /b 0");
            return sb.ToString();
        }

        // ------------------------ helpers ------------------------

        private static string GetCurrentVersion()
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                var v = asm.GetName().Version;
                return v != null ? $"{v.Major}.{v.Minor}.{v.Build}" : "0.0.0";
            }
            catch { return "0.0.0"; }
        }

        private static string NormalizeTag(string tag)
        {
            if (string.IsNullOrEmpty(tag)) return "0.0.0";
            tag = tag.Trim();
            if (tag.StartsWith("v", StringComparison.OrdinalIgnoreCase)) tag = tag.Substring(1);
            return tag;
        }

        /// <summary>
        /// Returns &gt; 0 if a is newer than b, 0 if equal, &lt; 0 if older.
        /// Tolerates short versions ("1.2" vs "1.2.0").
        /// </summary>
        private static int CompareVersions(string a, string b)
        {
            int[] pa = Parse(a), pb = Parse(b);
            int len = Math.Max(pa.Length, pb.Length);
            for (int i = 0; i < len; i++)
            {
                int x = i < pa.Length ? pa[i] : 0;
                int y = i < pb.Length ? pb[i] : 0;
                if (x != y) return x.CompareTo(y);
            }
            return 0;

            static int[] Parse(string v)
            {
                if (string.IsNullOrEmpty(v)) return new[] { 0 };
                // Strip any "-beta" / "+meta" suffix for a numeric compare.
                int cut = v.IndexOfAny(new[] { '-', '+' });
                if (cut >= 0) v = v.Substring(0, cut);
                return v.Split('.')
                        .Select(s => int.TryParse(s, out var n) ? n : 0)
                        .ToArray();
            }
        }
    }
}
