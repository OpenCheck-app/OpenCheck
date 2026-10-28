using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Win32;
using PCCheck.Engine;

namespace PCCheck
{
    /// <summary>
    /// The window. The UI is a local HTML page (built into the .exe) shown with Microsoft Edge WebView2.
    /// The page can't load anything from the internet (see the Content-Security-Policy in index.html
    /// and the navigation blocking below).
    /// </summary>
    public sealed class MainForm : Form
    {
        readonly WebView2 web;
        readonly string webDataDir = Path.Combine(Path.GetTempPath(), "OpenCheck.WebView2");
        bool allowNavigation;
        Scanner scanner;
        Report report;
        bool scanning;
        ProgressUpdate latestRunning;
        readonly ConcurrentQueue<ProgressUpdate> finishedAreas = new ConcurrentQueue<ProgressUpdate>();
        readonly Timer progressTimer;

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        public MainForm()
        {
            bool dark = WindowsUsesDarkMode();
            Text = "OpenCheck";
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            ClientSize = new Size(1120, 740);
            MinimumSize = new Size(980, 680);
            BackColor = dark ? Color.FromArgb(0x0D, 0x10, 0x15) : Color.FromArgb(0xF4, 0xF5, 0xF7);

            web = new WebView2 { Dock = DockStyle.Fill, DefaultBackgroundColor = BackColor };
            Controls.Add(web);

            // Progress messages are batched so the UI stays smooth even when the scanner reports very often.
            progressTimer = new Timer { Interval = 60 };
            progressTimer.Tick += (s, e) => FlushProgress();

            Load += async (s, e) => await InitializeWebViewAsync();
            HandleCreated += (s, e) => SetTitleBarDark(dark);
            FormClosing += (s, e) => { if (scanner != null) scanner.Cancel(); };
        }

        async Task InitializeWebViewAsync()
        {
            try
            {
                var env = await CoreWebView2Environment.CreateAsync(null, webDataDir);
                await web.EnsureCoreWebView2Async(env);
            }
            catch (WebView2RuntimeNotFoundException)
            {
                MessageBox.Show(this,
                    "This app needs Microsoft Edge WebView2, which comes with Windows 10 and 11.\n\n" +
                    "Install the \"Evergreen Runtime\" from Microsoft's website (search for \"WebView2 Runtime\"), then open this app again.",
                    "OpenCheck", MessageBoxButtons.OK, MessageBoxIcon.Information);
                Close();
                return;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "The window couldn't start: " + ex.Message, "OpenCheck", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Close();
                return;
            }

            var core = web.CoreWebView2;
            var settings = core.Settings;
            settings.AreDevToolsEnabled = false;
            settings.AreBrowserAcceleratorKeysEnabled = false;
            settings.IsStatusBarEnabled = false;
            settings.IsZoomControlEnabled = false;
            settings.IsBuiltInErrorPageEnabled = false;
            settings.AreHostObjectsAllowed = false;
            settings.IsWebMessageEnabled = true;

            // The page may never navigate anywhere or open new windows.
            core.NewWindowRequested += (s, e) => e.Handled = true;
            core.NavigationStarting += (s, e) =>
            {
                if (allowNavigation) { allowNavigation = false; return; }
                e.Cancel = true;
            };
            core.WebMessageReceived += OnWebMessage;
            core.NavigationCompleted += (s, e) =>
            {
                Post(new Dictionary<string, object> { { "type", "version" }, { "version", Application.ProductVersion }, { "sha256", OwnFingerprint() } });
            };

            allowNavigation = true;
            core.NavigateToString(SignatureSet.ReadResource("index.html"));
        }

        void OnWebMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            Dictionary<string, object> msg;
            try { msg = Json.Object(Json.Parse(e.WebMessageAsJson)); }
            catch { return; }
            string type = Json.Str(msg, "type");

            switch (type)
            {
                case "start":
                    if (!scanning && report == null) StartScan(Json.Str(msg, "who"), ScanOptions.FromJson(Json.Object(Json.Get(msg, "settings"))));
                    break;
                case "theme":
                    ApplyTheme(Json.Bool(msg, "dark"));
                    break;
                case "save":
                    if (report == null) return;
                    try { Post(new Dictionary<string, object> { { "type", "saved" }, { "path", ReportWriter.SaveToDesktop(report) } }); }
                    catch (Exception ex) { PostError("Couldn't save the report: " + ex.Message); }
                    break;
                case "previewCopy":
                    if (report == null) return;
                    Post(new Dictionary<string, object> { { "type", "copyPreview" }, { "text", ReportWriter.BuildDiscordText(report) } });
                    break;
                case "copy":
                    if (report == null) return;
                    try
                    {
                        Clipboard.SetText(ReportWriter.BuildDiscordText(report));
                        Post(new Dictionary<string, object> { { "type", "copied" } });
                    }
                    catch (Exception ex) { PostError("Couldn't copy: " + ex.Message); }
                    break;
                case "close":
                    Close();
                    break;
            }
        }

        void StartScan(string who, ScanOptions options)
        {
            scanning = true;
            progressTimer.Start();
            SignatureSet signatures;
            try { signatures = SignatureSet.LoadEmbedded(); }
            catch (Exception ex) { PostError("The cheat list couldn't load: " + ex.Message); return; }

            scanner = new Scanner(signatures, options, p =>
            {
                if (p.State == "running") { lock (finishedAreas) latestRunning = p; }
                else
                {
                    // An area finishing is never dropped, and is shown right away.
                    finishedAreas.Enqueue(p);
                    BeginInvokeSafe(() => { FlushProgress(); });
                }
            });

            Task.Run(() => scanner.Run(who)).ContinueWith(t =>
            {
                BeginInvokeSafe(() =>
                {
                    progressTimer.Stop();
                    FlushProgress();
                    scanning = false;
                    if (t.IsFaulted)
                    {
                        PostError("The check stopped unexpectedly: " + t.Exception.GetBaseException().Message);
                        return;
                    }
                    report = t.Result;
                    Post(new Dictionary<string, object> { { "type", "done" }, { "report", ReportWriter.ToUi(report) } });
                });
            });
        }

        void FlushProgress()
        {
            ProgressUpdate done;
            while (finishedAreas.TryDequeue(out done)) PostProgress(done);
            ProgressUpdate running;
            lock (finishedAreas) { running = latestRunning; latestRunning = null; }
            if (running != null) PostProgress(running);
        }

        void PostProgress(ProgressUpdate p)
        {
            Post(new Dictionary<string, object>
            {
                { "type", "progress" }, { "area", p.Area }, { "state", p.State }, { "detail", p.Detail }, { "percent", p.Percent }
            });
        }

        void BeginInvokeSafe(Action a)
        {
            try { if (!IsDisposed && IsHandleCreated) BeginInvoke(a); }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }

        void Post(Dictionary<string, object> message)
        {
            if (web.CoreWebView2 == null) return;
            web.CoreWebView2.PostWebMessageAsJson(Json.Serialize(message));
        }

        void PostError(string text)
        {
            Post(new Dictionary<string, object> { { "type", "error" }, { "message", text } });
        }

        /// <summary>SHA-256 of this .exe, shown on the welcome screen and in every report.</summary>
        static string OwnFingerprint()
        {
            try
            {
                using (var sha = System.Security.Cryptography.SHA256.Create())
                using (var fs = new FileStream(Application.ExecutablePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
            }
            catch { return null; }
        }

        static bool WindowsUsesDarkMode()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                {
                    object v = k == null ? null : k.GetValue("AppsUseLightTheme");
                    return v is int && (int)v == 0;
                }
            }
            catch { return false; }
        }

        void SetTitleBarDark(bool dark)
        {
            try
            {
                int value = dark ? 1 : 0;
                if (DwmSetWindowAttribute(Handle, 20, ref value, sizeof(int)) != 0)
                    DwmSetWindowAttribute(Handle, 19, ref value, sizeof(int));
            }
            catch { }
        }

        /// <summary>Theme chosen in Settings: match the window frame and background to it.</summary>
        void ApplyTheme(bool dark)
        {
            BackColor = dark ? Color.FromArgb(0x0D, 0x10, 0x15) : Color.FromArgb(0xF4, 0xF5, 0xF7);
            try { web.DefaultBackgroundColor = BackColor; } catch { }
            if (IsHandleCreated) SetTitleBarDark(dark);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            progressTimer.Dispose();
            web.Dispose();
            base.OnFormClosed(e);
        }
    }
}
