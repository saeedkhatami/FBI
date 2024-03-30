using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using Octokit;
using System.Net.Http;
using System.Threading.Tasks;
using FileMode = System.IO.FileMode;
using System.IO.Compression;
using Application = System.Windows.Application;

namespace FBI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly string localVersion = "0.1.0";
        private readonly string[] RequieredFiles = new string[] { "BindIP.dll", "BindIP64.dll", "ForceBindIP.exe", "ForceBindIP64.exe" };
        public MainWindow()
        {
            InitializeComponent();
            CheckRequieredFiles();
            DownloadProgress.Visibility = Visibility.Hidden;
            CheckForUpdates();
            BrowseApp.Click += (sender, e) => OpenAppSelector();
            Start.Click += (sender, e) => LaunchApp();
            NetAdapter.DropDownOpened += (sender, e) => LoadAvailableNetworkAdapters();
        }
        private string ForceBindIPPath => Environment.CurrentDirectory;
        private string ForceBindExe;
        private void Window_MouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                this.DragMove();
            }
        }
        private void LoadAvailableNetworkAdapters()
        {
            NetAdapter.Items.Clear();
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            NetAdapter.Items.Add(new NetworkAdapterInfo(ni.Name, ip.Address.ToString()));
                    }
                }
            }
        }
        private void CheckRequieredFiles()
        {
            string curDir = Environment.CurrentDirectory;
            foreach (string s in RequieredFiles)
            {
                if (!File.Exists(Path.Combine(curDir, s)))
                {
                    MessageBox.Show("Error code 1", "Error");
                    Environment.Exit(-1);
                }
            }
        }
        public static int GetExecutableArchitecture(string filePath)
        {
            try
            {
                using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    stream.Seek(0x3C, SeekOrigin.Begin);
                    byte[] peOffsetBytes = new byte[4];
                    stream.Read(peOffsetBytes, 0, 4);
                    int peOffset = BitConverter.ToInt32(peOffsetBytes, 0);

                    stream.Seek(peOffset, SeekOrigin.Begin);
                    byte[] peSignatureBytes = new byte[4];
                    stream.Read(peSignatureBytes, 0, 4);

                    uint peSignature = BitConverter.ToUInt32(peSignatureBytes, 0);
                    if (peSignature != 0x00004550) // "PE\0\0"
                    {
                        MessageBox.Show("Error code: 99");
                        return 99;
                    }

                    stream.Seek(0x4, SeekOrigin.Current); // Skip machine architecture field
                    byte[] machineBytes = new byte[2];
                    stream.Read(machineBytes, 0, 2);
                    ushort machine = BitConverter.ToUInt16(machineBytes, 0);

                    if (machine == 0x8664) // AMD64
                    {
                        return 64;
                    }
                    else if (machine == 0x014C) // x86
                    {
                        return 32;
                    }
                    else
                    {
                        MessageBox.Show("Error code: 98");
                        return 98;
                    }
                }
            }
            catch (Exception ex)
            {
                string msg = ex.Message;
                MessageBox.Show("Error code: 97");
                return 97;
            }
        }
        private void LaunchApp()
        {
            try
            {
                string targetAppPath = AppPath.Text;
                int targetAppArchitecture = GetExecutableArchitecture(targetAppPath);
                if (targetAppArchitecture == 32)
                {
                    ForceBindExe = "ForceBindIP.exe";
                }
                else if (targetAppArchitecture == 64)
                {
                    ForceBindExe = "ForceBindIP64.exe";
                }
                else
                {
                    MessageBox.Show("Error code: 97");
                    return;
                }

                string args = $"{((NetworkAdapterInfo)NetAdapter.SelectedItem).IP} \"{targetAppPath}\"";
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Path.Combine(ForceBindIPPath, ForceBindExe);
                psi.Arguments = args;
                psi.WorkingDirectory = Path.GetDirectoryName(targetAppPath);
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void OpenAppSelector()
        {
            OpenFileDialog diag = new OpenFileDialog();
            diag.Filter = "Application (*.exe)|*.exe";
            diag.Multiselect = false;
            diag.Title = "Select a application to open";
            if (diag.ShowDialog() == DialogResult.Equals(true))
                AppPath.Text = diag.FileName;
        }
        private void NetAdapter_ContextMenuOpening(object sender, ContextMenuEventArgs e)
        {
            LoadAvailableNetworkAdapters();
        }
        private void A_MouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                this.DragMove();
            }
        }
        private async void CheckForUpdates()
        {
            var client = new GitHubClient(new ProductHeaderValue("FBI"));
            var releases = await client.Repository.Release.GetAll("saeedkhatami", "FBI");

            if (releases.Count > 0)
            {
                var latestRelease = releases[0];
                var latestVersion = latestRelease.TagName;

                if (IsUpdateAvailable(localVersion, latestVersion))
                {
                    MessageBoxResult result = MessageBox.Show($"A new update ({latestVersion}) is available. Do you want to update?", "Update Available", MessageBoxButton.YesNo);

                    if (result == MessageBoxResult.Yes)
                    {
                        // Download the ZIP file and show progress
                        await DownloadAndShowProgress(latestRelease.Assets[0].BrowserDownloadUrl);
                    }
                }
                else
                {
                    MessageBox.Show("Your application is up to date.");
                }
            }
            else
            {
                MessageBox.Show("No releases found for the repository.");
            }
        }
        private bool IsUpdateAvailable(string localVersion, string latestVersion)
        {
            Version local = new Version(localVersion);
            Version latest = new Version(latestVersion);

            return latest > local;
        }
        private async Task DownloadAndShowProgress(string downloadUrl)
        {
            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead);
                response.EnsureSuccessStatusCode();

                var totalBytes = response.Content.Headers.ContentLength ?? -1;
                var bytesRead = 0L;

                // Corrected usage of FileStream constructor
                using (var fileStream = new FileStream("FBI.zip", FileMode.Create, FileAccess.Write))
                {
                    using (var stream = await response.Content.ReadAsStreamAsync())
                    {
                        var buffer = new byte[8192];
                        var bytesReadThisTime = 0;
                        do
                        {
                            bytesReadThisTime = await stream.ReadAsync(buffer, 0, buffer.Length);
                            await fileStream.WriteAsync(buffer, 0, bytesReadThisTime);
                            bytesRead += bytesReadThisTime;

                            // Update progress bar
                            DownloadProgress.Visibility = Visibility.Visible;
                            DownloadProgress.Value = (double)bytesRead / totalBytes * 100;
                        } while (bytesReadThisTime > 0);
                    }
                }

                MessageBox.Show("Download complete!");
                DownloadProgress.Visibility = Visibility.Hidden;

                var result = MessageBox.Show("Download complete! Do you want to extract and install the latest version now?", "Download Complete", MessageBoxButton.YesNo);
                if (result == MessageBoxResult.Yes)
                {
                    ExtractAndInstall("FBI.zip");
                }

                System.Windows.Application.Current.Shutdown();
            }
        }
        private void ExtractAndInstall(string zipFilePath)
        {
            try
            {
                ExtractZipFile(zipFilePath);

                // Launch the updated version
                var appPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FBI.exe");
                Process.Start(appPath);

                // Close the current instance
                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error extracting or installing the latest version: {ex.Message}");
            }
        }
        private void ExtractZipFile(string zipFilePath)
        {
            try
            {
                // Extract ZIP file contents
                ZipFile.ExtractToDirectory(zipFilePath, "temp");

                // Replace the old version with the updated one
                ReplaceOldVersion("temp");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error extracting or replacing files: {ex.Message}");
            }
        }
        private void ReplaceOldVersion(string tempFolderPath)
        {
            // Replace the old version with the updated one
            try
            {
                var oldAppFolderPath = AppDomain.CurrentDomain.BaseDirectory;
                var tempAppFolderPath = Path.Combine(tempFolderPath, "FBI");

                // Copy files from temporary folder to the application folder
                foreach (var file in Directory.GetFiles(tempAppFolderPath, "*", SearchOption.AllDirectories))
                {
                    var relativePath = file.Substring(tempAppFolderPath.Length + 1);
                    var destinationPath = Path.Combine(oldAppFolderPath, relativePath);

                    // Create directories if they don't exist
                    Directory.CreateDirectory(Path.GetDirectoryName(destinationPath));

                    // Copy the file
                    File.Copy(file, destinationPath, true);
                }

                // Delete the temporary folder
                Directory.Delete(tempFolderPath, true);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error replacing old version: {ex.Message}");
            }
        }
        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }
        private void AlwaysOnTop_Checked(object sender, RoutedEventArgs e)
        {
            this.Topmost = true;
        }
        private void AlwaysOnTop_Unchecked(object sender, RoutedEventArgs e)
        {
            this.Topmost = false;
        }
    }
}