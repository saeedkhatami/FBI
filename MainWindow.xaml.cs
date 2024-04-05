using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Input;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using Octokit;
using System.Net.Http;
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
        // Define localVersion and RequiredFiles
        private readonly string localVersion = "0.3.0";
        private readonly string[] RequiredFiles = new string[] { "BindIP.dll", "BindIP64.dll", "ForceBindIP.exe", "ForceBindIP64.exe" };
        private string ForceBindIPPath => Environment.CurrentDirectory;
        private string ForceBindExe;
        enum PlatformFile : uint
        {
            Unknown = 0,
            x86 = 1,
            x64 = 2
        }
        // Constructor
        public MainWindow()
        {
            InitializeComponent();
            // Perform initialization tasks
            CheckRequiredFiles();
            DownloadBar.Visibility = Visibility.Hidden;
            CheckForUpdates();
            // Attach event handlers
            BrowseApp.Click += (sender, e) => OpenAppSelector();
            Start.Click += (sender, e) => LaunchApp();
            NetAdapter.DropDownOpened += (sender, e) => LoadAvailableNetworkAdapters();
        }
        // Load available network adapters into the dropdown list
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

        // Check if required files exist
        private void CheckRequiredFiles()
        {
            string curDir = Environment.CurrentDirectory;
            foreach (string s in RequiredFiles)
            {
                if (!File.Exists(Path.Combine(curDir, s)))
                {
                    MessageBox.Show("Error code 1", "Error");
                    Environment.Exit(-1);
                }
            }
        }

        // Launch the selected application with ForceBindIP
        private void LaunchApp()
        {
            try
            {
                string targetAppPath = AppPath.Text;
                if (NetAdapter.SelectedItem != null)
                {
                    if (GetPlatformFile(AppPath.Text) == PlatformFile.x64)
                    {
                        ForceBindExe = "ForceBindIP64.exe";
                    }
                    else if (GetPlatformFile(AppPath.Text) == PlatformFile.x86)
                    {
                        ForceBindExe = "ForceBindIP.exe";
                    }

                    string args = $"{((NetworkAdapterInfo)NetAdapter.SelectedItem).IP} \"{targetAppPath}\"";
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = Path.Combine(ForceBindIPPath, ForceBindExe);
                    psi.Arguments = args;
                    psi.WorkingDirectory = Path.GetDirectoryName(targetAppPath);
                    Process.Start(psi);
                }
                else
                {
                    MessageBox.Show("Please select an app or network adapter.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }


        // Open file selector dialog to choose application
        private void OpenAppSelector()
        {
            OpenFileDialog diag = new OpenFileDialog();
            diag.Filter = "Application (*.exe)|*.exe";
            diag.Multiselect = false;
            diag.Title = "Select an application to open";

            if (diag.ShowDialog() == true)
                AppPath.Text = diag.FileName;

            architecture.Content = GetPlatformFile(AppPath.Text);
        }

        // Check for updates on GitHub repository
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

        // Check if an update is available
        private bool IsUpdateAvailable(string localVersion, string latestVersion)
        {
            Version local = new Version(localVersion);
            Version latest = new Version(latestVersion);

            return latest > local;
        }

        // Download the update and show progress
        private async Task DownloadAndShowProgress(string downloadUrl)
        {
            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead);
                response.EnsureSuccessStatusCode();

                var totalBytes = response.Content.Headers.ContentLength ?? -1;
                var bytesRead = 0L;

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

                            DownloadBar.Visibility = Visibility.Visible;
                            DownloadBar.Value = (double)bytesRead / totalBytes * 100;
                        } while (bytesReadThisTime > 0);
                    }
                }

                MessageBox.Show("Download complete!");
                DownloadBar.Visibility = Visibility.Hidden;

                var result = MessageBox.Show("Download complete! Do you want to extract and install the latest version now?", "Download Complete", MessageBoxButton.YesNo);
                if (result == MessageBoxResult.Yes)
                {
                    ExtractAndInstall("FBI.zip");
                }

                System.Windows.Application.Current.Shutdown();
            }
        }

        // Extract and install the downloaded update
        private void ExtractAndInstall(string zipFilePath)
        {
            try
            {
                ExtractZipFile(zipFilePath);
                var appPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FBI.exe");
                Process.Start(appPath);
                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error extracting or installing the latest version: {ex.Message}");
            }
        }

        // Extract ZIP file
        private void ExtractZipFile(string zipFilePath)
        {
            try
            {
                ZipFile.ExtractToDirectory(zipFilePath, "temp");
                ReplaceOldVersion("temp");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error extracting or replacing files: {ex.Message}");
            }
        }

        // Replace old version with the updated one
        private void ReplaceOldVersion(string tempFolderPath)
        {
            try
            {
                var oldAppFolderPath = AppDomain.CurrentDomain.BaseDirectory;
                var tempAppFolderPath = Path.Combine(tempFolderPath, "FBI");

                foreach (var file in Directory.GetFiles(tempAppFolderPath, "*", SearchOption.AllDirectories))
                {
                    var relativePath = file.Substring(tempAppFolderPath.Length + 1);
                    var destinationPath = Path.Combine(oldAppFolderPath, relativePath);

                    Directory.CreateDirectory(Path.GetDirectoryName(destinationPath));

                    // If the file is FBI.exe or FBI.dll, close the process before replacing it, bug found in version 0.2.0 which this code is in 0.1.0
                    if (Path.GetFileName(file) == "FBI.exe" || Path.GetFileName(file) == "FBI.dll")
                    {
                        foreach (var process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(destinationPath)))
                        {
                            process.Kill(); // Kill the process using the file
                            process.WaitForExit(); // Wait until the process is terminated
                        }
                    }

                    File.Copy(file, destinationPath, true);
                }

                Directory.Delete(tempFolderPath, true);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error replacing old version: {ex.Message}");
            }
        }


        // Shutdown the application
        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        // Minimize the window
        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        // Set the window to always on top
        private void AlwaysOnTop_Checked(object sender, RoutedEventArgs e)
        {
            this.Topmost = true;
        }

        // Unset the window from always on top
        private void AlwaysOnTop_Unchecked(object sender, RoutedEventArgs e)
        {
            this.Topmost = false;
        }

        // Method to handle dragging the window
        private void A_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                this.DragMove();
            }
        }
        
        // Auto architecture detector
        static PlatformFile GetPlatformFile(string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader br = new BinaryReader(fs))
            {
                fs.Seek(0x3C, SeekOrigin.Begin);
                int peOffset = br.ReadInt32();
                fs.Seek(peOffset, SeekOrigin.Begin);
                uint peHead = br.ReadUInt32();

                if (peHead != 0x00004550)
                    return PlatformFile.Unknown;

                fs.Seek(peOffset + 4, SeekOrigin.Begin);
                ushort machine = br.ReadUInt16();

                if (machine == 0x014c)
                    return PlatformFile.x86;
                else if (machine == 0x8664)
                    return PlatformFile.x64;
                else
                    return PlatformFile.Unknown;
            }
        }
    }
}
