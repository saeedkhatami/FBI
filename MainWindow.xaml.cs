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
using System.Text.Json;


namespace FBI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly string localVersion = "0.4.2";
        private readonly string[] RequiredFiles = new string[] { "BindIP.dll", "BindIP64.dll", "ForceBindIP.exe", "ForceBindIP64.exe" };
        private string ForceBindIPPath => Environment.CurrentDirectory;
        private string ForceBindExe;
        enum PlatformFile : uint
        {
            Unknown = 0,
            x86 = 1,
            x64 = 2
        }
        public MainWindow()
        {
            InitializeComponent();
            CheckRequiredFiles();
            DownloadBar.Visibility = Visibility.Hidden;
            BrowseApp.Click += (sender, e) => OpenAppSelector();
            Start.Click += (sender, e) => LaunchApp();
            NetAdapter.DropDownOpened += (sender, e) => LoadAvailableNetworkAdapters();
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

        private void CheckRequiredFiles()
        {
            string curDir = Environment.CurrentDirectory;
            foreach (string s in RequiredFiles)
            {
                if (!File.Exists(Path.Combine(curDir, s)))
                {
                    MessageBox.Show("Missing file", "Error");
                    Environment.Exit(-1);
                }
            }
        }

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

                    if (Path.GetFileName(file) == "FBI.exe" || Path.GetFileName(file) == "FBI.dll")
                    {
                        foreach (var process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(destinationPath)))
                        {
                            process.Kill();
                            process.WaitForExit();
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

        private void A_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                this.DragMove();
            }
        }
        
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

        private void CheckforUpdateButton_Click(object sender, RoutedEventArgs e)
        {
            CheckForUpdates();
        }
        private void SaveAppState(string fileName)
        {
            var appState = new AppState
            {
                SelectedAppPath = AppPath.Text,
                SelectedNetworkAdapter = NetAdapter.SelectedItem?.ToString(),
            };

            string json = JsonSerializer.Serialize(appState);
            File.WriteAllText(fileName, json);
        }

        private void LoadAppState(string fileName)
        {
            if (File.Exists(fileName))
            {
                string json = File.ReadAllText(fileName);
                var appState = JsonSerializer.Deserialize<AppState>(json);

                AppPath.Text = appState.SelectedAppPath;
                NetAdapter.SelectedItem = appState.SelectedNetworkAdapter;
            }
        }


        private void LoadButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "JSON files (*.json)|*.json";
            openFileDialog.Title = "Load Application State";

            if (openFileDialog.ShowDialog() == true)
            {
                LoadAppState(openFileDialog.FileName);
            }
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "JSON files (*.json)|*.json";
            saveFileDialog.Title = "Save Application State";

            if (saveFileDialog.ShowDialog() == true)
            {
                SaveAppState(saveFileDialog.FileName);
            }
        }
    }
}
