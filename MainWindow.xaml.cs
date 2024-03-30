using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using Path = System.IO.Path;

namespace FBI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly string[] RequieredFiles = new string[] { "BindIP.dll", "BindIP64.dll", "ForceBindIP.exe", "ForceBindIP64.exe" };
        public MainWindow()
        {
            InitializeComponent();

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

        private void CheckBox64_Checked(object sender, RoutedEventArgs e)
        {

        }
    }
}