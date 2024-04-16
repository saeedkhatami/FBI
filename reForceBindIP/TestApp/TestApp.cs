using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace TestApp
{
    internal class TestApp
    {
        private static void ListInterfaces() {
            foreach (NetworkInterface netIf in NetworkInterface.GetAllNetworkInterfaces()) {
                List<String> addressesV4 = new List<String>(1);
                foreach (UnicastIPAddressInformation ucastAddr in netIf.GetIPProperties().UnicastAddresses) {
                    switch (ucastAddr.Address.AddressFamily) {
                        case AddressFamily.InterNetwork: {
                            addressesV4.Add($"{ucastAddr.Address}/{ucastAddr.PrefixLength}");
                            break;
                        }
                        default: {
                            Console.WriteLine(
                                $"[!] Unsupported address family '{ucastAddr.Address.AddressFamily}' " +
                                $"for {ucastAddr.Address}/{ucastAddr.PrefixLength} " +
                                $"on {netIf.Id} {netIf.Name} ({netIf.Description})");
                            continue;
                        }
                    }
                }

                if (addressesV4.Count > 0) {
                    Console.WriteLine(
                        $"{netIf.Id} {netIf.Name} ({netIf.Description}) - [{String.Join(", ", addressesV4)}]");
                }
            }
        }

        [DllImport("ws2_32.dll", CallingConvention = CallingConvention.Winapi)]
        static extern int getsockname(IntPtr s, Byte[] addr, ref int addrlen);

        private static void LocalBindToUndef() {
            using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) {
                s.EnableBroadcast = true;
                s.SendTo(new Byte[] { 0x42 }, 1, SocketFlags.Broadcast, new IPEndPoint(IPAddress.Broadcast, 62900));

                Byte[] addr = new Byte[16];
                int addrlen = 16;
                int rv;
                if ((rv = getsockname(s.Handle, addr, ref addrlen)) != 0) {
                    throw new ApplicationException($"getsockname failed with code {rv}");
                }

                UInt16 port = BitConverter.ToUInt16(addr, 2);
                IPAddress ipv4 = new IPAddress(BitConverter.ToUInt32(addr, 4));
                Console.WriteLine($"Local IPv4 socket address is {ipv4}:{port}");
            }
        }

        private static void LocalBindToUndefV2() {
            using (UdpClient udpClient = new UdpClient()) {
                udpClient.EnableBroadcast = true;
                udpClient.Send(new Byte[] { 0x42 }, 1, "255.255.255.255", 62900);

                Byte[] addr = new Byte[16];
                int addrlen = 16;
                int rv;
                if ((rv = getsockname(udpClient.Client.Handle, addr, ref addrlen)) != 0) {
                    throw new ApplicationException($"getsockname failed with code {rv}");
                }

                UInt16 port = BitConverter.ToUInt16(addr, 2);
                IPAddress ipv4 = new IPAddress(BitConverter.ToUInt32(addr, 4));
                Console.WriteLine($"Local IPv4 socket address is {ipv4}:{port}");
            }
        }

        public static void Main(String[] args) {
            try {
                LocalBindToUndefV2();
            }
            catch (Exception e) {
                Console.WriteLine(e.Message);
                Console.WriteLine();
                Console.WriteLine(e.StackTrace);
            }

            if (!Debugger.IsAttached) {
                Console.WriteLine("Press any key to exit");
                Console.ReadKey();
            }
        }
    }
}