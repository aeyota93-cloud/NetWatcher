using System.Net;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Tests;

public class TcpCloserTests
{
    private static TcpRow Tcp(TcpState state, string remote, int port, int pid, int localPort = 50000) =>
        new(state, IPAddress.Parse("192.168.1.10"), localPort, IPAddress.Parse(remote), port, pid);

    private static DestinationRow Target(string process, string ip, int port, string proto = "TCP") =>
        new() { Process = process, Services = "", Proto = proto, RemoteIp = IPAddress.Parse(ip), RemotePort = port };

    [Fact]
    public void Chooses_open_connections_of_the_program_to_the_address()
    {
        var table = new[]
        {
            Tcp(TcpState.Established, "149.154.167.51", 443, 10, 50001),
            Tcp(TcpState.Established, "149.154.167.51", 443, 10, 50002),
            Tcp(TcpState.TimeWait, "149.154.167.51", 443, 10, 50003),   // already closing
            Tcp(TcpState.Established, "149.154.167.51", 443, 20, 50004), // another program
            Tcp(TcpState.Established, "149.154.167.51", 80, 10, 50005),  // another port
        };
        string Name(int pid) => pid == 10 ? "Telegram.exe" : "chrome.exe";

        var plan = TcpCloser.Choose(table, Name, [Target("telegram.exe", "149.154.167.51", 443), Target("Telegram.exe", "2001:db8::1", 443), Target("Telegram.exe", "1.2.3.4", 443, "UDP")]);
        Assert.Equal([50001, 50002], plan.Close.Select(r => r.LocalPort));
        Assert.Equal(1, plan.Ipv6Skipped);
        Assert.Equal(1, plan.UdpSkipped);
    }

    [Fact]
    public void Native_row_uses_network_byte_order()
    {
        var (local, localPort, remote, remotePort) = TcpCloser.Native(Tcp(TcpState.Established, "1.2.3.4", 443, 1, 0x1234));
        // In memory the address bytes go in order: 1, 2, 3, 4.
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, BitConverter.GetBytes(remote));
        Assert.Equal(new byte[] { 192, 168, 1, 10 }, BitConverter.GetBytes(local));
        // Port 443 = 0x01BB is stored as bytes 01 BB.
        Assert.Equal(new byte[] { 0x01, 0xBB, 0, 0 }, BitConverter.GetBytes(remotePort));
        Assert.Equal(new byte[] { 0x12, 0x34, 0, 0 }, BitConverter.GetBytes(localPort));
    }
}
