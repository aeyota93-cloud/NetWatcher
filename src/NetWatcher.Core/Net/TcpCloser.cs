using System.Net;
using System.Net.Sockets;

namespace NetWatcher.Core.Net;

/// <summary>
/// Which open TCP connections to break for the chosen rows. Windows can break only IPv4 connections
/// (SetTcpEntry takes an IPv4 row; there is no IPv6 counterpart), and only for an administrator.
/// </summary>
public static class TcpCloser
{
    public sealed record Plan(IReadOnlyList<TcpRow> Close, int Ipv6Skipped, int UdpSkipped);

    /// <param name="v4Table">Rows of the IPv4 TCP table only: a dual-stack socket in the IPv6 table cannot be broken.</param>
    /// <param name="processName">Program file name by process id, as in <see cref="DestinationRow.Process"/>.</param>
    public static Plan Choose(IEnumerable<TcpRow> v4Table, Func<int, string> processName, IEnumerable<DestinationRow> targets)
    {
        var wanted = new HashSet<(string Process, UInt128 Ip, int Port)>();
        var ipv6 = 0;
        var udp = 0;
        foreach (var t in targets)
        {
            if (t.Proto != "TCP")
            {
                udp++;
                continue;
            }
            if (t.RemoteIp.AddressFamily == AddressFamily.InterNetworkV6)
            {
                ipv6++;
                continue;
            }
            wanted.Add((t.Process.ToLowerInvariant(), IpKey.From(t.RemoteIp), t.RemotePort));
        }

        var close = v4Table
            .Where(r => r.State is TcpState.Established or TcpState.SynSent or TcpState.SynReceived or TcpState.CloseWait)
            .Where(r => wanted.Contains((processName(r.Pid).ToLowerInvariant(), IpKey.From(r.RemoteIp), r.RemotePort)))
            .ToList();
        return new Plan(close, ipv6, udp);
    }

    /// <summary>MIB_TCPROW fields: addresses as they lie in memory, ports in network byte order in the low two bytes.</summary>
    public static (uint Local, uint LocalPort, uint Remote, uint RemotePort) Native(TcpRow r) =>
        (Addr(r.LocalIp), PortValue(r.LocalPort), Addr(r.RemoteIp), PortValue(r.RemotePort));

    private static uint Addr(IPAddress ip) => BitConverter.ToUInt32(IpKey.Normalize(ip).GetAddressBytes(), 0);

    private static uint PortValue(int port) => (uint)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
}
