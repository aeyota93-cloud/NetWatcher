using System.Runtime.InteropServices;
using NetWatcher.Core.Net;

namespace NetWatcher.App.Native;

/// <summary>
/// Extended TCP statistics of one connection (iphlpapi): the round trip time Windows itself measures for it.
/// Collection is switched on per connection (administrator only) and then read.
/// </summary>
internal static class TcpStats
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort;
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcpConnectionEStats(ref MIB_TCPROW row, int estatsType, byte[] rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcpConnectionEStats(ref MIB_TCPROW row, int estatsType,
        byte[] rw, uint rwVersion, uint rwSize, nint ros, uint rosVersion, uint rosSize, byte[] rod, uint rodVersion, uint rodSize);

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcp6ConnectionEStats(byte[] row, int estatsType, byte[] rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcp6ConnectionEStats(byte[] row, int estatsType,
        byte[] rw, uint rwVersion, uint rwSize, nint ros, uint rosVersion, uint rosSize, byte[] rod, uint rodVersion, uint rodSize);

    public const uint AccessDenied = 5;

    private static MIB_TCPROW V4(TcpRow r)
    {
        var (local, localPort, remote, remotePort) = TcpCloser.Native(r);
        return new MIB_TCPROW { dwState = (uint)r.State, dwLocalAddr = local, dwLocalPort = localPort, dwRemoteAddr = remote, dwRemotePort = remotePort };
    }

    /// <summary>Switches path statistics on for the connection. 0 on success, 5 without administrator rights.</summary>
    public static uint Enable(TcpRow r)
    {
        var rw = new byte[] { 1 }; // EnableCollection = TRUE
        if (r.FromIpv6Table) return SetPerTcp6ConnectionEStats(TcpEStats.Tcp6Row(r), TcpEStats.PathType, rw, 0, TcpEStats.PathRwSize, 0);
        var row = V4(r);
        return SetPerTcpConnectionEStats(ref row, TcpEStats.PathType, rw, 0, TcpEStats.PathRwSize, 0);
    }

    /// <summary>Path statistics, or null when the call failed or collection is not on (then the data is undefined).</summary>
    public static TcpPathStats? Read(TcpRow r)
    {
        var rw = new byte[TcpEStats.PathRwSize];
        var rod = new byte[TcpEStats.PathRodSize];
        uint result;
        if (r.FromIpv6Table)
        {
            result = GetPerTcp6ConnectionEStats(TcpEStats.Tcp6Row(r), TcpEStats.PathType, rw, 0, (uint)rw.Length, 0, 0, 0, rod, 0, (uint)rod.Length);
        }
        else
        {
            var row = V4(r);
            result = GetPerTcpConnectionEStats(ref row, TcpEStats.PathType, rw, 0, (uint)rw.Length, 0, 0, 0, rod, 0, (uint)rod.Length);
        }
        // Microsoft: check EnableCollection in the returned Rw; when it is FALSE, the Rod data is undefined.
        if (result != 0 || rw[0] == 0) return null;
        return TcpEStats.ParsePath(rod);
    }
}
