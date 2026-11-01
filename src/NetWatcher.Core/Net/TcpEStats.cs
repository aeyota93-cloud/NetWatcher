using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace NetWatcher.Core.Net;

/// <summary>Round trip and resend figures Windows keeps for one TCP connection (TCP_ESTATS_PATH_ROD_v0).</summary>
public readonly record struct TcpPathStats(
    uint SampleRtt,
    uint SmoothedRtt,
    uint RttVar,
    uint MaxRtt,
    uint MinRtt,
    uint CountRtt,
    uint PktsRetrans,
    uint Timeouts);

/// <summary>
/// Extended TCP statistics (tcpestats.h): layouts and parsing, kept apart from the system calls so they can be tested.
/// Collection is off by default and must be switched on per connection with SetPerTcp(6)ConnectionEStats,
/// which only an administrator may call.
/// </summary>
public static class TcpEStats
{
    /// <summary>TCP_ESTATS_TYPE.TcpConnectionEstatsPath: SynOpts 0, Data 1, SndCong 2, Path 3.</summary>
    public const int PathType = 3;

    /// <summary>TCP_ESTATS_PATH_RW_v0: one BOOLEAN (a byte), EnableCollection.</summary>
    public const int PathRwSize = 1;

    /// <summary>TCP_ESTATS_PATH_ROD_v0: forty ULONG fields.</summary>
    public const int PathRodSize = 40 * 4;

    // Field positions in TCP_ESTATS_PATH_ROD_v0, in declaration order (FastRetran is 0).
    private const int Timeouts = 1, PktsRetrans = 5, SampleRtt = 26, SmoothedRtt = 27, RttVar = 28, MaxRtt = 29, MinRtt = 30, CountRtt = 32;

    /// <summary>MIB_TCP6ROW: State, LocalAddr[16], dwLocalScopeId, dwLocalPort, RemoteAddr[16], dwRemoteScopeId, dwRemotePort.</summary>
    public const int Tcp6RowSize = 4 + 16 + 4 + 4 + 16 + 4 + 4;

    public static TcpPathStats ParsePath(ReadOnlySpan<byte> rod)
    {
        if (rod.Length < PathRodSize) throw new ArgumentException("buffer too small", nameof(rod));
        return new TcpPathStats(F(rod, SampleRtt), F(rod, SmoothedRtt), F(rod, RttVar), F(rod, MaxRtt), F(rod, MinRtt),
            F(rod, CountRtt), F(rod, PktsRetrans), F(rod, Timeouts));
    }

    private static uint F(ReadOnlySpan<byte> rod, int field) => BinaryPrimitives.ReadUInt32LittleEndian(rod[(field * 4)..]);

    /// <summary>
    /// The MIB_TCP6ROW of a connection from the IPv6 table. IPv4 addresses there are IPv4-mapped (::ffff:a.b.c.d);
    /// the table reader turns them into plain IPv4, so they are mapped back. Scope ids are zero: link-local
    /// connections are not supported.
    /// </summary>
    public static byte[] Tcp6Row(TcpRow r)
    {
        var row = new byte[Tcp6RowSize];
        var span = row.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(span, (uint)r.State);
        V6(r.LocalIp).CopyTo(span[4..]);
        Port(r.LocalPort, span[24..]);
        V6(r.RemoteIp).CopyTo(span[28..]);
        Port(r.RemotePort, span[48..]);
        return row;
    }

    private static byte[] V6(IPAddress ip) =>
        (ip.AddressFamily == AddressFamily.InterNetwork ? ip.MapToIPv6() : ip).GetAddressBytes();

    // Network byte order in the low two bytes of the DWORD.
    private static void Port(int port, Span<byte> dst)
    {
        dst[0] = (byte)(port >> 8);
        dst[1] = (byte)port;
    }

    /// <summary>Connections worth asking: open, and not link-local (those need a scope id).</summary>
    public static bool Usable(TcpRow r) =>
        r.State == TcpState.Established && !(r.RemoteIp.AddressFamily == AddressFamily.InterNetworkV6 && r.RemoteIp.IsIPv6LinkLocal);
}
