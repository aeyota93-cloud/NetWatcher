using System.Buffers.Binary;
using System.Net;

namespace NetWatcher.Core.Net;

/// <summary>TCP connection states as Windows reports them (MIB_TCP_STATE).</summary>
public enum TcpState
{
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12,
}

/// <param name="FromIpv6Table">Read from the IPv6 table: IPv4 addresses there are dual-stack sockets.</param>
public readonly record struct TcpRow(TcpState State, IPAddress LocalIp, int LocalPort, IPAddress RemoteIp, int RemotePort, int Pid, bool FromIpv6Table = false)
{
    /// <summary>A live conversation with someone: not a listening socket and not a closed one.</summary>
    public bool IsActive => State is >= TcpState.SynSent and <= TcpState.LastAck;
}

/// <summary>
/// Reads the buffers filled by GetExtendedTcpTable with TCP_TABLE_OWNER_PID_ALL:
/// a DWORD count followed by MIB_TCPROW_OWNER_PID (24 bytes) or MIB_TCP6ROW_OWNER_PID (56 bytes).
/// Ports are in network byte order in the low two bytes of their DWORD.
/// </summary>
public static class TcpTableParser
{
    public const int V4RowSize = 24;
    public const int V6RowSize = 56;

    public static List<TcpRow> Parse(ReadOnlySpan<byte> buffer, bool ipv6)
    {
        var rows = new List<TcpRow>();
        if (buffer.Length < 4) return rows;
        var count = BinaryPrimitives.ReadInt32LittleEndian(buffer);
        var size = ipv6 ? V6RowSize : V4RowSize;
        for (var i = 0; i < count; i++)
        {
            var offset = 4 + i * size;
            if (offset + size > buffer.Length) break;
            var r = buffer.Slice(offset, size);
            rows.Add(ipv6 ? ParseV6(r) : ParseV4(r));
        }
        return rows;
    }

    private static TcpRow ParseV4(ReadOnlySpan<byte> r) => new(
        (TcpState)BinaryPrimitives.ReadInt32LittleEndian(r),
        new IPAddress(r.Slice(4, 4)),
        Port(r[8..]),
        new IPAddress(r.Slice(12, 4)),
        Port(r[16..]),
        BinaryPrimitives.ReadInt32LittleEndian(r[20..]));

    private static TcpRow ParseV6(ReadOnlySpan<byte> r) => new(
        (TcpState)BinaryPrimitives.ReadInt32LittleEndian(r[48..]),
        IpKey.Normalize(new IPAddress(r[..16])),
        Port(r[20..]),
        IpKey.Normalize(new IPAddress(r.Slice(24, 16))),
        Port(r[44..]),
        BinaryPrimitives.ReadInt32LittleEndian(r[52..]),
        FromIpv6Table: true);

    private static int Port(ReadOnlySpan<byte> p) => p[0] << 8 | p[1];
}
