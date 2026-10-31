using System.Buffers.Binary;
using System.Net;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Tests;

public class TcpTableTests
{
    private static void Port(Span<byte> at, int port)
    {
        at[0] = (byte)(port >> 8);
        at[1] = (byte)port;
    }

    [Fact]
    public void Parses_ipv4_rows()
    {
        var buf = new byte[4 + 2 * TcpTableParser.V4RowSize];
        BinaryPrimitives.WriteInt32LittleEndian(buf, 2);

        var r = buf.AsSpan(4, TcpTableParser.V4RowSize);
        BinaryPrimitives.WriteInt32LittleEndian(r, (int)TcpState.Established);
        IPAddress.Parse("192.168.1.10").GetAddressBytes().CopyTo(r[4..]);
        Port(r[8..], 50123);
        IPAddress.Parse("149.154.167.51").GetAddressBytes().CopyTo(r[12..]);
        Port(r[16..], 443);
        BinaryPrimitives.WriteInt32LittleEndian(r[20..], 4321);

        r = buf.AsSpan(4 + TcpTableParser.V4RowSize, TcpTableParser.V4RowSize);
        BinaryPrimitives.WriteInt32LittleEndian(r, (int)TcpState.Listen);

        var rows = TcpTableParser.Parse(buf, ipv6: false);
        Assert.Equal(2, rows.Count);
        var a = rows[0];
        Assert.Equal("149.154.167.51", a.RemoteIp.ToString());
        Assert.Equal(443, a.RemotePort);
        Assert.Equal(50123, a.LocalPort);
        Assert.Equal(4321, a.Pid);
        Assert.True(a.IsActive);
        Assert.False(rows[1].IsActive);
    }

    [Fact]
    public void Parses_ipv6_rows()
    {
        var buf = new byte[4 + TcpTableParser.V6RowSize];
        BinaryPrimitives.WriteInt32LittleEndian(buf, 1);
        var r = buf.AsSpan(4);
        IPAddress.Parse("::ffff:10.0.0.2").GetAddressBytes().CopyTo(r);
        Port(r[20..], 1234);
        IPAddress.Parse("2a00:1450:4010:c05::64").GetAddressBytes().CopyTo(r[24..]);
        Port(r[44..], 443);
        BinaryPrimitives.WriteInt32LittleEndian(r[48..], (int)TcpState.SynSent);
        BinaryPrimitives.WriteInt32LittleEndian(r[52..], 99);

        var row = Assert.Single(TcpTableParser.Parse(buf, ipv6: true));
        Assert.Equal("10.0.0.2", row.LocalIp.ToString());
        Assert.Equal("2a00:1450:4010:c05::64", row.RemoteIp.ToString());
        Assert.Equal(443, row.RemotePort);
        Assert.Equal(99, row.Pid);
        Assert.True(row.IsActive);
    }

    [Fact]
    public void Truncated_buffer_is_safe()
    {
        var buf = new byte[4 + 10];
        BinaryPrimitives.WriteInt32LittleEndian(buf, 5);
        Assert.Empty(TcpTableParser.Parse(buf, ipv6: false));
        Assert.Empty(TcpTableParser.Parse([], ipv6: true));
    }
}
