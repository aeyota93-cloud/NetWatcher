using System.Buffers.Binary;
using System.Net;
using NetWatcher.Core.Link;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Tests;

public class TcpEStatsTests
{
    [Fact]
    public void Path_rod_fields_are_read_from_their_positions()
    {
        // TCP_ESTATS_PATH_ROD_v0: 40 ULONGs; field i holds 1000 + i here.
        var rod = new byte[TcpEStats.PathRodSize];
        for (var i = 0; i < 40; i++) BinaryPrimitives.WriteUInt32LittleEndian(rod.AsSpan(i * 4), (uint)(1000 + i));
        var s = TcpEStats.ParsePath(rod);
        Assert.Equal(1026u, s.SampleRtt);
        Assert.Equal(1027u, s.SmoothedRtt);
        Assert.Equal(1028u, s.RttVar);
        Assert.Equal(1029u, s.MaxRtt);
        Assert.Equal(1030u, s.MinRtt);
        Assert.Equal(1032u, s.CountRtt);
        Assert.Equal(1005u, s.PktsRetrans);
        Assert.Equal(1001u, s.Timeouts);
        Assert.Equal(160, TcpEStats.PathRodSize);
        Assert.Throws<ArgumentException>(() => TcpEStats.ParsePath(new byte[10]));
    }

    [Fact]
    public void Tcp6_row_layout()
    {
        var row = new TcpRow(TcpState.Established, IPAddress.Parse("2001:db8::1"), 0x1234, IPAddress.Parse("2a00:1450::5"), 443, 7, FromIpv6Table: true);
        var b = TcpEStats.Tcp6Row(row);
        Assert.Equal(52, b.Length);
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32LittleEndian(b));               // State
        Assert.Equal(IPAddress.Parse("2001:db8::1").GetAddressBytes(), b[4..20]);   // LocalAddr
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, b[20..24]);                         // dwLocalScopeId
        Assert.Equal(new byte[] { 0x12, 0x34, 0, 0 }, b[24..28]);                   // dwLocalPort, network order
        Assert.Equal(IPAddress.Parse("2a00:1450::5").GetAddressBytes(), b[28..44]); // RemoteAddr
        Assert.Equal(new byte[] { 0x01, 0xBB, 0, 0 }, b[48..52]);                   // dwRemotePort 443

        // A dual-stack socket: the IPv4 address goes back as ::ffff:a.b.c.d.
        var mapped = TcpEStats.Tcp6Row(row with { RemoteIp = IPAddress.Parse("149.154.167.51") });
        Assert.Equal(IPAddress.Parse("::ffff:149.154.167.51").GetAddressBytes(), mapped[28..44]);
    }

    [Fact]
    public void Only_open_non_link_local_connections_are_asked()
    {
        var ok = new TcpRow(TcpState.Established, IPAddress.Parse("10.0.0.2"), 1, IPAddress.Parse("1.1.1.1"), 443, 1);
        Assert.True(TcpEStats.Usable(ok));
        Assert.False(TcpEStats.Usable(ok with { State = TcpState.TimeWait }));
        Assert.False(TcpEStats.Usable(ok with { RemoteIp = IPAddress.Parse("fe80::1") }));
    }

    [Fact]
    public void Connection_rtt_stands_in_for_ping()
    {
        var t0 = new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var tg = IPAddress.Parse("149.154.167.51");
        var key = LinkMonitor.KeyOf("Telegram.exe", "TCP", tg, 443);
        for (var s = 0; s < 30; s += 2)
            m.Add(t0.AddSeconds(s), [new FlowSample("Telegram.exe", "Telegram.exe", "", "", tg, 443, "TCP", 5, 5, 500, 500, 0, 0)]);
        Assert.Contains(key, m.ActiveTcpServers(t0.AddSeconds(30), TimeSpan.FromSeconds(30)));

        // No ping answers, but the connection's own round trip time is known.
        m.AddPing(tg, t0.AddSeconds(10), null);
        m.AddConnectionRtt(key, t0.AddSeconds(20), 48);
        m.AddConnectionRtt(key, t0.AddSeconds(25), 52);
        m.AddConnectionRtt(key, t0.AddSeconds(28), 50);

        var p = Assert.Single(m.Snapshot(t0.AddSeconds(30), TimeSpan.FromMinutes(2)));
        var server = Assert.Single(p.Servers);
        Assert.Equal(50, server.LatencyMs);
        Assert.Equal(LatencySource.Connection, server.LatencyFrom);
        Assert.Null(server.JitterMs);
        Assert.Equal(50, p.LatencyMs);
        Assert.Contains(p.Chart, c => c.LatencyMs != null);

        // Ping, when it answers, wins.
        m.AddPing(tg, t0.AddSeconds(29), 40);
        server = Assert.Single(Assert.Single(m.Snapshot(t0.AddSeconds(30), TimeSpan.FromMinutes(2))).Servers);
        Assert.Equal(LatencySource.Ping, server.LatencyFrom);
        Assert.Equal(40, server.LatencyMs);
    }
}
