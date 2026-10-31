using System.Net;
using NetWatcher.Core.Link;

namespace NetWatcher.Core.Tests;

public class LinkMonitorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);
    private static readonly IPAddress Game = IPAddress.Parse("155.133.252.38");
    private static readonly IPAddress Tg = IPAddress.Parse("149.154.167.51");

    private static FlowSample Udp(long outPk, long inPk) =>
        new("cs2.exe", "cs2.exe", "", "", Game, 27015, "UDP", outPk, inPk, outPk * 100, inPk * 100, 0, 0);

    private static FlowSample Tcp(long outPk, long inPk, int retrans = 0) =>
        new("Telegram.exe", "Telegram.exe", "", "", Tg, 443, "TCP", outPk, inPk, outPk * 500, inPk * 500, retrans, 0);

    /// <summary>One sample every 2 seconds from <paramref name="start"/> for <paramref name="seconds"/>.</summary>
    private static DateTimeOffset Feed(LinkMonitor m, DateTimeOffset start, int seconds, Func<FlowSample> sample)
    {
        var t = start;
        for (var s = 0; s < seconds; s += 2)
        {
            t = start.AddSeconds(s);
            m.Add(t, [sample()]);
        }
        return t;
    }

    [Fact]
    public void Game_stops_answering_then_recovers()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 60, () => Udp(128, 128));
        t = Feed(m, t.AddSeconds(2), 14, () => Udp(128, 0)); // 14 s of silence while sending

        var p = Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15)));
        Assert.Equal(LinkLevel.Fail, p.Level);
        Assert.StartsWith("нет ответа", p.StateText);
        var server = Assert.Single(p.Servers);
        Assert.Contains("получено 0", server.Reason);
        Assert.Null(Assert.Single(p.OutageList).End);

        t = Feed(m, t.AddSeconds(2), 10, () => Udp(128, 128));
        p = Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15)));
        Assert.Equal(LinkLevel.Ok, p.Level);
        var outage = Assert.Single(p.OutageList);
        Assert.NotNull(outage.End);
        Assert.InRange(outage.Duration(t).TotalSeconds, 14, 18);
        Assert.Contains(p.Chart, c => c.Down);
    }

    [Fact]
    public void Short_gap_is_not_an_outage()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 20, () => Udp(128, 128));
        // One silent sample: 4 s between the last answer and the next one — under the 5 s limit.
        t = Feed(m, t.AddSeconds(2), 2, () => Udp(128, 0));
        t = Feed(m, t.AddSeconds(2), 10, () => Udp(128, 128));
        Assert.Empty(Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15))).OutageList);
    }

    [Fact]
    public void Udp_that_never_answered_is_a_warning_not_an_outage()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 30, () => Udp(20, 0));
        var p = Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15)));
        Assert.Equal(LinkLevel.Warn, p.Level);
        Assert.Equal("ответов нет", p.StateText);
        Assert.Empty(p.OutageList);
    }

    [Fact]
    public void Tcp_upload_with_only_acks_back_is_fine()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 30, () => Tcp(400, 0)); // data goes out, acknowledgements are not counted as data
        var p = Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15)));
        Assert.Equal(LinkLevel.Ok, p.Level);
        Assert.Empty(p.OutageList);
    }

    [Fact]
    public void Tcp_silence_with_resends_is_an_outage()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 20, () => Tcp(10, 10));
        t = Feed(m, t.AddSeconds(2), 10, () => Tcp(2, 0, retrans: 2));
        var p = Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15)));
        Assert.Equal(LinkLevel.Fail, p.Level);
        Assert.Contains("повторн", p.Servers[0].Reason);
    }

    [Fact]
    public void Tcp_resends_mean_loss()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 30, () => Tcp(100, 100, retrans: 10));
        var p = Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15)));
        Assert.Equal(LinkLevel.Warn, p.Level);
        Assert.Equal("потери ~10%", p.StateText);
    }

    [Fact]
    public void Idle_program_is_not_broken()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 10, () => Udp(10, 10));
        var p = Assert.Single(m.Snapshot(t.AddSeconds(30), TimeSpan.FromMinutes(15)));
        Assert.Equal(LinkLevel.Idle, p.Level);
        Assert.Equal("простаивает", p.StateText);
    }

    [Fact]
    public void Ping_latency_jitter_and_loss()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 60, () => Udp(64, 64));
        double?[] rtts = [40, 50, 40, null, 50, null, 40, 50, 40, 50];
        for (var i = 0; i < rtts.Length; i++) m.AddPing(Game, t.AddSeconds(-50 + i * 5), rtts[i]);

        var p = Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15)));
        var s = p.Servers[0];
        Assert.True(s.Pingable);
        Assert.Equal(45, s.LatencyMs!.Value, 3);
        Assert.Equal(10, s.JitterMs!.Value, 3);
        Assert.Equal(LinkLevel.Warn, p.Level); // 2 of 10 pings lost
        Assert.Equal("потери 20%", p.StateText);
    }

    [Fact]
    public void Server_that_ignores_ping_has_no_loss()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 60, () => Udp(64, 64));
        for (var i = 0; i < 10; i++) m.AddPing(Game, t.AddSeconds(-50 + i * 5), null);
        var p = Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15)));
        Assert.Equal(LinkLevel.Ok, p.Level);
        Assert.Null(p.Servers[0].LatencyMs);
        Assert.False(p.Servers[0].Pingable);
    }

    [Fact]
    public void Ping_targets_are_the_busiest_servers()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        m.Add(T0, [Udp(1000, 1000), Tcp(5, 5), Tcp(1, 1) with { Ip = IPAddress.Parse("127.0.0.1") }]);
        Assert.Equal([Game, Tg], m.PingTargets(T0.AddSeconds(1), 5));
        Assert.Equal([Game], m.PingTargets(T0.AddSeconds(1), 1));
    }

    [Fact]
    public void An_hour_of_thirty_servers_is_fast()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = T0;
        for (var tick = 0; tick < 1800; tick++)
        {
            t = T0.AddSeconds(tick * 2);
            m.Add(t, Enumerable.Range(1, 30).Select(i => Udp(64, 64) with { Ip = IPAddress.Parse($"10.0.0.{i}"), GroupKey = $"app{i % 6}.exe" }));
            if (tick % 3 == 0)
                for (var i = 1; i <= 30; i++) m.AddPing(IPAddress.Parse($"10.0.0.{i}"), t, 30);
        }
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var programs = m.Snapshot(t, TimeSpan.FromHours(1));
        sw.Stop();
        Assert.Equal(6, programs.Count);
        Assert.True(sw.ElapsedMilliseconds < 1500, $"snapshot took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void One_silent_server_of_many_is_not_a_down_program()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var other = IPAddress.Parse("155.133.252.39");
        var t = T0;
        for (var s = 0; s < 60; s += 2)
        {
            t = T0.AddSeconds(s);
            // One server answers all the time, the other went silent after 20 s.
            m.Add(t, [Udp(64, 64), Udp(64, s < 20 ? 64 : 0) with { Ip = other }]);
        }
        var p = Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(5)));
        Assert.DoesNotContain(p.Chart, c => c.Down);
        Assert.Contains(p.Chart, c => c.Packets > 0);
        Assert.Contains(p.Servers, x => x.Level == LinkLevel.Fail);
    }

    [Fact]
    public void A_few_tcp_resends_are_not_drawn_as_loss()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 60, () => Tcp(200, 200, retrans: 1));
        Assert.All(Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(5))).Chart, c => Assert.Equal(0, c.LossPercent));
    }

    [Fact]
    public void Notes_are_added_to_the_reason()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var t = Feed(m, T0, 20, () => Udp(64, 64));
        t = Feed(m, t.AddSeconds(2), 10, () => Udp(64, 0));
        m.SetNote(LinkMonitor.KeyOf("cs2.exe", "UDP", Game, 27015), "трасса обрывается после узла 7");
        Assert.Contains("трасса обрывается", Assert.Single(m.Snapshot(t, TimeSpan.FromMinutes(15))).Servers[0].Reason);
    }
}
