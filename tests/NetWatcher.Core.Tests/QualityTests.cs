using NetWatcher.Core.Link;

namespace NetWatcher.Core.Tests;

public class QualityTests
{
    private static AimScore? Of(List<AimScore> scores, string name) => scores.FirstOrDefault(s => s.Experience == name);

    // The cases of Cloudflare's own tests (tests/unit/Results/ScoresCalculations.test.ts).
    [Fact]
    public void Aim_matches_cloudflare_tests()
    {
        Assert.Empty(Aim.Score(new AimInput(null, null, null, null, null, null)));

        // Excellent: latency 5, loss 0, download 100 Mbit/s, increase 10 ms → streaming great.
        var s = Aim.Score(new AimInput(5, null, 0, 10, 100e6, null));
        Assert.Equal(AimClass.Great, Of(s, "streaming")!.Class);

        // Poor: latency 200, loss 30%, increase 300 ms → gaming clamped to 0, bad.
        var g = Of(Aim.Score(new AimInput(200, null, 0.3, 300, null, null)), "gaming")!;
        Assert.Equal(0, g.Points);
        Assert.Equal(AimClass.Bad, g.Class);

        // Only latency: no experience can be scored.
        Assert.Empty(Aim.Score(new AimInput(10, null, null, null, null, null)));

        // Packet loss left out on purpose: 70 / 40 / 50 points.
        var o = Aim.Score(new AimInput(5, 5, 0, 5, 100e6, null), ["packetLoss"]);
        Assert.Equal(70, Of(o, "streaming")!.Points);
        Assert.Equal(40, Of(o, "gaming")!.Points);
        Assert.Equal(50, Of(o, "rtc")!.Points);

        // Missing packet loss counts as 0 points, the experience is still scored.
        Assert.NotNull(Of(Aim.Score(new AimInput(5, null, null, 5, 100e6, null)), "streaming"));
    }

    [Fact]
    public void Internet_chart_shows_delay_and_missing_replies()
    {
        var now = new DateTimeOffset(2026, 11, 7, 12, 0, 0, TimeSpan.Zero);
        var q = new QualityMonitor(TimeSpan.FromMinutes(20));
        q.AddPing(false, now.AddMinutes(-9), 40);
        q.AddPing(false, now.AddMinutes(-9).AddSeconds(2), 60);
        q.AddPing(false, now.AddMinutes(-1), null);
        q.AddPing(false, now.AddMinutes(-30), 500);
        q.AddPing(true, now.AddMinutes(-1), 1);

        var chart = q.InternetChart(now, TimeSpan.FromMinutes(10), 10);

        Assert.Equal(2, chart.Count);
        Assert.Equal(50, chart[0].LatencyMs);
        Assert.Equal(0, chart[0].LossPercent);
        Assert.Null(chart[1].LatencyMs);
        Assert.Equal(100, chart[1].LossPercent);
        // No reply to a ping is not a proof of a broken link.
        Assert.False(chart[1].Down);
        Assert.Empty(new QualityMonitor(TimeSpan.FromMinutes(20)).InternetChart(now, TimeSpan.FromMinutes(10), 10));
    }

    [Fact]
    public void Aim_thresholds()
    {
        Assert.Equal(20, Aim.LatencyPoints(9.9));
        Assert.Equal(10, Aim.LatencyPoints(10));
        Assert.Equal(-20, Aim.LatencyPoints(500));
        Assert.Equal(10, Aim.PacketLossPoints(0));
        Assert.Equal(5, Aim.PacketLossPoints(0.01));
        Assert.Equal(-20, Aim.PacketLossPoints(0.5));
        Assert.Equal(10, Aim.JitterPoints(5));
        Assert.Equal(0, Aim.BandwidthPoints(0.5e6));
        Assert.Equal(30, Aim.BandwidthPoints(100e6));
        // Without load data nothing is scored; streaming also needs the download speed.
        var noDownload = Aim.Score(new AimInput(15, 3, 0, 8, null, null));
        Assert.Equal(["gaming", "rtc"], noDownload.Select(x => x.Experience));
        Assert.Equal("почти не растёт", Aim.IncreaseText(5));
        Assert.Equal("растёт сильно", Aim.IncreaseText(80));
    }

    [Fact]
    public void Passive_monitor_sees_latency_grow_under_own_load()
    {
        var t0 = new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
        var q = new QualityMonitor(TimeSpan.FromHours(1));
        q.AddTraffic(t0, 0, 0);
        // 60 s idle (a little traffic), then 30 s downloading at ~80 Mbit/s; a ping every 2 s.
        for (var s = 2; s <= 90; s += 2)
        {
            var t = t0.AddSeconds(s);
            var loaded = s > 60;
            q.AddTraffic(t, loaded ? 20_000_000 : 5_000, loaded ? 200_000 : 2_000);
            q.AddPing(false, t.AddSeconds(-1), loaded ? 120 + s % 3 : 20 + s % 3);
            q.AddPing(true, t.AddSeconds(-1), 2);
        }
        var r = q.Report(t0.AddSeconds(91), TimeSpan.FromMinutes(10));
        Assert.Equal(2, r.Gateway.LatencyMs);
        Assert.InRange(r.Internet.LatencyMs!.Value, 20, 22);           // idle latency only
        Assert.InRange(r.Load.DownLoadedMs!.Value, 120, 122);
        Assert.InRange(r.Load.IncreaseMs!.Value, 98, 102);
        Assert.Equal(80e6, r.Load.PeakInBps, 1);
        // Gaming: latency 21 ms → 5, no loss → 10, +100 ms under load → −10: 5 points, "poor".
        var gaming = Of(r.Scores.ToList(), "gaming")!;
        Assert.Equal(5, gaming.Points);
        Assert.Equal(AimClass.Poor, gaming.Class);
        Assert.DoesNotContain(r.Scores, x => x.Experience == "streaming"); // no download speed without a test

        // A test result fills the download speed and its own increase.
        var withTest = q.Report(t0.AddSeconds(91), TimeSpan.FromMinutes(10), 95e6, 40e6, 8);
        Assert.Contains(withTest.Scores, x => x.Experience == "streaming");
        Assert.True(Of(withTest.Scores.ToList(), "gaming")!.Class >= AimClass.Good);

        // Stale traffic must not turn unavailable kernel capture into a known load or AIM score.
        var unavailable = q.Report(t0.AddSeconds(91), TimeSpan.FromMinutes(10), trafficAvailable: false);
        Assert.Equal(LoadStats.Empty, unavailable.Load);
        Assert.Empty(unavailable.Scores);
        Assert.NotNull(unavailable.Internet.LatencyMs);

        // An explicit load test measures the increase without kernel capture.
        var testedWithoutCapture = q.Report(t0.AddSeconds(91), TimeSpan.FromMinutes(10), 95e6, 40e6, 8, trafficAvailable: false);
        Assert.Equal(LoadStats.Empty, testedWithoutCapture.Load);
        Assert.Equal(3, testedWithoutCapture.Scores.Count);
    }

    [Fact]
    public void Light_traffic_is_not_load()
    {
        var t0 = new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
        var q = new QualityMonitor(TimeSpan.FromHours(1));
        q.AddTraffic(t0, 0, 0);
        for (var s = 2; s <= 60; s += 2)
        {
            q.AddTraffic(t0.AddSeconds(s), 100_000, 10_000); // 400 kbit/s at most
            q.AddPing(false, t0.AddSeconds(s - 1), 30);
        }
        var r = q.Report(t0.AddSeconds(61), TimeSpan.FromMinutes(10));
        Assert.Null(r.Load.IncreaseMs);
        Assert.Empty(r.Scores);
        Assert.Equal(30, r.Internet.LatencyMs);
        Assert.Equal(0, r.Internet.Loss);
    }

    [Fact]
    public void Load_test_math()
    {
        var samples = new List<(double, long)> { (0, 0), (1, 5_000_000), (2, 15_000_000), (4, 40_000_000), (6, 65_000_000) };
        Assert.Equal(25_000_000 * 8 / 2.0, LoadTestMath.Rate(samples, 2)!.Value, 1);
        Assert.Null(LoadTestMath.Rate([(0, 0), (2.5, 100)], 2));

        var stats = LoadTestMath.Stats([20, 22, null, 21, 25]);
        Assert.Equal(21.5, stats.LatencyMs);
        Assert.Equal(0.2, stats.Loss, 3);
        Assert.Equal((2 + 1 + 4) / 3.0, stats.JitterMs!.Value, 3);

        var result = new LoadTestResult(DateTimeOffset.Now, "x", LoadTestMath.Stats([20, 20, 20]), 90e6, 30e6,
            LoadTestMath.Stats([30, 32]), LoadTestMath.Stats([220, 260]), 1, 1);
        Assert.Equal(11, result.DownIncreaseMs);
        Assert.Equal(220, result.UpIncreaseMs);
        Assert.Equal(220, result.IncreaseMs);
        Assert.Equal(3, result.Scores.Count);
        Assert.Equal("94 Мбит/с", LoadTestMath.Mbps(94.3e6));
        Assert.Equal("2,5 Мбит/с", LoadTestMath.Mbps(2.5e6));
    }
}
