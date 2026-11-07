using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetWatcher.Core.Diagnostics;

namespace NetWatcher.Core.Link;

/// <summary>A network snapshot; a missing metric sorts after known default-route metrics.</summary>
public sealed record QualityAdapter(string Name, string Description, NetworkInterfaceType Type,
    bool IsUp, IReadOnlyList<IPAddress> Gateways, uint? DefaultRouteMetric);

/// <summary>Latency of a reference point: median, jitter (mean step between neighbours), loss ratio.</summary>
public sealed record PathStats(double? LatencyMs, double? JitterMs, double Loss, int Samples)
{
    public static PathStats Empty { get; } = new(null, null, 0, 0);
}

/// <summary>
/// Latency to the internet with the line idle and loaded. "Loaded" means the computer's own traffic was at
/// least half of the highest seen in the window: it is load as it happened, not a measured line capacity.
/// </summary>
public sealed record LoadStats(double? IdleMs, double? DownLoadedMs, double? UpLoadedMs, double PeakInBps, double PeakOutBps, int DownSamples, int UpSamples)
{
    /// <summary>The larger growth of the two directions, as AIM's loadedLatencyIncrease; null without load data.</summary>
    public double? IncreaseMs => IdleMs is { } idle && (DownLoadedMs ?? UpLoadedMs) != null
        ? Math.Max(0, Math.Max(DownLoadedMs ?? double.MinValue, UpLoadedMs ?? double.MinValue) - idle)
        : null;

    public static LoadStats Empty { get; } = new(null, null, null, 0, 0, 0, 0);
}

/// <summary>What the passive quality monitor knows: the router, the internet, latency under load, AIM scores.</summary>
public sealed record QualityReport(PathStats Gateway, PathStats Internet, LoadStats Load, IReadOnlyList<AimScore> Scores);

/// <summary>
/// Passive connection quality: pings to the router and to an internet reference point every few seconds,
/// plus the computer's own traffic to the internet. Pings taken while the traffic was heavy show how much the
/// line's queues add (bufferbloat), without generating any load. Kept in memory.
/// </summary>
public sealed class QualityMonitor(TimeSpan history)
{
    /// <summary>Selects a home router without consulting the network or accepting a VPN gateway.</summary>
    public static IPAddress? SelectGateway(IEnumerable<QualityAdapter> adapters) => adapters
        .Where(a => a.IsUp && a.Type is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211
            && !NetProbe.IsTunnelAdapter(a.Name, a.Description, a.Type))
        .OrderBy(a => a.DefaultRouteMetric ?? uint.MaxValue)
        .SelectMany(a => a.Gateways)
        .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork
            && !ip.Equals(IPAddress.Any) && !IPAddress.IsLoopback(ip));

    /// <summary>Traffic under these rates is never "load": a few web pages are not a test of the line.</summary>
    public const double MinDownLoadBps = 2e6, MinUpLoadBps = 1e6;

    private readonly Lock _lock = new();
    private readonly List<(DateTimeOffset Time, double? Rtt)> _gateway = [];
    private readonly List<(DateTimeOffset Time, double? Rtt)> _internet = [];
    private readonly List<(DateTimeOffset Time, double InBps, double OutBps)> _traffic = [];
    private DateTimeOffset? _lastTraffic;

    public void ResetGateway()
    {
        lock (_lock) _gateway.Clear();
    }

    public void AddPing(bool gateway, DateTimeOffset time, double? rttMs)
    {
        lock (_lock)
        {
            var list = gateway ? _gateway : _internet;
            list.Add((time, rttMs));
            list.RemoveAll(p => time - p.Time > history);
        }
    }

    /// <summary>Bytes to and from the internet since the previous call (one collector tick).</summary>
    public void AddTraffic(DateTimeOffset time, long bytesIn, long bytesOut)
    {
        lock (_lock)
        {
            if (_lastTraffic is { } last && time > last)
            {
                var seconds = Math.Clamp((time - last).TotalSeconds, 0.5, 10);
                _traffic.Add((time, bytesIn * 8 / seconds, bytesOut * 8 / seconds));
                _traffic.RemoveAll(t => time - t.Time > history);
            }
            _lastTraffic = time;
        }
    }

    /// <summary>Reference pings to the internet as chart points: average delay and the share without a reply.</summary>
    public IReadOnlyList<ChartPoint> InternetChart(DateTimeOffset now, TimeSpan window, int points)
    {
        lock (_lock)
        {
            var from = now - window;
            var step = window / points;
            return _internet.Where(p => p.Time >= from && p.Time <= now)
                .GroupBy(p => Math.Min(points - 1, (int)((p.Time - from) / step)))
                .OrderBy(g => g.Key)
                .Select(g =>
                {
                    var replies = g.Where(p => p.Rtt != null).Select(p => p.Rtt!.Value).ToList();
                    return new ChartPoint(from + step * g.Key, replies.Count > 0 ? replies.Average() : null,
                        100.0 * (g.Count() - replies.Count) / g.Count(), false, g.Count());
                })
                .ToList();
        }
    }

    public QualityReport Report(DateTimeOffset now, TimeSpan window, double? downloadBps = null, double? uploadBps = null, double? testIncreaseMs = null,
        bool trafficAvailable = true)
    {
        lock (_lock)
        {
            var from = now - window;
            var gateway = Stats(_gateway.Where(p => p.Time >= from).ToList());
            var pings = _internet.Where(p => p.Time >= from).ToList();
            var traffic = trafficAvailable ? _traffic.Where(t => t.Time >= from).ToList() : [];
            var load = Load(pings, traffic);

            // Latency and jitter as AIM wants them: unloaded. Without enough idle samples, all of them.
            var internetAll = Stats(pings);
            var idle = pings.Where(p => Phase(p.Time, traffic, load) == 0).ToList();
            var internet = idle.Count(p => p.Rtt != null) >= 5 ? Stats(idle) with { Loss = internetAll.Loss } : internetAll;

            var scores = Aim.Score(new AimInput(
                internet.LatencyMs,
                internet.JitterMs,
                internet.Samples > 0 ? internet.Loss : null,
                testIncreaseMs ?? load.IncreaseMs,
                downloadBps,
                uploadBps));
            return new QualityReport(gateway, internet, load, scores);
        }
    }

    private static PathStats Stats(List<(DateTimeOffset Time, double? Rtt)> pings)
    {
        if (pings.Count == 0) return PathStats.Empty;
        var ok = pings.Where(p => p.Rtt != null).Select(p => p.Rtt!.Value).ToList();
        var loss = (double)(pings.Count - ok.Count) / pings.Count;
        if (ok.Count == 0) return new PathStats(null, null, loss, pings.Count);
        double? jitter = ok.Count > 1 ? ok.Zip(ok.Skip(1), (a, b) => Math.Abs(b - a)).Average() : null;
        return new PathStats(Median(ok), jitter, loss, pings.Count);
    }

    private static double Median(List<double> values)
    {
        var sorted = values.Order().ToList();
        var n = sorted.Count;
        return n % 2 == 1 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
    }

    private sealed record Peaks(double In, double Out);

    private static LoadStats Load(List<(DateTimeOffset Time, double? Rtt)> pings, List<(DateTimeOffset Time, double InBps, double OutBps)> traffic)
    {
        if (traffic.Count == 0) return LoadStats.Empty;
        var peaks = new Peaks(traffic.Max(t => t.InBps), traffic.Max(t => t.OutBps));
        var idle = new List<double>();
        var down = new List<double>();
        var up = new List<double>();
        foreach (var p in pings)
        {
            if (p.Rtt is not { } rtt) continue;
            switch (Phase(p.Time, traffic, peaks))
            {
                case 0: idle.Add(rtt); break;
                case 1: down.Add(rtt); break;
                case 2: up.Add(rtt); break;
            }
        }
        return new LoadStats(
            idle.Count >= 5 ? Median(idle) : null,
            down.Count >= 3 ? Median(down) : null,
            up.Count >= 3 ? Median(up) : null,
            peaks.In, peaks.Out, down.Count, up.Count);
    }

    private static int Phase(DateTimeOffset time, List<(DateTimeOffset Time, double InBps, double OutBps)> traffic, LoadStats load) =>
        Phase(time, traffic, new Peaks(load.PeakInBps, load.PeakOutBps));

    /// <summary>0 — idle, 1 — download load, 2 — upload load, -1 — in between or unknown.</summary>
    private static int Phase(DateTimeOffset time, List<(DateTimeOffset Time, double InBps, double OutBps)> traffic, Peaks peaks)
    {
        // The traffic sample that covers the moment of the ping: the first one taken after it.
        var i = traffic.FindIndex(t => t.Time >= time);
        if (i < 0) return -1;
        var (_, inBps, outBps) = traffic[i];
        var downLoaded = peaks.In >= MinDownLoadBps && inBps >= peaks.In / 2;
        var upLoaded = peaks.Out >= MinUpLoadBps && outBps >= peaks.Out / 2;
        if (downLoaded || upLoaded) return upLoaded && (!downLoaded || outBps / peaks.Out > inBps / peaks.In) ? 2 : 1;
        var quietIn = inBps < Math.Max(peaks.In * 0.1, 200e3);
        var quietOut = outBps < Math.Max(peaks.Out * 0.1, 200e3);
        return quietIn && quietOut ? 0 : -1;
    }
}
