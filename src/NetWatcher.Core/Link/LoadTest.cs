namespace NetWatcher.Core.Link;

/// <summary>
/// Result of the active test: latency with the line idle, then while downloading and while uploading as fast
/// as possible (what Waveform and Cloudflare call latency under load, or bufferbloat), and the speeds.
/// </summary>
public sealed record LoadTestResult(
    DateTimeOffset Time,
    string Server,
    PathStats Idle,
    double? DownBps,
    double? UpBps,
    PathStats DownLoaded,
    PathStats UpLoaded,
    long BytesDown,
    long BytesUp)
{
    public double? DownIncreaseMs => Idle.LatencyMs is { } idle && DownLoaded.LatencyMs is { } l ? Math.Max(0, l - idle) : null;
    public double? UpIncreaseMs => Idle.LatencyMs is { } idle && UpLoaded.LatencyMs is { } l ? Math.Max(0, l - idle) : null;

    /// <summary>As AIM's loadedLatencyIncrease: the larger of the two directions.</summary>
    public double? IncreaseMs => (DownIncreaseMs, UpIncreaseMs) switch
    {
        (null, null) => null,
        var (d, u) => Math.Max(d ?? 0, u ?? 0),
    };

    public List<AimScore> Scores => Aim.Score(new AimInput(
        Idle.LatencyMs, Idle.JitterMs, Idle.Samples > 0 ? Idle.Loss : null, IncreaseMs, DownBps, UpBps));
}

public static class LoadTestMath
{
    /// <summary>
    /// Speed from cumulative byte counts over time, leaving out the first seconds while TCP speeds up
    /// (slow start). Null when too little time is left to tell.
    /// </summary>
    public static double? Rate(IReadOnlyList<(double Seconds, long Bytes)> cumulative, double skipSeconds)
    {
        if (cumulative.Count < 2) return null;
        var start = cumulative.FirstOrDefault(s => s.Seconds >= skipSeconds);
        var end = cumulative[^1];
        if (start == default || end.Seconds - start.Seconds < 1) return null;
        return (end.Bytes - start.Bytes) * 8 / (end.Seconds - start.Seconds);
    }

    /// <summary>Latency statistics of a series of pings (null — lost), as the passive monitor counts them.</summary>
    public static PathStats Stats(IReadOnlyList<double?> rtts)
    {
        if (rtts.Count == 0) return PathStats.Empty;
        var ok = rtts.Where(r => r != null).Select(r => r!.Value).ToList();
        var loss = (double)(rtts.Count - ok.Count) / rtts.Count;
        if (ok.Count == 0) return new PathStats(null, null, loss, rtts.Count);
        var sorted = ok.Order().ToList();
        var n = sorted.Count;
        var median = n % 2 == 1 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
        double? jitter = ok.Count > 1 ? ok.Zip(ok.Skip(1), (a, b) => Math.Abs(b - a)).Average() : null;
        return new PathStats(median, jitter, loss, rtts.Count);
    }

    /// <summary>"94 Мбит/с".</summary>
    public static string Mbps(double bps) =>
        bps >= 10e6 ? $"{bps / 1e6:0} Мбит/с" : $"{bps / 1e6:0.0} Мбит/с".Replace('.', ',');
}
