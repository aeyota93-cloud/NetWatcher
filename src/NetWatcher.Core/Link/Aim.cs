namespace NetWatcher.Core.Link;

/// <summary>Quality class of an experience, worst to best.</summary>
public enum AimClass
{
    Bad,
    Poor,
    Average,
    Good,
    Great,
}

/// <summary>Inputs of the scoring. Null — not measured.</summary>
public sealed record AimInput(
    double? LatencyMs,
    double? JitterMs,
    double? PacketLoss,
    double? LoadedLatencyIncreaseMs,
    double? DownloadBps,
    double? UploadBps);

/// <summary>Score of one experience: points, class, and which inputs were not measured.</summary>
public sealed record AimScore(string Experience, int Points, AimClass Class, IReadOnlyList<string> Omitted)
{
    public string Title => Experience switch
    {
        "gaming" => "Игры",
        "rtc" => "Звонки",
        "streaming" => "Видео",
        _ => Experience,
    };

    public string ClassText => Aim.ClassText(Class);
}

/// <summary>
/// Cloudflare's AIM (Aggregated Internet Measurement) scoring, ported from the open source
/// Cloudflare speed test library (github.com/cloudflare/speedtest, src/config/internalConfig.ts and
/// src/Results/ScoresCalculations.ts; MIT License, Copyright (c) 2023 Cloudflare).
/// Each metric gives points by thresholds; an experience sums the points of its metrics and maps the sum
/// to bad / poor / average / good / great. A metric that was not measured is left out, as the library does.
/// </summary>
public static class Aim
{
    private static int Threshold(double[] domain, int[] range, double value)
    {
        var i = 0;
        while (i < domain.Length && value >= domain[i]) i++;
        return range[i];
    }

    public static int PacketLossPoints(double ratio) => Threshold([0.01, 0.05, 0.25, 0.5], [10, 5, 0, -10, -20], ratio);
    public static int LatencyPoints(double ms) => Threshold([10, 20, 50, 100, 500], [20, 10, 5, 0, -10, -20], ms);
    public static int LoadedLatencyIncreasePoints(double ms) => Threshold([10, 20, 50, 100, 500], [20, 10, 5, 0, -10, -20], ms);
    public static int JitterPoints(double ms) => Threshold([10, 20, 100, 500], [10, 5, 0, -10, -20], ms);
    public static int BandwidthPoints(double bps) => Threshold([1e6, 10e6, 50e6, 100e6], [0, 5, 10, 20, 30], bps);

    private static readonly (string Name, string[] Input, double[] Thresholds)[] Experiences =
    [
        ("gaming", ["latency", "packetLoss", "loadedLatencyIncrease"], [5, 15, 25, 30]),
        ("rtc", ["latency", "jitter", "packetLoss", "loadedLatencyIncrease"], [5, 15, 25, 40]),
        ("streaming", ["latency", "packetLoss", "download", "loadedLatencyIncrease"], [15, 20, 40, 60]),
    ];

    /// <summary>
    /// Scores of gaming, calls (rtc) and streaming. As in Cloudflare's library, an experience is scored only
    /// when all its inputs are measured — latency under load for all three, jitter for calls, download speed
    /// for streaming; a missing packet loss counts as 0 points. Metrics in <paramref name="omit"/> were
    /// deliberately not measured and are left out of the sums instead.
    /// </summary>
    public static List<AimScore> Score(AimInput m, IReadOnlyCollection<string>? omit = null)
    {
        omit ??= [];
        var points = new Dictionary<string, int> { ["packetLoss"] = 0 };
        if (m.LatencyMs is { } latency) points["latency"] = LatencyPoints(latency);
        if (m.PacketLoss is { } loss) points["packetLoss"] = PacketLossPoints(loss);
        if (m.JitterMs is { } jitter) points["jitter"] = JitterPoints(jitter);
        if (m.LoadedLatencyIncreaseMs is { } inc) points["loadedLatencyIncrease"] = LoadedLatencyIncreasePoints(inc);
        if (m.DownloadBps is { } down) points["download"] = BandwidthPoints(down);
        if (m.UploadBps is { } up) points["upload"] = BandwidthPoints(up);

        var result = new List<AimScore>();
        foreach (var e in Experiences)
        {
            var input = e.Input.Where(k => !omit.Contains(k)).ToList();
            if (!input.All(points.ContainsKey)) continue;
            var sum = Math.Max(0, input.Sum(k => points[k]));
            result.Add(new AimScore(e.Name, sum, (AimClass)Threshold(e.Thresholds, [0, 1, 2, 3, 4], sum), e.Input.Except(input).ToList()));
        }
        return result;
    }

    public static string ClassText(AimClass c) => c switch
    {
        AimClass.Great => "отлично",
        AimClass.Good => "хорошо",
        AimClass.Average => "средне",
        AimClass.Poor => "слабо",
        _ => "плохо",
    };

    /// <summary>How much latency grows under load, in the words of AIM's own thresholds (10 / 20 / 50 / 100 / 500 ms).</summary>
    public static string IncreaseText(double ms) => ms switch
    {
        < 10 => "почти не растёт",
        < 20 => "растёт немного",
        < 50 => "растёт заметно",
        < 100 => "растёт сильно",
        < 500 => "растёт очень сильно",
        _ => "растёт критически",
    };
}
