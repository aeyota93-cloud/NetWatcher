namespace NetWatcher.Core.Link;

/// <summary>What the "Связь" table shows about a server, as numbers rather than text, for filtering.</summary>
public sealed record ServerFacts(
    string Name,
    string Address,
    string Owner,
    string Proto,
    LinkLevel Level,
    bool HasDomain,
    double? LatencyMs,
    double? JitterMs,
    double? LossPercent,
    double? AnswerAgoSeconds,
    long Bytes);

public enum ProtoFilter { All, Tcp, Udp }

/// <summary>How the program reached the server: by a name it looked up, or straight by address.</summary>
public enum AddressFilter { All, Domain, Ip }

public enum StateFilter { All, Ok, Problems, Fail, Idle }

/// <summary>Bands of latency, at the thresholds of Cloudflare's AIM scoring (20, 50, 100 ms).</summary>
public enum LatencyFilter { All, Under20, From20To50, From50To100, Over100, Unknown }

/// <summary>Bands of jitter, at the thresholds of Cloudflare's AIM scoring (10, 20 ms).</summary>
public enum JitterFilter { All, Under10, From10To20, Over20, Unknown }

public enum LossFilter { All, Some, None, Unknown }

public enum AnswerFilter { All, Now, Earlier, Never }

public enum TrafficFilter { All, Some, None }

/// <summary>
/// Filters of the server table in the "Связь" tab, one per column. All filters must pass.
/// The quick filters above the tabs set the protocol, address and state filters.
/// </summary>
public sealed class ServerFilter
{
    /// <summary>A loss of 1% or more counts as "есть потери", as the table marks it.</summary>
    public const double LossThreshold = 1;

    /// <summary>An answer within this many seconds is "сейчас", as the table says.</summary>
    public const double AnswerNowSeconds = 5;

    public string Text { get; set; } = "";
    public ProtoFilter Proto { get; set; }
    public AddressFilter Address { get; set; }
    public StateFilter State { get; set; }
    public LatencyFilter Latency { get; set; }
    public JitterFilter Jitter { get; set; }
    public LossFilter Loss { get; set; }
    public AnswerFilter Answer { get; set; }
    public TrafficFilter Traffic { get; set; }

    /// <summary>How many columns are filtered.</summary>
    public int ActiveCount =>
        (Text.Trim() != "" ? 1 : 0) + (Address != AddressFilter.All ? 1 : 0) + (Proto != ProtoFilter.All ? 1 : 0)
        + (State != StateFilter.All ? 1 : 0) + (Latency != LatencyFilter.All ? 1 : 0) + (Jitter != JitterFilter.All ? 1 : 0)
        + (Loss != LossFilter.All ? 1 : 0) + (Answer != AnswerFilter.All ? 1 : 0) + (Traffic != TrafficFilter.All ? 1 : 0);

    public bool IsActive => ActiveCount > 0;

    public void Clear()
    {
        Text = "";
        Proto = ProtoFilter.All;
        Address = AddressFilter.All;
        State = StateFilter.All;
        Latency = LatencyFilter.All;
        Jitter = JitterFilter.All;
        Loss = LossFilter.All;
        Answer = AnswerFilter.All;
        Traffic = TrafficFilter.All;
    }

    public bool Pass(ServerFacts s)
    {
        foreach (var word in DestinationRow.SplitQuery(Text))
            if (!Has(s.Name, word) && !Has(s.Address, word) && !Has(s.Owner, word)) return false;

        if (Proto == ProtoFilter.Tcp && s.Proto != "TCP") return false;
        if (Proto == ProtoFilter.Udp && s.Proto != "UDP") return false;
        if (Address == AddressFilter.Domain && !s.HasDomain) return false;
        if (Address == AddressFilter.Ip && s.HasDomain) return false;

        var stateOk = State switch
        {
            StateFilter.Ok => s.Level == LinkLevel.Ok,
            StateFilter.Problems => s.Level is LinkLevel.Warn or LinkLevel.Fail,
            StateFilter.Fail => s.Level == LinkLevel.Fail,
            StateFilter.Idle => s.Level == LinkLevel.Idle,
            _ => true,
        };
        if (!stateOk) return false;

        var latencyOk = (Latency, s.LatencyMs) switch
        {
            (LatencyFilter.All, _) => true,
            (LatencyFilter.Unknown, var v) => v == null,
            (_, null) => false,
            (LatencyFilter.Under20, { } v) => v < 20,
            (LatencyFilter.From20To50, { } v) => v is >= 20 and < 50,
            (LatencyFilter.From50To100, { } v) => v is >= 50 and < 100,
            (LatencyFilter.Over100, { } v) => v >= 100,
            _ => true,
        };
        if (!latencyOk) return false;

        var jitterOk = (Jitter, s.JitterMs) switch
        {
            (JitterFilter.All, _) => true,
            (JitterFilter.Unknown, var v) => v == null,
            (_, null) => false,
            (JitterFilter.Under10, { } v) => v < 10,
            (JitterFilter.From10To20, { } v) => v is >= 10 and < 20,
            (JitterFilter.Over20, { } v) => v >= 20,
            _ => true,
        };
        if (!jitterOk) return false;

        var lossOk = (Loss, s.LossPercent) switch
        {
            (LossFilter.All, _) => true,
            (LossFilter.Unknown, var v) => v == null,
            (_, null) => false,
            (LossFilter.Some, { } v) => v >= LossThreshold,
            (LossFilter.None, { } v) => v < LossThreshold,
            _ => true,
        };
        if (!lossOk) return false;

        var answerOk = (Answer, s.AnswerAgoSeconds) switch
        {
            (AnswerFilter.All, _) => true,
            (AnswerFilter.Never, var v) => v == null,
            (_, null) => false,
            (AnswerFilter.Now, { } v) => v < AnswerNowSeconds,
            (AnswerFilter.Earlier, { } v) => v >= AnswerNowSeconds,
            _ => true,
        };
        if (!answerOk) return false;

        return Traffic switch
        {
            TrafficFilter.Some => s.Bytes > 0,
            TrafficFilter.None => s.Bytes == 0,
            _ => true,
        };
    }

    private static bool Has(string text, string word) => text.Contains(word, StringComparison.OrdinalIgnoreCase);
}
