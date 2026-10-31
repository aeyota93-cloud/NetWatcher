using System.Net;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Link;

public enum LinkLevel
{
    /// <summary>No traffic right now.</summary>
    Idle,
    Ok,
    Warn,
    Fail,
}

/// <summary>Traffic of one program with one server since the previous sample.</summary>
public readonly record struct FlowSample(
    string GroupKey,
    string Process,
    string Services,
    string Path,
    IPAddress Ip,
    int Port,
    string Proto,
    long PacketsOut,
    long PacketsIn,
    long BytesOut,
    long BytesIn,
    int Retransmits,
    int NoAnswer);

/// <summary>A period when a server stopped answering while the program kept sending.</summary>
public sealed record Outage(string ServerKey, string GroupKey, IPAddress Ip, int Port, string Proto, DateTimeOffset Start, DateTimeOffset? End)
{
    public TimeSpan Duration(DateTimeOffset now) => (End ?? now) - Start;
}

/// <summary>State of one program–server pair.</summary>
public sealed record ServerLink(
    string Key,
    string GroupKey,
    IPAddress Ip,
    int Port,
    string Proto,
    LinkLevel Level,
    string StateText,
    double? LatencyMs,
    double? JitterMs,
    double? LossPercent,
    DateTimeOffset? LastAnswer,
    long BytesOut,
    long BytesIn,
    long PacketsOut,
    long PacketsIn,
    bool Pingable,
    string Reason);

/// <summary>One point of a chart: average latency, loss and whether the link was down.</summary>
public readonly record struct ChartPoint(DateTimeOffset Time, double? LatencyMs, double LossPercent, bool Down, long Packets = 0);

/// <summary>State of a program as a whole.</summary>
public sealed record ProgramLink(
    string GroupKey,
    string Process,
    string Services,
    string Path,
    LinkLevel Level,
    string StateText,
    double? LatencyMs,
    double? JitterMs,
    double LossPercent,
    int Outages,
    IReadOnlyList<ServerLink> Servers,
    IReadOnlyList<Outage> OutageList,
    IReadOnlyList<ChartPoint> Chart,
    string Protocols);

/// <summary>
/// Passive link quality per program and server: packets each way from the system's network
/// events, retransmissions, and periodic pings. Kept in memory for the last hour.
/// </summary>
public sealed class LinkMonitor(TimeSpan history)
{
    /// <summary>Silence after which a server that keeps being written to counts as not answering.</summary>
    public static readonly TimeSpan NoAnswerAfter = TimeSpan.FromSeconds(5);

    /// <summary>No traffic for this long: the program is idle, not broken.</summary>
    public static readonly TimeSpan IdleAfter = TimeSpan.FromSeconds(10);

    /// <summary>Recent window for loss, latency and the current state.</summary>
    public static readonly TimeSpan RecentWindow = TimeSpan.FromSeconds(60);

    private readonly Lock _lock = new();
    private readonly Dictionary<string, Server> _servers = [];
    private readonly Dictionary<UInt128, List<(DateTimeOffset Time, double? Rtt)>> _pings = [];
    private readonly Dictionary<string, string> _notes = [];

    private sealed class Server
    {
        public required string Key;
        public required string GroupKey, Process, Services, Path, Proto;
        public required IPAddress Ip;
        public required int Port;
        public readonly List<Tick> Ticks = [];
        public DateTimeOffset? EverAnswered;
    }

    private readonly record struct Tick(DateTimeOffset Time, long Out, long In, long BytesOut, long BytesIn, int Retrans, int NoAnswer);

    public static string KeyOf(string groupKey, string proto, IPAddress ip, int port) => $"{groupKey}|{proto}|{ip}|{port}";

    public void Add(DateTimeOffset time, IEnumerable<FlowSample> samples)
    {
        lock (_lock)
        {
            foreach (var s in samples)
            {
                var key = KeyOf(s.GroupKey, s.Proto, s.Ip, s.Port);
                if (!_servers.TryGetValue(key, out var server))
                    _servers[key] = server = new Server
                    {
                        Key = key, GroupKey = s.GroupKey, Process = s.Process, Services = s.Services, Path = s.Path,
                        Proto = s.Proto, Ip = IpKey.Normalize(s.Ip), Port = s.Port,
                    };
                server.Ticks.Add(new Tick(time, s.PacketsOut, s.PacketsIn, s.BytesOut, s.BytesIn, s.Retransmits, s.NoAnswer));
                if (s.PacketsIn > 0) server.EverAnswered = time;
            }
            Trim(time);
        }
    }

    public void AddPing(IPAddress ip, DateTimeOffset time, double? rttMs)
    {
        lock (_lock)
        {
            var key = IpKey.From(ip);
            if (!_pings.TryGetValue(key, out var list)) _pings[key] = list = [];
            list.Add((time, rttMs));
            list.RemoveAll(p => time - p.Time > history);
        }
    }

    /// <summary>An explanation found later, e.g. where the route breaks.</summary>
    public void SetNote(string serverKey, string note)
    {
        lock (_lock) _notes[serverKey] = note;
    }

    /// <summary>Busiest servers of the last 30 seconds, to ping.</summary>
    public List<IPAddress> PingTargets(DateTimeOffset now, int max)
    {
        lock (_lock)
        {
            return _servers.Values
                .Select(s => (s.Ip, Packets: s.Ticks.Where(t => now - t.Time <= TimeSpan.FromSeconds(30)).Sum(t => t.Out + t.In)))
                .Where(x => x.Packets > 0 && !IpKey.IsUninteresting(x.Ip, true))
                .GroupBy(x => IpKey.From(x.Ip))
                .Select(g => (g.First().Ip, Packets: g.Sum(x => x.Packets)))
                .OrderByDescending(x => x.Packets)
                .Take(max)
                .Select(x => x.Ip)
                .ToList();
        }
    }

    private void Trim(DateTimeOffset now)
    {
        foreach (var (key, s) in _servers.ToList())
        {
            var cut = s.Ticks.FindIndex(t => now - t.Time <= history);
            if (cut < 0) _servers.Remove(key);
            else if (cut > 0) s.Ticks.RemoveRange(0, cut);
        }
    }

    // ---------------------------------------------------------------- analysis

    public List<ProgramLink> Snapshot(DateTimeOffset now, TimeSpan window, int chartPoints = 120)
    {
        lock (_lock)
        {
            var from = now - window;
            var servers = _servers.Values.Where(s => s.Ticks.Any(t => t.Time >= from)).ToList();
            return servers
                .GroupBy(s => s.GroupKey)
                .Select(g => BuildProgram(g.ToList(), now, from, chartPoints))
                .OrderByDescending(p => p.Level)
                .ThenBy(p => p.Process, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    private ProgramLink BuildProgram(List<Server> servers, DateTimeOffset now, DateTimeOffset from, int chartPoints)
    {
        var links = servers.Select(s => BuildServer(s, now)).ToList();
        var outages = servers.SelectMany(s => Outages(s, now)).Where(o => (o.End ?? now) >= from).OrderBy(o => o.Start).ToList();
        var active = links.Where(l => l.Level != LinkLevel.Idle).ToList();
        var level = active.Count == 0 ? LinkLevel.Idle : active.Max(l => l.Level);
        var main = active.Where(l => l.LatencyMs != null).OrderByDescending(l => l.PacketsOut + l.PacketsIn).FirstOrDefault();
        var loss = active.Select(l => l.LossPercent ?? 0).DefaultIfEmpty(0).Max();
        var worst = active.OrderByDescending(l => l.Level).FirstOrDefault();
        var state = level switch
        {
            LinkLevel.Fail or LinkLevel.Warn => worst!.StateText,
            LinkLevel.Ok => main?.LatencyMs is { } ms ? $"{ms:0} мс" : "работает",
            _ => "простаивает",
        };
        var first = servers[0];
        return new ProgramLink(
            first.GroupKey, first.Process, first.Services, first.Path, level, state,
            main?.LatencyMs, main?.JitterMs, loss, outages.Count,
            links.OrderByDescending(l => l.Level).ThenByDescending(l => l.PacketsOut + l.PacketsIn).ToList(),
            outages,
            Chart(servers, now, from, chartPoints),
            string.Join("+", servers.Select(s => s.Proto).Distinct().Order()));
    }

    private ServerLink BuildServer(Server s, DateTimeOffset now)
    {
        var recent = s.Ticks.Where(t => now - t.Time <= RecentWindow).ToList();
        long outPk = recent.Sum(t => t.Out), inPk = recent.Sum(t => t.In);
        long bOut = recent.Sum(t => t.BytesOut), bIn = recent.Sum(t => t.BytesIn);
        var retrans = recent.Sum(t => t.Retrans);
        var lastAnswer = s.Ticks.LastOrDefault(t => t.In > 0) is { Time: var la } tick && tick.In > 0 ? la : (DateTimeOffset?)null;
        var lastTraffic = s.Ticks.Count > 0 ? s.Ticks[^1].Time : DateTimeOffset.MinValue;
        var (latency, jitter, pingLoss, pingable) = PingStats(s.Ip, now);
        var outage = Outages(s, now).LastOrDefault(o => o.End == null);
        _notes.TryGetValue(s.Key, out var note);

        LinkLevel level;
        string text;
        double? loss = null;
        string reason;
        if (outage != null)
        {
            level = LinkLevel.Fail;
            var silent = (int)(now - outage.Start).TotalSeconds;
            text = $"нет ответа {silent} с";
            var silentTicks = s.Ticks.Where(t => t.Time >= outage.Start).ToList();
            reason = s.Proto == "UDP"
                ? $"UDP: {TextFormat.Plural(silentTicks.Sum(t => t.Out), "пакет отправлен", "пакета отправлено", "пакетов отправлено")}, получено 0 за {silent} с"
                : $"TCP: {TextFormat.Plural(silentTicks.Sum(t => t.Retrans + t.NoAnswer), "повторная отправка", "повторные отправки", "повторных отправок")} без ответа за {silent} с";
        }
        else if (now - lastTraffic > IdleAfter)
        {
            level = LinkLevel.Idle;
            text = "простаивает";
            reason = "";
        }
        else if (pingable && pingLoss >= 20)
        {
            level = LinkLevel.Warn;
            loss = pingLoss;
            text = $"потери {pingLoss:0}%";
            reason = $"пинг до сервера: потеряно {pingLoss:0}% за минуту";
        }
        else if (s.Proto == "TCP" && retrans >= 5 && outPk > 0 && retrans * 100.0 / outPk >= 5)
        {
            level = LinkLevel.Warn;
            loss = Math.Min(100, retrans * 100.0 / outPk);
            text = $"потери ~{loss:0}%";
            reason = $"TCP: {TextFormat.Plural(retrans, "повторная отправка", "повторные отправки", "повторных отправок")} из {outPk} пакетов за минуту";
        }
        else if (s.Proto == "UDP" && s.EverAnswered == null && s.Ticks.Sum(t => t.Out) >= 10)
        {
            level = LinkLevel.Warn;
            text = "ответов нет";
            reason = "программа отправляет пакеты, но этот сервер ни разу не ответил (бывает и у одностороннего трафика)";
        }
        else
        {
            level = LinkLevel.Ok;
            text = "работает";
            loss = pingable ? pingLoss : s.Proto == "TCP" && outPk > 0 ? retrans * 100.0 / outPk : null;
            reason = "";
        }

        if (note != null) reason = reason == "" ? note : $"{reason}; {note}";
        return new ServerLink(s.Key, s.GroupKey, s.Ip, s.Port, s.Proto, level, text, latency, jitter, loss, lastAnswer,
            bOut, bIn, outPk, inPk, pingable, reason);
    }

    /// <summary>
    /// Periods of silence. UDP: the program keeps sending, nothing comes back, and the server
    /// did answer before. TCP: no data back and the system resends — a plain upload, where only
    /// acknowledgements come back, must not look like an outage.
    /// </summary>
    private static List<Outage> Outages(Server s, DateTimeOffset now)
    {
        var result = new List<Outage>();
        DateTimeOffset? lastIn = null;
        DateTimeOffset? silenceStart = null;
        var retransInSilence = 0;
        var answeredBefore = false;

        void Close(DateTimeOffset end)
        {
            if (silenceStart is { } start && end - start >= NoAnswerAfter && (s.Proto == "UDP" ? answeredBefore : retransInSilence > 0))
                result.Add(new Outage(s.Key, s.GroupKey, s.Ip, s.Port, s.Proto, start, end));
        }

        foreach (var t in s.Ticks)
        {
            if (t.In > 0)
            {
                Close(t.Time);
                silenceStart = null;
                retransInSilence = 0;
                lastIn = t.Time;
                answeredBefore = true;
                continue;
            }
            if (t.Out > 0 || t.Retrans > 0 || t.NoAnswer > 0)
            {
                silenceStart ??= lastIn ?? t.Time;
                retransInSilence += t.Retrans + t.NoAnswer;
            }
        }

        // Still silent: an ongoing outage, provided the program is still trying.
        if (silenceStart is { } open && now - open >= NoAnswerAfter && s.Ticks.Count > 0 && now - s.Ticks[^1].Time <= IdleAfter
            && (s.Proto == "UDP" ? answeredBefore : retransInSilence > 0))
            result.Add(new Outage(s.Key, s.GroupKey, s.Ip, s.Port, s.Proto, open, null));
        return result;
    }

    /// <summary>Average, jitter and loss of pings over the recent window.</summary>
    private (double? Latency, double? Jitter, double Loss, bool Pingable) PingStats(IPAddress ip, DateTimeOffset now)
    {
        if (!_pings.TryGetValue(IpKey.From(ip), out var list) || list.Count == 0) return (null, null, 0, false);
        // A server that never answers ping is not "losing" packets — it just does not do ping.
        var pingable = list.Any(p => p.Rtt != null && now - p.Time <= TimeSpan.FromMinutes(5));
        var recent = list.Where(p => now - p.Time <= RecentWindow).ToList();
        if (!pingable || recent.Count == 0) return (null, null, 0, pingable);
        var ok = recent.Where(p => p.Rtt != null).Select(p => p.Rtt!.Value).ToList();
        var loss = 100.0 * (recent.Count - ok.Count) / recent.Count;
        double? avg = ok.Count > 0 ? ok.Average() : null;
        // Jitter as the mean difference between consecutive round trips (the idea of RFC 3550).
        double? jitter = ok.Count > 1 ? ok.Zip(ok.Skip(1), (a, b) => Math.Abs(b - a)).Average() : null;
        return (avg, jitter, loss, true);
    }

    /// <summary>Buckets pings, resends and outages into chart points in one pass over the data.</summary>
    private List<ChartPoint> Chart(List<Server> servers, DateTimeOffset now, DateTimeOffset from, int points)
    {
        var step = (now - from).Ticks / (double)points;
        int Bucket(DateTimeOffset t) => Math.Clamp((int)((t - from).Ticks / step), 0, points - 1);

        var pingSum = new double[points];
        var pingOk = new int[points];
        var pingAll = new int[points];
        var anyPingOk = false;
        foreach (var key in servers.Select(s => IpKey.From(s.Ip)).Distinct())
        {
            if (!_pings.TryGetValue(key, out var list)) continue;
            foreach (var p in list)
            {
                if (p.Time < from) continue;
                var b = Bucket(p.Time);
                pingAll[b]++;
                if (p.Rtt is { } rtt)
                {
                    pingOk[b]++;
                    pingSum[b] += rtt;
                    anyPingOk = true;
                }
            }
        }

        var outPk = new long[points];
        var resends = new long[points];
        foreach (var s in servers)
        {
            if (s.Proto != "TCP") continue;
            foreach (var t in s.Ticks)
            {
                if (t.Time < from) continue;
                var b = Bucket(t.Time);
                outPk[b] += t.Out;
                resends[b] += t.Retrans;
            }
        }

        // A program is down in a bucket only when every server it talked to then was silent:
        // one of thirty servers not answering is not "no link".
        var packets = new long[points];
        var activeServers = new int[points];
        var silentServers = new int[points];
        foreach (var s in servers)
        {
            var active = new bool[points];
            foreach (var t in s.Ticks)
            {
                if (t.Time < from || t.Out + t.In == 0) continue;
                var b = Bucket(t.Time);
                active[b] = true;
                packets[b] += t.Out + t.In;
            }
            var silent = new bool[points];
            foreach (var o in Outages(s, now))
            {
                if ((o.End ?? now) < from) continue;
                for (var b = Bucket(o.Start < from ? from : o.Start); b <= Bucket(o.End ?? now); b++) silent[b] = true;
            }
            for (var b = 0; b < points; b++)
            {
                if (!active[b]) continue;
                activeServers[b]++;
                if (silent[b]) silentServers[b]++;
            }
        }

        var result = new List<ChartPoint>(points);
        for (var b = 0; b < points; b++)
        {
            double loss = 0;
            if (anyPingOk && pingAll[b] > 0 && pingOk[b] < pingAll[b]) loss = 100.0 * (pingAll[b] - pingOk[b]) / pingAll[b];
            else if (outPk[b] > 0)
            {
                // A few resends are normal TCP life; only a noticeable share counts as loss.
                var r = Math.Min(100, resends[b] * 100.0 / outPk[b]);
                if (resends[b] >= 3 && r >= 5) loss = r;
            }
            var down = activeServers[b] > 0 && silentServers[b] == activeServers[b];
            result.Add(new ChartPoint(from + TimeSpan.FromTicks((long)(step * b)), pingOk[b] > 0 ? pingSum[b] / pingOk[b] : null, loss, down, packets[b]));
        }
        return result;
    }
}
