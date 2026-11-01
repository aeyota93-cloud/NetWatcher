using System.Net;
using System.Net.NetworkInformation;
using NetWatcher.App.Native;
using NetWatcher.Core;
using NetWatcher.Core.Diagnostics;
using NetWatcher.Core.Link;
using NetWatcher.Core.Net;

namespace NetWatcher.App.Monitoring;

/// <summary>
/// Keeps the link monitor fed with pings, traces a route once when a server stops answering,
/// and raises Windows notifications for the programs the user asked about.
/// </summary>
internal sealed class LinkService(AppState state) : IDisposable
{
    private static readonly TimeSpan PingEvery = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan RetraceAfter = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan NotifyAgainAfter = TimeSpan.FromMinutes(1);

    private readonly CancellationTokenSource _stop = new();
    private readonly Dictionary<string, DateTime> _traced = [];
    private readonly Dictionary<string, (bool Down, DateTime NotifiedAt, DateTimeOffset Since)> _alerts = [];

    // Connections whose extended statistics were switched on, so it is done once per connection.
    private readonly HashSet<TcpRow> _statsOn = [];
    private bool _statsDenied;

    /// <summary>Shows a Windows notification; set by the main window once it has a tray icon.</summary>
    public Action<string, string, bool>? Notify { get; set; }

    /// <summary>Program title for notifications ("Counter-Strike 2" rather than cs2.exe).</summary>
    public Func<string, string>? TitleOf { get; set; }

    public void Start()
    {
        _ = Task.Run(() => PingLoop(_stop.Token));
        _ = Task.Run(() => WatchLoop(_stop.Token));
        _ = Task.Run(() => QualityLoop(_stop.Token));
    }

    private async Task PingLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var now = DateTimeOffset.Now;
                var targets = state.Link.PingTargets(now, 16);
                await Task.WhenAll(targets.Select(ip => PingOne(ip, ct))).ConfigureAwait(false);
                ReadConnectionRtt(now);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // A failed round is skipped; the next one comes in a few seconds.
            }
            await Task.Delay(PingEvery, ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The round trip time Windows keeps for each open TCP connection of the programs being watched.
    /// It gives a latency for servers that ignore ping. Collection is switched on per connection
    /// (administrator only); without the rights this is skipped for the rest of the run.
    /// </summary>
    private void ReadConnectionRtt(DateTimeOffset now)
    {
        if (_statsDenied) return;
        var wanted = state.Link.ActiveTcpServers(now, TimeSpan.FromSeconds(30));
        if (wanted.Count == 0)
        {
            _statsOn.Clear();
            return;
        }
        var best = new Dictionary<string, double>();
        var open = new HashSet<TcpRow>();
        var asked = 0;
        foreach (var row in TcpTable.Read())
        {
            if (!TcpEStats.Usable(row) || asked >= 256) continue;
            var key = LinkMonitor.KeyOf(state.Collector.GroupKeyOf(row.Pid), "TCP", row.RemoteIp, row.RemotePort);
            if (!wanted.Contains(key)) continue;
            asked++;
            open.Add(row);
            if (!_statsOn.Contains(row))
            {
                var result = TcpStats.Enable(row);
                if (result == TcpStats.AccessDenied)
                {
                    _statsDenied = true;
                    return;
                }
                if (result != 0) continue;
                _statsOn.Add(row);
            }
            // SmoothedRtt is 0 until TCP has a sample; several connections to one server: the best one.
            if (TcpStats.Read(row) is { SmoothedRtt: > 0 } stats)
                best[key] = best.TryGetValue(key, out var b) ? Math.Min(b, stats.SmoothedRtt) : stats.SmoothedRtt;
        }
        _statsOn.IntersectWith(open);
        foreach (var (key, rtt) in best) state.Link.AddConnectionRtt(key, now, rtt);
    }

    // Internet reference points: Cloudflare and Google public DNS answer ping from almost everywhere.
    private static readonly IPAddress[] InternetTargets = [IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8")];
    private int _internetTarget;
    private int _internetMisses;
    private IPAddress? _gateway;
    private DateTime _gatewayAt = DateTime.MinValue;

    /// <summary>The router and the internet reference point being pinged now, for the window.</summary>
    public (IPAddress? Gateway, IPAddress Internet) QualityTargets => (_gateway, InternetTargets[_internetTarget]);

    /// <summary>
    /// Every 2 seconds: ping the router (is the home network, often Wi-Fi, fine?) and an internet point (the
    /// whole way out). Together with the computer's traffic this shows latency under load. Can be turned off.
    /// </summary>
    private async Task QualityLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (state.Settings.QualityPings)
                {
                    if (DateTime.UtcNow - _gatewayAt > TimeSpan.FromMinutes(1))
                    {
                        _gateway = DefaultGateway();
                        _gatewayAt = DateTime.UtcNow;
                    }
                    var now = DateTimeOffset.Now;
                    var internet = InternetTargets[_internetTarget];
                    var gatewayTask = _gateway is { } gw ? PingRtt(gw, ct) : Task.FromResult<double?>(null);
                    var internetTask = PingRtt(internet, ct);
                    var (g, i) = (await gatewayTask.ConfigureAwait(false), await internetTask.ConfigureAwait(false));
                    if (_gateway != null) state.Quality.AddPing(true, now, g);
                    state.Quality.AddPing(false, now, i);
                    // A reference point that stops answering (blocked in this network): try the other one.
                    _internetMisses = i == null ? _internetMisses + 1 : 0;
                    if (_internetMisses >= 10)
                    {
                        _internetTarget = (_internetTarget + 1) % InternetTargets.Length;
                        _internetMisses = 0;
                    }
                }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // A failed round is skipped.
            }
            await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
        }
    }

    /// <summary>IPv4 gateway of the first working network adapter that has one.</summary>
    private static IPAddress? DefaultGateway()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    private static async Task<double?> PingRtt(IPAddress ip, CancellationToken ct)
    {
        using var ping = new Ping();
        try
        {
            var r = await ping.SendPingAsync(ip, TimeSpan.FromSeconds(1), new byte[32], null, ct).ConfigureAwait(false);
            return r.Status == IPStatus.Success ? r.RoundtripTime : null;
        }
        catch (PingException)
        {
            return null;
        }
    }

    private async Task PingOne(IPAddress ip, CancellationToken ct)
    {
        using var ping = new Ping();
        double? rtt = null;
        try
        {
            var r = await ping.SendPingAsync(ip, TimeSpan.FromSeconds(1), new byte[32], null, ct).ConfigureAwait(false);
            if (r.Status == IPStatus.Success) rtt = r.RoundtripTime;
        }
        catch (PingException)
        {
            // No answer.
        }
        state.Link.AddPing(ip, DateTimeOffset.Now, rtt);
    }

    private async Task WatchLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                Check(DateTimeOffset.Now);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // Watching must never bring the program down.
            }
            await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
        }
    }

    private void Check(DateTimeOffset now)
    {
        var programs = state.Link.Snapshot(now, TimeSpan.FromMinutes(2), chartPoints: 1);
        var anyOk = programs.Any(p => p.Level == LinkLevel.Ok);
        foreach (var key in _traced.Where(t => DateTime.UtcNow - t.Value > RetraceAfter).Select(t => t.Key).ToList()) _traced.Remove(key);

        foreach (var p in programs)
        {
            // Trace the route once per broken server, to say where it breaks.
            foreach (var s in p.Servers.Where(s => s.Level == LinkLevel.Fail))
            {
                if (_traced.TryGetValue(s.Key, out var at) && DateTime.UtcNow - at < RetraceAfter) continue;
                _traced[s.Key] = DateTime.UtcNow;
                _ = Task.Run(() => TraceAsync(s.Key, s.Ip));
            }

            var wanted = state.Settings.NotifyFor(p.GroupKey);
            _alerts.TryGetValue(p.GroupKey, out var alert);
            var title = TitleOf?.Invoke(p.GroupKey) ?? p.Process;
            if (p.Level == LinkLevel.Fail && !alert.Down)
            {
                var since = p.OutageList.LastOrDefault(o => o.End == null)?.Start ?? now;
                if (wanted && DateTime.UtcNow - alert.NotifiedAt > NotifyAgainAfter)
                {
                    var reason = p.Servers.FirstOrDefault(s => s.Level == LinkLevel.Fail)?.Reason ?? "";
                    Notify?.Invoke($"{title}: пропала связь с сервером",
                        $"{Capital(p.StateText)}. {reason}" + (anyOk ? " Другие программы получают ответы." : ""), true);
                    alert = alert with { NotifiedAt = DateTime.UtcNow };
                }
                _alerts[p.GroupKey] = alert with { Down = true, Since = since };
            }
            else if (p.Level != LinkLevel.Fail && alert.Down)
            {
                // Idle means the program stopped trying, not that the server answered again.
                if (wanted && p.Level != LinkLevel.Idle)
                    Notify?.Invoke($"{title}: связь восстановилась", $"Простой {(int)(now - alert.Since).TotalSeconds} с.", false);
                _alerts[p.GroupKey] = alert with { Down = false };
            }
        }
    }

    private async Task TraceAsync(string serverKey, IPAddress ip)
    {
        try
        {
            var hops = await state.Probe.TraceAsync(ip, 20, 3, null, _stop.Token).ConfigureAwait(false);
            var asn = state.Asn;
            var info = hops
                .Select(h => new HopInfo(h.Ttl, h.Addresses, h.Address != null && !IpKey.IsPrivate(h.Address) ? asn.Lookup(h.Address) : null,
                    h.Sent, h.Replies, h.AvgMs, h.BestMs, h.WorstMs, h.Reached))
                .ToList();
            var analysis = TraceAnalysis.Of(info, asn.Lookup(ip));
            state.Link.SetNote(serverKey, "трасса: " + analysis.Text.Split(". Молчащие")[0]);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            state.Link.SetNote(serverKey, "трассу выполнить не удалось");
        }
    }

    private static string Capital(string s) => s.Length == 0 ? s : char.ToUpper(s[0]) + s[1..];

    public void Dispose() => _stop.Cancel();
}
