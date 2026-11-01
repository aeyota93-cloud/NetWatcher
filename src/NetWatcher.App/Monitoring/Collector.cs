using System.Net;
using NetWatcher.App.Native;
using NetWatcher.Core;
using NetWatcher.Core.Dns;
using NetWatcher.Core.Link;
using NetWatcher.Core.Net;
using NetWatcher.Core.Storage;

namespace NetWatcher.App.Monitoring;

/// <summary>
/// Every few seconds reads the TCP table, takes what ETW saw in between,
/// names the processes and services, and writes it all to the log.
/// </summary>
internal sealed class Collector : IDisposable
{
    private readonly LogStore _store;
    private readonly DnsIndex _dns;
    private readonly Func<Settings> _settings;
    private readonly ProcessTable _processes = new();
    private readonly EtwMonitor _etw = new();
    private readonly CancellationTokenSource _stop = new();
    private DateTime _servicesAt = DateTime.MinValue;
    private DateTime _purgedAt = DateTime.MinValue;

    // A connection attempt still waiting after this long counts as "no answer".
    private static readonly TimeSpan SynTimeout = TimeSpan.FromSeconds(3);
    private readonly Dictionary<(int Pid, int LocalPort, UInt128 Ip, int Port), DateTime> _synSince = [];
    private readonly HashSet<(int, int, UInt128, int)> _synReported = [];

    public ServiceTable Services { get; } = new();

    public event Action? Ticked;
    public string? LastError { get; private set; }

    private readonly LinkMonitor _link;

    public Collector(LogStore store, DnsIndex dns, LinkMonitor link, Func<Settings> settings)
    {
        _link = link;
        _store = store;
        _dns = dns;
        _settings = settings;
        _etw.ProcessStarted += _processes.NoteStarted;
    }

    public bool DnsCapture => _etw.DnsRunning;
    public bool IsElevated { get; } = Microsoft.Diagnostics.Tracing.Session.TraceEventSession.IsElevated() == true;
    public bool KernelCapture => _etw.KernelRunning;
    public string? CaptureError => _etw.Error;

    public void Start()
    {
        _etw.Start();
        var thread = new Thread(Loop) { IsBackground = true, Name = "Collector" };
        thread.Start();
    }

    private void Loop()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                Tick();
                LastError = null;
            }
            catch (Exception e)
            {
                LastError = e.Message;
            }
            Ticked?.Invoke();
            _stop.Token.WaitHandle.WaitOne(TimeSpan.FromSeconds(_settings().PollSeconds));
        }
    }

    private void Tick()
    {
        var settings = _settings();
        var now = DateTimeOffset.Now;

        if (DateTime.UtcNow - _servicesAt > TimeSpan.FromSeconds(30))
        {
            Services.Refresh();
            _processes.Trim();
            _servicesAt = DateTime.UtcNow;
        }

        var seen = new Dictionary<(int Pid, UInt128 Ip, int Port, string Proto), Observation>();

        Observation? Add(int pid, IPAddress ip, int port, string proto)
        {
            if (pid <= 0 || IpKey.IsUninteresting(ip, settings.HideLoopback)) return null;
            var key = (pid, IpKey.From(ip), port, proto);
            if (seen.TryGetValue(key, out var existing)) return existing;
            var p = _processes.Get(pid);
            return seen[key] = new Observation(p.Name, Services.ForPid(pid), p.Path, proto, IpKey.Normalize(ip), port, now);
        }

        void Update(int pid, IPAddress ip, int port, string proto, Func<Observation, Observation> change)
        {
            if (Add(pid, ip, port, proto) is not { } o) return;
            seen[(pid, IpKey.From(ip), port, proto)] = change(o);
        }

        // TCP table: open connections, and attempts stuck without an answer.
        var stillWaiting = new HashSet<(int, int, UInt128, int)>();
        foreach (var row in TcpTable.Read())
        {
            if (!row.IsActive) continue;
            Add(row.Pid, row.RemoteIp, row.RemotePort, "TCP");
            if (row.State == TcpState.Established)
                Update(row.Pid, row.RemoteIp, row.RemotePort, "TCP", o => o with { Established = true });
            // With the kernel events running, every resent SYN is already counted from them; counting a
            // stuck attempt here too would make one slow connection look like two failed ones.
            else if (row.State == TcpState.SynSent && !_etw.KernelRunning)
            {
                var key = (row.Pid, row.LocalPort, IpKey.From(row.RemoteIp), row.RemotePort);
                stillWaiting.Add(key);
                if (!_synSince.TryGetValue(key, out var since)) _synSince[key] = DateTime.UtcNow;
                else if (DateTime.UtcNow - since >= SynTimeout && _synReported.Add(key))
                    Update(row.Pid, row.RemoteIp, row.RemotePort, "TCP", o => o with { NoAnswer = o.NoAnswer + 1 });
            }
        }
        foreach (var key in _synSince.Keys.Where(k => !stillWaiting.Contains(k)).ToList())
        {
            _synSince.Remove(key);
            _synReported.Remove(key);
        }

        foreach (var c in _etw.TakeConnections())
            Add(c.Pid, IpKey.ToAddress(c.Ip), c.Port, c.Proto);
        var reconnects = _etw.TakeReconnects();
        var retransmits = _etw.TakeRetransmits();
        foreach (var (c, n) in reconnects)
            Update(c.Pid, IpKey.ToAddress(c.Ip), c.Port, "TCP", o => o with { NoAnswer = o.NoAnswer + n });
        foreach (var (c, n) in retransmits)
            Update(c.Pid, IpKey.ToAddress(c.Ip), c.Port, "TCP", o => o with { Retransmits = o.Retransmits + n });

        // Link monitor: packets each way per program and server, with resends.
        var flows = new Dictionary<(string Group, UInt128 Ip, int Port, string Proto), FlowSample>();
        void AddFlow(EtwConnection c, long outPk, long inPk, long outB, long inB, int retrans, int noAnswer)
        {
            var ip = IpKey.ToAddress(c.Ip);
            if (IpKey.IsUninteresting(ip, settings.HideLoopback)) return;
            var p = _processes.Get(c.Pid);
            var services = Services.ForPid(c.Pid);
            var group = services == "" ? p.Name : $"{p.Name} · {services}";
            var key = (group, c.Ip, c.Port, c.Proto);
            flows[key] = flows.TryGetValue(key, out var f)
                ? f with
                {
                    PacketsOut = f.PacketsOut + outPk, PacketsIn = f.PacketsIn + inPk, BytesOut = f.BytesOut + outB, BytesIn = f.BytesIn + inB,
                    Retransmits = f.Retransmits + retrans, NoAnswer = f.NoAnswer + noAnswer,
                }
                : new FlowSample(group, p.Name, services, p.Path, ip, c.Port, c.Proto, outPk, inPk, outB, inB, retrans, noAnswer);
        }
        foreach (var (c, f) in _etw.TakeFlows()) AddFlow(c, f.PacketsOut, f.PacketsIn, f.BytesOut, f.BytesIn, 0, 0);
        foreach (var (c, n) in retransmits) AddFlow(c, 0, 0, 0, 0, n, 0);
        foreach (var (c, n) in reconnects) AddFlow(c, 0, 0, 0, 0, 0, n);
        _link.Add(now, flows.Values);

        var dns = new List<DnsObservation>();
        var failures = new List<DnsFailure>();
        foreach (var d in _etw.TakeDns())
        {
            var process = _processes.Get(d.Pid).Name;
            if (d.Status != 0)
            {
                if (DnsStatus.IsProblem(d.Status, d.Name)) failures.Add(new DnsFailure(process, d.Name, d.Status, d.Time));
                continue;
            }
            var (addresses, _) = DnsResultParser.Parse(d.Results);
            if (addresses.Count > 0 && addresses.All(IpKey.IsSinkhole))
            {
                // 0.0.0.0 instead of an address: a DNS filter said "no".
                if (DnsStatus.IsProblem(DnsStatus.BlockedAnswer, d.Name))
                    failures.Add(new DnsFailure(process, d.Name, DnsStatus.BlockedAnswer, d.Time));
                continue;
            }
            foreach (var ip in addresses)
            {
                dns.Add(new DnsObservation(process, d.Name, ip, d.Time));
                _dns.Add(ip, d.Name, process, d.Time);
            }
        }

        _store.Write(seen.Values.ToList(), dns);
        _store.WriteDnsFailures(failures);

        if (DateTime.UtcNow - _purgedAt > TimeSpan.FromHours(1))
        {
            var cutoff = now.AddDays(-settings.RetentionDays);
            _store.Purge(cutoff);
            _dns.RemoveOlderThan(cutoff);
            _purgedAt = DateTime.UtcNow;
        }
    }

    /// <summary>Run the cleanup on the next tick, e.g. after the retention setting changed.</summary>
    public void PurgeSoon() => _purgedAt = DateTime.MinValue;

    public void Dispose()
    {
        _stop.Cancel();
        _etw.Dispose();
    }
}
