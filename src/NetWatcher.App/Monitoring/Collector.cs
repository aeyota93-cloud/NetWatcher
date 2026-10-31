using System.Net;
using NetWatcher.App.Native;
using NetWatcher.Core;
using NetWatcher.Core.Dns;
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

    public ServiceTable Services { get; } = new();

    public event Action? Ticked;
    public string? LastError { get; private set; }

    public Collector(LogStore store, DnsIndex dns, Func<Settings> settings)
    {
        _store = store;
        _dns = dns;
        _settings = settings;
        _etw.ProcessStarted += _processes.NoteStarted;
    }

    public bool DnsCapture => _etw.DnsRunning;
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

        void Add(int pid, IPAddress ip, int port, string proto)
        {
            if (pid <= 0 || IpKey.IsUninteresting(ip, settings.HideLoopback)) return;
            var key = (pid, IpKey.From(ip), port, proto);
            if (seen.ContainsKey(key)) return;
            var p = _processes.Get(pid);
            seen[key] = new Observation(p.Name, Services.ForPid(pid), p.Path, proto, IpKey.Normalize(ip), port, now);
        }

        foreach (var row in TcpTable.Read())
            if (row.IsActive) Add(row.Pid, row.RemoteIp, row.RemotePort, "TCP");

        foreach (var c in _etw.TakeConnections())
            Add(c.Pid, IpKey.ToAddress(c.Ip), c.Port, c.Proto);

        var dns = new List<DnsObservation>();
        foreach (var d in _etw.TakeDns())
        {
            var process = _processes.Get(d.Pid).Name;
            var (addresses, _) = DnsResultParser.Parse(d.Results);
            foreach (var ip in addresses)
            {
                dns.Add(new DnsObservation(process, d.Name, ip, d.Time));
                _dns.Add(ip, d.Name, process, d.Time);
            }
        }

        _store.Write(seen.Values.ToList(), dns);

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
