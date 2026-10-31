using System.Collections.Concurrent;
using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using NetWatcher.Core.Net;

namespace NetWatcher.App.Monitoring;

internal readonly record struct EtwConnection(int Pid, UInt128 Ip, int Port, string Proto);

internal readonly record struct EtwDns(int Pid, string Name, string Results, int Status, DateTimeOffset Time);

/// <summary>
/// Event Tracing for Windows: the system's own event stream. Two sessions:
/// the kernel one reports every TCP connect and UDP send with its process id
/// (so short connections and QUIC are not missed); the DNS client one reports
/// "process asked for name X and got addresses Y". Both need administrator rights.
/// </summary>
internal sealed class EtwMonitor : IDisposable
{
    private const string KernelSessionName = "NetWatcher-Kernel";
    private const string DnsSessionName = "NetWatcher-Dns";

    // Microsoft-Windows-DNS-Client
    private static readonly Guid DnsClientProvider = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    private const int DnsQueryCompleted = 3008;

    private readonly ConcurrentDictionary<EtwConnection, byte> _connections = new();
    private readonly ConcurrentQueue<EtwDns> _dns = new();

    // Per destination: SYN sent again (no answer yet) and data packets sent again (loss).
    private readonly ConcurrentDictionary<EtwConnection, int> _reconnects = new();
    private readonly ConcurrentDictionary<EtwConnection, int> _retransmits = new();
    private TraceEventSession? _kernel;
    private TraceEventSession? _dnsSession;

    public event Action<int, string>? ProcessStarted;

    public bool KernelRunning { get; private set; }
    public bool DnsRunning { get; private set; }
    public string? Error { get; private set; }

    public void Start()
    {
        if (TraceEventSession.IsElevated() != true)
        {
            Error = "нет прав администратора";
            return;
        }

        try
        {
            _kernel = new TraceEventSession(KernelSessionName) { StopOnDispose = true };
            _kernel.EnableKernelProvider(
                KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.Process);
            var k = _kernel.Source.Kernel;
            k.TcpIpConnect += d => Add(d.ProcessID, d.daddr, d.dport, "TCP");
            k.TcpIpConnectIPV6 += d => Add(d.ProcessID, d.daddr, d.dport, "TCP");
            k.UdpIpSend += d => Add(d.ProcessID, d.daddr, d.dport, "UDP");
            k.UdpIpSendIPV6 += d => Add(d.ProcessID, d.daddr, d.dport, "UDP");
            k.TcpIpReconnect += d => Count(_reconnects, d.ProcessID, d.daddr, d.dport);
            k.TcpIpReconnectIPV6 += d => Count(_reconnects, d.ProcessID, d.daddr, d.dport);
            k.TcpIpRetransmit += d => Count(_retransmits, d.ProcessID, d.daddr, d.dport);
            k.TcpIpRetransmitIPV6 += d => Count(_retransmits, d.ProcessID, d.daddr, d.dport);
            k.ProcessStart += d => ProcessStarted?.Invoke(d.ProcessID, d.ImageFileName);
            Run(_kernel, "сетевые события ядра", () => KernelRunning = false);
            KernelRunning = true;
        }
        catch (Exception e)
        {
            Error = "сетевые события ядра: " + e.Message;
        }

        try
        {
            _dnsSession = new TraceEventSession(DnsSessionName) { StopOnDispose = true };
            _dnsSession.EnableProvider(DnsClientProvider, TraceEventLevel.Verbose, ulong.MaxValue);
            var parser = new RegisteredTraceEventParser(_dnsSession.Source);
            parser.All += OnDnsEvent;
            Run(_dnsSession, "DNS", () => DnsRunning = false);
            DnsRunning = true;
        }
        catch (Exception e)
        {
            Error = (Error == null ? "" : Error + "; ") + "DNS: " + e.Message;
        }
    }

    private void Run(TraceEventSession session, string what, Action onStop)
    {
        var thread = new Thread(() =>
        {
            try
            {
                session.Source.Process();
            }
            catch (Exception e)
            {
                Error = what + ": " + e.Message;
            }
            onStop();
        })
        {
            IsBackground = true,
            Name = "ETW " + what,
        };
        thread.Start();
    }

    private void Add(int pid, IPAddress ip, int port, string proto)
    {
        if (pid <= 0 || ip == null) return;
        // UDP sends come per packet; keep one entry until the collector takes it.
        _connections.TryAdd(new EtwConnection(pid, IpKey.From(ip), port, proto), 0);
    }

    private static void Count(ConcurrentDictionary<EtwConnection, int> map, int pid, IPAddress ip, int port)
    {
        if (pid <= 0 || ip == null) return;
        map.AddOrUpdate(new EtwConnection(pid, IpKey.From(ip), port, "TCP"), 1, (_, n) => n + 1);
    }

    private static Dictionary<EtwConnection, int> Drain(ConcurrentDictionary<EtwConnection, int> map)
    {
        var result = new Dictionary<EtwConnection, int>();
        foreach (var key in map.Keys)
            if (map.TryRemove(key, out var n)) result[key] = n;
        return result;
    }

    /// <summary>Unanswered SYNs per destination since the last call.</summary>
    public Dictionary<EtwConnection, int> TakeReconnects() => Drain(_reconnects);

    /// <summary>Resent data packets per destination since the last call.</summary>
    public Dictionary<EtwConnection, int> TakeRetransmits() => Drain(_retransmits);

    private void OnDnsEvent(TraceEvent e)
    {
        if ((int)e.ID != DnsQueryCompleted) return;
        try
        {
            var status = (int)Convert.ToInt64(e.PayloadByName("QueryStatus") ?? 0);
            var name = e.PayloadByName("QueryName") as string;
            var results = e.PayloadByName("QueryResults") as string ?? "";
            if (string.IsNullOrEmpty(name)) return;
            if (status == 0 && results == "") return;
            // Failed questions are kept too: they explain "the site does not open".
            _dns.Enqueue(new EtwDns(e.ProcessID, name, results, status, DateTimeOffset.Now));
        }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
        {
            // A malformed event is skipped, the stream goes on.
        }
    }

    /// <summary>Connections seen since the last call.</summary>
    public List<EtwConnection> TakeConnections()
    {
        var list = new List<EtwConnection>(_connections.Count);
        foreach (var key in _connections.Keys)
            if (_connections.TryRemove(key, out _)) list.Add(key);
        return list;
    }

    /// <summary>DNS answers since the last call.</summary>
    public List<EtwDns> TakeDns()
    {
        var list = new List<EtwDns>();
        while (_dns.TryDequeue(out var d)) list.Add(d);
        return list;
    }

    public void Dispose()
    {
        _kernel?.Dispose();
        _dnsSession?.Dispose();
    }
}
