using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Diagnostics;

public sealed record DnsProbe(IReadOnlyList<IPAddress> Addresses, bool NotFound, string? Error, double Ms)
{
    public bool Ok => Addresses.Count > 0;
    public bool Sinkhole => Addresses.Count > 0 && Addresses.All(IpKey.IsSinkhole);
}

public enum TcpOutcome
{
    Ok,
    Timeout,
    Refused,
    Reset,
    Unreachable,
    Error,
}

public sealed record TcpProbe(TcpOutcome Outcome, double Ms, string? Error = null);

public enum TlsOutcome
{
    /// <summary>The handshake completed.</summary>
    Ok,

    /// <summary>The server answered with a TLS error — it is reachable and talking.</summary>
    Alert,

    /// <summary>The connection was cut: reset or closed in the middle of the handshake.</summary>
    Reset,
    Timeout,
    Error,
}

public sealed record TlsProbe(TlsOutcome Outcome, double Ms, string? Error = null)
{
    public bool Cut => Outcome is TlsOutcome.Reset or TlsOutcome.Timeout;
    public bool ServerAnswered => Outcome is TlsOutcome.Ok or TlsOutcome.Alert;
}

public sealed record PingProbe(int Sent, int Received, double AvgMs, string? Error = null)
{
    public double LossPercent => Sent == 0 ? 0 : 100.0 * (Sent - Received) / Sent;
}

public sealed record HopProbe(int Ttl, IPAddress? Address, int Sent, int Replies, double? AvgMs, bool Reached);

/// <summary>Network operations used by the check; a fake one is used in tests.</summary>
public interface INetProbe
{
    Task<DnsProbe> ResolveSystemAsync(string host, CancellationToken ct);

    /// <summary>The same name through DNS over HTTPS, past the provider's resolver.</summary>
    Task<DnsProbe> ResolveIndependentAsync(string host, CancellationToken ct);

    Task<TcpProbe> ConnectAsync(IPAddress ip, int port, CancellationToken ct);
    Task<TlsProbe> TlsAsync(IPAddress ip, int port, string serverName, CancellationToken ct);
    Task<PingProbe> PingAsync(IPAddress ip, int count, CancellationToken ct);
    Task<IReadOnlyList<HopProbe>> TraceAsync(IPAddress ip, int maxHops, CancellationToken ct);
}

/// <summary>The real network.</summary>
public sealed class NetProbe(HttpClient http) : INetProbe
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);

    public async Task<DnsProbe> ResolveSystemAsync(string host, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var list = await System.Net.Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            return new DnsProbe(list.Select(IpKey.Normalize).Distinct().ToList(), false, null, sw.Elapsed.TotalMilliseconds);
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.HostNotFound)
        {
            return new DnsProbe([], true, "домен не найден", sw.Elapsed.TotalMilliseconds);
        }
        catch (SocketException e)
        {
            return new DnsProbe([], false, e.SocketErrorCode == SocketError.TryAgain ? "DNS-сервер не ответил" : e.Message, sw.Elapsed.TotalMilliseconds);
        }
    }

    public async Task<DnsProbe> ResolveIndependentAsync(string host, CancellationToken ct)
    {
        // Two public resolvers with the same JSON API; the second one if the first is unreachable.
        string[] servers = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
        var sw = Stopwatch.StartNew();
        string? lastError = null;
        foreach (var server in servers)
        {
            try
            {
                var a = await QueryDoh(server, host, "A", ct).ConfigureAwait(false);
                if (a.Status == 3) return new DnsProbe([], true, "домен не найден", sw.Elapsed.TotalMilliseconds);
                var list = a.Addresses;
                if (list.Count == 0) list = (await QueryDoh(server, host, "AAAA", ct).ConfigureAwait(false)).Addresses;
                return new DnsProbe(list, false, list.Count == 0 ? "нет адресов" : null, sw.Elapsed.TotalMilliseconds);
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
            {
                lastError = e is TaskCanceledException ? "не ответил" : e.Message;
            }
        }
        return new DnsProbe([], false, "независимый DNS недоступен: " + lastError, sw.Elapsed.TotalMilliseconds);
    }

    private async Task<(int Status, List<IPAddress> Addresses)> QueryDoh(string server, string host, string type, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, $"{server}?name={Uri.EscapeDataString(host)}&type={type}");
        req.Headers.Accept.ParseAdd("application/dns-json");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(6));
        using var resp = await http.SendAsync(req, cts.Token).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        return ParseDohJson(await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false));
    }

    /// <summary>Reads {"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]} (RFC 8484 JSON flavour).</summary>
    public static (int Status, List<IPAddress> Addresses) ParseDohJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var status = root.TryGetProperty("Status", out var s) && s.TryGetInt32(out var v) ? v : 2;
        var list = new List<IPAddress>();
        if (root.TryGetProperty("Answer", out var answers) && answers.ValueKind == JsonValueKind.Array)
            foreach (var a in answers.EnumerateArray())
                if (a.TryGetProperty("type", out var t) && t.TryGetInt32(out var type) && type is 1 or 28
                    && a.TryGetProperty("data", out var d) && IpKey.TryParse(d.GetString(), out var ip) && !list.Contains(ip))
                    list.Add(ip);
        return (status, list);
    }

    public async Task<TcpProbe> ConnectAsync(IPAddress ip, int port, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(ConnectTimeout);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(ip, port), cts.Token).ConfigureAwait(false);
            return new TcpProbe(TcpOutcome.Ok, sw.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new TcpProbe(TcpOutcome.Timeout, sw.Elapsed.TotalMilliseconds);
        }
        catch (SocketException e)
        {
            return new TcpProbe(Map(e.SocketErrorCode), sw.Elapsed.TotalMilliseconds, e.Message);
        }
    }

    private static TcpOutcome Map(SocketError e) => e switch
    {
        SocketError.ConnectionRefused => TcpOutcome.Refused,
        SocketError.ConnectionReset or SocketError.ConnectionAborted => TcpOutcome.Reset,
        SocketError.TimedOut => TcpOutcome.Timeout,
        SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.NetworkDown => TcpOutcome.Unreachable,
        _ => TcpOutcome.Error,
    };

    public async Task<TlsProbe> TlsAsync(IPAddress ip, int port, string serverName, CancellationToken ct)
    {
        using var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(ConnectTimeout);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(ip, port), cts.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            return new TlsProbe(TlsOutcome.Error, 0, "не удалось подключиться");
        }

        var sw = Stopwatch.StartNew();
        await using var ssl = new SslStream(new NetworkStream(socket, ownsSocket: false), false);
        using var hs = CancellationTokenSource.CreateLinkedTokenSource(ct);
        hs.CancelAfter(TimeSpan.FromSeconds(6));
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = serverName,
                // Only the handshake matters here, not who signed the certificate.
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            }, hs.Token).ConfigureAwait(false);
            return new TlsProbe(TlsOutcome.Ok, sw.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new TlsProbe(TlsOutcome.Timeout, sw.Elapsed.TotalMilliseconds);
        }
        catch (AuthenticationException e)
        {
            return new TlsProbe(TlsOutcome.Alert, sw.Elapsed.TotalMilliseconds, e.Message);
        }
        catch (IOException e)
        {
            return new TlsProbe(TlsOutcome.Reset, sw.Elapsed.TotalMilliseconds, e.Message);
        }
    }

    public async Task<PingProbe> PingAsync(IPAddress ip, int count, CancellationToken ct)
    {
        using var ping = new Ping();
        int received = 0;
        double total = 0;
        try
        {
            for (var i = 0; i < count; i++)
            {
                var reply = await ping.SendPingAsync(ip, TimeSpan.FromSeconds(2), new byte[32], null, ct).ConfigureAwait(false);
                if (reply.Status == IPStatus.Success)
                {
                    received++;
                    total += reply.RoundtripTime;
                }
            }
            return new PingProbe(count, received, received == 0 ? 0 : total / received);
        }
        catch (PingException e)
        {
            return new PingProbe(count, 0, 0, e.InnerException?.Message ?? e.Message);
        }
    }

    public async Task<IReadOnlyList<HopProbe>> TraceAsync(IPAddress ip, int maxHops, CancellationToken ct)
    {
        // All hops at once: three probes each, so the whole trace takes a few seconds.
        var tasks = Enumerable.Range(1, maxHops).Select(ttl => Hop(ip, ttl, ct)).ToList();
        var hops = (await Task.WhenAll(tasks).ConfigureAwait(false)).OrderBy(h => h.Ttl).ToList();
        var end = hops.FindIndex(h => h.Reached);
        return end >= 0 ? hops.Take(end + 1).ToList() : hops;
    }

    private static async Task<HopProbe> Hop(IPAddress target, int ttl, CancellationToken ct)
    {
        using var ping = new Ping();
        IPAddress? address = null;
        var replies = 0;
        var reached = false;
        double total = 0;
        for (var i = 0; i < 3; i++)
        {
            try
            {
                var sw = Stopwatch.StartNew();
                var r = await ping.SendPingAsync(target, TimeSpan.FromMilliseconds(1500), new byte[32], new PingOptions(ttl, true), ct).ConfigureAwait(false);
                if (r.Status is IPStatus.TtlExpired or IPStatus.TimeExceeded or IPStatus.Success)
                {
                    replies++;
                    total += r.Status == IPStatus.Success && r.RoundtripTime > 0 ? r.RoundtripTime : sw.Elapsed.TotalMilliseconds;
                    address ??= r.Address;
                    reached |= r.Status == IPStatus.Success;
                }
            }
            catch (PingException)
            {
                // Counted as no answer.
            }
        }
        return new HopProbe(ttl, address, 3, replies, replies == 0 ? null : total / replies, reached);
    }
}
