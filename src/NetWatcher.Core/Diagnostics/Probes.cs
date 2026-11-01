using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
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
    /// <summary>Server Hello received, handshake completed.</summary>
    Ok,

    /// <summary>The server answered with a TLS alert: it is reachable and talking.</summary>
    Alert,

    /// <summary>Connection reset during the handshake (OONI: interference.reset).</summary>
    Reset,

    /// <summary>Connection closed during the handshake (OONI: interference.closed).</summary>
    Closed,
    Timeout,
    Error,
}

/// <summary>What the certificate check said; the handshake goes on regardless.</summary>
public enum CertStatus
{
    NotChecked,
    Valid,

    /// <summary>Certificate for another name (OONI counts ssl_invalid_hostname as success for SNI tests).</summary>
    NameMismatch,

    /// <summary>Signed by an authority Windows does not trust: a proxy, antivirus or interception.</summary>
    UnknownAuthority,

    /// <summary>Expired or otherwise broken.</summary>
    Invalid,
}

public sealed record TlsProbe(TlsOutcome Outcome, double Ms, CertStatus Cert = CertStatus.NotChecked, string? Subject = null, string? Error = null)
{
    public bool Cut => Outcome is TlsOutcome.Reset or TlsOutcome.Closed or TlsOutcome.Timeout;
}

public sealed record PingProbe(int Sent, int Received, double AvgMs, string? Error = null)
{
    public double LossPercent => Sent == 0 ? 0 : 100.0 * (Sent - Received) / Sent;
}

/// <summary>Statistics of one hop over several rounds, like a line of MTR.</summary>
public sealed record HopProbe(int Ttl, IReadOnlyList<IPAddress> Addresses, int Sent, int Replies, double? AvgMs, double? BestMs, double? WorstMs, bool Reached)
{
    public IPAddress? Address => Addresses.Count > 0 ? Addresses[0] : null;
}

/// <summary>Which resolver really answered a question sent to a public DNS server.</summary>
public sealed record WhoamiProbe(IPAddress? Resolver, string? Error);

public enum QuicOutcome
{
    Ok,
    Timeout,
    Error,

    /// <summary>QUIC needs Windows 11 / Server 2022 or newer.</summary>
    NotSupported,
}

public sealed record QuicProbe(QuicOutcome Outcome, double Ms, string? Error = null);

/// <summary>Largest ping payload that passed with "do not fragment".</summary>
public sealed record MtuProbe(int? MaxPayload, bool TooBigReported, bool Ipv6, string? Error = null)
{
    /// <summary>Payload + IP and ICMP headers.</summary>
    public int? PathMtu => MaxPayload is { } p ? p + (Ipv6 ? 48 : 28) : null;

    /// <summary>The usual Ethernet payload limit for the probe.</summary>
    public int FullPayload => Ipv6 ? 1452 : 1472;
}

/// <summary>Network operations used by the check; a scripted one is used in tests.</summary>
public interface INetProbe
{
    Task<DnsProbe> ResolveSystemAsync(string host, CancellationToken ct);

    /// <summary>The same name through DNS over HTTPS, past the provider's resolver.</summary>
    Task<DnsProbe> ResolveIndependentAsync(string host, CancellationToken ct);

    /// <summary>TXT o-o.myaddr.l.google.com asked straight from <paramref name="server"/> over UDP or TCP.</summary>
    Task<WhoamiProbe> WhoamiAsync(IPAddress server, bool tcp, CancellationToken ct);

    Task<TcpProbe> ConnectAsync(IPAddress ip, int port, CancellationToken ct);
    Task<TlsProbe> TlsAsync(IPAddress ip, int port, string serverName, CancellationToken ct);

    /// <summary>
    /// The UDP port the site advertises for HTTP/3 in its Alt-Svc header; 0 when it does not, null when unknown.
    /// </summary>
    Task<int?> Http3PortAsync(string host, int port, CancellationToken ct);

    Task<QuicProbe> QuicAsync(IPAddress ip, int port, string serverName, CancellationToken ct);
    Task<PingProbe> PingAsync(IPAddress ip, int count, CancellationToken ct);
    Task<MtuProbe> MtuAsync(IPAddress ip, CancellationToken ct);

    /// <summary>The VPN adapter that traffic to <paramref name="ip"/> would take, described; null for an ordinary network.</summary>
    string? TunnelTo(IPAddress ip);

    /// <summary>MTR-style: <paramref name="rounds"/> probes per hop, reporting the table after every round.</summary>
    Task<IReadOnlyList<HopProbe>> TraceAsync(IPAddress ip, int maxHops, int rounds, Action<IReadOnlyList<HopProbe>>? progress, CancellationToken ct);
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
        // Two public resolvers with the same JSON API, by address first: their names would go through the
        // system DNS, and a broken system DNS must not take the independent one down with it.
        string[] servers = ["https://1.1.1.1/dns-query", "https://8.8.8.8/resolve", "https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
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

    /// <summary>Reads {"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]} (the JSON flavour of DNS over HTTPS).</summary>
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

    public async Task<WhoamiProbe> WhoamiAsync(IPAddress server, bool tcp, CancellationToken ct)
    {
        var id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        var query = DnsWire.BuildQuery(id, "o-o.myaddr.l.google.com", DnsWire.TypeTxt);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(4));
        try
        {
            byte[] answer;
            if (tcp)
            {
                using var s = new Socket(server.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await s.ConnectAsync(new IPEndPoint(server, 53), cts.Token).ConfigureAwait(false);
                var framed = new byte[query.Length + 2];
                framed[0] = (byte)(query.Length >> 8);
                framed[1] = (byte)query.Length;
                query.CopyTo(framed, 2);
                await s.SendAsync(framed, SocketFlags.None, cts.Token).ConfigureAwait(false);
                var len = new byte[2];
                await ReceiveExactly(s, len, cts.Token).ConfigureAwait(false);
                answer = new byte[len[0] << 8 | len[1]];
                await ReceiveExactly(s, answer, cts.Token).ConfigureAwait(false);
            }
            else
            {
                using var s = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                await s.SendToAsync(query, SocketFlags.None, new IPEndPoint(server, 53), cts.Token).ConfigureAwait(false);
                var buf = new byte[4096];
                var n = await s.ReceiveAsync(buf, SocketFlags.None, cts.Token).ConfigureAwait(false);
                answer = buf[..n];
            }
            var resp = DnsWire.Parse(answer);
            if (resp.Id != id) return new WhoamiProbe(null, "чужой ответ");
            var ip = resp.Answers
                .Where(a => a.Type == DnsWire.TypeTxt)
                .Select(a => IpKey.TryParse(a.Text, out var x) ? x : null)
                .FirstOrDefault(x => x != null);
            return new WhoamiProbe(ip, ip == null ? $"нет адреса в ответе (код {resp.RCode})" : null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new WhoamiProbe(null, "нет ответа");
        }
        catch (Exception e) when (e is SocketException or FormatException)
        {
            return new WhoamiProbe(null, e.Message);
        }
    }

    private static async Task ReceiveExactly(Socket s, byte[] buffer, CancellationToken ct)
    {
        var got = 0;
        while (got < buffer.Length)
        {
            var n = await s.ReceiveAsync(buffer.AsMemory(got), SocketFlags.None, ct).ConfigureAwait(false);
            if (n == 0) throw new SocketException((int)SocketError.ConnectionReset);
            got += n;
        }
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

    /// <summary>Sorts certificate problems the way OONI does for SNI tests.</summary>
    public static CertStatus Classify(SslPolicyErrors errors, X509Chain? chain)
    {
        if (errors == SslPolicyErrors.None) return CertStatus.Valid;
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
        {
            var statuses = chain?.ChainStatus.Select(s => s.Status).ToList() ?? [];
            if (statuses.Any(s => s is X509ChainStatusFlags.UntrustedRoot or X509ChainStatusFlags.PartialChain))
                return CertStatus.UnknownAuthority;
            return CertStatus.Invalid;
        }
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)) return CertStatus.NameMismatch;
        return CertStatus.Invalid;
    }

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
            return new TlsProbe(TlsOutcome.Error, 0, Error: "не удалось подключиться");
        }

        var sw = Stopwatch.StartNew();
        var cert = CertStatus.NotChecked;
        string? subject = null;
        await using var ssl = new SslStream(new NetworkStream(socket, ownsSocket: false), false);
        using var hs = CancellationTokenSource.CreateLinkedTokenSource(ct);
        hs.CancelAfter(TimeSpan.FromSeconds(6));
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = serverName,
                // Record the verdict on the certificate but finish the handshake anyway.
                RemoteCertificateValidationCallback = (_, c, chain, errors) =>
                {
                    cert = Classify(errors, chain);
                    subject = c?.Subject;
                    return true;
                },
            }, hs.Token).ConfigureAwait(false);
            return new TlsProbe(TlsOutcome.Ok, sw.Elapsed.TotalMilliseconds, cert, subject);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new TlsProbe(TlsOutcome.Timeout, sw.Elapsed.TotalMilliseconds);
        }
        catch (AuthenticationException e)
        {
            return new TlsProbe(TlsOutcome.Alert, sw.Elapsed.TotalMilliseconds, Error: e.Message);
        }
        catch (IOException e)
        {
            var reset = e.InnerException is SocketException { SocketErrorCode: SocketError.ConnectionReset or SocketError.ConnectionAborted };
            return new TlsProbe(reset ? TlsOutcome.Reset : TlsOutcome.Closed, sw.Elapsed.TotalMilliseconds, Error: e.Message);
        }
    }

    // Alt-Svc belongs to the origin that sent it, so redirects must not be followed here.
    private static readonly HttpClient NoRedirects = new(new SocketsHttpHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) };

    public async Task<int?> Http3PortAsync(string host, int port, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://{host}:{port}/") { Version = HttpVersion.Version11 };
            req.Headers.UserAgent.ParseAdd("NetWatcher");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(8));
            using var resp = await NoRedirects.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            return resp.Headers.TryGetValues("Alt-Svc", out var values) ? Http3PortOf(string.Join(",", values)) ?? 0 : 0;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads the HTTP/3 port from an Alt-Svc header such as <c>h3=":443"; ma=86400, h3-29=":8443"</c>.
    /// Only alternatives on the same host are taken: another host would need its own address.
    /// </summary>
    public static int? Http3PortOf(string altSvc)
    {
        foreach (var entry in altSvc.Split(','))
        {
            var value = entry.Split(';')[0].Trim();
            var eq = value.IndexOf('=');
            if (eq < 0) continue;
            var protocol = value[..eq].Trim();
            if (!(protocol == "h3" || protocol.StartsWith("h3-", StringComparison.Ordinal))) continue;
            var authority = value[(eq + 1)..].Trim().Trim('"');
            var colon = authority.LastIndexOf(':');
            if (colon < 0) continue;
            if (authority[..colon] != "") continue;
            if (int.TryParse(authority[(colon + 1)..], out var p) && p is > 0 and < 65536) return p;
        }
        return null;
    }

    public async Task<QuicProbe> QuicAsync(IPAddress ip, int port, string serverName, CancellationToken ct)
    {
        if (!QuicConnection.IsSupported) return new QuicProbe(QuicOutcome.NotSupported, 0);
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(ConnectTimeout);
        try
        {
            await using var conn = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(ip, port),
                DefaultStreamErrorCode = 0,
                DefaultCloseErrorCode = 0,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = serverName,
                    ApplicationProtocols = [new SslApplicationProtocol("h3")],
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                },
            }, cts.Token).ConfigureAwait(false);
            return new QuicProbe(QuicOutcome.Ok, sw.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new QuicProbe(QuicOutcome.Timeout, sw.Elapsed.TotalMilliseconds);
        }
        catch (Exception e) when (e is QuicException or AuthenticationException or SocketException)
        {
            return new QuicProbe(QuicOutcome.Error, sw.Elapsed.TotalMilliseconds, e.Message);
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

    public async Task<MtuProbe> MtuAsync(IPAddress ip, CancellationToken ct)
    {
        var v6 = ip.AddressFamily == AddressFamily.InterNetworkV6;
        // IPv6 never fragments in the network, the minimum link MTU is 1280.
        int lo = v6 ? 1232 : 548, hi = v6 ? 1452 : 1472;
        var tooBig = false;
        using var ping = new Ping();

        async Task<IPStatus?> Send(int size)
        {
            // Two tries: one lost packet must not look like an MTU limit.
            IPStatus? last = null;
            for (var i = 0; i < 2; i++)
            {
                try
                {
                    var r = await ping.SendPingAsync(ip, TimeSpan.FromSeconds(2), new byte[size], new PingOptions(64, true), ct).ConfigureAwait(false);
                    if (r.Status == IPStatus.Success) return r.Status;
                    last = r.Status;
                }
                catch (PingException)
                {
                    return null;
                }
            }
            return last;
        }

        if (await Send(lo).ConfigureAwait(false) != IPStatus.Success)
            return new MtuProbe(null, false, v6, "адрес не отвечает на ping — размер пакетов проверить нельзя");
        var full = await Send(hi).ConfigureAwait(false);
        if (full == IPStatus.Success) return new MtuProbe(hi, false, v6);
        tooBig = full == IPStatus.PacketTooBig;

        while (hi - lo > 1)
        {
            var mid = (lo + hi) / 2;
            var status = await Send(mid).ConfigureAwait(false);
            if (status == IPStatus.Success) lo = mid;
            else
            {
                tooBig |= status == IPStatus.PacketTooBig;
                hi = mid;
            }
        }
        return new MtuProbe(lo, tooBig, v6);
    }

    // Words in the names of VPN adapters; PPP is left out on purpose — many providers connect over PPPoE.
    private static readonly string[] TunnelMarks =
        ["vpn", "wireguard", "wintun", "tap-windows", "openvpn", "amnezia", "anyconnect", "nordlynx", "outline", "warp",
         "tailscale", "zerotier", "sing-box", "sing-tun", "v2ray", "hiddify", "tun2socks", "clash", "tunnel"];

    public string? TunnelTo(IPAddress ip)
    {
        try
        {
            // Connecting a UDP socket sends nothing: Windows only picks the route and the local address.
            using var s = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            s.Connect(new IPEndPoint(ip, 443));
            var local = IpKey.Normalize(((IPEndPoint)s.LocalEndPoint!).Address);
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!n.GetIPProperties().UnicastAddresses.Any(u => IpKey.Normalize(u.Address).Equals(local))) continue;
                var text = (n.Name + " " + n.Description).ToLowerInvariant();
                var transition = text.Contains("teredo") || text.Contains("isatap") || text.Contains("6to4");
                // "tun0", "utun3": the usual names of TUN adapters of proxy clients.
                var tunName = n.Name.StartsWith("tun", StringComparison.OrdinalIgnoreCase) || n.Name.StartsWith("utun", StringComparison.OrdinalIgnoreCase);
                return !transition && (n.NetworkInterfaceType == NetworkInterfaceType.Tunnel || tunName || TunnelMarks.Any(text.Contains))
                    ? $"трафик к {ip} идёт через адаптер «{n.Name}» ({n.Description})"
                    : null;
            }
        }
        catch (Exception e) when (e is SocketException or NetworkInformationException)
        {
            // Unknown: say nothing rather than guess.
        }
        return null;
    }

    public async Task<IReadOnlyList<HopProbe>> TraceAsync(IPAddress ip, int maxHops, int rounds, Action<IReadOnlyList<HopProbe>>? progress, CancellationToken ct)
    {
        var stats = Enumerable.Range(1, maxHops).Select(_ => new HopStats()).ToArray();
        var last = maxHops;
        for (var round = 0; round < rounds; round++)
        {
            var started = Stopwatch.StartNew();
            // One probe per hop per round, all hops at once; rounds about a second apart, as MTR does.
            // Once the destination is found, longer TTLs only pile extra pings on it (and on its ICMP limit).
            await Task.WhenAll(Enumerable.Range(1, last).Select(ttl => Probe(ip, ttl, stats[ttl - 1], ct))).ConfigureAwait(false);
            for (var i = 0; i < last; i++)
                lock (stats[i].Lock)
                    if (stats[i].Reached)
                    {
                        last = i + 1;
                        break;
                    }
            progress?.Invoke(Snapshot(stats));
            var wait = TimeSpan.FromSeconds(1) - started.Elapsed;
            if (wait > TimeSpan.Zero && round < rounds - 1) await Task.Delay(wait, ct).ConfigureAwait(false);
        }
        return Snapshot(stats);
    }

    private sealed class HopStats
    {
        public readonly Lock Lock = new();
        public readonly List<IPAddress> Addresses = [];
        public int Sent, Replies;
        public double Sum;
        public double Best = double.MaxValue, Worst;
        public bool Reached;
    }

    private static async Task Probe(IPAddress target, int ttl, HopStats s, CancellationToken ct)
    {
        using var ping = new Ping();
        var sw = Stopwatch.StartNew();
        PingReply? r = null;
        try
        {
            r = await ping.SendPingAsync(target, TimeSpan.FromMilliseconds(1500), new byte[32], new PingOptions(ttl, true), ct).ConfigureAwait(false);
        }
        catch (PingException)
        {
            // Counted as lost.
        }
        var ms = r is { Status: IPStatus.Success, RoundtripTime: > 0 } ? r.RoundtripTime : sw.Elapsed.TotalMilliseconds;
        lock (s.Lock)
        {
            s.Sent++;
            if (r?.Status is IPStatus.TtlExpired or IPStatus.TimeExceeded or IPStatus.Success)
            {
                s.Replies++;
                s.Sum += ms;
                s.Best = Math.Min(s.Best, ms);
                s.Worst = Math.Max(s.Worst, ms);
                if (!s.Addresses.Contains(r.Address)) s.Addresses.Add(r.Address);
                s.Reached |= r.Status == IPStatus.Success;
            }
        }
    }

    private static List<HopProbe> Snapshot(HopStats[] stats)
    {
        var hops = new List<HopProbe>();
        for (var i = 0; i < stats.Length; i++)
        {
            var s = stats[i];
            lock (s.Lock)
            {
                hops.Add(new HopProbe(i + 1, s.Addresses.ToList(), s.Sent, s.Replies,
                    s.Replies == 0 ? null : s.Sum / s.Replies, s.Replies == 0 ? null : s.Best, s.Replies == 0 ? null : s.Worst, s.Reached));
                if (s.Reached) break;
            }
        }
        return hops;
    }
}
