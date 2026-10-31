using System.Net;
using System.Text;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Diagnostics;

public enum StepStatus
{
    Waiting,
    Running,
    Ok,
    Warn,
    Fail,
    Skipped,
}

/// <summary>One line of the check: "DNS", "Подключение", "Трасса"…</summary>
public sealed record CheckStep(string Id, string Title, StepStatus Status, string Text);

/// <summary>A hop of the route with its owner and MTR-style statistics.</summary>
public sealed record HopInfo(
    int Ttl,
    IReadOnlyList<IPAddress> Addresses,
    AsnInfo? Asn,
    int Sent,
    int Replies,
    double? AvgMs,
    double? BestMs,
    double? WorstMs,
    bool Reached)
{
    public IPAddress? Address => Addresses.Count > 0 ? Addresses[0] : null;
    public bool Answered => Address != null;
    public bool IsPrivate => Address != null && IpKey.IsPrivate(Address);
    public double LossPercent => Sent == 0 ? 0 : 100.0 * (Sent - Replies) / Sent;

    /// <summary>Several routers answered at this distance: load balancing.</summary>
    public bool Balanced => Addresses.Count > 1;

    public string OwnerText => Address == null ? "" : IsPrivate ? "локальная сеть" : Asn?.OwnerText ?? "";
}

/// <summary>What to check: a name or an address and a port.</summary>
public sealed record CheckTarget(string? Host, IPAddress? Ip, int Port)
{
    public string Display => (Host ?? Ip?.ToString() ?? "") + (Port is 443 or 0 ? "" : ":" + Port);

    /// <summary>
    /// Accepts "example.com", "example.com:8443", "https://example.com/page", "1.2.3.4",
    /// "1.2.3.4:80", "[2a00::1]:443". The port defaults to 443 (80 for http://).
    /// </summary>
    public static CheckTarget? Parse(string? text, int defaultPort = 443)
    {
        var t = (text ?? "").Trim();
        if (t == "") return null;
        var port = defaultPort;
        if (t.Contains("://"))
        {
            if (!Uri.TryCreate(t, UriKind.Absolute, out var uri) || uri.Host == "") return null;
            port = uri.IsDefaultPort ? (uri.Scheme == "http" ? 80 : 443) : uri.Port;
            return Make(uri.Host.Trim('[', ']'), port);
        }
        t = t.Split('/')[0];
        if (t.StartsWith('['))
        {
            var close = t.IndexOf(']');
            if (close < 0) return null;
            if (close + 2 < t.Length && t[close + 1] == ':' && int.TryParse(t[(close + 2)..], out var p6)) port = p6;
            return Make(t[1..close], port);
        }
        if (t.Count(c => c == ':') == 1)
        {
            var parts = t.Split(':');
            if (!int.TryParse(parts[1], out port)) return null;
            t = parts[0];
        }
        return Make(t, port);
    }

    private static CheckTarget? Make(string host, int port)
    {
        if (port is < 1 or > 65535) return null;
        if (IpKey.TryParse(host, out var ip)) return new CheckTarget(null, ip, port);
        host = host.TrimEnd('.').ToLowerInvariant();
        if (host.Length == 0 || host.Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '-' or '_'))) return null;
        return new CheckTarget(host, null, port);
    }
}

/// <summary>Everything the check found.</summary>
public sealed class CheckReport
{
    public required CheckTarget Target { get; init; }
    public DateTimeOffset Started { get; init; } = DateTimeOffset.Now;
    public DnsProbe? SystemDns { get; set; }
    public DnsProbe? IndependentDns { get; set; }
    public WhoamiProbe? WhoamiUdp { get; set; }
    public WhoamiProbe? WhoamiTcp { get; set; }
    public DnsProbe? SystemResolver { get; set; }
    public string? InterceptionWarning { get; set; }
    public IPAddress? Address { get; set; }
    public TcpProbe? Tcp { get; set; }
    public TlsProbe? Tls { get; set; }
    public SniResult? Sni { get; set; }
    public bool? Http3Advertised { get; set; }
    public QuicProbe? Quic { get; set; }
    public PingProbe? Ping { get; set; }
    public MtuProbe? Mtu { get; set; }
    public IReadOnlyList<HopInfo> Hops { get; set; } = [];
    public TraceAnalysis? Trace { get; set; }
    public List<CheckStep> Steps { get; } = [];
    public Verdict? Verdict { get; set; }

    /// <summary>A plain-text report to paste into a chat.</summary>
    public string ToText()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Проверка {Target.Display} — {Started.LocalDateTime:dd.MM.yyyy HH:mm}");
        if (Verdict != null)
        {
            sb.AppendLine($"Итог: {Verdict.Title}");
            sb.AppendLine(Verdict.Text);
        }
        sb.AppendLine();
        foreach (var s in Steps)
        {
            var mark = s.Status switch { StepStatus.Ok => "✓", StepStatus.Warn => "!", StepStatus.Fail => "✗", StepStatus.Skipped => "–", _ => " " };
            sb.AppendLine($"{mark} {s.Title}: {s.Text}");
        }
        if (Hops.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"Трасса ({Hops.Max(h => h.Sent)} проб на узел; потери на промежуточных узлах без потерь дальше — норма):");
            sb.AppendLine("  №  адрес                                    потери  ср.     лучш.   худш.   владелец");
            foreach (var h in Hops)
            {
                if (h.Address == null)
                {
                    sb.AppendLine($"{h.Ttl,3}  *");
                    continue;
                }
                static string Ms(double? v) => v is { } x ? $"{x:0} мс" : "";
                var addr = h.Address + (h.Balanced ? $" (+{h.Addresses.Count - 1})" : "");
                sb.AppendLine($"{h.Ttl,3}  {addr,-40} {h.LossPercent,5:0}%  {Ms(h.AvgMs),-7} {Ms(h.BestMs),-7} {Ms(h.WorstMs),-7} {h.OwnerText}");
            }
        }
        return sb.ToString().TrimEnd();
    }
}

/// <summary>Runs the steps in order and reports each one as it finishes.</summary>
public static class Checker
{
    /// <summary>OONI ts-024 default control SNI; its server is the test helper.</summary>
    public const string ControlSni = "example.org";

    /// <summary>Public resolver used to detect interception (its answers name the resolver that asked).</summary>
    public static readonly IPAddress GoogleDns = IPAddress.Parse("8.8.8.8");

    public const int GoogleAsn = 15169;
    public const int TraceRounds = 10;

    public static async Task<CheckReport> RunAsync(
        CheckTarget target,
        INetProbe probe,
        AsnDatabase asn,
        Action<CheckStep>? progress,
        CancellationToken ct = default,
        Action<IReadOnlyList<HopInfo>>? traceProgress = null)
    {
        var report = new CheckReport { Target = target };

        void Step(string id, string title, StepStatus status, string text)
        {
            var step = new CheckStep(id, title, status, text);
            var i = report.Steps.FindIndex(s => s.Id == id);
            if (i >= 0) report.Steps[i] = step;
            else report.Steps.Add(step);
            progress?.Invoke(step);
        }

        List<HopInfo> ToHops(IReadOnlyList<HopProbe> hops) => hops
            .Select(h => new HopInfo(h.Ttl, h.Addresses, h.Address != null && !IpKey.IsPrivate(h.Address) ? asn.Lookup(h.Address) : null,
                h.Sent, h.Replies, h.AvgMs, h.BestMs, h.WorstMs, h.Reached))
            .ToList();

        // 1. DNS and DNS interception, side by side.
        Step("dnsint", "Перехват DNS", StepStatus.Running, "спрашиваем 8.8.8.8 напрямую…");
        var interceptTask = Task.WhenAll(
            probe.WhoamiAsync(GoogleDns, false, ct),
            probe.WhoamiAsync(GoogleDns, true, ct));
        // whoami.akamai.net answers with the address of the resolver that asked it.
        var resolverTask = probe.ResolveSystemAsync("whoami.akamai.net", ct);

        if (target.Host is { } host)
        {
            Step("dns", "DNS", StepStatus.Running, "узнаём адрес…");
            var sysTask = probe.ResolveSystemAsync(host, ct);
            var indTask = probe.ResolveIndependentAsync(host, ct);
            await Task.WhenAll(sysTask, indTask).ConfigureAwait(false);
            report.SystemDns = sysTask.Result;
            report.IndependentDns = indTask.Result;
            var (status, text) = Verdicts.DescribeDns(report.SystemDns, report.IndependentDns, asn);
            Step("dns", "DNS", status, text);
            report.Address = report.SystemDns.Addresses.FirstOrDefault(a => !IpKey.IsSinkhole(a))
                             ?? report.IndependentDns.Addresses.FirstOrDefault();
        }
        else
        {
            report.Address = target.Ip;
            Step("dns", "DNS", StepStatus.Skipped, "адрес указан напрямую");
        }

        var whoami = await interceptTask.ConfigureAwait(false);
        report.WhoamiUdp = whoami[0];
        report.WhoamiTcp = whoami[1];
        report.SystemResolver = await resolverTask.ConfigureAwait(false);
        var (ist, itx) = Verdicts.DescribeInterception(report.WhoamiUdp, report.WhoamiTcp, report.SystemResolver, asn);
        Step("dnsint", "Перехват DNS", ist, itx);
        report.InterceptionWarning = Verdicts.InterceptionSummary(report.WhoamiUdp, report.WhoamiTcp, asn);

        if (report.Address is not { } ip)
        {
            foreach (var (id, title) in new[] { ("tcp", "Подключение"), ("tls", "Защищённое соединение"), ("quic", "HTTP/3 (QUIC, UDP 443)"), ("ping", "Задержка"), ("mtu", "Размер пакетов (MTU)"), ("trace", "Трасса") })
                Step(id, title, StepStatus.Skipped, "нет адреса");
            report.Verdict = Verdicts.Build(report);
            return report;
        }

        // 2. TCP
        Step("tcp", "Подключение", StepStatus.Running, $"{ip} порт {target.Port}…");
        report.Tcp = await probe.ConnectAsync(ip, target.Port, ct).ConfigureAwait(false);
        Step("tcp", "Подключение", report.Tcp.Outcome == TcpOutcome.Ok ? (report.Tcp.Ms > 300 ? StepStatus.Warn : StepStatus.Ok) : StepStatus.Fail,
            Verdicts.DescribeTcp(report.Tcp, ip, target.Port));

        var https = target.Host != null && target.Port is 443 or 8443;

        // 3. TLS to the site, with the certificate checked.
        if (report.Tcp.Outcome == TcpOutcome.Ok && https)
        {
            Step("tls", "Защищённое соединение", StepStatus.Running, "рукопожатие TLS…");
            report.Tls = await probe.TlsAsync(ip, target.Port, target.Host!, ct).ConfigureAwait(false);
            var (status, text) = Verdicts.DescribeTls(report.Tls);
            Step("tls", "Защищённое соединение", status, text);

            // OONI ts-017: a valid certificate for the name means the DNS answer was genuine,
            // even when another resolver points to a different network (a CDN picking a nearer server).
            if (report is { SystemDns: { } sys, IndependentDns: { } ind, Tls: { Outcome: TlsOutcome.Ok, Cert: CertStatus.Valid } }
                && Verdicts.Mismatch(sys, ind, asn))
                Step("dns", "DNS", StepStatus.Ok,
                    $"{sys.Addresses[0]} за {sys.Ms:0} мс; независимый DNS дал адрес другой сети, но сертификат сайта действителен — это CDN, а не подмена");

            // 3a. When the handshake fails: is it the name? OONI ts-024 — the same neutral server,
            // once with the site's name and once with a control name.
            if (report.Tls.Cut || report.Tls.Outcome is TlsOutcome.Alert or TlsOutcome.Error)
            {
                Step("sni", "Фильтр по имени (SNI)", StepStatus.Running, $"сравниваем с контрольным именем {ControlSni}…");
                report.Sni = await RunSniAsync(probe, target.Host!, ct).ConfigureAwait(false);
                Step("sni", "Фильтр по имени (SNI)", report.Sni.IsInterference || report.Sni.Code == "anomaly.timeout" ? StepStatus.Fail
                    : report.Sni.Code == "success.got_server_hello" ? StepStatus.Ok : StepStatus.Warn, report.Sni.Text);
            }
        }
        else
        {
            Step("tls", "Защищённое соединение", StepStatus.Skipped,
                report.Tcp.Outcome != TcpOutcome.Ok ? "нет подключения" : target.Host == null ? "нужно имя сайта, а не IP" : "порт не HTTPS");
        }

        // 4. HTTP/3: only if the site says it speaks it, otherwise silence proves nothing.
        if (report.Tls is { Outcome: TlsOutcome.Ok } && target.Port == 443)
        {
            Step("quic", "HTTP/3 (QUIC, UDP 443)", StepStatus.Running, "проверяем…");
            report.Http3Advertised = await probe.AdvertisesHttp3Async(target.Host!, target.Port, ct).ConfigureAwait(false);
            if (report.Http3Advertised == true)
                report.Quic = await probe.QuicAsync(ip, target.Port, target.Host!, ct).ConfigureAwait(false);
            var (qs, qt) = Verdicts.DescribeQuic(report.Http3Advertised, report.Quic);
            Step("quic", "HTTP/3 (QUIC, UDP 443)", qs, qt);
        }
        else
        {
            Step("quic", "HTTP/3 (QUIC, UDP 443)", StepStatus.Skipped, "нужно работающее HTTPS-соединение");
        }

        // 5. Ping and the MTR-style trace together, then the packet size.
        Step("ping", "Задержка", StepStatus.Running, "проверочные пакеты…");
        Step("trace", "Трасса", StepStatus.Running, $"{TraceRounds} проб на каждый узел…");
        var pingTask = probe.PingAsync(ip, 10, ct);
        var traceTask = probe.TraceAsync(ip, 20, TraceRounds, hops => traceProgress?.Invoke(ToHops(hops)), ct);
        await Task.WhenAll(pingTask, traceTask).ConfigureAwait(false);
        report.Ping = pingTask.Result;
        var (ps, pt) = Verdicts.DescribePing(report.Ping);
        Step("ping", "Задержка", ps, pt);

        report.Hops = ToHops(traceTask.Result);
        var trace = report.Trace = TraceAnalysis.Of(report.Hops, asn.Lookup(ip));
        Step("trace", "Трасса", trace.Reached ? (trace.LossFrom != null ? StepStatus.Warn : StepStatus.Ok) : StepStatus.Warn, trace.Text);

        Step("mtu", "Размер пакетов (MTU)", StepStatus.Running, "ищем самый большой проходящий пакет…");
        report.Mtu = await probe.MtuAsync(ip, ct).ConfigureAwait(false);
        var (ms, mt) = Verdicts.DescribeMtu(report.Mtu);
        Step("mtu", "Размер пакетов (MTU)", ms, mt);

        report.Verdict = Verdicts.Build(report);
        return report;
    }

    /// <summary>OONI ts-024: target and control handshakes against the control name's server.</summary>
    private static async Task<SniResult> RunSniAsync(INetProbe probe, string host, CancellationToken ct)
    {
        var helper = await probe.ResolveSystemAsync(ControlSni, ct).ConfigureAwait(false);
        if (helper.Addresses.FirstOrDefault(a => !IpKey.IsSinkhole(a)) is not { } helperIp)
            return SniResult.Classify(null, null);
        var target = await probe.TlsAsync(helperIp, 443, host, ct).ConfigureAwait(false);
        var control = await probe.TlsAsync(helperIp, 443, ControlSni, ct).ConfigureAwait(false);
        return SniResult.Classify(target, control);
    }
}
