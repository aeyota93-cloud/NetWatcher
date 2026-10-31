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

/// <summary>One line of the check: "DNS", "Подключение", "TLS", "Задержка", "Трасса".</summary>
public sealed record CheckStep(string Id, string Title, StepStatus Status, string Text);

/// <summary>A hop of the route with its owner.</summary>
public sealed record HopInfo(int Ttl, IPAddress? Address, AsnInfo? Asn, int Sent, int Replies, double? AvgMs, bool Reached)
{
    public bool Answered => Address != null;
    public bool IsPrivate => Address != null && IpKey.IsPrivate(Address);
    public double LossPercent => Sent == 0 ? 0 : 100.0 * (Sent - Replies) / Sent;

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
            t = uri.Host.Trim('[', ']');
            return Make(t, port);
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

/// <summary>Everything the check found, step by step.</summary>
public sealed class CheckReport
{
    public required CheckTarget Target { get; init; }
    public DateTimeOffset Started { get; init; } = DateTimeOffset.Now;
    public DnsProbe? SystemDns { get; set; }
    public DnsProbe? IndependentDns { get; set; }
    public IPAddress? Address { get; set; }
    public TcpProbe? Tcp { get; set; }
    public TlsProbe? TlsReal { get; set; }
    public TlsProbe? TlsOther { get; set; }
    public PingProbe? Ping { get; set; }
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
            sb.AppendLine("Трасса:");
            foreach (var h in Hops)
                sb.AppendLine(h.Address == null
                    ? $"{h.Ttl,3}  *"
                    : $"{h.Ttl,3}  {h.Address,-40} {(h.AvgMs is { } ms ? $"{ms:0} мс" : ""),-8} {(h.LossPercent > 0 ? $"потери {h.LossPercent:0}%" : ""),-12} {h.OwnerText}");
        }
        return sb.ToString().TrimEnd();
    }
}

/// <summary>Runs the steps in order and reports each one as it finishes.</summary>
public static class Checker
{
    public const string FakeServerName = "www.example.com";

    public static async Task<CheckReport> RunAsync(
        CheckTarget target,
        INetProbe probe,
        AsnDatabase asn,
        Action<CheckStep>? progress,
        CancellationToken ct = default)
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

        // 1. DNS
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

        if (report.Address is not { } ip)
        {
            Step("tcp", "Подключение", StepStatus.Skipped, "нет адреса");
            Step("tls", "Защищённое соединение", StepStatus.Skipped, "нет адреса");
            Step("ping", "Задержка", StepStatus.Skipped, "нет адреса");
            Step("trace", "Трасса", StepStatus.Skipped, "нет адреса");
            report.Verdict = Verdicts.Build(report);
            return report;
        }

        // 2. TCP
        Step("tcp", "Подключение", StepStatus.Running, $"{ip} порт {target.Port}…");
        report.Tcp = await probe.ConnectAsync(ip, target.Port, ct).ConfigureAwait(false);
        Step("tcp", "Подключение", report.Tcp.Outcome == TcpOutcome.Ok ? (report.Tcp.Ms > 300 ? StepStatus.Warn : StepStatus.Ok) : StepStatus.Fail,
            Verdicts.DescribeTcp(report.Tcp, ip, target.Port));

        // 3. TLS: with the real name and with a neutral one, to tell filtering by name from other failures.
        if (report.Tcp.Outcome == TcpOutcome.Ok && target.Host != null && target.Port is 443 or 8443 or 853)
        {
            Step("tls", "Защищённое соединение", StepStatus.Running, "рукопожатие TLS…");
            report.TlsReal = await probe.TlsAsync(ip, target.Port, target.Host, ct).ConfigureAwait(false);
            if (report.TlsReal.Cut)
                report.TlsOther = await probe.TlsAsync(ip, target.Port, FakeServerName, ct).ConfigureAwait(false);
            var (status, text) = Verdicts.DescribeTls(report.TlsReal, report.TlsOther, target.Host);
            Step("tls", "Защищённое соединение", status, text);
        }
        else
        {
            Step("tls", "Защищённое соединение", StepStatus.Skipped,
                report.Tcp.Outcome != TcpOutcome.Ok ? "нет подключения" : target.Host == null ? "нужно имя сайта, а не IP" : "порт не HTTPS");
        }

        // 4. Ping and 5. trace run together.
        Step("ping", "Задержка", StepStatus.Running, "проверочные пакеты…");
        Step("trace", "Трасса", StepStatus.Running, "ищем путь…");
        var pingTask = probe.PingAsync(ip, 5, ct);
        var traceTask = probe.TraceAsync(ip, 20, ct);
        await Task.WhenAll(pingTask, traceTask).ConfigureAwait(false);
        report.Ping = pingTask.Result;
        var (ps, pt) = Verdicts.DescribePing(report.Ping);
        Step("ping", "Задержка", ps, pt);

        report.Hops = traceTask.Result
            .Select(h => new HopInfo(h.Ttl, h.Address, h.Address != null && !IpKey.IsPrivate(h.Address) ? asn.Lookup(h.Address) : null,
                h.Sent, h.Replies, h.AvgMs, h.Reached))
            .ToList();
        var trace = report.Trace = TraceAnalysis.Of(report.Hops, asn.Lookup(ip));
        Step("trace", "Трасса", trace.Reached ? (trace.LossFrom != null ? StepStatus.Warn : StepStatus.Ok) : StepStatus.Warn, trace.Text);

        report.Verdict = Verdicts.Build(report);
        return report;
    }
}
