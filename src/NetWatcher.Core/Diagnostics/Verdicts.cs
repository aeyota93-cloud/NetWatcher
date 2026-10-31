using System.Net;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Diagnostics;

public enum VerdictLevel
{
    Ok,
    Warn,
    Fail,
}

/// <summary>The one-line answer and its explanation.</summary>
public sealed record Verdict(VerdictLevel Level, string Title, string Text);

/// <summary>Where the route stops or starts losing packets.</summary>
public sealed record TraceAnalysis(bool Reached, HopInfo? LastAnswered, HopInfo? LossFrom, string Where, string Text)
{
    public static TraceAnalysis Of(IReadOnlyList<HopInfo> hops, AsnInfo? targetAsn)
    {
        if (hops.Count == 0) return new(false, null, null, "", "трассировка не выполнялась");

        // The provider is the owner of the first public hop.
        var provider = hops.FirstOrDefault(h => h.Answered && !h.IsPrivate)?.Asn;

        string Segment(HopInfo h)
        {
            if (h.IsPrivate) return h.Ttl == 1 ? "ваш роутер" : "локальная сеть или сеть провайдера за NAT";
            if (h.Asn == null) return "сеть неизвестного владельца";
            if (targetAsn != null && h.Asn.Asn == targetAsn.Asn) return $"сеть владельца сайта ({h.Asn.OwnerText})";
            if (provider != null && h.Asn.Asn == provider.Asn) return $"сеть вашего провайдера ({h.Asn.OwnerText})";
            return $"промежуточная сеть {h.Asn.OwnerText}";
        }

        var reached = hops.Any(h => h.Reached);
        var last = hops.LastOrDefault(h => h.Answered);

        // Loss that starts at a hop and stays until the end is real loss; loss only on
        // a middle hop is usually a router that does not care to answer.
        HopInfo? lossFrom = null;
        var answered = hops.Where(h => h.Answered).ToList();
        if (reached && answered.Count > 0 && answered[^1].LossPercent > 0)
        {
            for (var i = answered.Count - 1; i >= 0 && answered[i].LossPercent > 0; i--) lossFrom = answered[i];
        }

        if (reached)
        {
            var text = $"адрес достигнут за {TextFormat.Plural(hops.Count, "узел", "узла", "узлов")}";
            if (lossFrom != null) text += $"; потери с узла {lossFrom.Ttl} — {Segment(lossFrom)}";
            return new(true, last, lossFrom, lossFrom != null ? Segment(lossFrom) : "", text);
        }

        if (last == null)
            return new(false, null, null, "", "ни один узел не ответил — трассировка блокируется или нет связи даже с роутером");

        var where = Segment(last);
        return new(false, last, null, where,
            $"обрывается после узла {last.Ttl} ({last.Address}) — {where}. Узлы, которые молчат посередине, — норма; важно, что дальше не отвечает никто");
    }
}

/// <summary>Plain-language rules that turn measurements into an answer.</summary>
public static class Verdicts
{
    public static (StepStatus, string) DescribeDns(DnsProbe sys, DnsProbe ind, AsnDatabase asn)
    {
        var ms = $"{sys.Ms:0} мс";
        if (sys.Sinkhole)
            return (StepStatus.Fail, $"системный DNS вернул заглушку {sys.Addresses[0]}" + (ind.Ok ? $", независимый — {ind.Addresses[0]}" : ""));
        if (!sys.Ok && ind.Ok)
            return (StepStatus.Fail, $"системный DNS: {sys.Error ?? "нет ответа"}; независимый нашёл {ind.Addresses[0]}");
        if (!sys.Ok && sys.NotFound && ind.NotFound)
            return (StepStatus.Fail, "домен не существует");
        if (!sys.Ok)
            return (StepStatus.Fail, $"не удалось узнать адрес: {sys.Error ?? "нет ответа"}");
        if (Mismatch(sys, ind, asn))
            return (StepStatus.Warn, $"{sys.Addresses[0]} за {ms}, но независимый DNS отдаёт адреса другой сети ({ind.Addresses[0]})");
        if (sys.Ms > 500)
            return (StepStatus.Warn, $"{sys.Addresses[0]}, но медленно: {ms}");
        return (StepStatus.Ok, $"{sys.Addresses[0]} за {ms}" + (sys.Addresses.Count > 1 ? $" (и ещё {sys.Addresses.Count - 1})" : ""));
    }

    /// <summary>Answers point to different owners: a CDN in another city, or a substituted answer.</summary>
    private static bool Mismatch(DnsProbe sys, DnsProbe ind, AsnDatabase asn)
    {
        if (!sys.Ok || !ind.Ok || sys.Addresses.Intersect(ind.Addresses).Any()) return false;
        var a = sys.Addresses.Select(x => asn.Lookup(x)?.Asn).Where(x => x != null).ToHashSet();
        var b = ind.Addresses.Select(x => asn.Lookup(x)?.Asn).Where(x => x != null).ToHashSet();
        return a.Count > 0 && b.Count > 0 && !a.Overlaps(b);
    }

    public static string DescribeTcp(TcpProbe tcp, IPAddress ip, int port) => tcp.Outcome switch
    {
        TcpOutcome.Ok => $"{ip}:{port} за {tcp.Ms:0} мс",
        TcpOutcome.Timeout => $"{ip}:{port} не ответил за {tcp.Ms / 1000:0} с",
        TcpOutcome.Refused => $"{ip}:{port} отклонил подключение",
        TcpOutcome.Reset => $"{ip}:{port} — подключение сброшено",
        TcpOutcome.Unreachable => $"нет маршрута до {ip}",
        _ => $"{ip}:{port} — {tcp.Error}",
    };

    public static (StepStatus, string) DescribeTls(TlsProbe real, TlsProbe? other, string host)
    {
        if (real.Outcome == TlsOutcome.Ok)
            return (real.Ms > 800 ? StepStatus.Warn : StepStatus.Ok, $"установлено за {real.Ms:0} мс");
        if (real.Outcome == TlsOutcome.Alert)
            return (StepStatus.Warn, "сервер ответил ошибкой TLS — он доступен, но отказал в рукопожатии");
        var cut = real.Outcome == TlsOutcome.Timeout ? "зависает" : "обрывается";
        if (other is { ServerAnswered: true })
            return (StepStatus.Fail, $"с именем {host} {cut}, с другим именем — проходит: фильтрация по имени сайта");
        return (StepStatus.Fail, $"{cut} и с другим именем тоже");
    }

    public static (StepStatus, string) DescribePing(PingProbe p)
    {
        if (p.Error != null && p.Received == 0) return (StepStatus.Skipped, "проверка недоступна: " + p.Error);
        if (p.Received == 0) return (StepStatus.Skipped, "сервер не отвечает на ping — многие так настроены, это не ошибка");
        var text = $"{p.AvgMs:0} мс в среднем, потери {p.LossPercent:0}%";
        return (p.LossPercent >= 20 || p.AvgMs > 200 ? StepStatus.Warn : StepStatus.Ok, text);
    }

    private static string Capital(string s) => s.Length == 0 ? s : char.ToUpper(s[0]) + s[1..];

    public static Verdict Build(CheckReport r)
    {
        var host = r.Target.Host ?? r.Target.Ip?.ToString() ?? "";
        var trace = r.Trace ?? TraceAnalysis.Of(r.Hops, null);
        var traceHint = trace.Reached || r.Hops.Count == 0 ? "" : $" Трасса {trace.Text}.";
        const string vpn = " Если включён VPN, проверка идёт через него.";

        // DNS
        if (r.SystemDns is { } sys && r.IndependentDns is { } ind)
        {
            if (sys.Sinkhole)
                return new(VerdictLevel.Fail, "Домен заблокирован через DNS",
                    $"Системный DNS вместо адреса {host} отвечает заглушкой {sys.Addresses[0]}. Так блокирует провайдер, родительский контроль или фильтр рекламы. " +
                    "Помогает другой DNS (в Windows: Параметры → Сеть → DNS через HTTPS) или VPN.");
            if (!sys.Ok && ind.Ok)
                return new(VerdictLevel.Fail, "Проблема с DNS: системный DNS не отдаёт адрес",
                    $"Ваш DNS-сервер ({sys.Error ?? "нет ответа"}), а независимый DNS знает адрес {ind.Addresses[0]}. " +
                    "Значит, сайт существует, но DNS провайдера или роутера его не отдаёт. Помогает сменить DNS или включить DNS через HTTPS.");
            if (!sys.Ok && sys.NotFound && ind.NotFound)
                return new(VerdictLevel.Fail, "Такого домена нет", $"Ни один DNS-сервер не знает {host}. Проверьте, нет ли опечатки.");
            if (!sys.Ok)
                return new(VerdictLevel.Fail, "DNS не работает",
                    "Ни системный, ни независимый DNS не ответили. Похоже, нет подключения к интернету или DNS полностью недоступен." + vpn);
        }

        // Connection
        if (r.Tcp is { } tcp && r.Address is { } ip)
        {
            var target = $"{ip}:{r.Target.Port}";
            switch (tcp.Outcome)
            {
                case TcpOutcome.Timeout:
                    return new(VerdictLevel.Fail, "Сервер не отвечает на подключение",
                        $"Адрес {target} молчит. Сервер выключен, перегружен или подключение к нему блокируется по адресу.{traceHint}{vpn}");
                case TcpOutcome.Refused:
                    return new(VerdictLevel.Fail, $"Порт {r.Target.Port} закрыт",
                        $"Сервер {ip} доступен, но на порту {r.Target.Port} никто не принимает подключения: служба не запущена или порт закрыт файрволом.");
                case TcpOutcome.Reset:
                    return new(VerdictLevel.Fail, "Подключение сбрасывается",
                        $"Подключение к {target} обрывается сразу. Так ведёт себя блокировка по адресу или защитный фильтр.{vpn}");
                case TcpOutcome.Unreachable:
                    return new(VerdictLevel.Fail, "Нет маршрута до адреса",
                        "Windows не знает, куда отправить пакеты: нет сети, отключён адаптер или не подходит IPv6." + vpn);
                case TcpOutcome.Error:
                    return new(VerdictLevel.Fail, "Не удалось подключиться", tcp.Error ?? "");
            }
        }

        // TLS
        if (r.TlsReal is { Cut: true } real)
        {
            if (r.TlsOther is { ServerAnswered: true })
                return new(VerdictLevel.Fail, "Блокировка по имени сайта (DPI)",
                    $"Подключение к серверу проходит, но защищённое соединение с именем {host} обрывается, а с другим именем — нет. " +
                    "Так работает фильтрация трафика у провайдера по имени сайта. Помогает VPN.");
            return new(VerdictLevel.Fail, "Защищённое соединение не устанавливается",
                $"Подключение к серверу проходит, но рукопожатие TLS {(real.Outcome == TlsOutcome.Timeout ? "зависает" : "обрывается")} с любым именем. " +
                "Это может быть блокировка по адресу или сбой на сервере." + vpn);
        }

        // Works, but maybe badly
        var problems = new List<string>();
        if (r.Ping is { Received: > 0 } ping)
        {
            if (ping.LossPercent >= 20)
                problems.Add($"потери пакетов {ping.LossPercent:0}%" + (trace.LossFrom != null ? $", начиная с узла {trace.LossFrom.Ttl} ({trace.Where})" : ""));
            if (ping.AvgMs > 200) problems.Add($"высокая задержка: {ping.AvgMs:0} мс");
        }
        if (r.Tcp is { Outcome: TcpOutcome.Ok, Ms: > 300 } slowTcp) problems.Add($"подключение долгое: {slowTcp.Ms:0} мс");
        if (r.SystemDns is { Ok: true, Ms: > 500 } slowDns) problems.Add($"DNS отвечает медленно: {slowDns.Ms:0} мс");
        if (r.TlsReal is { Outcome: TlsOutcome.Alert }) problems.Add("сервер отказал в рукопожатии TLS");

        var timings = string.Join(", ", new[]
        {
            r.SystemDns is { Ok: true } d ? $"DNS {d.Ms:0} мс" : "",
            r.Tcp is { Outcome: TcpOutcome.Ok } t ? $"подключение {t.Ms:0} мс" : "",
            r.TlsReal is { Outcome: TlsOutcome.Ok } s ? $"TLS {s.Ms:0} мс" : "",
            r.Ping is { Received: > 0 } p ? $"задержка {p.AvgMs:0} мс" : "",
        }.Where(x => x != ""));

        if (problems.Count > 0)
            return new(VerdictLevel.Warn, "Работает, но с проблемами",
                Capital(string.Join("; ", problems)) + "." + (timings != "" ? $" Замеры: {timings}." : ""));

        return new(VerdictLevel.Ok, "Всё работает", timings != "" ? $"{char.ToUpper(timings[0])}{timings[1..]}." : "Подключение проходит.");
    }
}
