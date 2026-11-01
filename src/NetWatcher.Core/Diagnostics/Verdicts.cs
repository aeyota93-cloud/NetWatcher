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

/// <summary>
/// Result of the SNI test as defined by OONI ts-024: the same neutral server is contacted
/// with the site's name (target) and with a control name. Codes are OONI's own.
/// </summary>
public sealed record SniResult(string Code, string Text)
{
    public bool IsInterference => Code.StartsWith("interference.", StringComparison.Ordinal);

    public static SniResult Classify(TlsProbe? target, TlsProbe? control)
    {
        var helper = Checker.ControlSni;
        if (target == null || control == null || control.Outcome != TlsOutcome.Ok)
            return new("anomaly.test_helper_unreachable",
                $"контрольный сервер {helper} недоступен — отличить фильтр по имени от других причин нельзя");
        return target.Outcome switch
        {
            // OONI counts a certificate for another name (ssl_invalid_hostname) as success: the helper
            // naturally has no certificate for the site's name.
            TlsOutcome.Ok when target.Cert is CertStatus.UnknownAuthority =>
                new("interference.unknown_authority", $"с именем сайта пришёл сертификат неизвестного издателя — ответ подменён по дороге"),
            TlsOutcome.Ok when target.Cert is CertStatus.Invalid =>
                new("interference.invalid_certificate", "с именем сайта пришёл недействительный сертификат — ответ подменён по дороге"),
            TlsOutcome.Ok =>
                new("success.got_server_hello", $"нейтральный сервер {helper} с именем сайта отвечает нормально — фильтра по имени нет"),
            // Many helpers (example.org sits behind Cloudflare) refuse a name they do not serve with a TLS
            // alert. The alert comes from the server after it read the ClientHello: the name got through.
            TlsOutcome.Alert =>
                new("success.got_server_hello", $"нейтральный сервер {helper} получил имя сайта и сам ответил отказом TLS — фильтра по имени нет"),
            TlsOutcome.Reset =>
                new("interference.reset", $"с именем сайта соединение сбрасывается, с контрольным {helper} — проходит"),
            TlsOutcome.Closed =>
                new("interference.closed", $"с именем сайта соединение закрывается, с контрольным {helper} — проходит"),
            TlsOutcome.Timeout =>
                new("anomaly.timeout", $"с именем сайта рукопожатие зависает, с контрольным {helper} — проходит"),
            _ => new("anomaly.unexpected_failure", $"неожиданная ошибка: {target.Error}"),
        };
    }
}

/// <summary>Where the route stops or starts losing packets, read the way MTR output is read.</summary>
public sealed record TraceAnalysis(bool Reached, HopInfo? LastAnswered, HopInfo? LossFrom, bool DestinationOnlyLoss, string Where, string Text)
{
    /// <summary>With ten probes, two lost ones are worth mentioning; one may be chance.</summary>
    public const double LossThreshold = 20;

    public static TraceAnalysis Of(IReadOnlyList<HopInfo> hops, AsnInfo? targetAsn)
    {
        if (hops.Count == 0) return new(false, null, null, false, "", "трассировка не выполнялась");

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
        var balanced = hops.Where(h => h.Balanced).Select(h => h.Ttl).ToList();
        var balanceNote = balanced.Count > 0
            ? $"; на узлах {string.Join(", ", balanced)} отвечают разные роутеры — балансировка нагрузки, трасса может смешивать несколько путей"
            : "";

        if (reached)
        {
            // Real loss starts at a hop and carries on to the destination. Loss on a middle hop
            // that disappears further on is a router limiting its ICMP answers.
            var answered = hops.Where(h => h.Answered).ToList();
            HopInfo? lossFrom = null;
            var destinationOnly = false;
            if (answered[^1].LossPercent >= LossThreshold)
            {
                lossFrom = answered[^1];
                for (var i = answered.Count - 2; i >= 0 && answered[i].LossPercent >= LossThreshold / 2; i--) lossFrom = answered[i];
                destinationOnly = lossFrom == answered[^1];
            }

            var text = $"адрес достигнут за {TextFormat.Plural(hops.Count, "узел", "узла", "узлов")}";
            if (lossFrom != null)
                text += destinationOnly
                    ? $"; теряет ответы только конечный узел ({answered[^1].LossPercent:0}%) — он может сам ограничивать ICMP"
                    : $"; потери с узла {lossFrom.Ttl} до конца пути — {Segment(lossFrom)}";
            return new(true, last, lossFrom, destinationOnly, lossFrom != null ? Segment(lossFrom) : "", text + balanceNote);
        }

        if (last == null)
            return new(false, null, null, false, "", "ни один узел не ответил — трассировка блокируется или нет связи даже с роутером");

        var where = Segment(last);
        return new(false, last, null, false, where,
            $"обрывается после узла {last.Ttl} ({last.Address}) — {where}. Молчащие узлы посередине — норма; важно, что дальше не отвечает никто{balanceNote}");
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

    /// <summary>
    /// OONI ts-017: answers are consistent when they share addresses or AS numbers.
    /// Different owners can still be a CDN choosing a nearer server, so this is only a warning.
    /// </summary>
    public static bool Mismatch(DnsProbe sys, DnsProbe ind, AsnDatabase asn)
    {
        if (!sys.Ok || !ind.Ok || sys.Addresses.Intersect(ind.Addresses).Any()) return false;
        var a = sys.Addresses.Select(x => asn.Lookup(x)?.Asn).Where(x => x != null).ToHashSet();
        var b = ind.Addresses.Select(x => asn.Lookup(x)?.Asn).Where(x => x != null).ToHashSet();
        return a.Count > 0 && b.Count > 0 && !a.Overlaps(b);
    }

    public static (StepStatus, string) DescribeInterception(WhoamiProbe udp, WhoamiProbe tcp, DnsProbe? systemResolver, AsnDatabase asn)
    {
        var resolver = systemResolver is { Ok: true } r
            ? $" Ваш DNS выходит в интернет с адреса {r.Addresses[0]}{Owner(r.Addresses[0], asn)}."
            : "";
        if (asn.Count == 0)
            return (StepStatus.Skipped, "нужна база владельцев IP, чтобы понять, кто ответил." + resolver);

        var u = ResolverOf(udp, asn);
        var t = ResolverOf(tcp, asn);
        const string caveat = " Это признак, а не доказательство.";

        if (u == ResolverKind.Other)
            return (StepStatus.Warn, $"запросы к 8.8.8.8 по UDP перехватываются: ответил резолвер {udp.Resolver}{Owner(udp.Resolver!, asn)}" +
                                     (t == ResolverKind.Google ? ", а по TCP — Google, как и должно быть" : "") + "." + caveat + resolver);
        if (t == ResolverKind.Other)
            return (StepStatus.Warn, $"запросы к 8.8.8.8 по TCP перехватываются: ответил резолвер {tcp.Resolver}{Owner(tcp.Resolver!, asn)}." + caveat + resolver);
        if (u == ResolverKind.Unknown || t == ResolverKind.Unknown)
            return (StepStatus.Skipped, $"ответил адрес {(u == ResolverKind.Unknown ? udp.Resolver : tcp.Resolver)}, которого нет в базе владельцев IP — " +
                                        "понять, Google это или перехват, нельзя. Обновите базу владельцев." + resolver);
        if (u == ResolverKind.NoAnswer && t == ResolverKind.Google)
            return (StepStatus.Warn, "внешний DNS 8.8.8.8 по UDP не отвечает, по TCP — отвечает: UDP-порт 53 к чужим DNS закрыт." + resolver);
        if (u == ResolverKind.NoAnswer && t == ResolverKind.NoAnswer)
            return (StepStatus.Warn, $"8.8.8.8 не отвечает напрямую ни по UDP, ни по TCP ({udp.Error}) — сеть пропускает только свой DNS." + resolver);
        return (StepStatus.Ok, "запросы к 8.8.8.8 доходят до Google без подмены." + resolver);
    }

    /// <summary>One clause for the overall verdict, or null when DNS is not intercepted.</summary>
    public static string? InterceptionSummary(WhoamiProbe udp, WhoamiProbe tcp, AsnDatabase asn)
    {
        if (asn.Count == 0) return null;
        var u = ResolverOf(udp, asn);
        var t = ResolverOf(tcp, asn);
        if (u == ResolverKind.Other || t == ResolverKind.Other) return "запросы к публичному DNS перехватываются по дороге";
        if (u == ResolverKind.Unknown || t == ResolverKind.Unknown) return null;
        if (u == ResolverKind.NoAnswer && t == ResolverKind.Google) return "UDP-порт 53 к чужим DNS закрыт";
        if (u == ResolverKind.NoAnswer && t == ResolverKind.NoAnswer) return "публичные DNS напрямую недоступны";
        return null;
    }

    /// <summary>Who answered a question sent straight to 8.8.8.8.</summary>
    public enum ResolverKind
    {
        /// <summary>No answer at all.</summary>
        NoAnswer,
        Google,

        /// <summary>A known network that is not Google: the question was intercepted.</summary>
        Other,

        /// <summary>The address is missing from the owner database: nothing can be concluded.</summary>
        Unknown,
    }

    public static ResolverKind ResolverOf(WhoamiProbe w, AsnDatabase asn)
    {
        if (w.Resolver == null) return ResolverKind.NoAnswer;
        var owner = asn.Lookup(w.Resolver);
        if (owner == null) return ResolverKind.Unknown;
        return owner.Asn == Checker.GoogleAsn ? ResolverKind.Google : ResolverKind.Other;
    }

    private static string Owner(IPAddress ip, AsnDatabase asn) =>
        asn.Lookup(ip) is { } a ? $" ({a.OwnerText})" : "";

    public static string DescribeTcp(TcpProbe tcp, IPAddress ip, int port) => tcp.Outcome switch
    {
        TcpOutcome.Ok => $"{ip}:{port} за {tcp.Ms:0} мс",
        TcpOutcome.Timeout => $"{ip}:{port} не ответил за {tcp.Ms / 1000:0} с",
        TcpOutcome.Refused => $"{ip}:{port} отклонил подключение",
        TcpOutcome.Reset => $"{ip}:{port} — подключение сброшено",
        TcpOutcome.Unreachable => $"нет маршрута до {ip}",
        _ => $"{ip}:{port} — {tcp.Error}",
    };

    public static (StepStatus, string) DescribeTls(TlsProbe tls) => tls.Outcome switch
    {
        TlsOutcome.Ok => tls.Cert switch
        {
            CertStatus.Valid => (tls.Ms > 800 ? StepStatus.Warn : StepStatus.Ok, $"установлено за {tls.Ms:0} мс, сертификат действителен"),
            CertStatus.NameMismatch => (StepStatus.Warn, $"сертификат выдан на другое имя ({tls.Subject}) — сервер обслуживает другой сайт или ответ подменён"),
            CertStatus.UnknownAuthority => (StepStatus.Warn, $"сертификат от издателя, которому Windows не доверяет ({tls.Subject}) — так бывает с антивирусом, корпоративным прокси или при перехвате трафика"),
            CertStatus.Invalid => (StepStatus.Warn, "сертификат недействителен: истёк или повреждён"),
            _ => (StepStatus.Ok, $"установлено за {tls.Ms:0} мс"),
        },
        TlsOutcome.Alert => (StepStatus.Fail, "сервер ответил ошибкой TLS — он доступен, но защищённое соединение не установлено"),
        TlsOutcome.Reset => (StepStatus.Fail, "соединение сброшено во время рукопожатия"),
        TlsOutcome.Closed => (StepStatus.Fail, "соединение закрыто во время рукопожатия"),
        TlsOutcome.Timeout => (StepStatus.Fail, "рукопожатие зависло"),
        _ => (StepStatus.Fail, tls.Error ?? "ошибка"),
    };

    public static (StepStatus, string) DescribeQuic(bool? advertised, QuicProbe? quic)
    {
        if (advertised == null) return (StepStatus.Skipped, "не удалось узнать, поддерживает ли сайт HTTP/3");
        if (advertised == false) return (StepStatus.Skipped, "сайт не объявляет HTTP/3 — проверять нечего");
        return quic?.Outcome switch
        {
            QuicOutcome.Ok => (StepStatus.Ok, $"работает, рукопожатие за {quic.Ms:0} мс"),
            QuicOutcome.NotSupported => (StepStatus.Skipped, "проверка QUIC доступна в Windows 11 и новее"),
            QuicOutcome.Timeout => (StepStatus.Warn, "сайт объявляет HTTP/3, но UDP 443 не проходит — браузер перейдёт на TCP. Так выглядит фильтрация UDP"),
            _ => (StepStatus.Warn, $"ошибка QUIC: {quic?.Error}"),
        };
    }

    public static (StepStatus, string) DescribePing(PingProbe p)
    {
        if (p.Error != null && p.Received == 0) return (StepStatus.Skipped, "проверка недоступна: " + p.Error);
        if (p.Received == 0) return (StepStatus.Skipped, "адрес не отвечает на ping — многие серверы так настроены, это не ошибка");
        var text = $"{p.AvgMs:0} мс в среднем, потери {p.LossPercent:0}% из {p.Sent}";
        return (p.LossPercent >= TraceAnalysis.LossThreshold || p.AvgMs > 200 ? StepStatus.Warn : StepStatus.Ok, text);
    }

    public static (StepStatus, string) DescribeMtu(MtuProbe m)
    {
        if (m.Error != null) return (StepStatus.Skipped, m.Error);
        if (m.MaxPayload == m.FullPayload) return (StepStatus.Ok, $"пакеты полного размера ({m.PathMtu} байт) проходят");
        if (m.TooBigReported)
            return (StepStatus.Ok, $"MTU пути {m.PathMtu} байт, сеть честно сообщает об ограничении (так бывает с PPPoE, VPN и туннелями)");
        return (StepStatus.Warn, $"пакеты больше {m.PathMtu} байт пропадают без уведомления — похоже на «чёрную дыру» MTU, " +
                                 "но так же выглядит сервер, который не отвечает на большие ping");
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

        // A UDP service: only the path to the server can be checked, not the service itself.
        if (r.Target.Udp && r.Address != null)
        {
            const string service = " Работает ли сама служба, так не проверить: она отвечает только своей программе — смотрите вкладку «Связь».";
            if (r.Ping is { Received: > 0 } up)
                return up.LossPercent >= TraceAnalysis.LossThreshold
                    ? new(VerdictLevel.Warn, "Сервер доступен, но теряет пакеты", $"Задержка {up.AvgMs:0} мс, потери {up.LossPercent:0}%." + service + vpn)
                    : new(VerdictLevel.Ok, "Сервер доступен по сети", $"Задержка {up.AvgMs:0} мс, потерь нет." + service);
            return new(VerdictLevel.Warn, "Сервер не отвечает на проверочные пакеты",
                "Многие игровые и голосовые серверы не отвечают на ping, так что это не доказывает, что сервер недоступен." +
                (r.Hops.Count > 0 ? $" Трасса: {trace.Text}." : "") + service);
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

        // TLS, explained by the OONI ts-024 SNI test. An alert also means HTTPS did not open.
        if (r.Tls is { } tls && (tls.Cut || tls.Outcome is TlsOutcome.Error or TlsOutcome.Alert))
        {
            var failed = tls.Outcome switch
            {
                TlsOutcome.Timeout => "зависает",
                TlsOutcome.Alert => "заканчивается ошибкой TLS от сервера",
                _ => "обрывается",
            };
            const string method = " Проверено по методике OONI (ts-024): нейтральный сервер, имя сайта против контрольного.";
            return r.Sni?.Code switch
            {
                { } c when c.StartsWith("interference.", StringComparison.Ordinal) =>
                    new(VerdictLevel.Fail, "Блокировка по имени сайта (DPI)",
                        $"Сервер сайта доступен, но защищённое соединение с ним не устанавливается, а на нейтральном сервере {Capitalless(r.Sni.Text)}. " +
                        "Значит, соединения режутся по имени сайта (SNI) где-то по пути. Помогает VPN." + method),
                "anomaly.timeout" =>
                    new(VerdictLevel.Fail, "Похоже на блокировку по имени сайта",
                        $"На нейтральном сервере {Capitalless(r.Sni.Text)}. OONI относит такой результат к аномалиям: он типичен для фильтра по имени, но доказательством не является." + method),
                "success.got_server_hello" =>
                    new(VerdictLevel.Fail, "Защищённое соединение с сайтом не устанавливается",
                        $"Фильтра по имени не видно: {r.Sni.Text}. " +
                        (tls.Outcome == TlsOutcome.Alert
                            ? "Сервер сайта сам отказывает в защищённом соединении: сбой или настройка на его стороне."
                            : "Вероятнее блокировка адреса сайта или сбой на его стороне.") + vpn),
                _ =>
                    new(VerdictLevel.Fail, "Защищённое соединение не устанавливается",
                        $"Рукопожатие TLS с {host} {failed}. " +
                        (r.Sni != null ? Capital(r.Sni.Text) + "." : "") + vpn),
            };
        }

        // Works, but maybe badly
        var problems = new List<string>();
        if (r.Tls is { Outcome: TlsOutcome.Ok, Cert: CertStatus.UnknownAuthority or CertStatus.Invalid or CertStatus.NameMismatch } badCert)
            problems.Add(DescribeTls(badCert).Item2);
        if (r.Ping is { Received: > 0 } ping)
        {
            if (ping.LossPercent >= TraceAnalysis.LossThreshold)
                problems.Add(trace.LossFrom == null ? $"потери пакетов {ping.LossPercent:0}%"
                    : trace.DestinationOnlyLoss ? $"потери {ping.LossPercent:0}% только на самом сервере — он может ограничивать ответы на ping"
                    : $"потери пакетов {ping.LossPercent:0}%, начиная с узла {trace.LossFrom.Ttl} ({trace.Where})");
            if (ping.AvgMs > 200) problems.Add($"высокая задержка: {ping.AvgMs:0} мс");
        }
        if (r.Mtu is { Error: null, TooBigReported: false } mtu && mtu.MaxPayload != mtu.FullPayload)
            problems.Add($"пакеты больше {mtu.PathMtu} байт пропадают без уведомления — возможна «чёрная дыра» MTU, при которой мелкие запросы проходят, а крупные загрузки зависают");
        if (r.Quic is { Outcome: QuicOutcome.Timeout })
            problems.Add("HTTP/3 (UDP 443) не проходит — сайты работают через TCP, но это признак фильтрации UDP");
        if (r.Tcp is { Outcome: TcpOutcome.Ok, Ms: > 300 } slowTcp) problems.Add($"подключение долгое: {slowTcp.Ms:0} мс");
        if (r.SystemDns is { Ok: true, Ms: > 500 } slowDns) problems.Add($"DNS отвечает медленно: {slowDns.Ms:0} мс");
        if (r.InterceptionWarning is { } dnsWarning) problems.Add(dnsWarning);
        if (r.DnsMismatch)
            problems.Add("системный и независимый DNS дают адреса разных сетей, а сертификат сайта, который снял бы подозрение, не проверялся — это может быть CDN или подмена");
        if (r.FailedAddress is { } firstAddress)
            problems.Add($"адрес {firstAddress.Ip} ({(firstAddress.Ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4")}) не подключается, сайт работает через {r.Address}");

        var timings = string.Join(", ", new[]
        {
            r.SystemDns is { Ok: true } d ? $"DNS {d.Ms:0} мс" : "",
            r.Tcp is { Outcome: TcpOutcome.Ok } t ? $"подключение {t.Ms:0} мс" : "",
            r.Tls is { Outcome: TlsOutcome.Ok } s ? $"TLS {s.Ms:0} мс" : "",
            r.Ping is { Received: > 0 } p ? $"задержка {p.AvgMs:0} мс" : "",
        }.Where(x => x != ""));

        if (problems.Count > 0)
            return new(VerdictLevel.Warn, "Работает, но с проблемами",
                Capital(string.Join("; ", problems)) + "." + (timings != "" ? $" Замеры: {timings}." : ""));

        return new(VerdictLevel.Ok, "Всё работает", timings != "" ? Capital(timings) + "." : "Подключение проходит.");
    }

    private static string Capitalless(string s) => s.Length == 0 ? s : char.ToLower(s[0]) + s[1..];
}
