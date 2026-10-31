namespace NetWatcher.Core;

public enum HealthLevel
{
    /// <summary>Not enough to judge: UDP or a connection too short to see.</summary>
    Unknown,
    Ok,
    Warn,
    Fail,
}

/// <summary>
/// A verdict about one destination from what the system already reported,
/// without sending anything: unanswered connection attempts and resent packets.
/// </summary>
public readonly record struct Health(HealthLevel Level, string Reason)
{
    public static Health Of(DestinationRow r)
    {
        // Heuristic. Windows sends the SYN and by default retries it twice with an initial
        // timeout of about 3 s (MaxSynRetransmissions = 2, InitialRto = 3000 ms in
        // `netsh interface tcp show global`; sources differ, so this is not a hard rule).
        // Two unanswered attempts without a single open connection: the server did not answer.
        if (r.NoAnswer >= 2 && r.Established == 0)
            return new(HealthLevel.Fail, "Не отвечает: попытки подключения остаются без ответа — сервер недоступен или подключение блокируется");
        if (r.NoAnswer > 0)
            return new(HealthLevel.Warn, $"Подключается не с первого раза: {TextFormat.Plural(r.NoAnswer, "попытка", "попытки", "попыток")} без ответа");
        if (r.Retransmits >= 20 && r.Retransmits >= r.Hits)
            return new(HealthLevel.Warn, $"Возможны потери: {TextFormat.Plural(r.Retransmits, "повторная отправка", "повторные отправки", "повторных отправок")} пакетов");
        if (r.Established > 0)
            return new(HealthLevel.Ok, "Соединение устанавливается");
        return new(HealthLevel.Unknown, "");
    }

    public bool IsProblem => Level is HealthLevel.Warn or HealthLevel.Fail;

    /// <summary>The worst of several, e.g. for a domain with many addresses.</summary>
    public static Health Worst(IEnumerable<Health> all) =>
        all.DefaultIfEmpty(new Health(HealthLevel.Unknown, "")).MaxBy(h => h.Level);
}

/// <summary>Windows DNS client status codes in plain words.</summary>
public static class DnsStatus
{
    /// <summary>Our own code: the answer was 0.0.0.0 or 127.0.0.1 — a typical DNS block.</summary>
    public const int BlockedAnswer = -1;

    public static string Describe(int status) => status switch
    {
        BlockedAnswer => "ответ-заглушка 0.0.0.0 — похоже на блокировку через DNS",
        9003 => "домен не существует",
        9501 => "у домена нет записей этого типа",
        1460 => "DNS-сервер не ответил",
        9002 => "ошибка DNS-сервера",
        9005 => "DNS-сервер отказал в ответе",
        9004 => "DNS-сервер не поддерживает такой запрос",
        1214 => "неправильное имя",
        87 => "неправильный запрос",
        _ => $"ошибка {status}",
    };

    /// <summary>
    /// Whether a failed question is worth showing. Windows asks for many names that fail
    /// by design: local names, wpad, IPv6 records a domain does not have.
    /// </summary>
    public static bool IsProblem(int status, string domain)
    {
        if (status == 0 || status == 9501) return false;
        var d = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (!d.Contains('.')) return false;
        string[] local = [".local", ".lan", ".home", ".arpa", ".internal", ".localdomain", ".corp", ".localhost"];
        if (local.Any(d.EndsWith)) return false;
        if (d.StartsWith("wpad.", StringComparison.Ordinal) || d.StartsWith("_", StringComparison.Ordinal)) return false;
        return true;
    }
}
