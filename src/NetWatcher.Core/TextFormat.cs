namespace NetWatcher.Core;

/// <summary>Short Russian wording for numbers, times and ports.</summary>
public static class TextFormat
{
    public static string Plural(long n, string one, string few, string many)
    {
        var mod100 = n % 100;
        var mod10 = n % 10;
        var word = mod100 is >= 11 and <= 14 ? many : mod10 == 1 ? one : mod10 is >= 2 and <= 4 ? few : many;
        return $"{Number(n)} {word}";
    }

    /// <summary>12 345 — thousands split by a space, whatever the system language.</summary>
    public static string Number(long n) =>
        n.ToString("N0", System.Globalization.CultureInfo.InvariantCulture).Replace(',', ' ');

    /// <summary>"сейчас", "5 мин", "14:32", "28.10 14:32".</summary>
    public static string Relative(DateTimeOffset now, DateTimeOffset time, TimeSpan liveWindow)
    {
        var ago = now - time;
        if (ago < liveWindow || ago < TimeSpan.FromSeconds(60)) return "сейчас";
        if (ago < TimeSpan.FromHours(1)) return $"{(int)ago.TotalMinutes} мин";
        var local = time.ToLocalTime();
        return local.Date == now.ToLocalTime().Date ? local.ToString("HH:mm") : local.ToString("dd.MM HH:mm");
    }

    private static readonly Dictionary<(string, int), string> Ports = new()
    {
        [("TCP", 443)] = "HTTPS",
        [("UDP", 443)] = "QUIC / HTTP3",
        [("TCP", 80)] = "HTTP",
        [("UDP", 53)] = "DNS",
        [("TCP", 53)] = "DNS",
        [("TCP", 853)] = "DNS over TLS",
        [("UDP", 123)] = "время (NTP)",
        [("UDP", 3478)] = "STUN, звонки",
        [("UDP", 19302)] = "STUN, звонки",
        [("TCP", 22)] = "SSH",
        [("TCP", 3389)] = "удалённый рабочий стол",
        [("TCP", 25)] = "почта (SMTP)",
        [("TCP", 587)] = "почта (SMTP)",
        [("TCP", 993)] = "почта (IMAP)",
        [("TCP", 5228)] = "уведомления Google",
        [("UDP", 51820)] = "WireGuard",
        [("UDP", 1194)] = "OpenVPN",
        [("TCP", 1194)] = "OpenVPN",
    };

    /// <summary>"UDP 443 (QUIC / HTTP3)" or just "TCP 5000".</summary>
    public static string Port(string proto, int port) =>
        Ports.TryGetValue((proto, port), out var name) ? $"{proto} {port} ({name})" : $"{proto} {port}";
}
