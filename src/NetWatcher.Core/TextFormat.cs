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

    /// <summary>"820 Б", "86 КБ", "1,2 МБ", "3,4 ГБ".</summary>
    public static string Bytes(long n)
    {
        string[] units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
        double v = n;
        var u = 0;
        while (v >= 1024 && u < units.Length - 1)
        {
            v /= 1024;
            u++;
        }
        var text = u == 0 || v >= 10 ? v.ToString("0", System.Globalization.CultureInfo.InvariantCulture)
            : v.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture).Replace('.', ',');
        return $"{text} {units[u]}";
    }

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
