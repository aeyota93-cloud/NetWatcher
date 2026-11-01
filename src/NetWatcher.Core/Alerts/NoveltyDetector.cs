using System.Net;

namespace NetWatcher.Core.Alerts;

public enum NoveltyKind
{
    /// <summary>A program went online for the first time.</summary>
    Program,

    /// <summary>A program reached a server in a country it never went to before.</summary>
    Country,

    /// <summary>A program reached a network (AS) it never went to before.</summary>
    Network,
}

/// <summary>Something a program did on the network for the first time.</summary>
public sealed record Novelty(NoveltyKind Kind, string GroupKey, string Process, string Value, string ValueText, string Domain, IPAddress Ip);

/// <summary>Which kinds of news to report.</summary>
public sealed record AlertOptions(bool NewProgram, bool NewCountry, bool NewNetwork, bool SkipBrowsers)
{
    public static AlertOptions From(Settings s) => new(s.AlertNewProgram, s.AlertNewCountry, s.AlertNewNetwork, s.AlertSkipBrowsers);
}

/// <summary>
/// Remembers what each program has ever done — went online at all, went to a country, went to a network —
/// and reports the first time. Everything is remembered even while alerts are off or the program is still
/// learning, so turning alerts on later does not flood the user with old news.
/// </summary>
public sealed class NoveltyDetector
{
    /// <summary>The first day after installation only learns: everything would be new.</summary>
    public static readonly TimeSpan LearningPeriod = TimeSpan.FromHours(24);

    // Browsers go to new countries and networks with every site; only their first start online is news.
    private static readonly HashSet<string> Browsers = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "opera_gx.exe", "browser.exe", "brave.exe",
        "vivaldi.exe", "iexplore.exe", "chromium.exe", "librewolf.exe", "waterfox.exe", "tor.exe", "arc.exe",
    };

    private readonly HashSet<string> _known;
    private readonly List<string> _added = [];

    public NoveltyDetector(IEnumerable<string> known) => _known = new HashSet<string>(known, StringComparer.Ordinal);

    public int KnownCount => _known.Count;

    public static bool IsBrowser(string process) => Browsers.Contains(process);

    /// <summary>A program is the same program wherever it runs from only if the path is the same.</summary>
    public static string ProgramKey(DestinationRow r) =>
        r.Services != "" || r.Path == "" ? r.GroupKey.ToLowerInvariant() : r.Path.ToLowerInvariant();

    /// <summary>Keys learned since the last call, to be saved.</summary>
    public List<string> TakeAdded()
    {
        var list = _added.ToList();
        _added.Clear();
        return list;
    }

    /// <summary>
    /// Learns from the rows (with owners and countries filled in) and returns what is new.
    /// <paramref name="report"/> false: only learn. Countries and networks are not looked at when the
    /// databases behind them are missing, so they are not all "new" once the database arrives.
    /// </summary>
    public List<Novelty> Check(IEnumerable<DestinationRow> rows, AlertOptions options, bool report, bool haveCountries, bool haveNetworks)
    {
        var news = new List<Novelty>();
        foreach (var r in rows.OrderBy(r => r.FirstSeen))
        {
            var program = ProgramKey(r);
            var programIsNew = Learn("p|" + program);
            if (programIsNew && report && options.NewProgram)
                news.Add(new Novelty(NoveltyKind.Program, r.GroupKey, r.Process, "", "", r.PrimaryDomain, r.RemoteIp));

            var browser = options.SkipBrowsers && IsBrowser(r.Process);
            var country = r.CountryText;
            if (haveCountries && country != "" && Learn($"c|{program}|{country}") && !programIsNew && report && options.NewCountry && !browser)
                news.Add(new Novelty(NoveltyKind.Country, r.GroupKey, r.Process, country, Geo.Countries.Name(country), r.PrimaryDomain, r.RemoteIp));

            if (haveNetworks && r.Asn is { Asn: > 0 } a && Learn($"a|{program}|{a.Asn}") && !programIsNew && report && options.NewNetwork && !browser)
                news.Add(new Novelty(NoveltyKind.Network, r.GroupKey, r.Process, a.AsnText, a.OwnerText, r.PrimaryDomain, r.RemoteIp));
        }
        return news;
    }

    private bool Learn(string key)
    {
        if (!_known.Add(key)) return false;
        _added.Add(key);
        return true;
    }

    /// <summary>
    /// One notification for everything that came in since the last one: a single event is told in full,
    /// several are summed up per program. <paramref name="titleOf"/> gives the program's readable name.
    /// </summary>
    public static (string Title, string Text) Compose(IReadOnlyList<Novelty> news, Func<string, string> titleOf)
    {
        static string Where(Novelty n) => n.Domain != "" ? $"{n.Domain} ({n.Ip})" : n.Ip.ToString();

        if (news.Count == 1)
        {
            var n = news[0];
            var name = titleOf(n.GroupKey);
            return n.Kind switch
            {
                NoveltyKind.Program => ($"Новая программа в сети: {name}", $"{n.Process} впервые вышла в интернет: {Where(n)}"),
                NoveltyKind.Country => ($"{name}: новая страна — {n.ValueText}", $"Впервые обращается к серверу в этой стране: {Where(n)}"),
                _ => ($"{name}: новая сеть — {n.ValueText}", $"Впервые обращается в эту сеть: {Where(n)}"),
            };
        }

        var lines = news
            .GroupBy(n => n.GroupKey)
            .Select(g =>
            {
                var parts = new List<string>();
                if (g.Any(n => n.Kind == NoveltyKind.Program)) parts.Add("впервые в сети");
                var countries = g.Where(n => n.Kind == NoveltyKind.Country).Select(n => n.Value).Distinct().ToList();
                if (countries.Count > 0) parts.Add((countries.Count == 1 ? "новая страна " : "новые страны ") + string.Join(", ", countries));
                var nets = g.Count(n => n.Kind == NoveltyKind.Network);
                if (nets > 0) parts.Add(TextFormat.Plural(nets, "новая сеть", "новые сети", "новых сетей"));
                return $"{titleOf(g.Key)}: {string.Join("; ", parts)}";
            })
            .ToList();
        var programs = lines.Count;
        var text = string.Join("\n", lines.Take(3)) + (programs > 3 ? $"\nи ещё {TextFormat.Plural(programs - 3, "программа", "программы", "программ")}" : "");
        return ($"Новое в сети: {TextFormat.Plural(news.Count, "событие", "события", "событий")}", text);
    }
}
