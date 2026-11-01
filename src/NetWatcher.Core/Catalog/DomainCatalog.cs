using NetWatcher.Core.Data;

namespace NetWatcher.Core.Catalog;

public enum DomainTag
{
    None,

    /// <summary>Windows telemetry or Microsoft ads (WindowsSpyBlocker "spy" list).</summary>
    Telemetry,

    /// <summary>Ads or analytics: DuckDuckGo blocks the whole domain as a tracker.</summary>
    Tracker,

    /// <summary>DuckDuckGo marks the domain as malware.</summary>
    Malware,
}

/// <summary>What the catalog knows about a domain.</summary>
public sealed record DomainInfo(string Domain, string Company, DomainTag Tag, IReadOnlyList<string> Categories, string Source)
{
    public string TagText => Tag switch
    {
        DomainTag.Tracker => "трекер",
        DomainTag.Telemetry => "телеметрия",
        DomainTag.Malware => "опасный",
        _ => "",
    };

    /// <summary>Tooltip: where the mark comes from and what it means.</summary>
    public string Explanation
    {
        get
        {
            var lines = new List<string>();
            if (Company != "") lines.Add($"Компания: {Company}");
            var cats = string.Join(", ", Categories.Select(DomainCatalog.CategoryName).Distinct());
            switch (Tag)
            {
                case DomainTag.Tracker:
                    lines.Add("DuckDuckGo блокирует этот домен как трекер" + (cats != "" ? $": {cats}" : ""));
                    break;
                case DomainTag.Malware:
                    lines.Add("DuckDuckGo отмечает этот домен как вредоносный" + (cats != "" ? $" ({cats})" : ""));
                    break;
                case DomainTag.Telemetry:
                    lines.Add(Source.Contains("ms")
                        ? "Адрес диагностических данных (телеметрии) Windows — по документации Microsoft"
                        : "В списке WindowsSpyBlocker: телеметрия и реклама Windows");
                    if (cats != "") lines.Add("DuckDuckGo: " + cats);
                    break;
                default:
                    if (cats != "") lines.Add("По данным DuckDuckGo компания использует свои домены для: " + cats);
                    break;
            }
            return string.Join("\n", lines);
        }
    }
}

/// <summary>
/// Owner company and purpose of known domains, built from DuckDuckGo Tracker Blocklists
/// (CC BY-NC-SA 4.0) and WindowsSpyBlocker (MIT) by tools/build-catalog.py.
/// A name matches its own entry and the entries of its parent domains: stats.g.doubleclick.net → doubleclick.net.
/// </summary>
public sealed class DomainCatalog
{
    public const string FileName = "domain-catalog.tsv.gz";
    public const string MirrorUrl = "https://github.com/aeyota93-cloud/NetWatcher/releases/download/catalog-db/domain-catalog.tsv.gz";
    public const string Attribution = "DuckDuckGo Tracker Blocklists (CC BY-NC-SA 4.0), WindowsSpyBlocker (MIT)";

    private readonly Dictionary<string, Entry> _entries;

    private readonly record struct Entry(string Company, DomainTag Tag, string[] Categories, string Source);

    private DomainCatalog(Dictionary<string, Entry> entries) => _entries = entries;

    public int Count => _entries.Count;

    public static DomainCatalog Empty { get; } = new([]);

    public static DomainCatalog LoadFile(string path)
    {
        using var stream = DataUpdater.OpenText(path);
        return Load(stream);
    }

    public static DomainCatalog Load(Stream tsv)
    {
        var entries = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        var companies = new Dictionary<string, string>(StringComparer.Ordinal);
        using var reader = new StreamReader(tsv);
        while (reader.ReadLine() is { } line)
        {
            if (line.StartsWith('#')) continue;
            var f = line.Split('\t');
            if (f.Length < 5 || f[0] == "") continue;
            if (!companies.TryGetValue(f[1], out var company)) companies[f[1]] = company = f[1];
            var tag = f[2] switch
            {
                "tracker" => DomainTag.Tracker,
                "telemetry" => DomainTag.Telemetry,
                "malware" => DomainTag.Malware,
                _ => DomainTag.None,
            };
            entries[f[0].Trim().TrimEnd('.')] = new Entry(company, tag, f[3] == "" ? [] : f[3].Split(','), f[4]);
        }
        return new DomainCatalog(entries);
    }

    /// <summary>
    /// The closest entry with a mark gives the mark, the closest entry with a company gives the company.
    /// Null when the catalog knows nothing about the name.
    /// </summary>
    public DomainInfo? Lookup(string domain)
    {
        if (_entries.Count == 0 || string.IsNullOrEmpty(domain)) return null;
        var name = domain.TrimEnd('.');
        string? company = null;
        Entry? tagged = null;
        string? taggedName = null;
        string[]? categories = null;
        string? source = null;
        var at = 0;
        while (true)
        {
            var candidate = name[at..];
            // Stop at the top-level domain: "com" alone says nothing.
            if (!candidate.Contains('.')) break;
            if (_entries.TryGetValue(candidate, out var e))
            {
                if (company == null && e.Company != "") company = e.Company;
                if (tagged == null && e.Tag != DomainTag.None)
                {
                    tagged = e;
                    taggedName = candidate;
                }
                categories ??= e.Categories.Length > 0 ? e.Categories : null;
                source ??= e.Source;
            }
            var dot = name.IndexOf('.', at);
            if (dot < 0) break;
            at = dot + 1;
        }
        if (company == null && tagged == null && categories == null) return null;
        return new DomainInfo(
            taggedName ?? domain,
            company ?? "",
            tagged?.Tag ?? DomainTag.None,
            tagged?.Categories ?? categories ?? [],
            tagged?.Source ?? source ?? "");
    }

    /// <summary>The most telling entry among several domains of one address.</summary>
    public DomainInfo? Lookup(IEnumerable<string> domains)
    {
        DomainInfo? best = null;
        foreach (var d in domains)
        {
            var info = Lookup(d);
            if (info == null) continue;
            if (best == null || info.Tag > best.Tag || (info.Tag == best.Tag && best.Company == "" && info.Company != "")) best = info;
        }
        return best;
    }

    /// <summary>DuckDuckGo's category names in Russian.</summary>
    public static string CategoryName(string category) => category switch
    {
        "Advertising" => "реклама",
        "Ad Motivated Tracking" => "слежка для рекламы",
        "Ad Fraud" => "защита рекламы от накруток",
        "Action Pixels" => "пиксели действий",
        "Analytics" => "аналитика",
        "Audience Measurement" => "измерение аудитории",
        "Third-Party Analytics Marketing" => "маркетинговая аналитика",
        "Session Replay" => "запись действий пользователя",
        "Embedded Content" => "встроенный контент",
        "Content Delivery" => "доставка контента",
        "Social Network" => "соцсеть",
        "Social - Share" => "кнопки «поделиться»",
        "Social - Comment" => "комментарии",
        "Federated Login" => "вход через аккаунт",
        "SSO" => "единый вход",
        "Online Payment" => "оплата",
        "Support Chat Widget" => "чат поддержки",
        "Tag Manager" => "менеджер тегов",
        "Badge" => "значки",
        "Malware" => "вредоносное ПО",
        "Unknown High Risk Behavior" => "подозрительное поведение",
        "Obscure Ownership" => "скрытый владелец",
        _ => category,
    };
}

/// <summary>Fresh catalog from our weekly copy on GitHub.</summary>
public static class CatalogUpdater
{
    private const string Hint = "Каталог собирается из открытых списков при выпуске программы; попробуйте позже.";

    public static Task<DomainCatalog> DownloadAsync(HttpClient http, string destination, CancellationToken ct = default) =>
        DataUpdater.DownloadAsync(http, [DomainCatalog.MirrorUrl], destination, DomainCatalog.LoadFile, c => c.Count, 500, Hint, ct);
}
