using System.Collections.Concurrent;
using System.Globalization;

namespace NetWatcher.Core.Asn;

/// <summary>
/// Readable owner names. The offline database has registry handles such as
/// "MICROSOFT-CORP-MSN-AS-BLOCK" or "AMAZON-02"; people want "Microsoft" and "Amazon".
/// </summary>
public static class AsnNames
{
    // Words that describe the record, not the owner.
    private static readonly HashSet<string> Noise = new(StringComparer.OrdinalIgnoreCase)
    {
        "AS", "ASN", "BLOCK", "CORP", "CORPORATION", "INC", "LLC", "LTD", "LIMITED", "PJSC", "JSC", "OJSC", "CJSC",
        "OOO", "ZAO", "GMBH", "AG", "BV", "B.V", "SA", "SAS", "SRL", "PLC", "CO", "COMPANY", "AUTONOMOUS", "SYSTEM",
        "NETBLK", "BACKBONE", "GLOBAL", "PTE",
    };

    // Short names that stay upper-case.
    private static readonly HashSet<string> Acronyms = new(StringComparer.OrdinalIgnoreCase)
    {
        "MTS", "OVH", "VK", "MSN", "IBM", "AT&T", "NTT", "KPN", "BT", "UPC", "DE", "CIX", "IX", "ISP", "CDN", "TV", "IT",
        "RU", "US", "EU", "UK", "SPB", "MSK", "ER", "GTS", "TTK", "MGTS", "HP",
    };

    // Well-known networks whose handles clean up badly.
    private static readonly Dictionary<int, string> Known = new()
    {
        [13335] = "Cloudflare", [209242] = "Cloudflare", [15169] = "Google", [396982] = "Google Cloud", [36040] = "YouTube",
        [16509] = "Amazon", [14618] = "Amazon", [8075] = "Microsoft", [8068] = "Microsoft", [8069] = "Microsoft",
        [12076] = "Microsoft Azure", [16625] = "Akamai", [20940] = "Akamai", [32787] = "Akamai", [54113] = "Fastly",
        [32934] = "Meta (Facebook)", [63293] = "Meta (Facebook)", [714] = "Apple", [6185] = "Apple", [2906] = "Netflix",
        [13238] = "Яндекс", [208722] = "Яндекс Облако", [200350] = "Яндекс Облако", [47764] = "VK", [47541] = "VK",
        [62041] = "Telegram", [62014] = "Telegram", [59930] = "Telegram", [44907] = "Telegram", [211157] = "Telegram",
        [32590] = "Valve (Steam)", [24940] = "Hetzner", [16276] = "OVH", [14061] = "DigitalOcean", [63949] = "Akamai (Linode)",
        [20473] = "Vultr", [36459] = "GitHub", [8560] = "IONOS", [12389] = "Ростелеком", [8359] = "МТС", [3216] = "Билайн",
        [31133] = "МегаФон", [25513] = "МГТС", [20485] = "ТрансТелеКом", [9049] = "ЭР-Телеком", [42610] = "Ростелеком",
        [49505] = "Selectel", [50340] = "Selectel", [197695] = "REG.RU", [9123] = "TimeWeb", [29182] = "RU-CENTER",
        [60068] = "CDN77", [22822] = "Edgio (Limelight)", [3356] = "Lumen (Level 3)", [1299] = "Arelion (Telia)",
        [174] = "Cogent", [6939] = "Hurricane Electric", [2914] = "NTT", [3257] = "GTT", [6453] = "Tata Communications",
        [19551] = "Imperva (Incapsula)", [394536] = "Zscaler", [62597] = "NSOne", [13414] = "X (Twitter)", [46489] = "Twitch",
        [11344] = "Discord", [49544] = "i3D.net", [57976] = "Blizzard", [8403] = "Spotify", [43515] = "Google",
        [19679] = "Dropbox", [55102] = "Zoom", [30103] = "Zoom", [138699] = "TikTok", [396986] = "ByteDance",
    };

    /// <summary>Names learnt at run time (for example from PeeringDB); they win over everything else.</summary>
    public static ConcurrentDictionary<int, string> Learned { get; } = new();

    public static string Display(int asn, string raw)
    {
        if (Learned.TryGetValue(asn, out var learned) && learned != "") return learned;
        if (Known.TryGetValue(asn, out var known)) return known;
        return Clean(raw);
    }

    /// <summary>"MICROSOFT-CORP-MSN-AS-BLOCK" → "Microsoft MSN", "AMAZON-02" → "Amazon".</summary>
    public static string Clean(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";
        var text = raw.Trim();

        // "HANDLE - Real Org Name, CC": the part after " - " is the organisation.
        var dash = text.IndexOf(" - ", StringComparison.Ordinal);
        if (dash > 0 && dash + 3 < text.Length) text = text[(dash + 3)..];
        // A trailing ", US" country.
        var comma = text.LastIndexOf(',');
        if (comma > 0 && text.Length - comma <= 4) text = text[..comma];

        var words = text
            .Split([' ', '-', '_', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(w => w.TrimEnd('.'))
            .Where(w => w != "" && !Noise.Contains(w) && !w.All(char.IsDigit))
            .ToList();
        if (words.Count == 0) return raw.Trim();

        // Upper-case handles read better in title case; mixed-case names are kept as written.
        var shouting = text.Count(char.IsUpper) > text.Count(char.IsLower) * 2;
        return string.Join(' ', words.Select(w =>
            Acronyms.Contains(w) ? w.ToUpperInvariant()
            : shouting ? CultureInfo.InvariantCulture.TextInfo.ToTitleCase(w.ToLowerInvariant())
            : w));
    }
}
