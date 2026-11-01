using System.Net;
using NetWatcher.Core.Data;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Geo;

/// <summary>
/// Where an address is located, by country: DB-IP "IP to Country Lite" (CC BY 4.0, monthly).
/// Lines are "range_start,range_end,country_code" for IPv4 and IPv6. This is the location of the
/// server, unlike the country in the owner database, which is where the network is registered.
/// </summary>
public sealed class GeoDatabase
{
    public const string FileName = "dbip-country-lite.csv.gz";

    /// <summary>Weekly copy published by the repository's "data-mirror" workflow.</summary>
    public const string MirrorUrl = "https://github.com/aeyota93-cloud/NetWatcher/releases/download/geo-db/dbip-country-lite.csv.gz";

    public const string Attribution = "IP Geolocation by DB-IP (db-ip.com), CC BY 4.0";

    /// <summary>DB-IP names the file by month: dbip-country-lite-2026-11.csv.gz.</summary>
    public static string OriginalUrl(DateTime month) => $"https://download.db-ip.com/free/dbip-country-lite-{month:yyyy-MM}.csv.gz";

    /// <summary>Our copy first, then DB-IP for this month and the previous one (a new month appears with a delay).</summary>
    public static IReadOnlyList<string> Sources(DateTime now) => [MirrorUrl, OriginalUrl(now), OriginalUrl(now.AddMonths(-1))];

    // Ranges are stored by their start only; a gap between ranges gets an entry with no country.
    private readonly UInt128[] _starts;
    private readonly ushort[] _codes;
    private readonly string[] _names;

    private GeoDatabase(UInt128[] starts, ushort[] codes, string[] names, int count)
    {
        _starts = starts;
        _codes = codes;
        _names = names;
        Count = count;
    }

    /// <summary>Number of ranges in the file.</summary>
    public int Count { get; }

    public static GeoDatabase Empty { get; } = new([], [], [""], 0);

    public static GeoDatabase LoadFile(string path)
    {
        using var stream = DataUpdater.OpenText(path);
        return Load(stream);
    }

    public static GeoDatabase Load(Stream csv)
    {
        var rows = new List<(UInt128 Start, UInt128 End, string Code)>(720_000);
        using (var reader = new StreamReader(csv))
        {
            while (reader.ReadLine() is { } line)
            {
                var f = line.Split(',');
                if (f.Length < 3) continue;
                var code = f[2].Trim().Trim('"').ToUpperInvariant();
                if (code.Length != 2 || code == "ZZ") continue; // ZZ: DB-IP's "unknown"
                if (!IpKey.TryParse(f[0].Trim('"'), out var a) || !IpKey.TryParse(f[1].Trim('"'), out var b)) continue;
                var start = IpKey.From(a);
                var end = IpKey.From(b);
                if (IpKey.IsV4(start) != IpKey.IsV4(end) || end < start) continue;
                rows.Add((start, end, code));
            }
        }
        rows.Sort((x, y) => x.Start.CompareTo(y.Start));

        var names = new List<string> { "" };
        var index = new Dictionary<string, ushort>(StringComparer.Ordinal) { [""] = 0 };
        var starts = new List<UInt128>(rows.Count + 1024);
        var codes = new List<ushort>(rows.Count + 1024);
        UInt128? next = null; // first address after the previous range
        foreach (var (start, end, code) in rows)
        {
            if (next is { } n && start < n) continue; // overlap: keep the first range
            if (next is { } gap && start > gap)
            {
                starts.Add(gap);
                codes.Add(0);
            }
            if (!index.TryGetValue(code, out var c))
            {
                index[code] = c = (ushort)names.Count;
                names.Add(code);
            }
            starts.Add(start);
            codes.Add(c);
            next = end == UInt128.MaxValue ? end : end + 1;
        }
        if (next is { } last && last != UInt128.MaxValue)
        {
            starts.Add(last);
            codes.Add(0);
        }
        return new GeoDatabase(starts.ToArray(), codes.ToArray(), names.ToArray(), rows.Count);
    }

    /// <summary>"DE", or "" when the address is not in the database.</summary>
    public string Lookup(IPAddress ip)
    {
        if (_starts.Length == 0) return "";
        var key = IpKey.From(ip);
        var i = Array.BinarySearch(_starts, key);
        if (i < 0) i = ~i - 1; // last start before the address
        return i < 0 ? "" : _names[_codes[i]];
    }
}

/// <summary>Fresh country database from our copy on GitHub or from DB-IP.</summary>
public static class GeoUpdater
{
    private const string Hint = "Можно скачать файл «IP to Country Lite» в формате CSV на db-ip.com и указать его кнопкой «Загрузить из файла».";

    public static Task<GeoDatabase> DownloadAsync(HttpClient http, string destination, CancellationToken ct = default) =>
        DataUpdater.DownloadAsync(http, GeoDatabase.Sources(DateTime.UtcNow), destination, GeoDatabase.LoadFile, d => d.Count, 1000, Hint, ct);

    public static GeoDatabase Import(string source, string destination) =>
        DataUpdater.Import(source, destination, GeoDatabase.LoadFile, d => d.Count, 1000);
}
