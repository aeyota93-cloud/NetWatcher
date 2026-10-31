using System.IO.Compression;
using System.Net;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Asn;

/// <summary>Who owns an address: the announced range, its AS number and owner name.</summary>
public sealed record AsnInfo(
    int Asn,
    string Country,
    string Owner,
    UInt128 RangeStart,
    UInt128 RangeEnd)
{
    public IPAddress FirstAddress => IpKey.ToAddress(RangeStart);
    public IPAddress LastAddress => IpKey.ToAddress(RangeEnd);

    /// <summary>The range as networks; a range does not always fit one CIDR.</summary>
    public List<Cidr> Networks => CidrMath.FromRange(RangeStart, RangeEnd);

    /// <summary>The network of the range that holds the address.</summary>
    public Cidr NetworkOf(IPAddress ip) => Networks.First(n => n.Contains(ip));

    public string AsnText => Asn > 0 ? "AS" + Asn : "";

    /// <summary>"Microsoft" instead of "MICROSOFT-CORP-MSN-AS-BLOCK".</summary>
    public string Name => AsnNames.Display(Asn, Owner);

    /// <summary>"AS8075 · Microsoft".</summary>
    public string OwnerText => Asn > 0 ? $"AS{Asn} · {Name}" : Name;
}

/// <summary>
/// Offline lookup table "range → AS → owner" in the iptoasn.com format
/// (ip2asn-combined.tsv: range_start, range_end, AS_number, country_code, AS_description).
/// </summary>
public sealed class AsnDatabase
{
    public const string DownloadUrl = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";
    public const string FileName = "ip2asn-combined.tsv.gz";

    private readonly UInt128[] _starts;
    private readonly UInt128[] _ends;
    private readonly int[] _asns;
    private readonly string[] _countries;
    private readonly string[] _owners;

    private AsnDatabase(List<Row> rows)
    {
        rows.Sort((a, b) => a.Start.CompareTo(b.Start));
        _starts = rows.Select(r => r.Start).ToArray();
        _ends = rows.Select(r => r.End).ToArray();
        _asns = rows.Select(r => r.Asn).ToArray();
        _countries = rows.Select(r => r.Country).ToArray();
        _owners = rows.Select(r => r.Owner).ToArray();
    }

    public int Count => _starts.Length;

    public static AsnDatabase Empty { get; } = new([]);

    public static AsnDatabase LoadFile(string path)
    {
        using var file = File.OpenRead(path);
        // Decide by content, not by name: a download in progress has no .gz extension.
        Span<byte> head = stackalloc byte[2];
        var read = file.Read(head);
        file.Position = 0;
        var gzip = read == 2 && head[0] == 0x1F && head[1] == 0x8B;
        if (!gzip && read > 0 && head[0] == (byte)'<')
            throw new InvalidDataException("Сервер вернул веб-страницу вместо базы. Попробуйте позже или скачайте файл вручную.");
        Stream stream = gzip ? new GZipStream(file, CompressionMode.Decompress) : file;
        using (stream) return Load(stream);
    }

    public static AsnDatabase Load(Stream tsv)
    {
        var rows = new List<Row>(800_000);
        var owners = new Dictionary<string, string>(StringComparer.Ordinal);
        using var reader = new StreamReader(tsv);
        while (reader.ReadLine() is { } line)
        {
            var f = line.Split('\t');
            if (f.Length < 5) continue;
            if (!int.TryParse(f[2], out var asn) || asn == 0) continue; // 0 = not routed
            if (!IpKey.TryParse(f[0], out var a) || !IpKey.TryParse(f[1], out var b)) continue;
            var start = IpKey.From(a);
            var end = IpKey.From(b);
            if (IpKey.IsV4(start) != IpKey.IsV4(end) || end < start) continue;

            // Owner names repeat a lot; keep one copy of each.
            var ownerText = f[4].Trim();
            if (!owners.TryGetValue(ownerText, out var owner)) owners[ownerText] = owner = ownerText;
            rows.Add(new Row(start, end, asn, f[3].Trim() is "None" or "" ? "" : f[3].Trim(), owner));
        }
        return new AsnDatabase(rows);
    }

    public AsnInfo? Lookup(IPAddress ip)
    {
        if (_starts.Length == 0) return null;
        var key = IpKey.From(ip);
        // Last range that starts at or before the address.
        int lo = 0, hi = _starts.Length - 1, found = -1;
        while (lo <= hi)
        {
            var mid = lo + (hi - lo) / 2;
            if (_starts[mid] <= key)
            {
                found = mid;
                lo = mid + 1;
            }
            else hi = mid - 1;
        }
        if (found < 0 || key > _ends[found]) return null;
        return new AsnInfo(_asns[found], _countries[found], _owners[found], _starts[found], _ends[found]);
    }

    private readonly record struct Row(UInt128 Start, UInt128 End, int Asn, string Country, string Owner);
}
