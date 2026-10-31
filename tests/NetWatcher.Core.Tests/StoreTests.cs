using System.Net;
using System.Text;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Dns;
using NetWatcher.Core.Storage;

namespace NetWatcher.Core.Tests;

public sealed class StoreTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("netwatcher-test").FullName;
    private readonly LogStore _store;

    public StoreTests() => _store = new LogStore(Path.Combine(_dir, "log.db"));

    public void Dispose()
    {
        _store.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    private static Observation Obs(string process, string ip, int port, DateTimeOffset t, string services = "") =>
        new(process, services, @"C:\x\" + process, "TCP", IPAddress.Parse(ip), port, t);

    [Fact]
    public void Folds_repeated_sightings()
    {
        var t = DateTimeOffset.UtcNow;
        _store.Write([Obs("chrome.exe", "1.1.1.1", 443, t), Obs("chrome.exe", "1.1.1.1", 443, t.AddSeconds(2))], []);
        _store.Write([Obs("chrome.exe", "1.1.1.1", 443, t.AddSeconds(4))], []);

        var row = Assert.Single(_store.Query(t.AddMinutes(-1)));
        Assert.Equal(3, row.Hits);
        Assert.Equal(t.ToUnixTimeMilliseconds(), row.FirstSeen.ToUnixTimeMilliseconds());
        Assert.Equal(t.AddSeconds(4).ToUnixTimeMilliseconds(), row.LastSeen.ToUnixTimeMilliseconds());
    }

    [Fact]
    public void Query_filters_by_period_and_folds_hours()
    {
        var now = DateTimeOffset.UtcNow;
        _store.Write([
            Obs("svchost.exe", "13.107.4.50", 443, now.AddHours(-30), "wuauserv"),
            Obs("svchost.exe", "13.107.4.50", 443, now.AddHours(-2), "wuauserv"),
            Obs("svchost.exe", "13.107.4.50", 443, now, "wuauserv"),
            Obs("old.exe", "9.9.9.9", 53, now.AddDays(-3)),
        ], []);

        var day = _store.Query(now.AddDays(-1));
        var row = Assert.Single(day);
        Assert.Equal(2, row.Hits);
        Assert.Equal("svchost.exe · wuauserv", row.GroupKey);

        Assert.Equal(2, _store.Query(now.AddDays(-7)).Count);
    }

    [Fact]
    public void Purge_removes_old_rows_and_dns()
    {
        var now = DateTimeOffset.UtcNow;
        _store.Write(
            [Obs("a.exe", "1.1.1.1", 443, now.AddDays(-10)), Obs("b.exe", "2.2.2.2", 443, now)],
            [new DnsObservation("a.exe", "old.example", IPAddress.Parse("1.1.1.1"), now.AddDays(-10)),
             new DnsObservation("b.exe", "new.example", IPAddress.Parse("2.2.2.2"), now)]);

        Assert.Equal(2, _store.Purge(now.AddDays(-7)));
        Assert.Equal("b.exe", Assert.Single(_store.Query(DateTimeOffset.MinValue)).Process);

        var idx = new DnsIndex();
        _store.LoadDns(idx);
        Assert.Empty(idx.Get(IPAddress.Parse("1.1.1.1"), null));
        Assert.Equal(["new.example"], idx.Get(IPAddress.Parse("2.2.2.2"), "b.exe"));
    }

    [Fact]
    public void Enrich_and_search()
    {
        var now = DateTimeOffset.UtcNow;
        _store.Write(
            [Obs("telegram.exe", "149.154.167.51", 443, now), Obs("svchost.exe", "142.250.74.110", 443, now, "Dnscache")],
            [new DnsObservation("telegram.exe", "api.telegram.org", IPAddress.Parse("149.154.167.51"), now)]);
        var idx = new DnsIndex();
        _store.LoadDns(idx);
        var asn = AsnDatabase.Load(new MemoryStream(Encoding.UTF8.GetBytes(
            "142.250.0.0\t142.251.255.255\t15169\tUS\tGOOGLE\n149.154.160.0\t149.154.175.255\t62041\tGB\tTELEGRAM\n")));

        var rows = _store.Query(now.AddMinutes(-1));
        Analysis.Enrich(rows, idx, asn, new Dictionary<string, string> { ["Dnscache"] = "DNS-клиент" });

        static List<string> Find(List<DestinationRow> rows, string q) =>
            rows.Where(r => r.Matches(DestinationRow.SplitQuery(q))).Select(r => r.Process).ToList();

        Assert.Equal(["telegram.exe"], Find(rows, "api.telegram"));
        Assert.Equal(["telegram.exe"], Find(rows, "AS62041"));
        Assert.Equal(["svchost.exe"], Find(rows, "dns-клиент"));
        Assert.Equal(["svchost.exe"], Find(rows, "142.250.0.0/15"));
        Assert.Equal(["svchost.exe"], Find(rows, "google 443"));
        Assert.Empty(Find(rows, "google telegram"));

        var groups = Analysis.Groups(rows);
        Assert.Equal(["svchost.exe · Dnscache", "telegram.exe"], groups.Select(g => g.Key));
        Assert.Equal("DNS-клиент (Dnscache)", groups[0].ServicesDisplay);

        Assert.Equal(["142.250.0.0/15", "149.154.160.0/20"],
            Analysis.Subnets(rows, SubnetMode.Owner, ipv4Only: false).Select(c => c.ToString()));
        Assert.Equal(["142.250.74.0/24", "149.154.167.0/24"],
            Analysis.Subnets(rows, SubnetMode.Wide24, ipv4Only: true).Select(c => c.ToString()));
    }

    [Fact]
    public void Settings_survive_a_broken_file()
    {
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path, "{ not json");
        Assert.Equal(7, Settings.Load(path).RetentionDays);

        new Settings { RetentionDays = 900, PollSeconds = 0 }.Save(path);
        var s = Settings.Load(path);
        Assert.Equal(365, s.RetentionDays);
        Assert.Equal(1, s.PollSeconds);
    }
}
