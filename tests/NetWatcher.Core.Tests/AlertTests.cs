using System.Net;
using NetWatcher.Core.Alerts;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Storage;

namespace NetWatcher.Core.Tests;

public class AlertTests
{
    private static readonly AlertOptions All = new(true, true, true, true);

    private static DestinationRow Row(string process, string path, string ip, string country, int asn, string services = "") => new()
    {
        Process = process, Services = services, Path = path, Proto = "TCP", RemoteIp = IPAddress.Parse(ip), RemotePort = 443,
        ServerCountry = country, Asn = asn > 0 ? new AsnInfo(asn, "US", "OWNER", 0, 0) : null,
        Domains = ["example.com"],
    };

    [Fact]
    public void First_time_program_country_and_network()
    {
        var d = new NoveltyDetector([]);
        var steam = @"C:\Steam\steam.exe";

        // A new program: one event, not three.
        var news = d.Check([Row("steam.exe", steam, "1.1.1.1", "DE", 100)], All, true, true, true);
        Assert.Equal([NoveltyKind.Program], news.Select(n => n.Kind));

        // Same program, same place: nothing.
        Assert.Empty(d.Check([Row("steam.exe", steam, "1.1.1.2", "DE", 100)], All, true, true, true));

        // A new country and a new network.
        news = d.Check([Row("steam.exe", steam, "2.2.2.2", "NL", 200)], All, true, true, true);
        Assert.Equal([NoveltyKind.Country, NoveltyKind.Network], news.Select(n => n.Kind));
        Assert.Equal("NL", news[0].Value);
        Assert.Equal("AS200", news[1].Value);

        // The same file name elsewhere is another program.
        Assert.Single(d.Check([Row("steam.exe", @"D:\Temp\steam.exe", "1.1.1.1", "DE", 100)], All, true, true, true));
    }

    [Fact]
    public void Learning_remembers_without_reporting()
    {
        var d = new NoveltyDetector([]);
        Assert.Empty(d.Check([Row("a.exe", @"C:\a.exe", "1.1.1.1", "DE", 1)], All, false, true, true));
        var added = d.TakeAdded();
        Assert.Equal(3, added.Count);
        Assert.Empty(d.TakeAdded());

        // A restart with the saved keys knows the same.
        var again = new NoveltyDetector(added);
        Assert.Empty(again.Check([Row("a.exe", @"C:\a.exe", "1.1.1.1", "DE", 1)], All, true, true, true));
    }

    [Fact]
    public void Options_browsers_and_missing_databases()
    {
        var d = new NoveltyDetector([]);
        d.Check([Row("chrome.exe", @"C:\chrome.exe", "1.1.1.1", "DE", 1), Row("cs2.exe", @"C:\cs2.exe", "1.1.1.1", "DE", 1)], All, false, true, true);

        // Browsers: new countries are not news.
        Assert.Empty(d.Check([Row("chrome.exe", @"C:\chrome.exe", "3.3.3.3", "JP", 3)], All, true, true, true));
        // ...unless asked for.
        Assert.Equal(2, d.Check([Row("chrome.exe", @"C:\chrome.exe", "4.4.4.4", "BR", 4)], All with { SkipBrowsers = false }, true, true, true).Count);

        // Network news off.
        Assert.Equal([NoveltyKind.Country], d.Check([Row("cs2.exe", @"C:\cs2.exe", "5.5.5.5", "SE", 5)], All with { NewNetwork = false }, true, true, true).Select(n => n.Kind));

        // Without the country database countries are neither reported nor remembered.
        Assert.Empty(d.Check([Row("cs2.exe", @"C:\cs2.exe", "6.6.6.6", "FI", 5)], All, true, false, true));
        Assert.Single(d.Check([Row("cs2.exe", @"C:\cs2.exe", "6.6.6.6", "FI", 5)], All, true, true, true));
    }

    [Fact]
    public void Services_are_told_apart_by_service_name()
    {
        var d = new NoveltyDetector([]);
        var svchost = @"C:\Windows\System32\svchost.exe";
        Assert.Single(d.Check([Row("svchost.exe", svchost, "1.1.1.1", "US", 1, "BITS")], All, true, true, true));
        Assert.Single(d.Check([Row("svchost.exe", svchost, "1.1.1.1", "US", 1, "wuauserv")], All, true, true, true));
    }

    [Fact]
    public void Notification_text()
    {
        string Title(string key) => key == "steam.exe" ? "Steam" : key;
        var one = new Novelty(NoveltyKind.Country, "steam.exe", "steam.exe", "NL", "Нидерланды (NL)", "cdn.steam.com", IPAddress.Parse("2.2.2.2"));
        var (title, text) = NoveltyDetector.Compose([one], Title);
        Assert.Equal("Steam: новая страна — Нидерланды (NL)", title);
        Assert.Contains("cdn.steam.com (2.2.2.2)", text);

        var many = new List<Novelty>
        {
            one,
            one with { Value = "DE" },
            one with { Kind = NoveltyKind.Network, Value = "AS1" },
            new(NoveltyKind.Program, "cs2.exe", "cs2.exe", "", "", "", IPAddress.Parse("3.3.3.3")),
        };
        (title, text) = NoveltyDetector.Compose(many, Title);
        Assert.Equal("Новое в сети: 4 события", title);
        Assert.Contains("Steam: новые страны NL, DE; 1 новая сеть", text);
        Assert.Contains("cs2.exe: впервые в сети", text);
    }

    [Fact]
    public void Known_keys_are_stored_and_cleared()
    {
        var dir = Directory.CreateTempSubdirectory("netwatcher-alerts").FullName;
        try
        {
            using var store = new LogStore(Path.Combine(dir, "log.db"));
            store.AddKnown(["p|a", "c|a|DE"], DateTimeOffset.Now);
            store.AddKnown(["p|a"], DateTimeOffset.Now);
            Assert.Equal(["c|a|DE", "p|a"], store.LoadKnown().Order());
            store.Clear();
            Assert.Empty(store.LoadKnown());
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
