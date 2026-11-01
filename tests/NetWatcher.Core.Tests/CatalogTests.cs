using System.Net;
using System.Text;
using NetWatcher.Core.Catalog;

namespace NetWatcher.Core.Tests;

public class CatalogTests
{
    // The format written by tools/build-catalog.py.
    private const string Tsv = """
        # NetWatcher domain catalog
        doubleclick.net	Google Ads (Google)	tracker	Ad Motivated Tracking,Advertising	ddg
        google.com	Google		Advertising,Content Delivery	ddg
        microsoft.com	Microsoft			ddg
        vortex.data.microsoft.com		telemetry		wsb
        yadro.ru	ECO PC	malware	Analytics,Malware	ddg
        hotjar.com	Hotjar	tracker	Analytics,Session Replay	ddg
        """;

    private static DomainCatalog Load() => DomainCatalog.Load(new MemoryStream(Encoding.UTF8.GetBytes(Tsv)));

    [Fact]
    public void Exact_and_parent_domains_match()
    {
        var c = Load();
        Assert.Equal(6, c.Count);

        var ads = c.Lookup("stats.g.doubleclick.net")!;
        Assert.Equal(DomainTag.Tracker, ads.Tag);
        Assert.Equal("doubleclick.net", ads.Domain);
        Assert.Equal("Google Ads (Google)", ads.Company);
        Assert.Equal("трекер", ads.TagText);
        Assert.Contains("реклама", ads.Explanation);

        // A telemetry host without a company takes the company of its parent domain.
        var tel = c.Lookup("vortex.data.microsoft.com")!;
        Assert.Equal(DomainTag.Telemetry, tel.Tag);
        Assert.Equal("Microsoft", tel.Company);

        // The rest of microsoft.com is only a company, no mark.
        var ms = c.Lookup("www.microsoft.com")!;
        Assert.Equal(DomainTag.None, ms.Tag);
        Assert.Equal("", ms.TagText);

        Assert.Null(c.Lookup("example.org"));
        Assert.Null(c.Lookup("com"));
        Assert.Null(c.Lookup(""));
        Assert.Equal("Google", c.Lookup("www.google.com.")!.Company);
    }

    [Fact]
    public void Several_domains_give_the_strongest_mark()
    {
        var c = Load();
        var best = c.Lookup(["www.google.com", "mc.yadro.ru", "hotjar.com"])!;
        Assert.Equal(DomainTag.Malware, best.Tag);
        Assert.Null(c.Lookup(["example.org"]));
        Assert.Equal("опасный", best.TagText);
    }

    [Fact]
    public void Rows_get_marks_and_quick_filters_use_them()
    {
        var c = Load();
        DestinationRow Row(string domain, string ip) =>
            new() { Process = "chrome.exe", Services = "", Proto = "TCP", RemoteIp = IPAddress.Parse(ip), RemotePort = 443, Domains = [domain] };
        var rows = new List<DestinationRow> { Row("static.hotjar.com", "1.1.1.1"), Row("vortex.data.microsoft.com", "2.2.2.2"), Row("www.google.com", "3.3.3.3") };
        foreach (var r in rows) r.Catalog = c.Lookup(r.Domains);

        Assert.Equal(["static.hotjar.com"], QuickFilters.Apply(rows, QuickFilter.Trackers).Select(r => r.PrimaryDomain));
        Assert.Equal(["vortex.data.microsoft.com"], QuickFilters.Apply(rows, QuickFilter.Telemetry).Select(r => r.PrimaryDomain));
        Assert.Equal(2, QuickFilters.Apply(rows, QuickFilter.Trackers | QuickFilter.Telemetry).Count);
        Assert.Single(rows, r => r.Matches(["hotjar"]));
        Assert.Single(rows, r => r.Matches(["телеметрия"]));
        Assert.Equal(2, rows.Count(r => r.Matches(["google"]) || r.Matches(["Microsoft"])));
    }
}
