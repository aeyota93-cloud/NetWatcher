using System.Net;
using System.Text;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Dns;
using NetWatcher.Core.Storage;

namespace NetWatcher.Core.Tests;

public class FeatureTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);

    private static DestinationRow Row(string process, string ip, string proto = "TCP", int port = 443, params string[] domains) => new()
    {
        Process = process,
        Services = "",
        Proto = proto,
        RemoteIp = IPAddress.Parse(ip),
        RemotePort = port,
        LastSeen = Now,
        FirstSeen = Now,
        Hits = 1,
        Domains = domains,
    };

    private static AsnDatabase Asn() => AsnDatabase.Load(new MemoryStream(Encoding.UTF8.GetBytes(
        "13.107.4.0\t13.107.4.255\t8068\tUS\tMICROSOFT-CORP-MSN-AS-BLOCK\n" +
        "142.250.0.0\t142.251.255.255\t15169\tUS\tGOOGLE\n")));

    [Fact]
    public void Quick_filters()
    {
        var asn = Asn();
        var rows = new List<DestinationRow>
        {
            Row("a.exe", "142.250.1.1", "UDP", 443, "youtube.com"),
            Row("a.exe", "13.107.4.50", "TCP", 443, "fe3cr.delivery.mp.microsoft.com"),
            Row("a.exe", "9.9.9.9", "TCP", 443),
            Row("a.exe", "2a00::1", "TCP", 443),
        };
        foreach (var r in rows) r.Asn = asn.Lookup(r.RemoteIp);
        rows[2].IsNew = true;

        int Count(QuickFilter f) => QuickFilters.Apply(rows, f).Count;
        Assert.Equal(4, Count(QuickFilter.None));
        Assert.Equal(1, Count(QuickFilter.Udp));
        Assert.Equal(3, Count(QuickFilter.Tcp));
        Assert.Equal(4, Count(QuickFilter.Tcp | QuickFilter.Udp));
        Assert.Equal(2, Count(QuickFilter.WithDomain));
        Assert.Equal(2, Count(QuickFilter.NoDomain));
        Assert.Equal(1, Count(QuickFilter.OnlyNew));
        Assert.Equal(3, Count(QuickFilter.HideMicrosoft));
        Assert.Equal(3, Count(QuickFilter.Ipv4));
        Assert.Equal(1, Count(QuickFilter.Tcp | QuickFilter.NoDomain | QuickFilter.Ipv4));
    }

    [Fact]
    public void Groups_by_domain()
    {
        var rows = new List<DestinationRow>
        {
            Row("c.exe", "142.250.1.1", "UDP", 443, "youtube.com"),
            Row("c.exe", "142.250.1.2", "TCP", 443, "youtube.com", "googlevideo.com"),
            Row("c.exe", "1.1.1.1", "TCP", 443),
            Row("c.exe", "1.1.1.2", "TCP", 443),
        };
        var groups = DomainGroup.Build(rows);
        Assert.Equal(3, groups.Count);
        var yt = groups.Single(g => g.Domain == "youtube.com");
        Assert.Equal(2, yt.Addresses);
        Assert.Equal(2, groups.Count(g => g.Domain == ""));
    }

    [Fact]
    public void Export_formats()
    {
        var rows = new List<DestinationRow>
        {
            Row("c.exe", "142.250.74.110", "TCP", 443, "youtube.com"),
            Row("c.exe", "142.250.74.78", "TCP", 443, "youtube.com"),
            Row("c.exe", "87.250.250.242", "TCP", 443, "ya.ru"),
            Row("c.exe", "2a00:1450:4010:c05::64", "TCP", 443, "google.com"),
        };
        var nl = Environment.NewLine;

        Assert.Equal($"87.250.250.242{nl}142.250.74.78{nl}142.250.74.110{nl}2a00:1450:4010:c05::64",
            Export.Build(rows, ExportWhat.Addresses, 0, ExportTarget.Lines, false, false).Text);

        var subnets = Export.Build(rows, ExportWhat.Subnets, 2, ExportTarget.Lines, true, true);
        Assert.Equal($"87.250.250.0/24  # ya.ru{nl}142.250.74.0/24  # youtube.com", subnets.Text);
        Assert.Equal(2, subnets.Items);
        Assert.Equal(3, subnets.Addresses);

        Assert.Equal("AllowedIPs = 87.250.250.0/24, 142.250.74.0/24",
            Export.Build(rows, ExportWhat.Subnets, 2, ExportTarget.WireGuard, true, false).Text);
        Assert.Equal("87.250.250.0/24,142.250.74.0/24",
            Export.Build(rows, ExportWhat.Subnets, 2, ExportTarget.WindowsFirewall, true, true).Text);
        Assert.Equal($"87.250.250.0 255.255.255.0{nl}142.250.74.0 255.255.255.0",
            Export.Build(rows, ExportWhat.Subnets, 2, ExportTarget.Mask, true, false).Text);
        Assert.Equal("AllowedIPs = 87.250.250.242/32, 142.250.74.78/32, 142.250.74.110/32",
            Export.Build(rows, ExportWhat.Addresses, 0, ExportTarget.WireGuard, true, false).Text);
        Assert.Equal($"google.com{nl}ya.ru{nl}youtube.com",
            Export.Build(rows, ExportWhat.Domains, 0, ExportTarget.WireGuard, false, false).Text);
        Assert.Equal("", Export.Build([], ExportWhat.Subnets, 2, ExportTarget.WireGuard, true, false).Text);
    }

    [Fact]
    public void New_since_skips_the_first_hour_of_the_log()
    {
        Assert.Null(Analysis.NewSince(Now, null));
        Assert.Null(Analysis.NewSince(Now, Now.AddMinutes(-30)));
        Assert.Equal(Now.AddHours(-2), Analysis.NewSince(Now, Now.AddHours(-3)));
        Assert.Equal(Now.AddHours(-24), Analysis.NewSince(Now, Now.AddDays(-5)));
    }

    [Fact]
    public void Text_helpers()
    {
        Assert.Equal("1 адрес", TextFormat.Plural(1, "адрес", "адреса", "адресов"));
        Assert.Equal("12 адресов", TextFormat.Plural(12, "адрес", "адреса", "адресов"));
        Assert.Equal("22 адреса", TextFormat.Plural(22, "адрес", "адреса", "адресов"));
        Assert.Equal("12 345 адресов", TextFormat.Plural(12345, "адрес", "адреса", "адресов"));
        Assert.Equal("сейчас", TextFormat.Relative(Now, Now.AddSeconds(-20), TimeSpan.FromSeconds(10)));
        Assert.Equal("5 мин", TextFormat.Relative(Now, Now.AddMinutes(-5), TimeSpan.FromSeconds(10)));
        Assert.Equal("UDP 443 (QUIC / HTTP3)", TextFormat.Port("UDP", 443));
        Assert.Equal("TCP 5000", TextFormat.Port("TCP", 5000));
    }

    [Fact]
    public void Store_first_seen_activity_and_dns_journal()
    {
        var dir = Directory.CreateTempSubdirectory("netwatcher-test").FullName;
        try
        {
            using var store = new LogStore(Path.Combine(dir, "log.db"));
            var now = DateTimeOffset.UtcNow;
            store.Write([
                new Observation("a.exe", "", "", "TCP", IPAddress.Parse("1.1.1.1"), 443, now.AddHours(-3)),
                new Observation("a.exe", "", "", "TCP", IPAddress.Parse("1.1.1.1"), 443, now),
                new Observation("svchost.exe", "BITS", "", "TCP", IPAddress.Parse("2.2.2.2"), 80, now),
            ], []);

            var first = store.FirstSeenByRow();
            Assert.Equal((now.AddHours(-3)).ToUnixTimeMilliseconds(), first["a.exe|TCP|1.1.1.1|443"].ToUnixTimeMilliseconds());
            Assert.True(first.ContainsKey("svchost.exe · BITS|TCP|2.2.2.2|80"));
            Assert.Equal(now.AddHours(-3).ToUnixTimeMilliseconds(), store.LogStart()!.Value.ToUnixTimeMilliseconds());

            var activity = store.Activity(now, 7);
            Assert.Equal(7, activity["a.exe"].Length);
            Assert.Equal(1, activity["a.exe"][6]);
            Assert.Equal(1, activity["a.exe"][3]);
            Assert.Equal(1, activity["svchost.exe · BITS"][6]);

            var idx = new DnsIndex();
            idx.Add(IPAddress.Parse("1.1.1.1"), "one.one", "a.exe", now);
            idx.Add(IPAddress.Parse("1.0.0.1"), "one.one", "a.exe", now);
            idx.Add(IPAddress.Parse("8.8.8.8"), "dns.google", "b.exe", now.AddMinutes(-1));
            var answers = idx.Answers(p => p == "a.exe", now.AddHours(-1));
            var a = Assert.Single(answers);
            Assert.Equal(["1.0.0.1", "1.1.1.1"], a.Addresses.Select(x => x.ToString()));
            Assert.Equal(2, idx.Answers(null, now.AddHours(-1)).Count);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
