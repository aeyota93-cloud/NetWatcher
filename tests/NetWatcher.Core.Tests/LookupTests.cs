using System.IO.Compression;
using System.Net;
using System.Text;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Dns;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Tests;

public class LookupTests
{
    // Same layout as iptoasn.com ip2asn-combined.tsv.
    private const string Sample =
        "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
        "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
        "142.250.0.0\t142.251.255.255\t15169\tUS\tGOOGLE\n" +
        "5.255.255.0\t5.255.255.200\t13238\tRU\tYANDEX LLC\n" +
        "2a00:1450::\t2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n";

    private static AsnDatabase Db() => AsnDatabase.Load(new MemoryStream(Encoding.UTF8.GetBytes(Sample)));

    [Fact]
    public void Finds_owner_and_network()
    {
        var info = Db().Lookup(IPAddress.Parse("142.250.74.110"))!;
        Assert.Equal(15169, info.Asn);
        Assert.Equal("AS15169 · Google", info.OwnerText);
        Assert.Equal("142.250.0.0/15", info.NetworkOf(IPAddress.Parse("142.250.74.110")).ToString());
    }

    [Fact]
    public void Unaligned_range_gives_the_block_with_the_address()
    {
        var ip = IPAddress.Parse("5.255.255.150");
        var info = Db().Lookup(ip)!;
        Assert.Equal("5.255.255.128/26", info.NetworkOf(ip).ToString());
    }

    [Fact]
    public void Ipv6_lookup()
    {
        Assert.Equal(15169, Db().Lookup(IPAddress.Parse("2a00:1450:4010:c05::64"))!.Asn);
    }

    [Theory]
    [InlineData("1.0.2.1")] // not routed
    [InlineData("9.9.9.9")] // not in table
    [InlineData("0.0.0.1")] // before the first range
    public void Unknown_addresses(string ip) => Assert.Null(Db().Lookup(IPAddress.Parse(ip)));

    [Fact]
    public void Loads_gzip_file()
    {
        var path = System.IO.Path.GetTempFileName() + ".gz";
        try
        {
            using (var f = File.Create(path))
            using (var gz = new GZipStream(f, CompressionLevel.Fastest))
                gz.Write(Encoding.UTF8.GetBytes(Sample));
            Assert.Equal(4, AsnDatabase.LoadFile(path).Count);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Loads_gzip_by_content_whatever_the_name()
    {
        // The updater reads the file while it is still called *.download.
        var path = System.IO.Path.GetTempFileName() + ".download";
        try
        {
            using (var f = File.Create(path))
            using (var gz = new GZipStream(f, CompressionLevel.Fastest))
                gz.Write(Encoding.UTF8.GetBytes(Sample));
            Assert.Equal(4, AsnDatabase.LoadFile(path).Count);

            File.WriteAllText(path, Sample);
            Assert.Equal(4, AsnDatabase.LoadFile(path).Count);

            File.WriteAllText(path, "<html>Just a moment...</html>");
            Assert.Throws<InvalidDataException>(() => AsnDatabase.LoadFile(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Parses_dns_client_results()
    {
        var (ips, aliases) = DnsResultParser.Parse("type:  5 star-mini.c10r.facebook.com;::ffff:157.240.1.35;2a03:2880:f10c:83:face:b00c:0:25de;");
        Assert.Equal(["157.240.1.35", "2a03:2880:f10c:83:face:b00c:0:25de"], ips.Select(i => i.ToString()));
        Assert.Equal(["star-mini.c10r.facebook.com"], aliases);
    }

    [Fact]
    public void Dns_index_uses_only_the_process_own_domains_when_available()
    {
        var idx = new DnsIndex();
        var ip = IPAddress.Parse("104.16.1.1");
        var t = DateTimeOffset.UtcNow;
        idx.Add(ip, "other.example.", "chrome.exe", t.AddMinutes(1));
        idx.Add(ip, "Telegram.org", "telegram.exe", t);
        idx.Add(ip, "api.telegram.org", "TELEGRAM.EXE", t.AddSeconds(10));
        Assert.Equal(["api.telegram.org", "telegram.org"], idx.Get(ip, "Telegram.exe"));
        Assert.Equal(["api.telegram.org"], idx.Get(ip, "telegram.exe", 1));

        idx.RemoveOlderThan(t.AddSeconds(30));
        Assert.Equal(["other.example"], idx.Get(ip, "telegram.exe"));
    }

    [Fact]
    public void Dns_index_falls_back_to_all_domains_newest_first()
    {
        var idx = new DnsIndex();
        var ip = IPAddress.Parse("104.16.1.1");
        var t = DateTimeOffset.UtcNow;
        idx.Add(ip, "older.example", "chrome.exe", t);
        idx.Add(ip, "newer.example", "firefox.exe", t.AddSeconds(10));
        idx.Add(ip, "older.example", "firefox.exe", t.AddSeconds(-10));

        Assert.Equal(["newer.example", "older.example"], idx.Get(ip, "telegram.exe"));
        Assert.Equal(["newer.example", "older.example"], idx.Get(ip, null));
        Assert.Equal(["newer.example"], idx.Get(ip, "telegram.exe", 1));
        Assert.Equal(["newer.example"], idx.Get(ip, null, 1));
    }

    [Fact]
    public void Parses_rdap_answer()
    {
        const string json = """
            {
              "handle": "NET-142-250-0-0-1",
              "startAddress": "142.250.0.0",
              "endAddress": "142.251.255.255",
              "name": "GOOGLE",
              "country": "US",
              "cidr0_cidrs": [{"v4prefix": "142.250.0.0", "length": 15}],
              "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]]]
              }]
            }
            """;
        var r = RdapClient.Parse(json, "rdap.arin.net");
        Assert.Equal("142.250.0.0/15", r.Networks.Single().ToString());
        Assert.Equal(["Google LLC"], r.Organizations);
        Assert.Contains("Сеть: 142.250.0.0 255.254.0.0", r.ToText(AddressFormat.Mask));
    }

    [Fact]
    public void Rdap_without_cidrs_uses_range()
    {
        var r = RdapClient.Parse("""{"startAddress":"10.0.0.0","endAddress":"10.0.2.255"}""", "x");
        Assert.Equal(["10.0.0.0/23", "10.0.2.0/24"], r.Networks.Select(n => n.ToString()));
    }
}
