using System.IO.Compression;
using System.Net;
using System.Text;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Geo;

namespace NetWatcher.Core.Tests;

public class GeoTests
{
    private const string Csv = """
        1.0.0.0,1.0.0.255,AU
        1.0.1.0,1.0.3.255,CN
        5.0.0.0,5.0.0.255,ZZ
        104.16.0.0,104.16.255.255,DE
        2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
        2a06:98c0::,2a06:98c1:ffff:ffff:ffff:ffff:ffff:ffff,NL
        """;

    private static GeoDatabase Load(string text) => GeoDatabase.Load(new MemoryStream(Encoding.UTF8.GetBytes(text)));

    [Theory]
    [InlineData("1.0.0.0", "AU")]
    [InlineData("1.0.0.255", "AU")]
    [InlineData("1.0.2.7", "CN")]
    [InlineData("1.0.4.0", "")]          // gap after a range
    [InlineData("0.255.255.255", "")]    // before the first range
    [InlineData("5.0.0.1", "")]          // ZZ means unknown
    [InlineData("104.16.132.229", "DE")]
    [InlineData("104.17.0.0", "")]       // after the last IPv4 range
    [InlineData("2001:200::1", "JP")]
    [InlineData("2a06:98c1:3120::3", "NL")]
    [InlineData("2a06:98c2::1", "")]     // after the very last range
    public void Lookup_by_range(string ip, string country)
    {
        var db = Load(Csv);
        Assert.Equal(5, db.Count);
        Assert.Equal(country, db.Lookup(IPAddress.Parse(ip)));
    }

    [Fact]
    public void Reads_gzip_and_refuses_a_web_page()
    {
        var dir = Directory.CreateTempSubdirectory("netwatcher-geo").FullName;
        try
        {
            var gz = Path.Combine(dir, "geo.download");
            using (var file = File.Create(gz))
            using (var zip = new GZipStream(file, CompressionLevel.Fastest))
                zip.Write(Encoding.UTF8.GetBytes(Csv));
            Assert.Equal("DE", GeoDatabase.LoadFile(gz).Lookup(IPAddress.Parse("104.16.0.1")));

            var html = Path.Combine(dir, "page.gz");
            File.WriteAllText(html, "<html>blocked</html>");
            Assert.Throws<InvalidDataException>(() => GeoDatabase.LoadFile(html));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Monthly_file_names_and_sources()
    {
        Assert.Equal("https://download.db-ip.com/free/dbip-country-lite-2026-11.csv.gz", GeoDatabase.OriginalUrl(new DateTime(2026, 11, 1)));
        var sources = GeoDatabase.Sources(new DateTime(2026, 1, 3));
        Assert.Equal(GeoDatabase.MirrorUrl, sources[0]);
        Assert.EndsWith("2026-01.csv.gz", sources[1]);
        Assert.EndsWith("2025-12.csv.gz", sources[2]);
    }

    [Fact]
    public void Server_country_wins_and_registration_is_explained()
    {
        var row = new DestinationRow
        {
            Process = "chrome.exe", Services = "", Proto = "TCP", RemoteIp = IPAddress.Parse("104.16.132.229"), RemotePort = 443,
            Asn = new AsnInfo(13335, "US", "CLOUDFLARENET", 0, 0),
        };
        Assert.Equal("US", row.CountryText);
        row.ServerCountry = "DE";
        Assert.Equal("DE", row.CountryText);
        Assert.Equal("US", row.RegisteredCountry);
        Assert.Contains("DE", Countries.Tip("DE", "US"));
        Assert.Contains("US", Countries.Tip("DE", "US"));
        Assert.DoesNotContain("зарегистрирована", Countries.Tip("DE", "DE"));
        Assert.Contains("DE", Countries.Describe("DE", "US"));
        Assert.Equal("—", Countries.Describe("", ""));
    }
}
