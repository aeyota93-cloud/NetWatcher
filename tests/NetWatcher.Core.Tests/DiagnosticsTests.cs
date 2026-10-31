using System.Net;
using System.Text;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Diagnostics;
using NetWatcher.Core.Storage;

namespace NetWatcher.Core.Tests;

public class DiagnosticsTests
{
    private static IPAddress Ip(string s) => IPAddress.Parse(s);

    private static AsnDatabase Asn() => AsnDatabase.Load(new MemoryStream(Encoding.UTF8.GetBytes(
        "95.0.0.0\t95.255.255.255\t12389\tRU\tROSTELECOM-AS\n" +
        "80.0.0.0\t80.255.255.255\t1299\tSE\tTWELVE99 Arelion, fka Telia Carrier\n" +
        "104.16.0.0\t104.23.255.255\t13335\tUS\tCLOUDFLARENET\n" +
        "151.101.0.0\t151.101.255.255\t54113\tUS\tFASTLY\n")));

    /// <summary>A scripted network: each test sets only what it needs.</summary>
    private sealed class FakeProbe : INetProbe
    {
        public DnsProbe Sys = new([Ip("104.16.1.1")], false, null, 12);
        public DnsProbe Ind = new([Ip("104.16.1.1")], false, null, 30);
        public TcpProbe Tcp = new(TcpOutcome.Ok, 40);
        public Func<string, TlsProbe> Tls = _ => new TlsProbe(TlsOutcome.Ok, 90);
        public PingProbe Ping = new(5, 5, 35);
        public List<HopProbe> Trace =
        [
            new(1, Ip("192.168.1.1"), 3, 3, 1, false),
            new(2, Ip("95.1.1.1"), 3, 3, 8, false),
            new(3, null, 3, 0, null, false),
            new(4, Ip("104.16.1.1"), 3, 3, 35, true),
        ];

        public Task<DnsProbe> ResolveSystemAsync(string host, CancellationToken ct) => Task.FromResult(Sys);
        public Task<DnsProbe> ResolveIndependentAsync(string host, CancellationToken ct) => Task.FromResult(Ind);
        public Task<TcpProbe> ConnectAsync(IPAddress ip, int port, CancellationToken ct) => Task.FromResult(Tcp);
        public Task<TlsProbe> TlsAsync(IPAddress ip, int port, string name, CancellationToken ct) => Task.FromResult(Tls(name));
        public Task<PingProbe> PingAsync(IPAddress ip, int count, CancellationToken ct) => Task.FromResult(Ping);
        public Task<IReadOnlyList<HopProbe>> TraceAsync(IPAddress ip, int max, CancellationToken ct) => Task.FromResult<IReadOnlyList<HopProbe>>(Trace);
    }

    private static Task<CheckReport> Run(FakeProbe p, string target = "example.org") =>
        Checker.RunAsync(CheckTarget.Parse(target)!, p, Asn(), null);

    [Fact]
    public async Task All_good()
    {
        var r = await Run(new FakeProbe());
        Assert.Equal(VerdictLevel.Ok, r.Verdict!.Level);
        Assert.Equal("Всё работает", r.Verdict.Title);
        Assert.Contains("подключение 40 мс", r.Verdict.Text);
        Assert.Equal(5, r.Steps.Count);
        Assert.Contains("Трасса", r.ToText());
    }

    [Fact]
    public async Task Dns_sinkhole_is_a_block()
    {
        var r = await Run(new FakeProbe { Sys = new([Ip("0.0.0.0")], false, null, 5) });
        Assert.Equal("Домен заблокирован через DNS", r.Verdict!.Title);
        Assert.Equal(StepStatus.Fail, r.Steps.Single(s => s.Id == "dns").Status);
    }

    [Fact]
    public async Task System_dns_fails_but_independent_works()
    {
        var r = await Run(new FakeProbe { Sys = new([], false, "DNS-сервер не ответил", 2000) });
        Assert.Equal("Проблема с DNS: системный DNS не отдаёт адрес", r.Verdict!.Title);
        Assert.NotNull(r.Tcp); // the check goes on with the independent answer
    }

    [Fact]
    public async Task No_such_domain()
    {
        var p = new FakeProbe { Sys = new([], true, "домен не найден", 10), Ind = new([], true, "домен не найден", 20) };
        var r = await Run(p);
        Assert.Equal("Такого домена нет", r.Verdict!.Title);
        Assert.Null(r.Tcp);
    }

    [Fact]
    public async Task Timeout_points_to_where_the_route_breaks()
    {
        var p = new FakeProbe
        {
            Tcp = new(TcpOutcome.Timeout, 5000),
            Ping = new(5, 0, 0),
            Trace = [new(1, Ip("192.168.1.1"), 3, 3, 1, false), new(2, Ip("95.1.1.1"), 3, 3, 8, false), new(3, null, 3, 0, null, false)],
        };
        var r = await Run(p);
        Assert.Equal("Сервер не отвечает на подключение", r.Verdict!.Title);
        Assert.Contains("обрывается после узла 2", r.Verdict.Text);
        Assert.Contains("сеть вашего провайдера (AS12389 · Ростелеком)", r.Verdict.Text);
        Assert.Equal(StepStatus.Skipped, r.Steps.Single(s => s.Id == "tls").Status);
    }

    [Fact]
    public async Task Tls_cut_only_for_the_real_name_is_dpi()
    {
        var p = new FakeProbe
        {
            Tls = name => name == Checker.FakeServerName ? new TlsProbe(TlsOutcome.Alert, 80) : new TlsProbe(TlsOutcome.Reset, 30),
        };
        var r = await Run(p);
        Assert.Equal("Блокировка по имени сайта (DPI)", r.Verdict!.Title);
    }

    [Fact]
    public async Task Tls_cut_for_any_name_is_not_called_dpi()
    {
        var r = await Run(new FakeProbe { Tls = _ => new TlsProbe(TlsOutcome.Timeout, 6000) });
        Assert.Equal("Защищённое соединение не устанавливается", r.Verdict!.Title);
    }

    [Fact]
    public async Task Refused_port()
    {
        var r = await Run(new FakeProbe { Tcp = new(TcpOutcome.Refused, 20) }, "104.16.1.1:8080");
        Assert.Equal("Порт 8080 закрыт", r.Verdict!.Title);
        Assert.Equal(StepStatus.Skipped, r.Steps.Single(s => s.Id == "dns").Status);
    }

    [Fact]
    public async Task Loss_that_starts_at_a_hop_and_stays()
    {
        var p = new FakeProbe
        {
            Ping = new(5, 3, 60),
            Trace =
            [
                new(1, Ip("192.168.1.1"), 3, 3, 1, false),
                new(2, Ip("95.1.1.1"), 3, 3, 8, false),
                new(3, Ip("80.1.1.1"), 3, 2, 40, false),
                new(4, Ip("104.16.1.1"), 3, 2, 60, true),
            ],
        };
        var r = await Run(p);
        Assert.Equal(VerdictLevel.Warn, r.Verdict!.Level);
        Assert.Contains("Потери пакетов 40%", r.Verdict.Text);
        Assert.Contains("начиная с узла 3 (промежуточная сеть AS1299 · Arelion (Telia))", r.Verdict.Text);
    }

    [Theory]
    [InlineData("example.org", "example.org", null, 443)]
    [InlineData("https://Example.org/page?x=1", "example.org", null, 443)]
    [InlineData("http://example.org", "example.org", null, 80)]
    [InlineData("example.org:8443", "example.org", null, 8443)]
    [InlineData("1.2.3.4", null, "1.2.3.4", 443)]
    [InlineData("1.2.3.4:22", null, "1.2.3.4", 22)]
    [InlineData("[2a00::1]:8080", null, "2a00::1", 8080)]
    [InlineData("2a00::1", null, "2a00::1", 443)]
    public void Parses_targets(string text, string? host, string? ip, int port)
    {
        var t = CheckTarget.Parse(text)!;
        Assert.Equal(host, t.Host);
        Assert.Equal(ip, t.Ip?.ToString());
        Assert.Equal(port, t.Port);
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad host")]
    [InlineData("example.org:99999")]
    public void Rejects_bad_targets(string text) => Assert.Null(CheckTarget.Parse(text));

    [Fact]
    public void Reads_doh_json()
    {
        var (status, ips) = NetProbe.ParseDohJson("""{"Status":0,"Answer":[{"type":5,"data":"x.cdn."},{"type":1,"data":"104.16.1.1"}]}""");
        Assert.Equal(0, status);
        Assert.Equal(["104.16.1.1"], ips.Select(i => i.ToString()));
        Assert.Equal(3, NetProbe.ParseDohJson("""{"Status":3}""").Status);
    }
}

public class OwnerNameTests
{
    [Theory]
    [InlineData("MICROSOFT-CORP-MSN-AS-BLOCK", "Microsoft MSN")]
    [InlineData("AMAZON-02", "Amazon")]
    [InlineData("HETZNER-AS", "Hetzner")]
    [InlineData("OVH", "OVH")]
    [InlineData("TWELVE99 Arelion, fka Telia Carrier", "TWELVE99 Arelion fka Telia Carrier")]
    [InlineData("SOMEHOST-AS - Some Host Ltd, DE", "Some Host")]
    [InlineData("Yandex enterprise network", "Yandex enterprise network")]
    public void Cleans_registry_handles(string raw, string expected) => Assert.Equal(expected, AsnNames.Clean(raw));

    [Fact]
    public void Known_and_learned_names_win()
    {
        Assert.Equal("Cloudflare", AsnNames.Display(13335, "CLOUDFLARENET"));
        AsnNames.Learned[64512] = "Test Net";
        Assert.Equal("Test Net", AsnNames.Display(64512, "WHATEVER-AS"));
        AsnNames.Learned.TryRemove(64512, out _);
    }

    [Fact]
    public void Parses_peeringdb()
    {
        const string json = """{"data":[{"name":"Cloudflare","aka":"","info_type":"Content","website":"https://www.cloudflare.com","policy_general":"Open"}],"meta":{}}""";
        var n = PeeringDbClient.Parse(json, 13335)!;
        Assert.Equal("Cloudflare", n.Name);
        Assert.Equal("контент и CDN (сайты, видео, облака)", n.TypeText);
        Assert.Contains("Тип сети", n.ToText());
        Assert.Null(PeeringDbClient.Parse("""{"data":[]}""", 1));
    }

    [Fact]
    public void PeeringDb_cache_survives_restart()
    {
        var dir = Directory.CreateTempSubdirectory("nw-pdb").FullName;
        try
        {
            var path = Path.Combine(dir, "peeringdb.json");
            File.WriteAllText(path, """[{"Asn":64513,"Net":{"Asn":64513,"Name":"Cached Net","Aka":"","Type":"NSP","Website":"","Policy":""}},{"Asn":64514,"Net":null}]""");
            var c = new PeeringDbClient(new HttpClient(), path);
            Assert.Equal("Cached Net", c.Cached(64513)!.Name);
            Assert.True(c.WasAsked(64514));
            Assert.Null(c.Cached(64514));
            Assert.Equal("Cached Net", AsnNames.Display(64513, "X"));
            AsnNames.Learned.TryRemove(64513, out _);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}

public class HealthTests
{
    private static DestinationRow Row(long hits, long est, long noAnswer, long retrans) => new()
    {
        Process = "a.exe", Services = "", Proto = "TCP", RemoteIp = IPAddress.Parse("1.1.1.1"), RemotePort = 443,
        Hits = hits, Established = est, NoAnswer = noAnswer, Retransmits = retrans,
    };

    [Fact]
    public void Levels()
    {
        Assert.Equal(HealthLevel.Fail, Row(3, 0, 2, 0).Health.Level);
        Assert.Equal(HealthLevel.Warn, Row(3, 0, 1, 0).Health.Level);
        Assert.Equal(HealthLevel.Warn, Row(10, 8, 3, 0).Health.Level);
        Assert.Equal(HealthLevel.Warn, Row(10, 10, 0, 40).Health.Level);
        Assert.Equal(HealthLevel.Ok, Row(10, 10, 0, 5).Health.Level);
        Assert.Equal(HealthLevel.Unknown, Row(1, 0, 0, 0).Health.Level);
        Assert.Equal(HealthLevel.Fail, Health.Worst([Row(1, 1, 0, 0).Health, Row(3, 0, 2, 0).Health]).Level);
    }

    [Fact]
    public void Problem_filter()
    {
        var rows = new List<DestinationRow> { Row(3, 0, 2, 0), Row(10, 10, 0, 0) };
        Assert.Single(QuickFilters.Apply(rows, QuickFilter.Problems));
    }

    [Theory]
    [InlineData(9003, "blocked.example", true)]
    [InlineData(9501, "example.org", false)]
    [InlineData(9003, "wpad.home.lan", false)]
    [InlineData(9003, "printer", false)]
    [InlineData(1460, "example.org", true)]
    [InlineData(-1, "ads.example", true)]
    public void Dns_problems(int status, string domain, bool expected) => Assert.Equal(expected, DnsStatus.IsProblem(status, domain));

    [Fact]
    public void Store_keeps_health_and_dns_failures()
    {
        var dir = Directory.CreateTempSubdirectory("nw-health").FullName;
        try
        {
            using var store = new LogStore(Path.Combine(dir, "log.db"));
            var now = DateTimeOffset.UtcNow;
            var ip = IPAddress.Parse("1.1.1.1");
            store.Write([
                new Observation("a.exe", "", "", "TCP", ip, 443, now, NoAnswer: 1),
                new Observation("a.exe", "", "", "TCP", ip, 443, now.AddSeconds(2), NoAnswer: 1, Retransmits: 3),
            ], []);
            var row = Assert.Single(store.Query(now.AddMinutes(-1)));
            Assert.Equal(2, row.NoAnswer);
            Assert.Equal(3, row.Retransmits);
            Assert.Equal(HealthLevel.Fail, row.Health.Level);

            store.WriteDnsFailures([new DnsFailure("a.exe", "Blocked.Example.", 9003, now), new DnsFailure("a.exe", "blocked.example", 9003, now)]);
            var f = Assert.Single(store.DnsFailures(now.AddMinutes(-1)));
            Assert.Equal("blocked.example", f.Domain);
            Assert.Equal(2, f.Hits);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
