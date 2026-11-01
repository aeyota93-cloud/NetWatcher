using System.Net;
using System.Text;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Diagnostics;
using NetWatcher.Core.Dns;
using NetWatcher.Core.Link;

namespace NetWatcher.Core.Tests;

/// <summary>Cases from the v0.4.1 audit (docs: AUDIT-v0.4.1.md, stage 1).</summary>
public class AuditFixesTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);
    private static readonly IPAddress Game = IPAddress.Parse("155.133.252.38");
    private static readonly IPAddress Site = IPAddress.Parse("149.154.167.51");
    private static readonly IPAddress Helper = IPAddress.Parse("93.184.215.14");

    private static FlowSample Udp(long o, long i) => new("cs2.exe", "cs2.exe", "", "", Game, 27015, "UDP", o, i, o * 100, i * 100, 0, 0);
    private static FlowSample Tcp(long o, long i, int noAnswer = 0) => new("app.exe", "app.exe", "", "", Site, 443, "TCP", o, i, o * 100, i * 100, 0, noAnswer);

    private static LinkMonitor Played(Func<FlowSample> sample)
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        for (var s = 0; s <= 10; s += 2) m.Add(T0.AddSeconds(s), [sample()]);
        return m;
    }

    // ------------------------------------------------------------ #3: silence after an idle pause

    [Fact]
    public void Udp_resumed_after_idle_is_not_an_outage_at_once()
    {
        var m = Played(() => Udp(20, 20));
        var resume = T0.AddMinutes(30);
        m.Add(resume, [Udp(1, 0)]);
        var p = m.Snapshot(resume.AddSeconds(1), TimeSpan.FromMinutes(2)).Single();
        Assert.NotEqual(LinkLevel.Fail, p.Level);
        Assert.Empty(p.OutageList);
    }

    [Fact]
    public void Udp_resumed_after_idle_and_unanswered_counts_from_the_first_packet()
    {
        var m = Played(() => Udp(20, 20));
        var resume = T0.AddMinutes(30);
        for (var s = 0; s <= 8; s += 2) m.Add(resume.AddSeconds(s), [Udp(5, 0)]);
        var p = m.Snapshot(resume.AddSeconds(8), TimeSpan.FromMinutes(2)).Single();
        Assert.Equal(LinkLevel.Fail, p.Level);
        Assert.Equal("нет ответа 8 с", p.StateText);
    }

    [Fact]
    public void One_syn_retry_after_idle_is_not_a_long_outage()
    {
        var m = Played(() => Tcp(10, 10));
        var resume = T0.AddMinutes(20);
        m.Add(resume, [Tcp(1, 0, noAnswer: 1)]);
        m.Add(resume.AddSeconds(2), [Tcp(5, 5)]);
        var p = m.Snapshot(resume.AddSeconds(3), TimeSpan.FromMinutes(30)).Single();
        Assert.NotEqual(LinkLevel.Fail, p.Level);
        Assert.Empty(p.OutageList);
    }

    [Fact]
    public void Silence_ends_when_the_program_stops_trying()
    {
        var m = Played(() => Udp(20, 20));
        // Silent for 10 s while still sending, then the program goes quiet for a minute.
        for (var s = 12; s <= 22; s += 2) m.Add(T0.AddSeconds(s), [Udp(5, 0)]);
        var later = T0.AddSeconds(90);
        m.Add(later, [Udp(1, 1)]);
        var outage = m.Snapshot(later, TimeSpan.FromMinutes(5)).Single().OutageList.Single();
        Assert.Equal(T0.AddSeconds(22), outage.End); // not stretched to the next answer a minute later
    }

    // ------------------------------------------------------------ #2: TLS alert is a failed HTTPS

    private sealed class Probe : INetProbe
    {
        public Func<IPAddress, string, TlsProbe> Tls = (_, _) => new TlsProbe(TlsOutcome.Ok, 90, CertStatus.Valid);
        public DnsProbe HelperDns = new([Helper], false, null, 5);
        public WhoamiProbe Whoami = new(IPAddress.Parse("74.125.1.1"), null);

        public Task<DnsProbe> ResolveSystemAsync(string host, CancellationToken ct) =>
            Task.FromResult(host == Checker.ControlSni ? HelperDns : new DnsProbe([IPAddress.Parse("104.16.1.1")], false, null, 10));
        public Task<DnsProbe> ResolveIndependentAsync(string host, CancellationToken ct) =>
            Task.FromResult(new DnsProbe([IPAddress.Parse("104.16.1.1")], false, null, 20));
        public Task<WhoamiProbe> WhoamiAsync(IPAddress server, bool tcp, CancellationToken ct) => Task.FromResult(Whoami);
        public Task<TcpProbe> ConnectAsync(IPAddress ip, int port, CancellationToken ct) => Task.FromResult(new TcpProbe(TcpOutcome.Ok, 40));
        public Task<TlsProbe> TlsAsync(IPAddress ip, int port, string name, CancellationToken ct) => Task.FromResult(Tls(ip, name));
        public Task<int?> Http3PortAsync(string host, int port, CancellationToken ct) => Task.FromResult<int?>(0);
        public Task<QuicProbe> QuicAsync(IPAddress ip, int port, string name, CancellationToken ct) => Task.FromResult(new QuicProbe(QuicOutcome.Ok, 1));
        public Task<PingProbe> PingAsync(IPAddress ip, int count, CancellationToken ct) => Task.FromResult(new PingProbe(10, 10, 30));
        public Task<MtuProbe> MtuAsync(IPAddress ip, CancellationToken ct) => Task.FromResult(new MtuProbe(1472, false, false));
        public string? TunnelTo(IPAddress ip) => null;
        public Task<IReadOnlyList<HopProbe>> TraceAsync(IPAddress ip, int max, int rounds, Action<IReadOnlyList<HopProbe>>? progress, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<HopProbe>>([new HopProbe(1, [IPAddress.Parse("104.16.1.1")], 10, 10, 30, 30, 30, true)]);
    }

    private static AsnDatabase Asn() => AsnDatabase.Load(new MemoryStream(Encoding.UTF8.GetBytes(
        "74.125.0.0\t74.125.255.255\t15169\tUS\tGOOGLE\n" +
        "95.0.0.0\t95.255.255.255\t12389\tRU\tROSTELECOM-AS\n" +
        "104.16.0.0\t104.23.255.255\t13335\tUS\tCLOUDFLARENET\n")));

    private static Task<CheckReport> Run(Probe p) => Checker.RunAsync(CheckTarget.Parse("site.example")!, p, Asn(), null);

    [Fact]
    public async Task Tls_alert_with_sni_interference_is_a_block()
    {
        var p = new Probe
        {
            Tls = (ip, name) => ip.Equals(Helper)
                ? name == Checker.ControlSni ? new TlsProbe(TlsOutcome.Ok, 50, CertStatus.Valid) : new TlsProbe(TlsOutcome.Reset, 20)
                : new TlsProbe(TlsOutcome.Alert, 20, Error: "alert"),
        };
        var r = await Run(p);
        Assert.Equal(VerdictLevel.Fail, r.Verdict!.Level);
        Assert.Equal("Похоже на блокировку по имени сайта", r.Verdict.Title);
        Assert.Equal(StepStatus.Fail, r.Steps.Single(s => s.Id == "tls").Status);
    }

    [Fact]
    public async Task Tls_alert_without_a_helper_is_still_a_failed_https()
    {
        var p = new Probe
        {
            HelperDns = new([], true, "домен не найден", 5),
            Tls = (_, _) => new TlsProbe(TlsOutcome.Alert, 20, Error: "alert"),
        };
        var r = await Run(p);
        Assert.Equal(VerdictLevel.Fail, r.Verdict!.Level);
        Assert.Contains("ошибкой TLS от сервера", r.Verdict.Text);
    }

    // ------------------------------------------------------------ #13: an owner missing from the database

    [Fact]
    public void Resolver_kinds()
    {
        var asn = Asn();
        Assert.Equal(Verdicts.ResolverKind.NoAnswer, Verdicts.ResolverOf(new WhoamiProbe(null, "нет ответа"), asn));
        Assert.Equal(Verdicts.ResolverKind.Google, Verdicts.ResolverOf(new WhoamiProbe(IPAddress.Parse("74.125.1.1"), null), asn));
        Assert.Equal(Verdicts.ResolverKind.Other, Verdicts.ResolverOf(new WhoamiProbe(IPAddress.Parse("95.2.2.2"), null), asn));
        Assert.Equal(Verdicts.ResolverKind.Unknown, Verdicts.ResolverOf(new WhoamiProbe(IPAddress.Parse("203.0.113.5"), null), asn));
    }

    [Fact]
    public async Task Unknown_owner_is_not_called_interception()
    {
        var r = await Run(new Probe { Whoami = new WhoamiProbe(IPAddress.Parse("203.0.113.5"), null) });
        Assert.Equal(StepStatus.Skipped, r.Steps.Single(s => s.Id == "dnsint").Status);
        Assert.Null(r.InterceptionWarning);
    }

    // ------------------------------------------------------------ #24: clearing the history

    [Fact]
    public void Dns_index_can_be_cleared()
    {
        var dns = new DnsIndex();
        dns.Add(Site, "t.me", "Telegram.exe", T0);
        dns.Clear();
        Assert.Empty(dns.Get(Site, "Telegram.exe"));
    }
    // ------------------------------------------------------------ stage 3: link monitor and log

    [Fact]
    public void A_minor_server_failing_is_a_warning_not_no_link()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var minor = IPAddress.Parse("155.133.252.39");
        for (var s = 0; s <= 30; s += 2)
            m.Add(T0.AddSeconds(s), [Udp(100, 100), Udp(5, s < 10 ? 5 : 0) with { Ip = minor }]);
        var p = m.Snapshot(T0.AddSeconds(30), TimeSpan.FromMinutes(5)).Single();
        Assert.Equal(LinkLevel.Warn, p.Level);
        Assert.Equal("не отвечает 1 из 2 серверов", p.StateText);
    }

    [Fact]
    public void The_main_server_failing_is_no_link()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var minor = IPAddress.Parse("155.133.252.39");
        for (var s = 0; s <= 30; s += 2)
            m.Add(T0.AddSeconds(s), [Udp(100, s < 10 ? 100 : 0), Udp(5, 5) with { Ip = minor }]);
        Assert.Equal(LinkLevel.Fail, m.Snapshot(T0.AddSeconds(30), TimeSpan.FromMinutes(5)).Single().Level);
    }

    [Fact]
    public void Unmeasured_loss_is_unknown_not_zero()
    {
        var m = Played(() => Udp(20, 20));
        Assert.Null(m.Snapshot(T0.AddSeconds(10), TimeSpan.FromMinutes(5)).Single().LossPercent);
    }

    [Fact]
    public void A_server_without_ping_draws_no_loss_next_to_one_with_ping()
    {
        var m = new LinkMonitor(TimeSpan.FromHours(1));
        var quiet = IPAddress.Parse("155.133.252.39");
        for (var s = 0; s <= 60; s += 2) m.Add(T0.AddSeconds(s), [Udp(10, 10), Udp(10, 10) with { Ip = quiet }]);
        for (var s = 0; s <= 60; s += 5)
        {
            m.AddPing(Game, T0.AddSeconds(s), 30);
            m.AddPing(quiet, T0.AddSeconds(s), null);
        }
        Assert.All(m.Snapshot(T0.AddSeconds(60), TimeSpan.FromMinutes(1)).Single().Chart, c => Assert.Equal(0, c.LossPercent));
    }

    [Fact]
    public void Old_problems_of_the_hour_stay_out_of_a_short_period()
    {
        var dir = Directory.CreateTempSubdirectory("nw-hour").FullName;
        try
        {
            using (var store = new Storage.LogStore(Path.Combine(dir, "log.db")))
            {
                var hour = new DateTimeOffset(2026, 10, 31, 10, 0, 0, TimeSpan.Zero);
                store.Write([
                    new Observation("a.exe", "", "", "TCP", Site, 443, hour.AddMinutes(1), NoAnswer: 2),
                    new Observation("a.exe", "", "", "TCP", Site, 443, hour.AddMinutes(50), Established: true),
                ], []);
                var now = Assert.Single(store.Query(hour.AddMinutes(49)));
                Assert.Equal(0, now.NoAnswer);
                Assert.Equal(1, now.Established);
                Assert.Equal(2, Assert.Single(store.Query(hour)).NoAnswer);
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(dir, true);
        }
    }
}
