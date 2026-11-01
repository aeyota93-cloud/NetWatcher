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
        "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n" +
        "74.125.0.0\t74.125.255.255\t15169\tUS\tGOOGLE\n" +
        "95.0.0.0\t95.255.255.255\t12389\tRU\tROSTELECOM-AS\n" +
        "80.0.0.0\t80.255.255.255\t1299\tSE\tTWELVE99 Arelion, fka Telia Carrier\n" +
        "93.184.0.0\t93.184.255.255\t15133\tUS\tEDGECAST\n" +
        "104.16.0.0\t104.23.255.255\t13335\tUS\tCLOUDFLARENET\n" +
        "151.101.0.0\t151.101.255.255\t54113\tUS\tFASTLY\n")));

    private static HopProbe Hop(int ttl, string? ip, int replies = 10, double ms = 10, bool reached = false, int sent = 10) =>
        new(ttl, ip == null ? [] : [Ip(ip)], sent, ip == null ? 0 : replies, ip == null ? null : ms, ip == null ? null : ms, ip == null ? null : ms, reached);

    /// <summary>A scripted network: each test sets only what it needs.</summary>
    private sealed class FakeProbe : INetProbe
    {
        public DnsProbe Sys = new([Ip("104.16.1.1")], false, null, 12);
        public DnsProbe Ind = new([Ip("104.16.1.1")], false, null, 30);
        public DnsProbe Helper = new([Ip("93.184.215.14")], false, null, 10);
        public WhoamiProbe Udp = new(Ip("74.125.1.1"), null);
        public WhoamiProbe Tcp = new(Ip("74.125.1.2"), null);
        public TcpProbe Connect = new(TcpOutcome.Ok, 40);
        public Func<IPAddress, string, TlsProbe> Tls = (_, _) => new TlsProbe(TlsOutcome.Ok, 90, CertStatus.Valid);
        public bool? H3 = false;
        public QuicProbe Quic = new(QuicOutcome.Ok, 50);
        public PingProbe Ping = new(10, 10, 35);
        public MtuProbe Mtu = new(1472, false, false);
        public List<HopProbe> Trace = [Hop(1, "192.168.1.1", ms: 1), Hop(2, "95.1.1.1", ms: 8), Hop(3, null), Hop(4, "104.16.1.1", ms: 35, reached: true)];

        public Task<DnsProbe> ResolveSystemAsync(string host, CancellationToken ct) =>
            Task.FromResult(host == Checker.ControlSni ? Helper : host == "whoami.akamai.net" ? new DnsProbe([Ip("95.2.2.2")], false, null, 5) : Sys);
        public Task<DnsProbe> ResolveIndependentAsync(string host, CancellationToken ct) => Task.FromResult(Ind);
        public Task<WhoamiProbe> WhoamiAsync(IPAddress server, bool tcp, CancellationToken ct) => Task.FromResult(tcp ? Tcp : Udp);
        public Func<IPAddress, TcpProbe>? ConnectTo;
        public Task<TcpProbe> ConnectAsync(IPAddress ip, int port, CancellationToken ct) => Task.FromResult(ConnectTo?.Invoke(ip) ?? Connect);
        public Task<TlsProbe> TlsAsync(IPAddress ip, int port, string name, CancellationToken ct) => Task.FromResult(Tls(ip, name));
        public Task<int?> Http3PortAsync(string host, int port, CancellationToken ct) => Task.FromResult(H3 switch { true => (int?)443, false => 0, null => null });
        public Task<QuicProbe> QuicAsync(IPAddress ip, int port, string name, CancellationToken ct) => Task.FromResult(Quic);
        public Task<PingProbe> PingAsync(IPAddress ip, int count, CancellationToken ct) => Task.FromResult(Ping);
        public Task<MtuProbe> MtuAsync(IPAddress ip, CancellationToken ct) => Task.FromResult(Mtu);
        public string? Tunnel;
        public string? TunnelTo(IPAddress ip) => Tunnel;
        public Task<IReadOnlyList<HopProbe>> TraceAsync(IPAddress ip, int max, int rounds, Action<IReadOnlyList<HopProbe>>? progress, CancellationToken ct)
        {
            progress?.Invoke(Trace);
            return Task.FromResult<IReadOnlyList<HopProbe>>(Trace);
        }
    }

    private static Task<CheckReport> Run(FakeProbe p, string target = "example.net") =>
        Checker.RunAsync(CheckTarget.Parse(target)!, p, Asn(), null);

    private static StepStatus StepOf(CheckReport r, string id) => r.Steps.Single(s => s.Id == id).Status;

    /// <summary>Helper server answers; the site's name is cut the given way.</summary>
    private static Func<IPAddress, string, TlsProbe> SiteCut(TlsOutcome siteOutcome, TlsOutcome helperWithSiteName) => (ip, name) =>
        ip.Equals(Ip("93.184.215.14"))
            ? name == Checker.ControlSni ? new TlsProbe(TlsOutcome.Ok, 80, CertStatus.Valid) : new TlsProbe(helperWithSiteName, 30, CertStatus.NameMismatch)
            : new TlsProbe(siteOutcome, 30);

    [Fact]
    public async Task All_good()
    {
        var r = await Run(new FakeProbe());
        Assert.Equal(VerdictLevel.Ok, r.Verdict!.Level);
        Assert.Equal("Проверки пройдены", r.Verdict.Title);
        Assert.Contains("подключение 40 мс", r.Verdict.Text);
        Assert.Equal(StepStatus.Ok, StepOf(r, "dnsint"));
        Assert.StartsWith("на запрос к 8.8.8.8 ответил DNS из сети Google.", r.Steps.Single(s => s.Id == "dnsint").Text);
        Assert.Contains("95.2.2.2 (AS12389 · Ростелеком)", r.Steps.Single(s => s.Id == "dnsint").Text);
        Assert.Equal(StepStatus.Skipped, StepOf(r, "quic")); // site does not advertise HTTP/3
        Assert.Contains("10 проб на узел", r.ToText());
    }

    [Fact]
    public async Task Dns_sinkhole_is_a_block()
    {
        var r = await Run(new FakeProbe { Sys = new([Ip("0.0.0.0")], false, null, 5) });
        Assert.Equal("DNS вернул заглушку", r.Verdict!.Title);
        Assert.Equal(StepStatus.Fail, StepOf(r, "dns"));
    }

    [Fact]
    public async Task System_dns_fails_but_independent_works()
    {
        var r = await Run(new FakeProbe { Sys = new([], false, "DNS-сервер не ответил", 2000) });
        Assert.Equal("Системный DNS не нашёл адрес", r.Verdict!.Title);
        Assert.NotNull(r.Tcp);
    }

    [Fact]
    public async Task No_such_domain()
    {
        var r = await Run(new FakeProbe { Sys = new([], true, "домен не найден", 10), Ind = new([], true, "домен не найден", 20) });
        Assert.Equal("DNS не нашёл домен", r.Verdict!.Title);
        Assert.Contains("Проверенные DNS-серверы не нашли адрес", r.Verdict.Text);
        Assert.Equal("DNS не нашёл домен", r.Steps.Single(s => s.Id == "dns").Text);
        Assert.Equal("DNS не нашёл домен", DnsStatus.Describe(9003));
        Assert.Null(r.Tcp);
    }

    [Fact]
    public async Task Different_network_with_valid_certificate_does_not_prove_spoofing()
    {
        var r = await Run(new FakeProbe { Ind = new([Ip("151.101.1.1")], false, null, 20) });
        Assert.Equal(StepStatus.Ok, StepOf(r, "dns"));
        Assert.Contains("сертификат сайта действителен. Различие адресов само по себе не доказывает подмену", r.Steps.Single(s => s.Id == "dns").Text);
    }

    [Fact]
    public async Task Timeout_reports_last_answer_without_proving_a_broken_route()
    {
        var p = new FakeProbe
        {
            Connect = new(TcpOutcome.Timeout, 5000),
            Ping = new(10, 0, 0),
            Trace = [Hop(1, "192.168.1.1"), Hop(2, "95.1.1.1"), Hop(3, null)],
        };
        var r = await Run(p);
        Assert.Equal("Сервер не отвечает на подключение", r.Verdict!.Title);
        Assert.Contains("после узла 2", r.Verdict.Text);
        Assert.Contains("Это не доказывает обрыв пути", r.Verdict.Text);
        Assert.Contains("сеть вашего провайдера (AS12389 · Ростелеком)", r.Verdict.Text);
        Assert.Equal(StepStatus.Skipped, StepOf(r, "tls"));
    }

    [Theory]
    [InlineData(TlsOutcome.Reset, "interference.reset")]
    [InlineData(TlsOutcome.Closed, "interference.closed")]
    public async Task Sni_interference_per_ooni(TlsOutcome cut, string code)
    {
        var r = await Run(new FakeProbe { Tls = SiteCut(cut, cut) });
        Assert.Equal(code, r.Sni!.Code);
        Assert.Equal("Похоже на блокировку по имени сайта", r.Verdict!.Title);
        Assert.Contains("ts-024", r.Verdict.Text);
        Assert.Contains("Это может указывать на фильтрацию", r.Verdict.Text);
    }

    [Fact]
    public async Task Sni_timeout_is_only_an_anomaly()
    {
        var r = await Run(new FakeProbe { Tls = SiteCut(TlsOutcome.Timeout, TlsOutcome.Timeout) });
        Assert.Equal("anomaly.timeout", r.Sni!.Code);
        Assert.Equal("Похоже на блокировку по имени сайта", r.Verdict!.Title);
    }

    [Fact]
    public async Task Name_passes_on_helper_so_not_sni()
    {
        // The site cuts TLS, but the neutral server answers the site's name (with its own certificate).
        var r = await Run(new FakeProbe { Tls = SiteCut(TlsOutcome.Reset, TlsOutcome.Ok) });
        Assert.Equal("success.got_server_hello", r.Sni!.Code);
        Assert.Contains("признаков фильтра на этом пути нет", r.Sni.Text);
        Assert.Equal("Защищённое соединение с сайтом не устанавливается", r.Verdict!.Title);
    }

    [Fact]
    public async Task Helper_unreachable_is_inconclusive()
    {
        var r = await Run(new FakeProbe { Tls = SiteCut(TlsOutcome.Reset, TlsOutcome.Reset), Helper = new([], false, "нет ответа", 10) });
        Assert.Equal("anomaly.test_helper_unreachable", r.Sni!.Code);
        Assert.Equal("Защищённое соединение не устанавливается", r.Verdict!.Title);
    }

    [Fact]
    public void Ooni_certificate_categories()
    {
        var ok = new TlsProbe(TlsOutcome.Ok, 10, CertStatus.Valid);
        Assert.Equal("interference.unknown_authority", SniResult.Classify(new(TlsOutcome.Ok, 10, CertStatus.UnknownAuthority), ok).Code);
        Assert.Equal("interference.invalid_certificate", SniResult.Classify(new(TlsOutcome.Ok, 10, CertStatus.Invalid), ok).Code);
        Assert.Equal("success.got_server_hello", SniResult.Classify(new(TlsOutcome.Ok, 10, CertStatus.NameMismatch), ok).Code);
        // example.org behind Cloudflare: a foreign name gets an alert from the server itself.
        Assert.Equal("success.got_server_hello", SniResult.Classify(new(TlsOutcome.Alert, 10), ok).Code);
        Assert.Equal("anomaly.unexpected_failure", SniResult.Classify(new(TlsOutcome.Error, 10, Error: "x"), ok).Code);
        Assert.Equal("anomaly.test_helper_unreachable", SniResult.Classify(new(TlsOutcome.Reset, 10), new(TlsOutcome.Timeout, 10)).Code);
        Assert.Contains("возможна подмена ответа", SniResult.Classify(new(TlsOutcome.Ok, 10, CertStatus.UnknownAuthority), ok).Text);
        Assert.Contains("сертификат не прошёл проверку — возможна подмена ответа", SniResult.Classify(new(TlsOutcome.Ok, 10, CertStatus.Invalid), ok).Text);
        Assert.Equal((StepStatus.Warn, "сертификат не прошёл проверку"), Verdicts.DescribeTls(new(TlsOutcome.Ok, 10, CertStatus.Invalid)));
    }

    [Fact]
    public async Task Untrusted_certificate_is_a_warning()
    {
        var r = await Run(new FakeProbe { Tls = (_, _) => new TlsProbe(TlsOutcome.Ok, 50, CertStatus.UnknownAuthority, "CN=Kaspersky") });
        Assert.Equal(VerdictLevel.Warn, r.Verdict!.Level);
        Assert.Contains("не доверяет", r.Verdict.Text);
        Assert.Equal("Есть признаки проблем", r.Verdict.Title);
    }

    [Fact]
    public async Task Refused_port()
    {
        var r = await Run(new FakeProbe { Connect = new(TcpOutcome.Refused, 20) }, "104.16.1.1:8080");
        Assert.Equal("Порт 8080 закрыт", r.Verdict!.Title);
        Assert.Equal(StepStatus.Skipped, StepOf(r, "dns"));
    }

    [Fact]
    public async Task Loss_that_starts_at_a_hop_and_stays()
    {
        var p = new FakeProbe
        {
            Ping = new(10, 6, 60),
            Trace = [Hop(1, "192.168.1.1"), Hop(2, "95.1.1.1"), Hop(3, "80.1.1.1", replies: 7, ms: 40), Hop(4, "104.16.1.1", replies: 6, ms: 60, reached: true)],
        };
        var r = await Run(p);
        Assert.Equal(VerdictLevel.Warn, r.Verdict!.Level);
        Assert.Contains("Потери пакетов 40%", r.Verdict.Text);
        Assert.Contains("начиная с узла 3 (промежуточная сеть AS1299 · Arelion (Telia))", r.Verdict.Text);
    }

    [Fact]
    public async Task Loss_on_a_middle_hop_only_is_ignored()
    {
        var p = new FakeProbe
        {
            Trace = [Hop(1, "192.168.1.1"), Hop(2, "95.1.1.1", replies: 3), Hop(3, "80.1.1.1"), Hop(4, "104.16.1.1", reached: true)],
        };
        var r = await Run(p);
        Assert.Equal(VerdictLevel.Ok, r.Verdict!.Level);
        Assert.Null(r.Trace!.LossFrom);
    }

    [Fact]
    public async Task Loss_only_at_the_destination_is_soft()
    {
        var p = new FakeProbe
        {
            Ping = new(10, 7, 35),
            Trace = [Hop(1, "192.168.1.1"), Hop(2, "95.1.1.1"), Hop(3, "104.16.1.1", replies: 7, reached: true)],
        };
        var r = await Run(p);
        Assert.True(r.Trace!.DestinationOnlyLoss);
        Assert.Contains("только на самом сервере", r.Verdict!.Text);
    }

    [Fact]
    public async Task Udp_dns_interception()
    {
        var r = await Run(new FakeProbe { Udp = new(Ip("95.3.3.3"), null) });
        Assert.Equal(StepStatus.Warn, StepOf(r, "dnsint"));
        Assert.Contains("по UDP ответил DNS из другой сети: 95.3.3.3 (AS12389 · Ростелеком), а по TCP — DNS из сети Google", r.Steps.Single(s => s.Id == "dnsint").Text);
        Assert.Contains("возможна подмена запросов к 8.8.8.8", r.Verdict!.Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Udp_53_closed()
    {
        var r = await Run(new FakeProbe { Udp = new(null, "нет ответа") });
        Assert.Contains("8.8.8.8 не ответил по UDP, но ответил по TCP. Возможна фильтрация UDP-порта 53", r.Steps.Single(s => s.Id == "dnsint").Text);

        var unanswered = await Run(new FakeProbe { Udp = new(null, "нет ответа"), Tcp = new(null, "нет ответа") });
        Assert.Contains("8.8.8.8 не ответил ни по UDP, ни по TCP (нет ответа). Причина не установлена.", unanswered.Steps.Single(s => s.Id == "dnsint").Text);
        Assert.Contains("8.8.8.8 не ответил напрямую", unanswered.Verdict!.Text);

        var otherTcp = await Run(new FakeProbe { Tcp = new(Ip("95.3.3.3"), null) });
        Assert.Contains("по TCP ответил DNS из другой сети: 95.3.3.3", otherTcp.Steps.Single(s => s.Id == "dnsint").Text);
        Assert.Contains("Возможна подмена запросов к 8.8.8.8.", otherTcp.Steps.Single(s => s.Id == "dnsint").Text);
    }

    [Fact]
    public async Task Http3_blocked()
    {
        var r = await Run(new FakeProbe { H3 = true, Quic = new(QuicOutcome.Timeout, 5000) });
        Assert.Equal(StepStatus.Warn, StepOf(r, "quic"));
        Assert.Contains("Проверка HTTP/3 не получила ответ по UDP 443", r.Verdict!.Text);
        Assert.Contains("возможна фильтрация, браузер может перейти на TCP", r.Verdict.Text);
        Assert.Contains("Возможна фильтрация; браузер может перейти на TCP", r.Steps.Single(s => s.Id == "quic").Text);
    }

    [Fact]
    public async Task Mtu_black_hole_and_honest_limit()
    {
        var hole = await Run(new FakeProbe { Mtu = new(1372, false, false) });
        Assert.Contains("«чёрная дыра» MTU", hole.Verdict!.Text);
        Assert.Equal(StepStatus.Warn, StepOf(hole, "mtu"));

        var pppoe = await Run(new FakeProbe { Mtu = new(1464, true, false) });
        Assert.Equal(StepStatus.Ok, StepOf(pppoe, "mtu"));
        Assert.Contains("MTU пути 1492", pppoe.Steps.Single(s => s.Id == "mtu").Text);
        Assert.Equal(VerdictLevel.Ok, pppoe.Verdict!.Level);
    }

    [Fact]
    public async Task Balanced_hops_are_mentioned()
    {
        var p = new FakeProbe
        {
            Trace = [Hop(1, "192.168.1.1"), new HopProbe(2, [Ip("95.1.1.1"), Ip("95.1.1.2")], 10, 10, 8, 7, 9, false), Hop(3, "104.16.1.1", reached: true)],
        };
        var r = await Run(p);
        Assert.Contains("балансировка нагрузки", r.Steps.Single(s => s.Id == "trace").Text);
        Assert.Contains("(+1)", r.ToText());
    }

    [Fact]
    public void Dns_wire_round_trip()
    {
        var q = DnsWire.BuildQuery(0x1234, "o-o.myaddr.l.google.com", DnsWire.TypeTxt);
        Assert.Equal(0x12, q[0]);
        // Answer: the question echoed, then a TXT record pointing back to it by compression.
        var answer = new List<byte>(q);
        answer[2] = 0x81; answer[3] = 0x80;  // response, no error
        answer[7] = 1;                        // one answer
        answer.AddRange([0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 60]);
        var txt = Encoding.ASCII.GetBytes("74.125.1.1");
        answer.AddRange([0, (byte)(txt.Length + 1), (byte)txt.Length]);
        answer.AddRange(txt);
        var r = DnsWire.Parse(answer.ToArray());
        Assert.Equal(0x1234, r.Id);
        Assert.Equal(0, r.RCode);
        Assert.Equal("74.125.1.1", Assert.Single(r.Answers).Text);
        Assert.Throws<FormatException>(() => DnsWire.Parse(new byte[5]));
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

    [Fact]
    public void Classifies_certificate_errors()
    {
        Assert.Equal(CertStatus.Valid, NetProbe.Classify(System.Net.Security.SslPolicyErrors.None, null));
        Assert.Equal(CertStatus.NameMismatch, NetProbe.Classify(System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch, null));
        Assert.Equal(CertStatus.Invalid, NetProbe.Classify(System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors, null));
    }

    // ------------------------------------------------------------ v0.4.1 audit, stage 2

    [Fact]
    public async Task Helper_that_refuses_a_foreign_name_means_no_sni_filter()
    {
        // example.org behind Cloudflare answers an unknown name with a TLS alert.
        var r = await Run(new FakeProbe { Tls = SiteCut(TlsOutcome.Reset, TlsOutcome.Alert) });
        Assert.Equal("success.got_server_hello", r.Sni!.Code);
        Assert.Equal(StepStatus.Ok, StepOf(r, "sni"));
        Assert.Contains("результат не подтверждает фильтрацию", r.Sni.Text);
        Assert.Equal("Защищённое соединение с сайтом не устанавливается", r.Verdict!.Title);
    }

    [Fact]
    public async Task Broken_ipv6_falls_back_to_ipv4()
    {
        var p = new FakeProbe
        {
            Sys = new([Ip("2606:4700::1"), Ip("104.16.1.1")], false, null, 12),
            ConnectTo = ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? new(TcpOutcome.Unreachable, 1) : new(TcpOutcome.Ok, 40),
        };
        var r = await Run(p);
        Assert.Equal(Ip("104.16.1.1"), r.Address);
        Assert.Equal(StepStatus.Warn, StepOf(r, "tcp"));
        Assert.Equal(VerdictLevel.Warn, r.Verdict!.Level);
        Assert.Contains("2606:4700::1 (IPv6) не подключается", r.Verdict.Text);
    }

    [Fact]
    public async Task Server_silent_to_icmp_is_fine_when_it_connects()
    {
        var p = new FakeProbe { Ping = new(10, 0, 0), Trace = [Hop(1, "192.168.1.1"), Hop(2, "95.1.1.1"), Hop(3, null), Hop(4, null)] };
        var r = await Run(p);
        Assert.Equal(StepStatus.Ok, StepOf(r, "trace"));
        Assert.Contains("не отвечает на трассировку — это нормально", r.Steps.Single(s => s.Id == "trace").Text);
        Assert.Equal(VerdictLevel.Ok, r.Verdict!.Level);
    }

    [Fact]
    public async Task Vpn_is_noticed_by_adapter_and_by_timing()
    {
        var byAdapter = await Run(new FakeProbe { Tunnel = "трафик идёт через адаптер «AmneziaVPN»" });
        Assert.NotNull(byAdapter.Tunnel);
        Assert.Contains("Проверка шла через VPN", byAdapter.ToText());

        var byTiming = await Run(new FakeProbe { Connect = new(TcpOutcome.Ok, 2), Trace = [Hop(1, "104.16.1.1", ms: 30, reached: true)] });
        Assert.Contains("локальный VPN или прокси", byTiming.Tunnel);

        var plain = await Run(new FakeProbe());
        Assert.Null(plain.Tunnel);
    }

    [Fact]
    public async Task Udp_service_is_not_judged_by_tcp()
    {
        var p = new FakeProbe { Connect = new(TcpOutcome.Refused, 5) };
        var r = await Run(p, "udp://104.16.1.1:27015");
        Assert.True(r.Target.Udp);
        Assert.Null(r.Tcp);
        Assert.Equal(StepStatus.Skipped, StepOf(r, "tcp"));
        Assert.Equal("Сервер доступен по сети", r.Verdict!.Title);
        Assert.Equal("TLS в этой проверке не используется", r.Steps.Single(s => s.Id == "tls").Text);
        Assert.Equal("udp://104.16.1.1:27015", r.Target.Display);
        Assert.Null(CheckTarget.Parse("udp://104.16.1.1")); // a UDP service needs its port
    }

    [Fact]
    public async Task Dns_mismatch_without_a_certificate_stays_in_the_verdict()
    {
        var r = await Run(new FakeProbe { Ind = new([Ip("151.101.1.1")], false, null, 20) }, "example.net:80");
        Assert.True(r.DnsMismatch);
        Assert.Equal(VerdictLevel.Warn, r.Verdict!.Level);
        Assert.Contains("адреса разных сетей", r.Verdict.Text);
    }

    [Theory]
    [InlineData("h3=\":443\"; ma=86400", 443)]
    [InlineData("h3-29=\":8443\"; ma=86400, h2=\":443\"", 8443)]
    [InlineData("h2=\":443\"", null)]
    [InlineData("h3=\"alt.example:443\"", null)]
    [InlineData("clear", null)]
    public void Reads_http3_port_from_alt_svc(string header, int? port) => Assert.Equal(port, NetProbe.Http3PortOf(header));
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
