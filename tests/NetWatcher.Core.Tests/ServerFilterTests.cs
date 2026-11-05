using NetWatcher.Core.Link;

namespace NetWatcher.Core.Tests;

public class ServerFilterTests
{
    private static readonly ServerFacts Claude = new("claude.ai", "160.79.104.10:443", "AS399358 · Anthropic PBC · US", "TCP",
        LinkLevel.Ok, true, 33, 1, 0, 1, 90_000);

    private static readonly ServerFacts Game = new("", "155.133.252.38:27015", "AS32590 · Valve · UA", "UDP",
        LinkLevel.Fail, false, null, null, null, 40, 12_000);

    private static readonly ServerFacts Idle = new("http-intake.logs.datadoghq.com", "34.149.66.165:443", "AS396982 · Google Cloud · US", "TCP",
        LinkLevel.Idle, true, 16, 0, null, null, 0);

    private static List<string> Names(ServerFilter f) =>
        new[] { Claude, Game, Idle }.Where(f.Pass).Select(s => s.Address).ToList();

    [Fact]
    public void Empty_filter_passes_everything()
    {
        var f = new ServerFilter();
        Assert.False(f.IsActive);
        Assert.Equal(3, Names(f).Count);
    }

    [Fact]
    public void Protocol_and_domain_or_address()
    {
        Assert.Equal(["155.133.252.38:27015"], Names(new ServerFilter { Proto = ProtoFilter.Udp }));
        Assert.Equal(2, Names(new ServerFilter { Proto = ProtoFilter.Tcp }).Count);
        Assert.Equal(["155.133.252.38:27015"], Names(new ServerFilter { Address = AddressFilter.Ip }));
        Assert.Equal(2, Names(new ServerFilter { Address = AddressFilter.Domain }).Count);
        Assert.Empty(Names(new ServerFilter { Proto = ProtoFilter.Udp, Address = AddressFilter.Domain }));
    }

    [Fact]
    public void Text_finds_name_address_and_owner()
    {
        Assert.Equal(["160.79.104.10:443"], Names(new ServerFilter { Text = "anthropic" }));
        Assert.Equal(["155.133.252.38:27015"], Names(new ServerFilter { Text = "155.133" }));
        Assert.Equal(["34.149.66.165:443"], Names(new ServerFilter { Text = "datadog google" }));
        Assert.Empty(Names(new ServerFilter { Text = "datadog valve" }));
    }

    [Fact]
    public void State_latency_jitter_loss_answer_traffic()
    {
        Assert.Equal(["155.133.252.38:27015"], Names(new ServerFilter { State = StateFilter.Problems }));
        Assert.Equal(["34.149.66.165:443"], Names(new ServerFilter { State = StateFilter.Idle }));
        Assert.Equal(["160.79.104.10:443"], Names(new ServerFilter { State = StateFilter.Ok }));

        Assert.Equal(["34.149.66.165:443"], Names(new ServerFilter { Latency = LatencyFilter.Under20 }));
        Assert.Equal(["160.79.104.10:443"], Names(new ServerFilter { Latency = LatencyFilter.From20To50 }));
        Assert.Equal(["155.133.252.38:27015"], Names(new ServerFilter { Latency = LatencyFilter.Unknown }));
        Assert.Empty(Names(new ServerFilter { Latency = LatencyFilter.Over100 }));

        Assert.Equal(2, Names(new ServerFilter { Jitter = JitterFilter.Under10 }).Count);
        Assert.Equal(["155.133.252.38:27015"], Names(new ServerFilter { Jitter = JitterFilter.Unknown }));

        Assert.Equal(["160.79.104.10:443"], Names(new ServerFilter { Loss = LossFilter.None }));
        Assert.Equal(2, Names(new ServerFilter { Loss = LossFilter.Unknown }).Count);
        Assert.Empty(Names(new ServerFilter { Loss = LossFilter.Some }));

        Assert.Equal(["160.79.104.10:443"], Names(new ServerFilter { Answer = AnswerFilter.Now }));
        Assert.Equal(["155.133.252.38:27015"], Names(new ServerFilter { Answer = AnswerFilter.Earlier }));
        Assert.Equal(["34.149.66.165:443"], Names(new ServerFilter { Answer = AnswerFilter.Never }));

        Assert.Equal(["34.149.66.165:443"], Names(new ServerFilter { Traffic = TrafficFilter.None }));
    }

    [Fact]
    public void Count_and_clear()
    {
        var f = new ServerFilter { Text = "x", Proto = ProtoFilter.Tcp, Loss = LossFilter.Some };
        Assert.Equal(3, f.ActiveCount);
        f.Clear();
        Assert.False(f.IsActive);
    }
}
