using System.Net;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Tests;

public class CidrTests
{
    private static IPAddress Ip(string s) => IPAddress.Parse(s);

    private static List<string> Str(IEnumerable<Cidr> list) => list.Select(c => c.ToString()).ToList();

    [Fact]
    public void Ipv4_round_trips_through_key()
    {
        var key = IpKey.From(Ip("142.250.74.110"));
        Assert.True(IpKey.IsV4(key));
        Assert.Equal("142.250.74.110", IpKey.ToAddress(key).ToString());
    }

    [Fact]
    public void Mapped_ipv6_is_treated_as_ipv4()
    {
        Assert.Equal(IpKey.From(Ip("1.2.3.4")), IpKey.From(Ip("::ffff:1.2.3.4")));
        Assert.True(IpKey.TryParse("::ffff:1.2.3.4", out var ip));
        Assert.Equal("1.2.3.4", ip.ToString());
    }

    [Fact]
    public void Ipv6_round_trips_through_key()
    {
        var key = IpKey.From(Ip("2a00:1450:4010:c05::64"));
        Assert.False(IpKey.IsV4(key));
        Assert.Equal("2a00:1450:4010:c05::64", IpKey.ToAddress(key).ToString());
    }

    [Theory]
    [InlineData("142.250.74.110/15", "142.250.0.0/15", "255.254.0.0")]
    [InlineData("10.1.2.3/8", "10.0.0.0/8", "255.0.0.0")]
    [InlineData("1.2.3.4/32", "1.2.3.4/32", "255.255.255.255")]
    [InlineData("0.0.0.0/0", "0.0.0.0/0", "0.0.0.0")]
    public void Parses_and_formats_ipv4(string input, string cidr, string mask)
    {
        Assert.True(Cidr.TryParse(input, out var c));
        Assert.Equal(cidr, c.ToString());
        Assert.Equal(mask, c.MaskText);
        Assert.Equal($"{c.Network} {mask}", c.Format(AddressFormat.Mask));
    }

    [Fact]
    public void Ipv6_mask_format_keeps_prefix()
    {
        Assert.True(Cidr.TryParse("2a00:1450::1/32", out var c));
        Assert.Equal("2a00:1450::/32", c.ToString());
        Assert.Equal("2a00:1450::/32", c.Format(AddressFormat.Mask));
    }

    [Fact]
    public void Contains_checks_bounds()
    {
        Cidr.TryParse("192.168.1.0/24", out var c);
        Assert.True(c.Contains(Ip("192.168.1.0")));
        Assert.True(c.Contains(Ip("192.168.1.255")));
        Assert.False(c.Contains(Ip("192.168.2.0")));
        Assert.False(c.Contains(Ip("::1")));
    }

    [Fact]
    public void Range_to_cidrs()
    {
        var list = CidrMath.FromRange(IpKey.From(Ip("10.0.0.0")), IpKey.From(Ip("10.0.2.255")));
        Assert.Equal(["10.0.0.0/23", "10.0.2.0/24"], Str(list));
    }

    [Fact]
    public void Unaligned_range_to_cidrs()
    {
        var list = CidrMath.FromRange(IpKey.From(Ip("1.0.0.1")), IpKey.From(Ip("1.0.0.6")));
        Assert.Equal(["1.0.0.1/32", "1.0.0.2/31", "1.0.0.4/31", "1.0.0.6/32"], Str(list));
    }

    [Fact]
    public void Whole_ipv4_space()
    {
        var list = CidrMath.FromRange(IpKey.From(Ip("0.0.0.0")), IpKey.From(Ip("255.255.255.255")));
        Assert.Equal(["0.0.0.0/0"], Str(list));
    }

    [Fact]
    public void Whole_ipv6_space()
    {
        var list = CidrMath.FromRange(UInt128.Zero, UInt128.MaxValue);
        Assert.Equal(["::/0"], Str(list));
    }

    [Fact]
    public void Summarize_merges_neighbours_only()
    {
        var list = CidrMath.Summarize([Ip("1.1.1.0"), Ip("1.1.1.1"), Ip("1.1.1.2"), Ip("1.1.1.3"), Ip("8.8.8.8"), Ip("1.1.1.1")]);
        Assert.Equal(["1.1.1.0/30", "8.8.8.8/32"], Str(list));
    }

    [Fact]
    public void Aggregate_widens_and_merges()
    {
        var list = CidrMath.Aggregate([Ip("1.1.0.5"), Ip("1.1.1.7"), Ip("1.1.1.9"), Ip("2a00:1450:4010:c05::64")], 24, 48);
        Assert.Equal(["1.1.0.0/23", "2a00:1450:4010::/48"], Str(list));
    }

    [Fact]
    public void Merge_drops_covered_networks()
    {
        Cidr.TryParse("10.0.0.0/8", out var a);
        Cidr.TryParse("10.1.0.0/16", out var b);
        Cidr.TryParse("11.0.0.0/8", out var c);
        Assert.Equal(["10.0.0.0/7"], Str(CidrMath.Merge([b, a, c])));
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("0.0.0.0", true)]
    [InlineData("239.255.255.250", true)]
    [InlineData("ff02::fb", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("192.168.1.1", false)]
    public void Uninteresting_addresses(string ip, bool expected) =>
        Assert.Equal(expected, IpKey.IsUninteresting(Ip(ip), hideLoopback: true));
}
