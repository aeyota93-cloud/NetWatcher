using System.Net;
using System.Net.NetworkInformation;
using NetWatcher.Core.Diagnostics;
using NetWatcher.Core.Link;

namespace NetWatcher.Core.Tests;

public class QualityGatewayTests
{
    private static QualityAdapter Adapter(string name, string description, NetworkInterfaceType type,
        uint? metric, bool up = true, params string[] gateways) =>
        new(name, description, type, up, gateways.Select(IPAddress.Parse).ToArray(), metric);

    [Fact]
    public void Router_is_physical_even_when_tun_has_the_lowest_metric()
    {
        var adapters = new[]
        {
            Adapter("tun0", "sing-box", NetworkInterfaceType.Ethernet, 1, true, "172.19.0.2"),
            Adapter("Wi-Fi", "Wireless", NetworkInterfaceType.Wireless80211, 50, true, "192.168.2.1"),
            Adapter("Ethernet", "Realtek", NetworkInterfaceType.Ethernet, 10, true, "192.168.1.1"),
            Adapter("Ethernet 2", "Realtek", NetworkInterfaceType.Ethernet, 2, false, "192.168.3.1"),
        };
        Assert.Equal(IPAddress.Parse("192.168.1.1"), QualityMonitor.SelectGateway(adapters));
        Assert.Equal(IPAddress.Parse("192.168.1.1"), QualityMonitor.SelectGateway(adapters.Reverse()));
    }

    [Fact]
    public void Missing_metrics_and_invalid_gateways_do_not_hide_a_working_router()
    {
        var adapters = new[]
        {
            Adapter("Ethernet", "Realtek", NetworkInterfaceType.Ethernet, 1, true, "0.0.0.0", "::", "127.0.0.1"),
            Adapter("Wi-Fi", "Wireless", NetworkInterfaceType.Wireless80211, null, true, "192.168.1.1"),
        };
        Assert.Equal(IPAddress.Parse("192.168.1.1"), QualityMonitor.SelectGateway(adapters));
        Assert.Equal(IPAddress.Parse("192.168.2.1"), QualityMonitor.SelectGateway(adapters.Append(
            Adapter("Ethernet 2", "Realtek", NetworkInterfaceType.Ethernet, 20, true, "192.168.2.1"))));
    }

    [Fact]
    public void No_physical_router_returns_null()
    {
        Assert.Null(QualityMonitor.SelectGateway([
            Adapter("VPN", "WireGuard", NetworkInterfaceType.Ethernet, 1, true, "172.19.0.2"),
            Adapter("Tunnel", "Adapter", NetworkInterfaceType.Tunnel, 2, true, "10.0.0.1"),
            Adapter("Loopback", "Adapter", NetworkInterfaceType.Loopback, 3, true, "127.0.0.1"),
            Adapter("Ethernet", "Realtek", NetworkInterfaceType.Ethernet, 4),
        ]));
    }

    [Theory]
    [InlineData("tun0", "Adapter", NetworkInterfaceType.Ethernet, true)]
    [InlineData("UTUN3", "Adapter", NetworkInterfaceType.Ethernet, true)]
    [InlineData("Ethernet", "Wintun Userspace Tunnel", NetworkInterfaceType.Ethernet, true)]
    [InlineData("Adapter", "Adapter", NetworkInterfaceType.Tunnel, true)]
    [InlineData("Ethernet", "Realtek", NetworkInterfaceType.Ethernet, false)]
    [InlineData("Wi-Fi", "Wireless", NetworkInterfaceType.Wireless80211, false)]
    [InlineData("Teredo", "Tunnel", NetworkInterfaceType.Tunnel, false)]
    [InlineData("ISATAP", "Tunnel", NetworkInterfaceType.Tunnel, false)]
    [InlineData("6to4", "Tunnel", NetworkInterfaceType.Tunnel, false)]
    [InlineData("PPP", "PPPoE", NetworkInterfaceType.Ppp, false)]
    public void Tunnel_detection_keeps_existing_rules(string name, string description, NetworkInterfaceType type, bool expected)
    {
        Assert.Equal(expected, NetProbe.IsTunnelAdapter(name, description, type));
    }
}
