using System.Net.Sockets;
using NetWatcher.Core.Net;

namespace NetWatcher.Core;

public enum ExportWhat
{
    Addresses,
    Domains,
    Subnets,
    OwnerNetworks,
}

/// <summary>Where the list will be pasted; decides separators and notation.</summary>
public enum ExportTarget
{
    /// <summary>One network per line, 1.2.3.0/24.</summary>
    Lines,

    /// <summary>AllowedIPs = 1.2.3.0/24, 5.6.7.0/24 — WireGuard and AmneziaWG configs.</summary>
    WireGuard,

    /// <summary>Comma separated, for "Remote IP addresses" of a Windows Firewall rule.</summary>
    WindowsFirewall,

    /// <summary>1.2.3.0 255.255.255.0 per line, for routers.</summary>
    Mask,
}

public sealed record ExportResult(string Text, int Items, int Addresses);

public static class Export
{
    /// <summary>Slider stops: IPv4 prefix and the IPv6 prefix used with it.</summary>
    public static readonly (int V4, int V6)[] Widths = [(32, 128), (28, 64), (24, 48), (20, 40), (16, 32)];

    public static ExportResult Build(
        IReadOnlyCollection<DestinationRow> rows,
        ExportWhat what,
        int widthIndex,
        ExportTarget target,
        bool ipv4Only,
        bool comments)
    {
        var list = ipv4Only ? rows.Where(r => r.RemoteIp.AddressFamily == AddressFamily.InterNetwork).ToList() : rows.ToList();
        var addresses = list.Select(r => r.RemoteIp).Distinct().Count();

        if (what == ExportWhat.Domains)
        {
            var domains = list.SelectMany(r => r.Domains).Distinct().Order(StringComparer.OrdinalIgnoreCase).ToList();
            return new ExportResult(string.Join(Environment.NewLine, domains), domains.Count, addresses);
        }

        var (v4, v6) = Widths[Math.Clamp(widthIndex, 0, Widths.Length - 1)];
        var ips = list.Select(r => r.RemoteIp).Distinct().ToList();
        List<Cidr> nets = what switch
        {
            ExportWhat.Addresses => ips.Select(ip => Cidr.Of(ip, ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128))
                .OrderBy(c => c.Start).ToList(),
            ExportWhat.Subnets => v4 == 32 ? CidrMath.Summarize(ips) : CidrMath.Aggregate(ips, v4, v6),
            _ => Analysis.Subnets(list, SubnetMode.Owner, ipv4Only),
        };

        string Item(Cidr c, bool forList)
        {
            // A bare address reads better than 1.2.3.4/32 in a plain list.
            var single = c.Prefix == (c.IsV4 ? 32 : 128);
            if (target == ExportTarget.Mask) return c.Format(AddressFormat.Mask);
            if (forList && single && what == ExportWhat.Addresses) return c.Network.ToString();
            return c.ToString();
        }

        string text = target switch
        {
            ExportTarget.WireGuard => nets.Count == 0 ? "" : "AllowedIPs = " + string.Join(", ", nets.Select(c => Item(c, false))),
            ExportTarget.WindowsFirewall => string.Join(",", nets.Select(c => Item(c, true))),
            _ => string.Join(Environment.NewLine, nets.Select(c =>
            {
                var line = Item(c, true);
                if (!comments) return line;
                var domains = list.Where(r => c.Contains(r.RemoteIp)).SelectMany(r => r.Domains).Distinct().Take(3).ToList();
                return domains.Count == 0 ? line : $"{line}  # {string.Join(", ", domains)}";
            })),
        };
        return new ExportResult(text, nets.Count, addresses);
    }
}
