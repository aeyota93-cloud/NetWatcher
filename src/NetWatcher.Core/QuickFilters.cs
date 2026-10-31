using System.Net.Sockets;

namespace NetWatcher.Core;

/// <summary>One-click filters above the table. Several can be on at once.</summary>
[Flags]
public enum QuickFilter
{
    None = 0,
    Tcp = 1,
    Udp = 2,
    WithDomain = 4,
    NoDomain = 8,
    OnlyNew = 16,
    HideMicrosoft = 32,
    Ipv4 = 64,
}

public static class QuickFilters
{
    // Networks Microsoft announces for Windows Update, telemetry, Defender, OneDrive and so on.
    private static readonly HashSet<int> MicrosoftAsns = [8068, 8069, 8070, 8071, 8072, 8073, 8074, 8075, 12076, 3598, 6584, 23468];

    private static readonly string[] MicrosoftDomains =
    [
        "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "msftconnecttest.com", "msn.com",
        "office.com", "office.net", "office365.com", "bing.com", "msedge.net", "azureedge.net", "azure.com",
        "skype.com", "xboxlive.com", "onedrive.com", "sharepoint.com", "s-microsoft.com", "microsoftonline.com",
        "windows.net", "trafficmanager.net", "msauth.net", "msftauth.net", "gfx.ms", "aka.ms",
    ];

    public static bool IsMicrosoft(DestinationRow r)
    {
        if (r.Asn is { } a && MicrosoftAsns.Contains(a.Asn)) return true;
        return r.Domains.Count > 0 && r.Domains.All(d => MicrosoftDomains.Any(m => d == m || d.EndsWith("." + m, StringComparison.Ordinal)));
    }

    public static bool Pass(DestinationRow r, QuickFilter f)
    {
        // TCP and UDP together mean "either", the same for the two domain filters.
        var tcp = f.HasFlag(QuickFilter.Tcp);
        var udp = f.HasFlag(QuickFilter.Udp);
        if (tcp != udp && r.Proto != (tcp ? "TCP" : "UDP")) return false;

        var with = f.HasFlag(QuickFilter.WithDomain);
        var without = f.HasFlag(QuickFilter.NoDomain);
        if (with != without && (r.Domains.Count > 0) != with) return false;

        if (f.HasFlag(QuickFilter.OnlyNew) && !r.IsNew) return false;
        if (f.HasFlag(QuickFilter.HideMicrosoft) && IsMicrosoft(r)) return false;
        if (f.HasFlag(QuickFilter.Ipv4) && r.RemoteIp.AddressFamily != AddressFamily.InterNetwork) return false;
        return true;
    }

    public static List<DestinationRow> Apply(IEnumerable<DestinationRow> rows, QuickFilter f) =>
        f == QuickFilter.None ? rows.ToList() : rows.Where(r => Pass(r, f)).ToList();
}
