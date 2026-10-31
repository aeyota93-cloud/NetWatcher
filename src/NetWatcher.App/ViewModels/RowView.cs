using System.Windows.Media;
using NetWatcher.App.Native;
using NetWatcher.Core;
using NetWatcher.Core.Net;

namespace NetWatcher.App.ViewModels;

/// <summary>One line of the address table. Updated in place so scrolling and selection survive a refresh.</summary>
public sealed class RowView : ObservableObject
{
    private string _domains = "";
    private string _owner = "";
    private string _network = "";
    private string _country = "";
    private string _services = "";
    private DateTime _firstSeen;
    private DateTime _lastSeen;
    private long _hits;

    public RowView(DestinationRow row, AddressFormat format)
    {
        Key = KeyOf(row);
        Row = row;
        Process = row.Process;
        Path = row.Path;
        Ip = row.RemoteIpText;
        IpSort = IpKey.From(row.RemoteIp);
        Port = row.RemotePort;
        Proto = row.Proto;
        GroupKey = row.GroupKey;
        Update(row, format);
    }

    public static string KeyOf(DestinationRow r) => $"{r.GroupKey}|{r.Proto}|{r.RemoteIpText}|{r.RemotePort}";

    public string Key { get; }
    public DestinationRow Row { get; private set; }
    public string GroupKey { get; }
    public string Process { get; }
    public string Path { get; }
    public ImageSource? Icon => IconCache.Get(Path);
    public string Ip { get; }
    public UInt128 IpSort { get; }
    public int Port { get; }
    public string Proto { get; }

    public string Services { get => _services; private set => Set(ref _services, value); }
    public string Domains { get => _domains; private set => Set(ref _domains, value); }
    public string Owner { get => _owner; private set => Set(ref _owner, value); }
    public string Network { get => _network; private set => Set(ref _network, value); }
    public string Country { get => _country; private set => Set(ref _country, value); }
    public DateTime FirstSeen { get => _firstSeen; private set => Set(ref _firstSeen, value); }
    public DateTime LastSeen { get => _lastSeen; private set => Set(ref _lastSeen, value); }
    public long Hits { get => _hits; private set => Set(ref _hits, value); }

    /// <summary>The first domain, or the address when no domain is known.</summary>
    public string DomainOrIp => Row.Domains.Count > 0 ? Row.Domains[0] : Ip;

    public void Update(DestinationRow row, AddressFormat format)
    {
        Row = row;
        Services = row.ServicesDisplay;
        Domains = row.DomainsText;
        Owner = row.OwnerText;
        Network = row.NetworkText(format);
        Country = row.CountryText;
        FirstSeen = row.FirstSeen.LocalDateTime;
        LastSeen = row.LastSeen.LocalDateTime;
        Hits = row.Hits;
    }

    /// <summary>The row as one tab-separated line, for pasting into a spreadsheet.</summary>
    public string ToLine() =>
        string.Join('\t', Process, Services, Ip, Port, Proto, Domains, Owner, Network, Country,
            FirstSeen.ToString("g"), LastSeen.ToString("g"), Hits);
}

/// <summary>An item in the left list: all programs, or one program/service.</summary>
public sealed class GroupView : ObservableObject
{
    private string _subtitle = "";
    private string _count = "";

    public GroupView(string key, string title, string path)
    {
        Key = key;
        Title = title;
        Path = path;
    }

    /// <summary>"" means "all programs".</summary>
    public string Key { get; }
    public bool IsAll => Key == "";
    public string Title { get; }
    public string Path { get; }
    public ImageSource? Icon => IconCache.Get(Path);
    public string Subtitle { get => _subtitle; set => Set(ref _subtitle, value); }
    public string Count { get => _count; set => Set(ref _count, value); }
}
