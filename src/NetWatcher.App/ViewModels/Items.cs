using System.Windows.Media;
using NetWatcher.App.Native;
using NetWatcher.Core;
using NetWatcher.Core.Geo;

namespace NetWatcher.App.ViewModels;

/// <summary>A period button: "Сейчас", "24 часа"…</summary>
public sealed class PeriodItem(string title, TimeSpan? span, bool live) : ObservableObject
{
    private bool _isOn;
    public string Title { get; } = title;
    public TimeSpan? Span { get; } = span;
    public bool Live { get; } = live;
    public Action<PeriodItem>? Selected { get; set; }

    public bool IsOn
    {
        get => _isOn;
        set
        {
            if (Set(ref _isOn, value) && value) Selected?.Invoke(this);
        }
    }
}

/// <summary>A quick filter chip above the table.</summary>
public sealed class FilterChip(string title, QuickFilter flag, string hint) : ObservableObject
{
    private bool _isOn;
    public string Title { get; } = title;
    public QuickFilter Flag { get; } = flag;
    public string Hint { get; } = hint;
    public Action? Changed { get; set; }

    public bool IsOn
    {
        get => _isOn;
        set
        {
            if (Set(ref _isOn, value)) Changed?.Invoke();
        }
    }
}

/// <summary>An entry in the left list: all, a program, or a Windows service.</summary>
public sealed class NavItem : ObservableObject
{
    private string _title = "";
    private string _subtitle = "";
    private string _count = "";
    private bool _isNew;
    private IReadOnlyList<double> _bars = [];

    public NavItem(string key, string section, string path)
    {
        Key = key;
        Section = section;
        Path = path;
    }

    /// <summary>"" — all programs.</summary>
    public string Key { get; }
    public bool IsAll => Key == "";

    /// <summary>"" for "all", then "Приложения" or "Службы Windows"; the list is grouped by it.</summary>
    public string Section { get; }
    public string Path { get; }
    /// <summary>
    /// Programs get their own icon. Windows services mostly live in svchost.exe and would all
    /// share its icon, so they get a letter on a neutral background instead.
    /// </summary>
    public ImageSource? Icon => Section == "Службы Windows" ? null : IconCache.Get(Path);
    public bool HasIcon => Icon != null;
    public Brush Color => Section == "Службы Windows" ? AppInfo.ServiceColor : AppInfo.ColorFor(Key);
    public string Letter => AppInfo.LetterFor(Title);
    public DateTimeOffset LastSeen { get; set; }
    public int Addresses { get; set; }
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public long Bytes => BytesIn + BytesOut;

    private string _countTip = "";
    public string CountTip { get => _countTip; set => Set(ref _countTip, value); }

    public string Title
    {
        get => _title;
        set
        {
            if (Set(ref _title, value)) OnPropertyChanged(nameof(Letter));
        }
    }
    public string Subtitle { get => _subtitle; set => Set(ref _subtitle, value); }
    public string Count { get => _count; set => Set(ref _count, value); }
    public bool IsNew { get => _isNew; set => Set(ref _isNew, value); }

    private int _problems;

    /// <summary>Destinations of this program that do not answer or lose packets.</summary>
    public int Problems
    {
        get => _problems;
        set
        {
            if (Set(ref _problems, value)) OnPropertyChanged(nameof(HasProblems));
        }
    }

    public bool HasProblems => _problems > 0;

    private string _linkLevel = "";
    private string _linkText = "";

    /// <summary>"", "Ok", "Warn", "Fail" — the dot next to the program.</summary>
    public string LinkLevel
    {
        get => _linkLevel;
        set
        {
            if (Set(ref _linkLevel, value)) OnPropertyChanged(nameof(HasLink));
        }
    }

    /// <summary>"45 мс" when the link is fine; empty when a problem is shown as an icon.</summary>
    public string LinkText { get => _linkText; set => Set(ref _linkText, value); }

    private string _linkTip = "";

    /// <summary>The whole state for the tooltip: "Не отвечает 1 из 21 сервера".</summary>
    public string LinkTip { get => _linkTip; set => Set(ref _linkTip, value); }

    public bool HasLink => _linkLevel is "Ok" or "Warn" or "Fail";

    /// <summary>Heights in pixels of the small activity bars, oldest first.</summary>
    public IReadOnlyList<double> Bars
    {
        get => _bars;
        set
        {
            if (Set(ref _bars, value)) OnPropertyChanged(nameof(HasBars));
        }
    }

    public bool HasBars => _bars.Any(b => b > 0);
}

public enum ItemKind
{
    /// <summary>A domain with several addresses; can be expanded.</summary>
    Group,

    /// <summary>An address inside an expanded domain.</summary>
    Child,

    /// <summary>A single address, with or without a domain.</summary>
    Single,
}

/// <summary>A line of the main table. Kept and updated in place, so selection and scrolling survive refreshes.</summary>
public sealed class TableItem : ObservableObject
{
    private string _domain = "";
    private string _ip = "";
    private string _program = "";
    private IReadOnlyList<string> _ports = [];
    private string _owner = "";
    private string _country = "";
    private string _network = "";
    private string _when = "";
    private bool _isExpanded;
    private bool _isNew;
    private DateTime _lastSeen;
    private long _hits;
    private long _bytes;
    private string _bytesText = "";
    private string _bytesTip = "";
    private HealthLevel _health;
    private string _healthReason = "";

    public TableItem(string key, ItemKind kind)
    {
        Key = key;
        Kind = kind;
    }

    public string Key { get; }
    public ItemKind Kind { get; }
    public bool IsGroup => Kind == ItemKind.Group;
    public bool IsChild => Kind == ItemKind.Child;
    public IReadOnlyList<DestinationRow> Rows { get; private set; } = [];

    public bool HasDomain => _domain != "";
    public string DomainText => HasDomain ? _domain : IsChild ? "" : "домен неизвестен";
    public string Ip { get => _ip; private set => Set(ref _ip, value); }
    public string Program { get => _program; private set => Set(ref _program, value); }
    public IReadOnlyList<string> Ports { get => _ports; private set => Set(ref _ports, value); }
    public string Owner { get => _owner; private set => Set(ref _owner, value); }
    public string Country { get => _country; private set => Set(ref _country, value); }
    public bool HasCountry => _country != "";

    private string _mark = "";
    private string _markKind = "";
    private string _markTip = "";

    /// <summary>"трекер", "телеметрия", "опасный" from the domain catalog; "" when there is no mark.</summary>
    public string Mark { get => _mark; private set { if (Set(ref _mark, value)) OnPropertyChanged(nameof(HasMark)); } }
    public bool HasMark => _mark != "";

    /// <summary>"Tracker", "Telemetry", "Malware" — drives the colour of the mark.</summary>
    public string MarkKind { get => _markKind; private set => Set(ref _markKind, value); }
    public string MarkTip { get => _markTip; private set => Set(ref _markTip, value); }

    private string _blockTip = "";

    /// <summary>A NetWatcher block covers this line; the tooltip says which.</summary>
    public bool IsBlocked => _blockTip != "";
    public string BlockTip { get => _blockTip; private set { if (Set(ref _blockTip, value)) OnPropertyChanged(nameof(IsBlocked)); } }

    public void SetBlock(Core.Blocking.BlockRule? rule) =>
        BlockTip = rule == null ? "" : $"Заблокировано: {rule.Describe()}\nСнять — правой кнопкой → «Снять блокировку…» или в окне «Блокировки»";

    private string _countryTip = "";
    public string CountryTip { get => _countryTip; private set => Set(ref _countryTip, value); }
    public string Network { get => _network; private set => Set(ref _network, value); }
    public string When { get => _when; private set => Set(ref _when, value); }
    public DateTime LastSeen { get => _lastSeen; private set => Set(ref _lastSeen, value); }
    public long Hits { get => _hits; private set => Set(ref _hits, value); }

    /// <summary>Data both ways over the period; the column sorts by it.</summary>
    public long Bytes { get => _bytes; private set => Set(ref _bytes, value); }
    public string BytesText { get => _bytesText; private set => Set(ref _bytesText, value); }
    public string BytesTip { get => _bytesTip; private set => Set(ref _bytesTip, value); }
    public bool IsNew { get => _isNew; private set => Set(ref _isNew, value); }
    public bool IsExpanded { get => _isExpanded; set => Set(ref _isExpanded, value); }

    /// <summary>Worst state among the rows: drives the ⚠ / ✕ mark.</summary>
    public HealthLevel Health { get => _health; private set => Set(ref _health, value); }
    public string HealthReason { get => _healthReason; private set => Set(ref _healthReason, value); }

    /// <summary>The raw registry name, for the tooltip.</summary>
    public string OwnerRaw => Rows.Count > 0 && Rows[0].Asn is { } a ? $"{a.OwnerText}\nВ реестре: {a.Owner}" : "";

    /// <summary>Chevron for groups: ▾ open, ▸ closed.</summary>
    public string Chevron => IsGroup ? (IsExpanded ? "" : "") : "";

    public void Update(
        IReadOnlyList<DestinationRow> rows,
        string domain,
        Func<DestinationRow, string> network,
        Func<DestinationRow, string> program,
        DateTimeOffset now,
        TimeSpan liveWindow)
    {
        Rows = rows;
        var first = rows[0];
        if (_domain != domain)
        {
            _domain = domain;
            OnPropertyChanged(nameof(DomainText));
            OnPropertyChanged(nameof(HasDomain));
        }

        var last = rows.Max(r => r.LastSeen);
        Ip = IsGroup ? TextFormat.Plural(rows.Select(r => r.RemoteIp).Distinct().Count(), "адрес", "адреса", "адресов") : first.RemoteIpText;
        var programs = rows.Select(program).Distinct().ToList();
        Program = programs.Count == 1 ? programs[0] : TextFormat.Plural(programs.Count, "программа", "программы", "программ");
        Ports = rows.Select(r => $"{r.RemotePort} {r.Proto}").Distinct().Take(3).ToList();
        Owner = first.Asn?.OwnerText ?? "";
        if (Country != first.CountryText)
        {
            Country = first.CountryText;
            OnPropertyChanged(nameof(HasCountry));
        }
        CountryTip = Countries.Tip(first.ServerCountry, first.RegisteredCountry);
        // Child rows sit under the group, which already shows the mark.
        var info = IsChild ? null : rows.Select(r => r.Catalog).Where(c => c != null).MaxBy(c => c!.Tag);
        Mark = info?.TagText ?? "";
        MarkKind = info?.Tag.ToString() ?? "";
        MarkTip = info?.Explanation ?? "";
        var nets = rows.Select(network).Where(n => n != "").Distinct().ToList();
        Network = nets.Count <= 1 ? nets.FirstOrDefault() ?? "" : TextFormat.Plural(nets.Count, "сеть", "сети", "сетей");
        LastSeen = last.LocalDateTime;
        When = TextFormat.Relative(now, last, liveWindow);
        Hits = rows.Sum(r => r.Hits);
        long bIn = rows.Sum(r => r.BytesIn), bOut = rows.Sum(r => r.BytesOut);
        Bytes = bIn + bOut;
        BytesText = Bytes > 0 ? TextFormat.Bytes(Bytes) : "";
        BytesTip = Bytes > 0 ? $"Получено {TextFormat.Bytes(bIn)}, отправлено {TextFormat.Bytes(bOut)}" : "Данных не замечено (или только служебные пакеты)";
        IsNew = rows.Any(r => r.IsNew);
        var health = Core.Health.Worst(rows.Select(r => r.Health));
        Health = health.Level;
        HealthReason = health.Reason;
        OnPropertyChanged(nameof(Chevron));
        OnPropertyChanged(nameof(OwnerRaw));
    }

    /// <summary>Tab-separated lines for pasting into a spreadsheet.</summary>
    public IEnumerable<string> Lines() => Rows.Select(r => string.Join('\t',
        r.Process, r.ServicesDisplay, r.RemoteIpText, r.RemotePort, r.Proto, r.DomainsText, r.OwnerText,
        r.NetworkText(Core.Net.AddressFormat.Cidr), r.CountryText, r.FirstSeen.LocalDateTime.ToString("g"),
        r.LastSeen.LocalDateTime.ToString("g"), r.Hits, r.BytesIn, r.BytesOut));
}

/// <summary>A line of the DNS journal: the program asked for a name and got these addresses.</summary>
public sealed record DnsItem(string Domain, string Program, string Addresses, string When, bool IsError = false);
