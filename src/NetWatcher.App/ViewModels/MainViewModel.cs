using System.Collections;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Threading;
using NetWatcher.App.Native;
using NetWatcher.Core;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Net;

namespace NetWatcher.App.ViewModels;

internal sealed partial class MainViewModel : ObservableObject
{
    private const string AllKey = "";
    private const string AppsSection = "Приложения";
    private const string ServicesSection = "Службы Windows";

    private readonly AppState _state;
    private readonly DispatcherTimer _refreshTimer;
    private readonly DispatcherTimer _clock;
    private readonly DispatcherTimer _searchDelay;
    private readonly DispatcherTimer _toastTimer;
    private readonly HashSet<string> _expanded = [];
    private readonly Dictionary<string, string> _groupTitles = [];

    private List<DestinationRow> _rows = [];
    private int _totalAddresses;
    private DateTimeOffset? _logStart;
    private DateTime _lastRefresh = DateTime.MinValue;
    private bool _refreshing;
    private bool _pending;
    private PeriodItem _period;
    private string? _clipboardBefore;

    // Data that changes slowly is read once in a while.
    private DateTime _slowAt = DateTime.MinValue;
    private Dictionary<string, DateTimeOffset> _firstSeen = [];
    private Dictionary<string, DateTimeOffset> _groupFirstSeen = [];
    private Dictionary<string, int[]> _activity = [];
    private List<Core.Storage.LogStore.DnsFailureRow> _dnsFailures = [];

    public MainViewModel(AppState state)
    {
        _state = state;

        Periods =
        [
            new("Сейчас", null, true),
            new("15 мин", TimeSpan.FromMinutes(15), false),
            new("1 час", TimeSpan.FromHours(1), false),
            new("24 часа", TimeSpan.FromDays(1), false),
            new("7 дней", TimeSpan.FromDays(7), false),
            new("Всё", null, false),
        ];
        _period = Periods[0];
        Periods[0].IsOn = true;
        foreach (var p in Periods) p.Selected = OnPeriod;

        Chips =
        [
            new("TCP", QuickFilter.Tcp, "Только соединения TCP"),
            new("UDP", QuickFilter.Udp, "Только UDP: QUIC/HTTP3, звонки, игры, DNS"),
            new("С доменом", QuickFilter.WithDomain, "Адреса, для которых известен домен"),
            new("Без домена", QuickFilter.NoDomain, "Программа обращается напрямую по IP — стоит присмотреться"),
            new("Проблемные", QuickFilter.Problems, "Адреса, которые не отвечают, подключаются с повторами или теряют пакеты; в журнале DNS — ошибки"),
            new("Только новые", QuickFilter.OnlyNew, "Адреса, на которые программа впервые пошла за последние сутки"),
            new("Скрыть Microsoft", QuickFilter.HideMicrosoft, "Убрать обращения к сетям и доменам Microsoft"),
            new("Только IPv4", QuickFilter.Ipv4, "Скрыть адреса IPv6"),
        ];
        foreach (var c in Chips) c.Changed = () => _ = RefreshAsync();

        Nav.Add(new NavItem(AllKey, "", "") { Title = "Все" });
        _selectedNav = Nav[0];

        Export = new ExportViewModel(() => VisibleRows.ToList(), Copy);
        Diagnostics = new DiagnosticsViewModel(state, Copy);

        _refreshTimer = new DispatcherTimer();
        _refreshTimer.Tick += (_, _) => _ = RefreshAsync();
        _clock = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clock.Tick += (_, _) => UpdateLive();
        _searchDelay = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _searchDelay.Tick += (_, _) =>
        {
            _searchDelay.Stop();
            _ = RefreshAsync();
        };
        _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
        _toastTimer.Tick += (_, _) =>
        {
            _toastTimer.Stop();
            ToastVisible = false;
        };

        RefreshCommand = new RelayCommand(() => _ = RefreshAsync());
        ClearSearchCommand = new RelayCommand(() => SearchText = "");
        ResetFiltersCommand = new RelayCommand(ResetFilters);
        ToggleCommand = new RelayCommand(p => Toggle(p as TableItem));
        CopyIpCommand = new RelayCommand(p => CopyLines(Rows(p).Select(r => r.RemoteIpText).Distinct(), "IP"));
        CopyDomainCommand = new RelayCommand(p => CopyLines(Rows(p).SelectMany(r => r.Domains).Distinct(), "домены"));
        CopyNetworkCommand = new RelayCommand(p => CopyLines(Rows(p).Select(r => r.NetworkText(Format)).Where(n => n != "").Distinct(), "сети"));
        CopyRowCommand = new RelayCommand(p => CopyLines(Items(p).SelectMany(i => i.Lines()), "строки"));
        CopyValueCommand = new RelayCommand(p => Copy(p as string ?? "", null));
        CopyAllIpsCommand = new RelayCommand(() => CopyLines(Analysis.Addresses(VisibleRows).Select(a => a.ToString()), "все IP"));
        CopyAllDomainsCommand = new RelayCommand(() => CopyLines(VisibleRows.SelectMany(r => r.Domains).Distinct().Order(StringComparer.OrdinalIgnoreCase), "все домены"));
        CopySummaryNetworksCommand = new RelayCommand(() => Copy(SumNetworksText, "сети владельцев"));
        SearchIpCommand = new RelayCommand(p => SearchFor(Rows(p).FirstOrDefault()?.RemoteIpText));
        SearchDomainCommand = new RelayCommand(p => SearchFor(Rows(p).FirstOrDefault()?.PrimaryDomain));
        SearchProgramCommand = new RelayCommand(p => SearchFor(Rows(p).FirstOrDefault()?.Process));
        SearchTextCommand = new RelayCommand(p => SearchFor(p as string));
        WhoElseCommand = new RelayCommand(() => SearchFor(SelectedItem?.Rows.FirstOrDefault()?.RemoteIpText));
        RdapCommand = new RelayCommand(p => _ = RdapAsync(Rows(p).FirstOrDefault() ?? SelectedItem?.Rows.FirstOrDefault()));
        OpenFolderCommand = new RelayCommand(p => OpenFolder(Rows(p).FirstOrDefault()?.Path));
        UndoCopyCommand = new RelayCommand(UndoCopy);
        OpenExportCommand = new RelayCommand(() => Export.Open(ExportContext));
        OpenVpnExportCommand = new RelayCommand(() => Export.Open(ExportContext, ExportWhat.Subnets));
        OpenOwnerExportCommand = new RelayCommand(() => Export.Open(ExportContext, ExportWhat.OwnerNetworks));
        DownloadAsnCommand = new RelayCommand(_ => _ = DownloadAsnAsync(), _ => !AsnBusy);
        HideBannerCommand = new RelayCommand(() =>
        {
            _bannerHidden = true;
            OnPropertyChanged(nameof(AsnBannerVisible));
        });
        SetThemeCommand = new RelayCommand(p =>
        {
            if (p is not string mode) return;
            _state.Settings.Theme = mode;
            _state.SaveSettings();
            ThemeService.Apply(mode);
            foreach (var n in new[] { nameof(ThemeGlyph), nameof(IsThemeSystem), nameof(IsThemeLight), nameof(IsThemeDark), nameof(ThemeTitle) })
                OnPropertyChanged(n);
        });
        OpenCheckCommand = new RelayCommand(p => Diagnostics.Open(CheckTargetOf(Items(p).FirstOrDefault() ?? (p == null ? SelectedItem : null))));
        OpenEmptyCheckCommand = new RelayCommand(() => Diagnostics.Open(null));
        PeeringDbCommand = new RelayCommand(() => _ = PeeringDbAsync(SelectedItem?.Rows.FirstOrDefault()?.Asn?.Asn));
        TogglePauseCommand = new RelayCommand(() => Paused = !Paused);
    }

    public void Start()
    {
        StartLink();
        UpdateTimer();
        _refreshTimer.Start();
        _clock.Start();
        _ = RefreshAsync();
    }

    // =====================================================================
    // Top bar: search, period, filters, live state
    // =====================================================================

    public PeriodItem[] Periods { get; }
    public FilterChip[] Chips { get; }

    private string _searchText = "";
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (!Set(ref _searchText, value)) return;
            OnPropertyChanged(nameof(HasSearch));
            _searchDelay.Stop();
            _searchDelay.Start();
        }
    }

    public bool HasSearch => _searchText.Length > 0;

    private QuickFilter Filters => Chips.Where(c => c.IsOn).Aggregate(QuickFilter.None, (a, c) => a | c.Flag);
    private bool FiltersActive => DestinationRow.SplitQuery(SearchText).Count > 0 || Filters != QuickFilter.None;

    private string _foundText = "";
    public string FoundText { get => _foundText; private set => Set(ref _foundText, value); }

    private bool _paused;
    public bool Paused
    {
        get => _paused;
        set
        {
            if (!Set(ref _paused, value)) return;
            OnPropertyChanged(nameof(PauseGlyph));
            if (value) _refreshTimer.Stop();
            else
            {
                _refreshTimer.Start();
                _ = RefreshAsync();
            }
            UpdateLive();
        }
    }

    public string PauseGlyph => Paused ? "" : "";

    private string _liveText = "";
    private string _liveShort = "";

    /// <summary>Short and of steady width, so the top bar does not jump every second.</summary>
    public string LiveShort { get => _liveShort; private set => Set(ref _liveShort, value); }
    public string LiveText { get => _liveText; private set => Set(ref _liveText, value); }
    private bool _liveOk = true;
    public bool LiveOk { get => _liveOk; private set => Set(ref _liveOk, value); }

    private void UpdateLive()
    {
        if (Paused)
        {
            LiveText = "Пауза — экран не обновляется, запись идёт";
            LiveShort = "Пауза";
            LiveOk = false;
            return;
        }
        var ago = (int)(DateTime.Now - _lastRefresh).TotalSeconds;
        LiveText = _lastRefresh == DateTime.MinValue ? "Запись идёт" : $"Запись идёт · обновлено {Math.Max(ago, 0)} с назад";
        LiveShort = _lastRefresh == DateTime.MinValue ? "Запись" : $"Запись · {Math.Min(Math.Max(ago, 0), 99)} с";
        LiveOk = _state.Collector.LastError == null;
    }

    private void OnPeriod(PeriodItem p)
    {
        foreach (var other in Periods)
            if (other != p) other.IsOn = false;
        _period = p;
        UpdateTimer();
        _ = RefreshAsync();
    }

    private void UpdateTimer()
    {
        _refreshTimer.Interval = TimeSpan.FromSeconds(_period.Live ? Math.Max(_state.Settings.PollSeconds, 2) : 10);
    }

    private void ResetFilters()
    {
        foreach (var c in Chips) c.IsOn = false;
        SearchText = "";
    }

    /// <summary>Esc: close the export panel, else clear search and filters.</summary>
    public void Escape()
    {
        if (Diagnostics.IsOpen) Diagnostics.CloseCommand.Execute(null);
        else if (Export.IsOpen) Export.IsOpen = false;
        else ResetFilters();
    }

    public void SettingsChanged()
    {
        UpdateTimer();
        _slowAt = DateTime.MinValue;
        _ = RefreshAsync();
    }

    // =====================================================================
    // Left list
    // =====================================================================

    public ObservableCollection<NavItem> Nav { get; } = [];

    private NavItem? _selectedNav;
    public NavItem? SelectedNav
    {
        get => _selectedNav;
        set
        {
            if (value == null || !Set(ref _selectedNav, value)) return;
            SelectedItem = null;
            UpdateHeader();
            ApplyTable();
            ApplyLink();
            UpdateDetails();
            if (Export.IsOpen) Export.Open(ExportContext);
        }
    }

    public int NavSortIndex
    {
        get => _state.Settings.SortByActivity ? 0 : 1;
        set
        {
            _state.Settings.SortByActivity = value == 0;
            _state.SaveSettings();
            OnPropertyChanged();
            ApplyNav();
        }
    }

    private IEnumerable<DestinationRow> VisibleRows =>
        SelectedNav is null or { IsAll: true } ? _rows : _rows.Where(r => r.GroupKey == SelectedNav.Key);

    private void ApplyNav()
    {
        var names = _state.Collector.Services.DisplayNames;
        var newSince = Analysis.NewSince(DateTimeOffset.Now, _logStart);
        var existing = Nav.Skip(1).ToDictionary(n => n.Key);
        var items = new List<NavItem>();

        foreach (var g in _rows.GroupBy(r => r.GroupKey))
        {
            var first = g.First();
            var path = g.Select(r => r.Path).FirstOrDefault(p => p != "") ?? "";
            var isService = first.Services != "" || first.Process is "System";
            var item = existing.GetValueOrDefault(g.Key) ?? new NavItem(g.Key, isService ? ServicesSection : AppsSection, path);
            item.Title = TitleOf(first, path, names);
            item.Subtitle = first.Services != "" ? $"{first.Process} · {first.Services.Replace(",", ", ")}" : first.Process;
            item.Addresses = g.Select(r => r.RemoteIp).Distinct().Count();
            item.Count = $"{item.Addresses} адр.";
            item.LastSeen = g.Max(r => r.LastSeen);
            item.IsNew = newSince is { } s && _groupFirstSeen.TryGetValue(g.Key, out var f) && f >= s;
            item.Problems = g.Count(r => r.Health.IsProblem);
            // Each program on its own scale, so a quiet one still shows its rhythm; empty hours draw nothing.
            var hours = _activity.GetValueOrDefault(g.Key) ?? new int[7];
            var own = Math.Max(1, hours.Max());
            item.Bars = hours.Select(v => v == 0 ? 0.0 : 3 + 11 * v / (double)own).ToList();
            _groupTitles[g.Key] = item.Title;
            items.Add(item);
        }

        // The selected entry stays even when the filters hide it, so the user does not lose their place.
        if (SelectedNav is { IsAll: false } sel && items.All(i => i.Key != sel.Key))
        {
            sel.Count = "0 адр.";
            sel.Bars = [];
            items.Add(sel);
        }

        var sorted = items.OrderBy(i => i.Section == AppsSection ? 0 : 1);
        var list = (_state.Settings.SortByActivity
                ? sorted.ThenByDescending(i => i.LastSeen).ThenByDescending(i => i.Addresses)
                : sorted.ThenBy(i => i.Title, StringComparer.CurrentCultureIgnoreCase))
            .ToList();

        var all = Nav[0];
        all.Subtitle = FiltersActive
            ? TextFormat.Plural(list.Count, "совпадение", "совпадения", "совпадений")
            : TextFormat.Plural(list.Count, "программа и служба", "программы и службы", "программ и служб");
        all.Count = $"{_rows.Select(r => r.RemoteIp).Distinct().Count()} адр.";

        Sync(Nav, list, 1);
    }

    private static string TitleOf(DestinationRow r, string path, IReadOnlyDictionary<string, string> names)
    {
        if (r.Services == "")
            return r.Process == "System" ? "Ядро Windows (System)" : AppInfo.FriendlyName(r.Process, path);
        var list = r.Services.Split(',');
        var main = names.TryGetValue(list[0], out var d) ? d : list[0];
        return list.Length == 1 ? main : $"{main} и ещё {list.Length - 1}";
    }

    /// <summary>Puts <paramref name="wanted"/> into <paramref name="target"/> from <paramref name="offset"/> on, moving instead of rebuilding.</summary>
    private static void Sync<T>(ObservableCollection<T> target, IReadOnlyList<T> wanted, int offset) where T : class
    {
        for (var i = 0; i < wanted.Count; i++)
        {
            var at = i + offset;
            var current = target.IndexOf(wanted[i]);
            if (current < 0) target.Insert(at, wanted[i]);
            else if (current != at) target.Move(current, at);
        }
        while (target.Count > wanted.Count + offset) target.RemoveAt(target.Count - 1);
    }

    // =====================================================================
    // Header and tabs
    // =====================================================================

    private string _headerTitle = "Все программы";
    public string HeaderTitle { get => _headerTitle; private set => Set(ref _headerTitle, value); }
    private string _headerSubtitle = "";
    public string HeaderSubtitle { get => _headerSubtitle; private set => Set(ref _headerSubtitle, value); }
    public bool ShowProgramColumn => SelectedNav is null or { IsAll: true };
    public NavItem? HeaderNav => SelectedNav;

    private string ExportContext => $"{HeaderTitle} · {_period.Title.ToLowerInvariant()}";

    private void UpdateHeader()
    {
        var n = SelectedNav;
        HeaderTitle = n is null or { IsAll: true } ? "Все программы" : n.Title;
        HeaderSubtitle = n is null or { IsAll: true } ? n?.Subtitle ?? "" : n.Path != "" ? n.Path : n.Subtitle;
        OnPropertyChanged(nameof(ShowProgramColumn));
        OnPropertyChanged(nameof(HeaderNav));
    }

    // 3 — "Связь", shown first and open by default.
    private int _tab = 3;
    public bool IsLinkTab { get => _tab == 3; set { if (value) SetTab(3); } }
    public bool IsDomainsTab { get => _tab == 0; set { if (value) SetTab(0); } }
    public bool IsAddressesTab { get => _tab == 1; set { if (value) SetTab(1); } }
    public bool IsDnsTab { get => _tab == 2; set { if (value) SetTab(2); } }
    public bool IsTableTab => _tab is 0 or 1;

    private void SetTab(int tab)
    {
        if (_tab == tab) return;
        _tab = tab;
        foreach (var n in new[] { nameof(IsDomainsTab), nameof(IsAddressesTab), nameof(IsDnsTab), nameof(IsTableTab), nameof(IsLinkTab) }) OnPropertyChanged(n);
        if (tab == 3) ApplyLink();
        SelectedItem = null;
        ApplyTable();
    }

    private string _domainsCount = "";
    public string DomainsCount { get => _domainsCount; private set => Set(ref _domainsCount, value); }
    private string _addressesCount = "";
    public string AddressesCount { get => _addressesCount; private set => Set(ref _addressesCount, value); }
    private int _dnsErrors;
    public int DnsErrors { get => _dnsErrors; private set { if (Set(ref _dnsErrors, value)) OnPropertyChanged(nameof(HasDnsErrors)); } }
    public bool HasDnsErrors => _dnsErrors > 0;
    private string _dnsCount = "";
    public string DnsCount { get => _dnsCount; private set => Set(ref _dnsCount, value); }

    // =====================================================================
    // Table
    // =====================================================================

    public ObservableCollection<TableItem> Table { get; } = [];
    public ObservableCollection<DnsItem> DnsItems { get; } = [];

    private TableItem? _selectedItem;
    public TableItem? SelectedItem
    {
        get => _selectedItem;
        set
        {
            if (Set(ref _selectedItem, value)) UpdateDetails();
        }
    }

    private TimeSpan LiveWindow => TimeSpan.FromSeconds(Math.Max(10, _state.Settings.PollSeconds * 3));

    private void ApplyTable()
    {
        var rows = VisibleRows.ToList();
        var now = DateTimeOffset.Now;
        var groups = DomainGroup.Build(rows);
        var existing = Table.ToDictionary(t => t.Key);
        var wanted = new List<TableItem>();
        var autoExpand = DestinationRow.SplitQuery(SearchText).Count > 0;

        string Net(DestinationRow r) => r.NetworkText(AddressFormat.Cidr);
        string Prog(DestinationRow r) => _groupTitles.GetValueOrDefault(r.GroupKey, r.Process);

        TableItem Item(string key, ItemKind kind, IReadOnlyList<DestinationRow> list, string domain)
        {
            var item = existing.GetValueOrDefault(key) ?? new TableItem(key, kind);
            item.Update(list, domain, Net, Prog, now, LiveWindow);
            return item;
        }

        if (_tab == 0)
        {
            foreach (var g in groups)
            {
                if (g.Rows.Count == 1)
                {
                    wanted.Add(Item("s:" + g.Rows[0].Key, ItemKind.Single, g.Rows, g.Domain));
                    continue;
                }
                var group = Item("g:" + g.Key, ItemKind.Group, g.Rows, g.Domain);
                group.IsExpanded = autoExpand || _expanded.Contains(g.Key);
                group.Update(g.Rows, g.Domain, Net, Prog, now, LiveWindow);
                wanted.Add(group);
                if (group.IsExpanded)
                    foreach (var r in g.Rows)
                        wanted.Add(Item("c:" + g.Key + "|" + r.Key, ItemKind.Child, [r], ""));
            }
        }
        else
        {
            foreach (var r in rows.OrderByDescending(r => r.LastSeen).ThenBy(r => IpKey.From(r.RemoteIp)))
                wanted.Add(Item("a:" + r.Key, ItemKind.Single, [r], r.PrimaryDomain));
        }

        Sync(Table, wanted, 0);
        if (SelectedItem != null && !Table.Contains(SelectedItem)) SelectedItem = null;

        DomainsCount = groups.Count.ToString();
        AddressesCount = rows.Count.ToString();
        ApplyDns();
        UpdateEmptyState();
    }

    private void Toggle(TableItem? item)
    {
        if (item is not { IsGroup: true }) return;
        var key = item.Key[2..];
        if (!_expanded.Remove(key)) _expanded.Add(key);
        ApplyTable();
    }

    private void ApplyDns()
    {
        var since = _period.Live ? DateTimeOffset.Now.AddMinutes(-15)
            : _period.Span is { } s ? DateTimeOffset.Now - s
            : DateTimeOffset.MinValue;
        var process = SelectedNav is null or { IsAll: true } ? null : SelectedNav.Key.Split(" · ")[0];
        var words = DestinationRow.SplitQuery(SearchText);
        var answers = _state.Dns.Answers(process == null ? null : p => string.Equals(p, process, StringComparison.OrdinalIgnoreCase), since);
        var now = DateTimeOffset.Now;
        var onlyErrors = Filters.HasFlag(QuickFilter.Problems);
        var good = onlyErrors ? [] : answers.Select(a => (Time: a.LastSeen, Item: new DnsItem(
            a.Domain,
            AppInfo.FriendlyName(a.Process, ""),
            string.Join(", ", a.Addresses.Take(6)) + (a.Addresses.Count > 6 ? $" и ещё {a.Addresses.Count - 6}" : ""),
            TextFormat.Relative(now, a.LastSeen, LiveWindow))));
        var bad = _dnsFailures
            .Where(f => process == null || string.Equals(f.Process, process, StringComparison.OrdinalIgnoreCase))
            .Select(f => (Time: f.LastSeen, Item: new DnsItem(
                f.Domain,
                AppInfo.FriendlyName(f.Process, ""),
                "✗ " + DnsStatus.Describe(f.Status) + (f.Hits > 1 ? $" ({TextFormat.Plural(f.Hits, "раз", "раза", "раз")})" : ""),
                TextFormat.Relative(now, f.LastSeen, LiveWindow),
                IsError: true)));
        var list = good.Concat(bad)
            .OrderByDescending(x => x.Time)
            .Select(x => x.Item)
            .Where(d => words.All(w => d.Domain.Contains(w, StringComparison.OrdinalIgnoreCase)
                                       || d.Program.Contains(w, StringComparison.OrdinalIgnoreCase)
                                       || d.Addresses.Contains(w, StringComparison.OrdinalIgnoreCase)))
            .Take(2000)
            .ToList();
        DnsErrors = list.Count(d => d.IsError);
        DnsCount = list.Count.ToString();
        if (_tab != 2) return;
        DnsItems.Clear();
        foreach (var d in list) DnsItems.Add(d);
    }

    // =====================================================================
    // Refresh
    // =====================================================================

    public async Task RefreshAsync()
    {
        if (_refreshing)
        {
            _pending = true;
            return;
        }
        _refreshing = true;
        try
        {
            var period = _period;
            var words = DestinationRow.SplitQuery(SearchText);
            var filters = Filters;
            var asn = _state.Asn;
            var names = _state.Collector.Services.DisplayNames;
            var live = LiveWindow;
            var slow = DateTime.UtcNow - _slowAt > TimeSpan.FromSeconds(30);

            var (rows, total) = await Task.Run(() =>
            {
                var now = DateTimeOffset.Now;
                if (slow)
                {
                    _firstSeen = _state.Store.FirstSeenByRow();
                    _groupFirstSeen = _firstSeen
                        .GroupBy(kv => kv.Key[..kv.Key.IndexOf('|')])
                        .ToDictionary(g => g.Key, g => g.Min(kv => kv.Value));
                    _activity = _state.Store.Activity(now, 7);
                    _logStart = _state.Store.LogStart();
                }
                var from = period.Live ? now - live
                    : period.Span is { } span ? now - span
                    : DateTimeOffset.FromUnixTimeMilliseconds(0);
                var list = _state.Store.Query(from);
                _dnsFailures = _state.Store.DnsFailures(period.Live ? now.AddMinutes(-15) : from);
                Analysis.Enrich(list, _state.Dns, asn, names);
                Analysis.MarkNew(list, _firstSeen, Analysis.NewSince(now, _logStart));
                var totalIps = list.Select(r => r.RemoteIp).Distinct().Count();
                var found = words.Count == 0 ? list : list.Where(r => r.Matches(words)).ToList();
                return (QuickFilters.Apply(found, filters), totalIps);
            });
            if (slow) _slowAt = DateTime.UtcNow;

            _rows = rows;
            _totalAddresses = total;
            _lastRefresh = DateTime.Now;

            ApplyNav();
            UpdateHeader();
            ApplyTable();
            ApplyLink();
            UpdateDetails();
            UpdateStatus();
            UpdateLive();
            if (Export.IsOpen) Export.Rebuild();

            var shown = _rows.Select(r => r.RemoteIp).Distinct().Count();
            FoundText = FiltersActive ? $"Найдено {shown} из {TextFormat.Plural(_totalAddresses, "адреса", "адресов", "адресов")} · Esc — сбросить" : "";
        }
        catch (Exception e)
        {
            Error = "Ошибка обновления: " + e.Message;
        }
        finally
        {
            _refreshing = false;
            if (_pending)
            {
                _pending = false;
                _ = RefreshAsync();
            }
        }
    }

    // =====================================================================
    // Details pane
    // =====================================================================

    public bool HasSelection => SelectedItem != null;
    public bool NoSelection => SelectedItem == null;

    private AddressFormat Format => _state.Settings.AddressFormat;

    public bool UseMask
    {
        get => Format == AddressFormat.Mask;
        set
        {
            _state.Settings.AddressFormat = value ? AddressFormat.Mask : AddressFormat.Cidr;
            _state.SaveSettings();
            OnPropertyChanged();
            OnPropertyChanged(nameof(UseCidr));
            UpdateDetails();
        }
    }

    public bool UseCidr { get => !UseMask; set => UseMask = !value; }

    private readonly Dictionary<string, string> _details = [];

    /// <summary>Details pane values by name: Title, Subtitle, Ip, Domains, Network, Owner, Country, Protocol, First, Last, Rdap…</summary>
    public IReadOnlyDictionary<string, string> D => new Dictionary<string, string>(_details);

    private bool _detailsNew;
    public bool DetailsNew { get => _detailsNew; private set => Set(ref _detailsNew, value); }
    private bool _rdapBusy;
    public bool RdapBusy { get => _rdapBusy; private set => Set(ref _rdapBusy, value); }
    private bool _hasRdap;
    public bool HasRdap { get => _hasRdap; private set => Set(ref _hasRdap, value); }

    private string _sumNetworksText = "";
    public string SumNetworksText { get => _sumNetworksText; private set => Set(ref _sumNetworksText, value); }

    private void UpdateDetails()
    {
        var keepRdap = _details.GetValueOrDefault("RdapFor");
        var rdap = _details.GetValueOrDefault("Rdap", "");
        var keepPdb = (For: _details.GetValueOrDefault("PdbFor"), Text: _details.GetValueOrDefault("Pdb", ""));
        _details.Clear();
        var item = SelectedItem;
        HasRdap = false;
        HasPdb = false;

        if (item == null)
        {
            var rows = VisibleRows.ToList();
            var ips = rows.Select(r => r.RemoteIp).Distinct().ToList();
            var asns = rows.Where(r => r.Asn != null).Select(r => r.Asn!.AsnText).Distinct().ToList();
            var owners = Core.Export.Build(rows, ExportWhat.OwnerNetworks, 0, ExportTarget.Lines, false, false);
            var noDomain = rows.Where(r => r.Domains.Count == 0).Select(r => r.RemoteIp).Distinct().Count();
            _details["SumTitle"] = $"Сводка: {HeaderTitle}";
            _details["SumAddresses"] = ips.Count.ToString();
            _details["SumNetworks"] = owners.Items == 0 ? "—"
                : owners.Items + (asns.Count > 0 ? $" ({string.Join(", ", asns.Take(4))}{(asns.Count > 4 ? "…" : "")})" : "");
            _details["SumCountries"] = string.Join(", ", rows.Select(r => r.CountryText).Where(c => c != "").Distinct().Take(8)) is { Length: > 0 } c ? c : "—";
            _details["SumNoDomain"] = ips.Count == 0 ? "—" : noDomain == 0 ? "нет"
                : $"{noDomain} из {ips.Count}" + (!_state.Collector.DnsCapture ? " — домены не видны: журнал DNS работает только с правами администратора"
                    : noDomain * 2 > ips.Count ? (SelectedNav?.IsAll == true ? " — программы часто ходят напрямую по IP" : " — программа часто ходит напрямую по IP")
                    : "");
            SumNetworksText = owners.Text;
        }
        else
        {
            var rows = item.Rows;
            var first = rows[0];
            var ips = rows.Select(r => r.RemoteIpText).Distinct().ToList();
            var domains = rows.SelectMany(r => r.Domains).Distinct().ToList();
            var groupDomain = item.IsChild ? "" : item.HasDomain ? item.DomainText : "";
            _details["Title"] = groupDomain != "" ? groupDomain : first.RemoteIpText;
            var programs = rows.Select(r => _groupTitles.GetValueOrDefault(r.GroupKey, r.Process)).Distinct().ToList();
            var hits = rows.Sum(r => r.Hits);
            var who = programs.Count == 1 ? programs[0] : TextFormat.Plural(programs.Count, "программа", "программы", "программ");
            _details["Subtitle"] = $"{who} · замечено {TextFormat.Plural(hits, "раз", "раза", "раз")}";
            _details["Ip"] = string.Join(Environment.NewLine, ips);
            _details["IpLabel"] = ips.Count == 1 ? "IP-адрес" : $"IP-адреса ({ips.Count})";
            _details["Domains"] = domains.Count > 0 ? string.Join(", ", domains) : "неизвестен — программа обратилась по IP без запроса DNS";
            _details["Network"] = string.Join(Environment.NewLine, rows.Select(r => r.NetworkText(Format)).Where(n => n != "").Distinct());
            _details["NetworkLabel"] = rows.Select(r => r.NetworkText(Format)).Where(n => n != "").Distinct().Count() > 1 ? "Сети владельцев" : "Сеть владельца";
            _details["Owner"] = first.Asn?.OwnerText is { Length: > 0 } o ? o : "неизвестен";
            _details["OwnerRaw"] = first.Asn != null ? "В реестре: " + first.Asn.Owner : "";
            var health = Health.Worst(rows.Select(r => r.Health));
            _details["Health"] = health.Level switch
            {
                HealthLevel.Fail or HealthLevel.Warn => health.Reason,
                HealthLevel.Ok => "соединение устанавливается",
                _ => first.Proto == "UDP" ? "UDP — без подтверждений, судить нельзя; нажмите «Проверить»" : "мало данных",
            };
            _details["HealthLevel"] = health.Level.ToString();
            if (keepPdb.For == first.Asn?.Asn.ToString() && keepPdb.For != null)
            {
                _details["PdbFor"] = keepPdb.For;
                _details["Pdb"] = keepPdb.Text;
                HasPdb = true;
            }
            else if (first.Asn is { } a && _state.PeeringDb.Cached(a.Asn) is { } cachedNet)
            {
                _details["PdbFor"] = a.Asn.ToString();
                _details["Pdb"] = cachedNet.ToText();
                HasPdb = true;
            }
            _details["Country"] = CountryName(first.CountryText);
            _details["Protocol"] = string.Join(", ", rows.Select(r => TextFormat.Port(r.Proto, r.RemotePort)).Distinct().Take(4));
            _details["First"] = When(rows.Min(r => r.FirstSeen));
            var lastSeen = rows.Max(r => r.LastSeen);
            _details["Last"] = TextFormat.Relative(DateTimeOffset.Now, lastSeen, LiveWindow) == "сейчас" ? "сейчас" : When(lastSeen);
            if (keepRdap == first.RemoteIpText)
            {
                _details["RdapFor"] = keepRdap;
                _details["Rdap"] = rdap;
                HasRdap = true;
            }
            DetailsNew = rows.Any(r => r.IsNew);
        }

        OnPropertyChanged(nameof(D));
        OnPropertyChanged(nameof(HasSelection));
        OnPropertyChanged(nameof(NoSelection));
    }

    private static string When(DateTimeOffset t)
    {
        var local = t.ToLocalTime();
        var today = DateTime.Today;
        return local.Date == today ? $"сегодня, {local:HH:mm}"
            : local.Date == today.AddDays(-1) ? $"вчера, {local:HH:mm}"
            : local.ToString("dd.MM.yyyy HH:mm");
    }

    private static string CountryName(string code)
    {
        if (code == "") return "—";
        try
        {
            return $"{new RegionInfo(code).DisplayName} ({code})";
        }
        catch (ArgumentException)
        {
            return code;
        }
    }

    private async Task RdapAsync(DestinationRow? row)
    {
        if (row == null) return;
        RdapBusy = true;
        void Show(string text)
        {
            // The user may have picked another address while the registry was answering.
            if (SelectedItem?.Rows.FirstOrDefault()?.RemoteIpText != row.RemoteIpText) return;
            _details["RdapFor"] = row.RemoteIpText;
            _details["Rdap"] = text;
            HasRdap = true;
            OnPropertyChanged(nameof(D));
        }
        Show("Запрос к реестру IP-адресов…");
        try
        {
            var r = await _state.Rdap.LookupAsync(row.RemoteIp);
            Show(r.ToText(Format));
        }
        catch (Exception e)
        {
            Show("Не удалось получить данные: " + e.Message);
        }
        finally
        {
            RdapBusy = false;
        }
    }

    // =====================================================================
    // Copy, toast, search shortcuts
    // =====================================================================

    private bool _toastVisible;
    public bool ToastVisible { get => _toastVisible; private set => Set(ref _toastVisible, value); }
    private string _toastValue = "";
    public string ToastValue { get => _toastValue; private set => Set(ref _toastValue, value); }
    private bool _canUndo;
    public bool CanUndo { get => _canUndo; private set => Set(ref _canUndo, value); }

    /// <summary>Copies and says so at the bottom, with "Отменить" to put the old clipboard back.</summary>
    public void Copy(string text, string? label)
    {
        if (string.IsNullOrEmpty(text))
        {
            _clipboardBefore = null;
            ShowToast("нечего копировать", false);
            return;
        }
        _clipboardBefore = Clip.GetText();
        Clip.SetText(text);
        var lines = text.Split('\n').Length;
        var value = lines > 1 ? $"{label ?? "строки"} ({lines})" : text.Length > 48 ? text[..48] + "…" : text;
        ShowToast(value, true);
    }

    private void ShowToast(string value, bool undo)
    {
        ToastValue = value;
        CanUndo = undo && _clipboardBefore != null;
        ToastVisible = true;
        _toastTimer.Stop();
        _toastTimer.Start();
    }

    private void UndoCopy()
    {
        if (_clipboardBefore != null) Clip.SetText(_clipboardBefore);
        _clipboardBefore = null;
        ToastVisible = false;
    }

    private void CopyLines(IEnumerable<string> lines, string label) => Copy(string.Join(Environment.NewLine, lines), label);

    private static List<TableItem> Items(object? p) =>
        p is IList list ? list.OfType<TableItem>().ToList() : p is TableItem t ? [t] : [];

    private static List<DestinationRow> Rows(object? p) => Items(p).SelectMany(i => i.Rows).Distinct().ToList();

    public void SearchFor(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        SelectedNav = Nav[0];
        SearchText = text;
    }

    private static void OpenFolder(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
    }

    // =====================================================================
    // Export, banner, empty states, status bar
    // =====================================================================

    public ExportViewModel Export { get; }

    private bool _bannerHidden;
    private bool _asnBusy;
    public bool AsnBusy { get => _asnBusy; private set => Set(ref _asnBusy, value); }
    private string _asnBusyText = "";
    public string AsnBusyText { get => _asnBusyText; private set => Set(ref _asnBusyText, value); }
    public bool AsnBannerVisible => !_bannerHidden && _state.Asn.Count == 0 && !_state.AsnLoading;
    public bool AsnOk => _state.Asn.Count > 0;
    public bool AsnMissing => !AsnOk;

    private async Task DownloadAsnAsync()
    {
        AsnBusy = true;
        AsnBusyText = "Скачивается…";
        try
        {
            _state.Asn = await AsnUpdater.DownloadAsync(AppPaths.Http, AppPaths.AsnDatabase);
            _state.SetAsnLoaded();
            AsnBusyText = "";
            _slowAt = DateTime.MinValue;
            _ = RefreshAsync();
        }
        catch (Exception e)
        {
            AsnBusyText = "Не удалось: " + e.Message;
        }
        finally
        {
            AsnBusy = false;
            foreach (var n in new[] { nameof(AsnBannerVisible), nameof(AsnOk), nameof(AsnMissing) }) OnPropertyChanged(n);
        }
    }

    private bool _showOnboarding;
    public bool ShowOnboarding { get => _showOnboarding; private set => Set(ref _showOnboarding, value); }
    private bool _showNothingFound;
    public bool ShowNothingFound { get => _showNothingFound; private set => Set(ref _showNothingFound, value); }
    private string _emptyTitle = "";
    public string EmptyTitle { get => _emptyTitle; private set => Set(ref _emptyTitle, value); }
    private string _emptyText = "";
    public string EmptyText { get => _emptyText; private set => Set(ref _emptyText, value); }
    public bool AdminOk => _state.Collector.IsElevated;
    public bool CaptureOk => _state.Collector.KernelCapture && _state.Collector.DnsCapture;
    public string RetentionText => $"Сейчас {TextFormat.Plural(_state.Settings.RetentionDays, "день", "дня", "дней")}. Можно от 1 до 365";
    public string[] Suggestions { get; } = ["telegram", "youtube.com", "Центр обновления", "10.0.0.0/8", "AS13335"];

    private void UpdateEmptyState()
    {
        var empty = IsTableTab && Table.Count == 0;
        ShowNothingFound = empty && FiltersActive;
        ShowOnboarding = empty && !FiltersActive;
        if (ShowNothingFound)
        {
            var q = SearchText.Trim();
            EmptyTitle = q != "" ? $"Ничего не найдено по «{q}»" : "Под эти фильтры ничего не подходит";
            EmptyText = _period.Live
                ? "Сейчас таких соединений нет. Попробуйте период «24 часа» или «Всё»."
                : "Попробуйте другой запрос, другой период или сбросьте фильтры.";
        }
        else if (ShowOnboarding)
        {
            EmptyTitle = _logStart == null ? "NetWatcher записывает соединения" : "За этот период соединений нет";
            EmptyText = _logStart == null
                ? "Первые данные появятся через пару секунд. Выберите программу слева или начните искать."
                : "Выберите период подлиннее сверху или другую программу слева.";
        }
        foreach (var n in new[] { nameof(AdminOk), nameof(CaptureOk), nameof(AsnOk), nameof(AsnMissing), nameof(RetentionText), nameof(AsnBannerVisible) })
            OnPropertyChanged(n);
    }

    private string _captureText = "";
    public string CaptureText { get => _captureText; private set => Set(ref _captureText, value); }
    private string _asnText = "";
    public string AsnText { get => _asnText; private set => Set(ref _asnText, value); }
    private string _journalText = "";
    public string JournalText { get => _journalText; private set => Set(ref _journalText, value); }
    private string _totalsText = "";
    public string TotalsText { get => _totalsText; private set => Set(ref _totalsText, value); }
    private string _error = "";
    public string Error { get => _error; private set => Set(ref _error, value); }

    public void UpdateStatus()
    {
        var c = _state.Collector;
        CaptureText = CaptureOk ? "TCP, UDP и DNS собираются" : "Только TCP" + (c.CaptureError is { } e ? $": {e}" : "");
        AsnText = _state.AsnStatus;
        JournalText = $"Журнал: {TextFormat.Plural(_state.Settings.RetentionDays, "день", "дня", "дней")} · {_state.Store.SizeBytes / 1024.0 / 1024.0:0.0} МБ";
        var programs = _rows.Select(r => r.GroupKey).Distinct().Count();
        TotalsText = $"{TextFormat.Plural(_rows.Select(r => r.RemoteIp).Distinct().Count(), "адрес", "адреса", "адресов")} · {TextFormat.Plural(programs, "программа", "программы", "программ")}";
        Error = c.LastError is { } err ? "Ошибка сбора: " + err : "";
        OnPropertyChanged(nameof(CaptureOk));
        OnPropertyChanged(nameof(AsnBannerVisible));
        OnPropertyChanged(nameof(RetentionText));
    }

    // =====================================================================
    // Commands
    // =====================================================================

    public RelayCommand RefreshCommand { get; }
    public RelayCommand ClearSearchCommand { get; }
    public RelayCommand ResetFiltersCommand { get; }
    public RelayCommand ToggleCommand { get; }
    public RelayCommand CopyIpCommand { get; }
    public RelayCommand CopyDomainCommand { get; }
    public RelayCommand CopyNetworkCommand { get; }
    public RelayCommand CopyRowCommand { get; }
    public RelayCommand CopyValueCommand { get; }
    public RelayCommand CopyAllIpsCommand { get; }
    public RelayCommand CopyAllDomainsCommand { get; }
    public RelayCommand CopySummaryNetworksCommand { get; }
    public RelayCommand SearchIpCommand { get; }
    public RelayCommand SearchDomainCommand { get; }
    public RelayCommand SearchProgramCommand { get; }
    public RelayCommand SearchTextCommand { get; }
    public RelayCommand WhoElseCommand { get; }
    public RelayCommand RdapCommand { get; }
    public RelayCommand OpenFolderCommand { get; }
    public RelayCommand UndoCopyCommand { get; }
    public RelayCommand OpenExportCommand { get; }
    public RelayCommand OpenVpnExportCommand { get; }
    public RelayCommand OpenOwnerExportCommand { get; }
    public RelayCommand DownloadAsnCommand { get; }
    public RelayCommand HideBannerCommand { get; }
    public RelayCommand SetThemeCommand { get; }
    public RelayCommand OpenCheckCommand { get; }
    public RelayCommand OpenEmptyCheckCommand { get; }
    public RelayCommand PeeringDbCommand { get; }

    public DiagnosticsViewModel Diagnostics { get; }

    // ---- theme menu ----
    public string ThemeGlyph => _state.Settings.Theme switch { "Light" => "\uE706", "Dark" => "\uE708", _ => "\uE7F4" };
    public string ThemeTitle => _state.Settings.Theme switch { "Light" => "Тема: светлая", "Dark" => "Тема: тёмная", _ => "Тема: как в Windows" };
    public bool IsThemeSystem => _state.Settings.Theme == "System";
    public bool IsThemeLight => _state.Settings.Theme == "Light";
    public bool IsThemeDark => _state.Settings.Theme == "Dark";

    /// <summary>"youtube.com" or "1.2.3.4:8080" for the check panel.</summary>
    private static string? CheckTargetOf(TableItem? item)
    {
        var r = item?.Rows.FirstOrDefault();
        if (r == null) return null;
        var host = r.PrimaryDomain != "" ? r.PrimaryDomain : r.RemoteIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{r.RemoteIpText}]" : r.RemoteIpText;
        return r.RemotePort == 443 ? host : $"{host}:{r.RemotePort}";
    }

    private async Task PeeringDbAsync(int? asn)
    {
        if (asn is not { } n || n <= 0) return;
        void Show(string text)
        {
            if (SelectedItem?.Rows.FirstOrDefault()?.Asn?.Asn != n) return;
            _details["PdbFor"] = n.ToString();
            _details["Pdb"] = text;
            HasPdb = true;
            OnPropertyChanged(nameof(D));
        }
        Show("Запрос к PeeringDB…");
        try
        {
            var net = await _state.PeeringDb.LookupAsync(n);
            Show(net?.ToText() ?? $"AS{n} нет в PeeringDB — сеть не публикует сведения о себе.");
            _ = RefreshAsync(); // the learnt name shows up in the table
        }
        catch (Exception e)
        {
            Show("Не удалось получить данные: " + e.Message);
        }
    }

    private bool _hasPdb;
    public bool HasPdb { get => _hasPdb; private set => Set(ref _hasPdb, value); }
    public RelayCommand TogglePauseCommand { get; }
}

/// <summary>The clipboard can be briefly locked by another program; try a few times.</summary>
internal static class Clip
{
    public static void SetText(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        for (var i = 0; i < 5; i++)
        {
            try
            {
                Clipboard.SetDataObject(text, true);
                return;
            }
            catch (System.Runtime.InteropServices.COMException)
            {
                Thread.Sleep(50);
            }
        }
    }

    public static string? GetText()
    {
        try
        {
            return Clipboard.ContainsText() ? Clipboard.GetText() : null;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            return null;
        }
    }
}
