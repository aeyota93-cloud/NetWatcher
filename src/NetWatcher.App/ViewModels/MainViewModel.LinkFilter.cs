using NetWatcher.Core;
using NetWatcher.Core.Link;

namespace NetWatcher.App.ViewModels;

/// <summary>
/// Filters of the server table in the "Связь" tab, one per column, and quick copying.
/// The quick filters above the tabs drive the matching columns: TCP/UDP → protocol, «С доменом» / «Без домена» →
/// how the server was reached, «Проблемные» → state; changing those columns turns the quick filters on and off.
/// The other quick filters («Трекеры», «Только новые»…) apply to the servers as they do to the table.
/// </summary>
internal sealed partial class MainViewModel
{
    // Columns without a quick filter of their own.
    private string _filterText = "";
    private StateFilter _filterStateLocal;
    private LatencyFilter _filterLatency;
    private JitterFilter _filterJitter;
    private LossFilter _filterLoss;
    private AnswerFilter _filterAnswer;
    private TrafficFilter _filterTraffic;

    /// <summary>Quick filters that have no column and apply to the servers as they are.</summary>
    private const QuickFilter ExtraServerFilters =
        QuickFilter.OnlyNew | QuickFilter.Trackers | QuickFilter.Telemetry | QuickFilter.HideMicrosoft | QuickFilter.Ipv4;

    private FilterChip Chip(QuickFilter flag) => Chips.First(c => c.Flag == flag);

    /// <summary>Sets two "either" quick filters to one of three states: none, the first, the second.</summary>
    private void SetPair(QuickFilter first, QuickFilter second, int value)
    {
        Chip(first).IsOn = value == 1;
        Chip(second).IsOn = value == 2;
    }

    private int GetPair(QuickFilter first, QuickFilter second)
    {
        var a = Chip(first).IsOn;
        var b = Chip(second).IsOn;
        return a == b ? 0 : a ? 1 : 2;
    }

    public string LinkFilterText
    {
        get => _filterText;
        set
        {
            if (Set(ref _filterText, value ?? "")) ApplyServerFilter();
        }
    }

    /// <summary>0 — all, 1 — TCP, 2 — UDP; the TCP and UDP quick filters.</summary>
    public int LinkFilterProto
    {
        get => GetPair(QuickFilter.Tcp, QuickFilter.Udp);
        set => SetPair(QuickFilter.Tcp, QuickFilter.Udp, value);
    }

    /// <summary>0 — all, 1 — by domain, 2 — by address; the «С доменом» and «Без домена» quick filters.</summary>
    public int LinkFilterAddress
    {
        get => GetPair(QuickFilter.WithDomain, QuickFilter.NoDomain);
        set => SetPair(QuickFilter.WithDomain, QuickFilter.NoDomain, value);
    }

    /// <summary>Index in <see cref="StateFilter"/>; «Проблемы» is the «Проблемные» quick filter.</summary>
    public int LinkFilterState
    {
        get => Chip(QuickFilter.Problems).IsOn ? (int)StateFilter.Problems : (int)_filterStateLocal;
        set
        {
            var state = (StateFilter)value;
            _filterStateLocal = state == StateFilter.Problems ? StateFilter.All : state;
            if (Chip(QuickFilter.Problems).IsOn != (state == StateFilter.Problems)) Chip(QuickFilter.Problems).IsOn = state == StateFilter.Problems;
            else ApplyServerFilter();
        }
    }

    public int LinkFilterLatency
    {
        get => (int)_filterLatency;
        set
        {
            _filterLatency = (LatencyFilter)value;
            ApplyServerFilter();
        }
    }

    public int LinkFilterJitter
    {
        get => (int)_filterJitter;
        set
        {
            _filterJitter = (JitterFilter)value;
            ApplyServerFilter();
        }
    }

    public int LinkFilterLoss
    {
        get => (int)_filterLoss;
        set
        {
            _filterLoss = (LossFilter)value;
            ApplyServerFilter();
        }
    }

    public int LinkFilterAnswer
    {
        get => (int)_filterAnswer;
        set
        {
            _filterAnswer = (AnswerFilter)value;
            ApplyServerFilter();
        }
    }

    public int LinkFilterTraffic
    {
        get => (int)_filterTraffic;
        set
        {
            _filterTraffic = (TrafficFilter)value;
            ApplyServerFilter();
        }
    }

    /// <summary>The column filters as they are now, quick filters included.</summary>
    private ServerFilter CurrentServerFilter() => new()
    {
        Text = _filterText ?? "",
        Proto = (ProtoFilter)LinkFilterProto,
        Address = (AddressFilter)LinkFilterAddress,
        State = (StateFilter)LinkFilterState,
        Latency = _filterLatency,
        Jitter = _filterJitter,
        Loss = _filterLoss,
        Answer = _filterAnswer,
        Traffic = _filterTraffic,
    };

    private QuickFilter ExtraFilters => Filters & ExtraServerFilters;

    /// <summary>Any column filter or quick filter that narrows the server list.</summary>
    public bool LinkFilterActive => CurrentServerFilter().IsActive || ExtraFilters != QuickFilter.None;

    private bool PassServer(ServerFilter filter, LinkServerView s) =>
        filter.Pass(s.Facts) && (ExtraFilters == QuickFilter.None || QuickFilters.Pass(s.Row, ExtraFilters));

    private string _linkShownText = "";
    public string LinkShownText { get => _linkShownText; private set => Set(ref _linkShownText, value); }

    /// <summary>Column filters changed: refresh the list now, without waiting for the timer.</summary>
    private void ApplyServerFilter()
    {
        NotifyServerFilter();
        if (!HoldServerList) ApplyLink();
    }

    private void NotifyServerFilter()
    {
        foreach (var n in new[]
                 {
                     nameof(LinkFilterProto), nameof(LinkFilterAddress), nameof(LinkFilterState), nameof(LinkFilterLatency),
                     nameof(LinkFilterJitter), nameof(LinkFilterLoss), nameof(LinkFilterAnswer), nameof(LinkFilterTraffic),
                     nameof(LinkFilterText), nameof(LinkFilterActive),
                 })
            OnPropertyChanged(n);
    }

    /// <summary>"Сбросить фильтры": every column and every quick filter (they narrow the servers too). The search stays.</summary>
    private void ResetServerFilters()
    {
        _filterText = "";
        _filterStateLocal = StateFilter.All;
        _filterLatency = LatencyFilter.All;
        _filterJitter = JitterFilter.All;
        _filterLoss = LossFilter.All;
        _filterAnswer = AnswerFilter.All;
        _filterTraffic = TrafficFilter.All;
        foreach (var c in Chips) c.IsOn = false;
        ApplyServerFilter();
    }

    /// <summary>The latency chart: a narrow strip by default, full height on request; kept in the settings.</summary>
    public bool LinkChartExpanded
    {
        get => _state.Settings.LinkChartExpanded;
        set
        {
            if (_state.Settings.LinkChartExpanded == value) return;
            _state.Settings.LinkChartExpanded = value;
            _state.SaveSettings();
            OnPropertyChanged();
            OnPropertyChanged(nameof(LinkChartCompact));
            OnPropertyChanged(nameof(LinkChartHeight));
            OnPropertyChanged(nameof(LinkChartToggleText));
        }
    }

    public bool LinkChartCompact => !LinkChartExpanded;
    public double LinkChartHeight => LinkChartExpanded ? 150 : 44;
    public string LinkChartToggleText => LinkChartExpanded ? "Свернуть" : "Развернуть";
    public RelayCommand? ToggleLinkChartCommand { get; private set; }

    public RelayCommand? ResetServerFiltersCommand { get; private set; }
    public RelayCommand? CopyServerIpCommand { get; private set; }
    public RelayCommand? CopyServerDomainCommand { get; private set; }
    public RelayCommand? CopyServerAddressCommand { get; private set; }
    public RelayCommand? CopyShownIpsCommand { get; private set; }
    public RelayCommand? CopyShownDomainsCommand { get; private set; }

    private void InitServerFilter()
    {
        ResetServerFiltersCommand = new RelayCommand(ResetServerFilters);
        ToggleLinkChartCommand = new RelayCommand(() => LinkChartExpanded = !LinkChartExpanded);
        CopyServerIpCommand = new RelayCommand(p =>
        {
            if (p is LinkServerView s) Copy(s.Ip, "IP");
        });
        CopyServerDomainCommand = new RelayCommand(p =>
        {
            if (p is LinkServerView { HasName: true } s) Copy(s.Name, "домен");
        });
        CopyServerAddressCommand = new RelayCommand(p =>
        {
            if (p is LinkServerView s) Copy(s.Address, "IP и порт");
        });
        CopyShownIpsCommand = new RelayCommand(() => CopyLines(LinkServers.Select(s => s.Ip).Distinct(), "IP показанных серверов"));
        CopyShownDomainsCommand = new RelayCommand(() =>
            CopyLines(LinkServers.Where(s => s.HasName).Select(s => s.Name).Distinct(StringComparer.OrdinalIgnoreCase), "домены показанных серверов"));
        foreach (var n in new[]
                 {
                     nameof(ResetServerFiltersCommand), nameof(ToggleLinkChartCommand), nameof(CopyServerIpCommand), nameof(CopyServerDomainCommand),
                     nameof(CopyServerAddressCommand), nameof(CopyShownIpsCommand), nameof(CopyShownDomainsCommand),
                 })
            OnPropertyChanged(n);
    }

    /// <summary>A server picked in the "Связь" table: its address goes to the details pane below, as a table row does.</summary>
    private void ShowServerDetails(LinkServerView? server)
    {
        if (server == null)
        {
            if (SelectedItem?.Key.StartsWith("link:", StringComparison.Ordinal) == true) SelectedItem = null;
            return;
        }
        var row = server.Row;
        var key = "link:" + row.Key;
        if (SelectedItem is { } current && current.Key == key)
        {
            current.Update([row], row.PrimaryDomain, r => r.NetworkText(Format), r => TitleFor(r.GroupKey), DateTimeOffset.Now, LiveWindow);
            UpdateDetails();
            return;
        }
        var item = new TableItem(key, ItemKind.Single);
        item.Update([row], row.PrimaryDomain, r => r.NetworkText(Format), r => TitleFor(r.GroupKey), DateTimeOffset.Now, LiveWindow);
        SelectedItem = item;
    }
}
