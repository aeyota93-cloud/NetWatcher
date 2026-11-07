using System.Diagnostics;

namespace NetWatcher.App.ViewModels;

/// <summary>What fills the window; "Main" is a program or "Все соединения".</summary>
internal enum AppPage { Main, Overview, Checks, Blocks, Settings }

/// <summary>The window frame: the menu on the left, the sections, the programs list and the quick filters panel.</summary>
internal sealed partial class MainViewModel
{
    private const string GuideUrl = "https://github.com/aeyota93-cloud/NetWatcher/blob/main/docs/guide.md";

    private NavItem? _lastProgram;
    private AppPage _page;
    private bool _filtersOpen;

    public RelayCommand ClearProgramSearchCommand { get; private set; } = null!;
    public RelayCommand FindProgramCommand { get; private set; } = null!;
    public RelayCommand OpenProgramFolderCommand { get; private set; } = null!;
    public RelayCommand BlockProgramCommand { get; private set; } = null!;
    public RelayCommand ShowOverviewCommand { get; private set; } = null!;
    public RelayCommand OpenProgramCommand { get; private set; } = null!;
    public RelayCommand ShowProgramsCommand { get; private set; } = null!;
    public RelayCommand ShowAllCommand { get; private set; } = null!;
    public RelayCommand ToggleRailCommand { get; private set; } = null!;
    public RelayCommand ToggleListCommand { get; private set; } = null!;
    public RelayCommand ToggleFiltersCommand { get; private set; } = null!;
    public RelayCommand OpenGuideCommand { get; private set; } = null!;

    /// <summary>Called from the constructor: the window binds to these commands right after it.</summary>
    private void InitShell()
    {
        ClearProgramSearchCommand = new RelayCommand(() => ProgramSearch = "");
        // The actions of the program in the header: the same as in the row menu, for the whole program.
        FindProgramCommand = new RelayCommand(() => SearchProgramCommand.Execute(ProgramRows()));
        OpenProgramFolderCommand = new RelayCommand(_ => OpenFolderCommand.Execute(ProgramRows()), _ => SelectedNav is { Path.Length: > 0 });
        BlockProgramCommand = new RelayCommand(() => BlockCommand.Execute(ProgramRows()));
        ShowOverviewCommand = new RelayCommand(() => ShowPage(AppPage.Overview));
        OpenProgramCommand = new RelayCommand(p =>
        {
            ShowPage(AppPage.Main);
            if (Nav.FirstOrDefault(n => n.Key == p as string) is { } program) SelectedNav = program;
        });
        ShowProgramsCommand = new RelayCommand(() =>
        {
            ShowPage(AppPage.Main);
            ShowPrograms();
        });
        ShowAllCommand = new RelayCommand(() =>
        {
            ShowPage(AppPage.Main);
            SelectedNav = Nav[0];
        });
        // The check opens from rows, menus and Ctrl+D: its panel state decides the page.
        Diagnostics.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName != nameof(DiagnosticsViewModel.IsOpen)) return;
            if (Diagnostics.IsOpen) ShowPage(AppPage.Checks);
            else if (_page == AppPage.Checks) ShowPage(AppPage.Main);
        };
        ToggleRailCommand = new RelayCommand(() =>
        {
            _state.Settings.MenuExpanded = !_state.Settings.MenuExpanded;
            _state.SaveSettings();
            OnPropertyChanged(nameof(MenuExpanded));
            OnPropertyChanged(nameof(MenuWidth));
            OnPropertyChanged(nameof(MenuToggleText));
        });
        ToggleListCommand = new RelayCommand(() =>
        {
            _state.Settings.ProgramListHidden = !_state.Settings.ProgramListHidden;
            _state.SaveSettings();
            NotifySection();
        });
        ToggleFiltersCommand = new RelayCommand(() => FiltersOpen = !FiltersOpen);
        OpenGuideCommand = new RelayCommand(() => Process.Start(new ProcessStartInfo(GuideUrl) { UseShellExecute = true }));
    }

    private string _programSearch = "";

    /// <summary>Narrows only the list on the left, not the table: it finds a program to open.</summary>
    public string ProgramSearch
    {
        get => _programSearch;
        set
        {
            if (Set(ref _programSearch, value ?? "")) OnPropertyChanged(nameof(ProgramSearchEmpty));
        }
    }

    public bool ProgramSearchEmpty => _programSearch == "";

    private string _programTraffic = "—", _programLatency = "—", _programLoss = "—", _programState = "", _programStateLevel = "";
    public string ProgramTraffic { get => _programTraffic; private set => Set(ref _programTraffic, value); }
    public string ProgramLatency { get => _programLatency; private set => Set(ref _programLatency, value); }
    public string ProgramLoss { get => _programLoss; private set => Set(ref _programLoss, value); }
    public string ProgramState { get => _programState; private set => Set(ref _programState, value); }
    public string ProgramStateLevel { get => _programStateLevel; private set => Set(ref _programStateLevel, value); }

    /// <summary>The line next to the program's name. A dash means "not measured", never "no problem".</summary>
    private void ApplyProgramFigures(NavItem? nav, Core.Link.ProgramLink? link)
    {
        ProgramTraffic = nav is { Bytes: > 0 } ? Core.TextFormat.Bytes(nav.Bytes) : "—";
        ProgramLatency = link?.LatencyMs is { } ms ? $"{ms:0} мс" : "—";
        ProgramLoss = link?.LossPercent is { } loss ? $"{loss:0}%" : "—";
        if (link == null || link.Level == Core.Link.LinkLevel.Idle)
        {
            ProgramState = "";
            ProgramStateLevel = "";
            return;
        }
        ProgramStateLevel = link.Level.ToString();
        ProgramState = link.Level == Core.Link.LinkLevel.Ok ? "Сбоев не видно" : char.ToUpper(link.StateText[0]) + link.StateText[1..];
    }

    public bool IsMainPage => _page == AppPage.Main;
    public bool IsOverviewPage => _page == AppPage.Overview;
    public bool IsChecksPage => _page == AppPage.Checks;
    public bool IsBlocksPage => _page == AppPage.Blocks;
    public bool IsSettingsPage => _page == AppPage.Settings;
    public bool MenuPrograms => IsMainPage && IsProgramsSection;
    public bool MenuAll => IsMainPage && IsAllSection;

    public void ShowPage(AppPage page)
    {
        if (_page == page) return;
        _page = page;
        // Leaving keeps a running check going: it is there when the user comes back.
        if (page != AppPage.Checks && Diagnostics.IsOpen) Diagnostics.IsOpen = false;
        NotifySection();
        if (page == AppPage.Overview) ApplyLink();
    }

    /// <summary>"Все соединения" is the "Все" item of the programs list; any other item is "Программы".</summary>
    public bool IsAllSection => SelectedNav is null or { IsAll: true };
    public bool IsProgramsSection => !IsAllSection;
    public string SectionTitle => IsOverviewPage ? "Сеть на виду" : IsAllSection ? "Все соединения" : "Программы";
    public string SectionSubtitle => IsOverviewPage ? "Какие программы используют интернет и где нет ответов."
        : IsAllSection ? "Общий список приложений и служб Windows." : "Соединения и связь выбранной программы.";

    public bool MenuExpanded => _state.Settings.MenuExpanded;
    public double MenuWidth => MenuExpanded ? 194 : 64;
    public string MenuToggleText => MenuExpanded ? "Свернуть меню" : "Развернуть меню";

    public bool IsProgramListVisible => IsProgramsSection && !_state.Settings.ProgramListHidden;
    public string ProgramListText => _state.Settings.ProgramListHidden ? "Показать список" : "Скрыть список";

    /// <summary>All quick filters are shown when the panel is open; the switched-on ones stay visible when it is closed.</summary>
    public bool FiltersOpen
    {
        get => _filtersOpen;
        private set
        {
            if (Set(ref _filtersOpen, value)) OnPropertyChanged(nameof(ChipsVisible));
        }
    }

    /// <summary>
    /// A program's "Связь" has a text filter of its own, so the search hides there.
    /// A search already typed stays visible: a filter that works must not be hidden.
    /// </summary>
    public bool ShowSearchBox => !IsLinkTab || HasSearch || IsAllSection;
    public bool ShowHeadingFilters => IsMainPage && !ShowSearchBox;
    public bool ShowListButton => IsMainPage && IsProgramsSection;

    private int _selectedCount;

    /// <summary>Rows selected in the table: a click, Ctrl+click, Shift+click or Ctrl+A.</summary>
    public int SelectedCount
    {
        get => _selectedCount;
        set
        {
            if (!Set(ref _selectedCount, value)) return;
            OnPropertyChanged(nameof(SelectionBarVisible));
            OnPropertyChanged(nameof(SelectionText));
        }
    }

    /// <summary>One selected row is an ordinary click, not a selection to act on.</summary>
    public bool SelectionBarVisible => IsTableTab && SelectedCount > 1;
    public string SelectionText => $"Выбрано: {SelectedCount}";

    public int ChipsOn => Chips.Count(c => c.IsOn);
    public bool HasChipsOn => ChipsOn > 0;
    public string FiltersText => ChipsOn > 0 ? $"Фильтры · {ChipsOn}" : "Фильтры";
    public bool ChipsVisible => FiltersOpen || HasChipsOn;

    private void NotifyChips()
    {
        OnPropertyChanged(nameof(ChipsOn));
        OnPropertyChanged(nameof(HasChipsOn));
        OnPropertyChanged(nameof(FiltersText));
        OnPropertyChanged(nameof(ChipsVisible));
    }

    private void NotifySection()
    {
        OnPropertyChanged(nameof(IsAllSection));
        OnPropertyChanged(nameof(IsProgramsSection));
        OnPropertyChanged(nameof(SectionTitle));
        OnPropertyChanged(nameof(SectionSubtitle));
        OnPropertyChanged(nameof(IsProgramListVisible));
        OnPropertyChanged(nameof(ProgramListText));
        OnPropertyChanged(nameof(ShowSearchBox));
        foreach (var n in new[] { nameof(IsMainPage), nameof(IsOverviewPage), nameof(IsChecksPage), nameof(IsBlocksPage), nameof(IsSettingsPage),
                     nameof(MenuPrograms), nameof(MenuAll), nameof(ShowHeadingFilters), nameof(ShowListButton) })
            OnPropertyChanged(n);
    }

    private void ShowPrograms()
    {
        if (ProgramToShow(Nav, _lastProgram) is { } program) SelectedNav = program;
        else ShowToast("Программы появятся, когда начнут обмениваться данными", false, "Пока пусто:");
    }

    /// <summary>Rows of the selected program, as the row menu commands take them.</summary>
    private List<TableItem> ProgramRows()
    {
        if (SelectedNav is not { IsAll: false } nav) return [];
        var item = new TableItem("program:" + nav.Key, ItemKind.Single);
        var rows = _rows.Where(r => r.GroupKey == nav.Key).ToList();
        if (rows.Count == 0) return [];
        item.Update(rows, rows[0].PrimaryDomain, r => r.NetworkText(Core.Net.AddressFormat.Cidr), r => nav.Title, DateTimeOffset.Now, LiveWindow);
        return [item];
    }

    /// <summary>The program seen last if it is still in the list, otherwise the first one.</summary>
    internal static NavItem? ProgramToShow(IEnumerable<NavItem> nav, NavItem? last)
    {
        var list = nav.Where(n => !n.IsAll).ToList();
        return last != null && list.Contains(last) ? last : list.FirstOrDefault();
    }
}
