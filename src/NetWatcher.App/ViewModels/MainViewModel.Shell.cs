using System.Diagnostics;

namespace NetWatcher.App.ViewModels;

/// <summary>The window frame: the menu on the left, the sections, the programs list and the quick filters panel.</summary>
internal sealed partial class MainViewModel
{
    private const string GuideUrl = "https://github.com/aeyota93-cloud/NetWatcher/blob/main/docs/guide.md";

    private NavItem? _lastProgram;
    private bool _filtersOpen;

    public RelayCommand ShowProgramsCommand { get; private set; } = null!;
    public RelayCommand ShowAllCommand { get; private set; } = null!;
    public RelayCommand ToggleRailCommand { get; private set; } = null!;
    public RelayCommand ToggleListCommand { get; private set; } = null!;
    public RelayCommand ToggleFiltersCommand { get; private set; } = null!;
    public RelayCommand OpenGuideCommand { get; private set; } = null!;

    /// <summary>Called from the constructor: the window binds to these commands right after it.</summary>
    private void InitShell()
    {
        ShowProgramsCommand = new RelayCommand(ShowPrograms);
        ShowAllCommand = new RelayCommand(() => SelectedNav = Nav[0]);
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

    /// <summary>"Все соединения" is the "Все" item of the programs list; any other item is "Программы".</summary>
    public bool IsAllSection => SelectedNav is null or { IsAll: true };
    public bool IsProgramsSection => !IsAllSection;
    public string SectionTitle => IsAllSection ? "Все соединения" : "Программы";
    public string SectionSubtitle => IsAllSection ? "Общий список приложений и служб Windows." : "Соединения и связь выбранной программы.";

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

    private int _selectedCount;

    /// <summary>Rows selected in the table, by check boxes or with Ctrl and Shift.</summary>
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
    }

    private void ShowPrograms()
    {
        if (ProgramToShow(Nav, _lastProgram) is { } program) SelectedNav = program;
        else ShowToast("Программы появятся, когда начнут обмениваться данными", false, "Пока пусто:");
    }

    /// <summary>The program seen last if it is still in the list, otherwise the first one.</summary>
    internal static NavItem? ProgramToShow(IEnumerable<NavItem> nav, NavItem? last)
    {
        var list = nav.Where(n => !n.IsAll).ToList();
        return last != null && list.Contains(last) ? last : list.FirstOrDefault();
    }
}
