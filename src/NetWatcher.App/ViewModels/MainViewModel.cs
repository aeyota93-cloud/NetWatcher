using System.Collections;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using NetWatcher.Core;
using NetWatcher.Core.Net;
using System.Globalization;
using System.Windows.Data;

namespace NetWatcher.App.ViewModels;

public sealed record PeriodOption(string Title, TimeSpan? Span, bool Live)
{
    public override string ToString() => Title;
}

public enum ListMode
{
    Addresses,
    Domains,
    Exact,
    Wide24,
    Wide16,
    Owner,
}

public sealed record ListModeOption(string Title, ListMode Mode)
{
    public override string ToString() => Title;
}

internal sealed class MainViewModel : ObservableObject
{
    private readonly AppState _state;
    private readonly DispatcherTimer _autoRefresh;
    private readonly DispatcherTimer _searchDelay;
    private readonly DispatcherTimer _noticeTimer;
    private string _notice = "";
    private List<DestinationRow> _allRows = [];
    private bool _refreshing;
    private bool _pending;

    private string _searchText = "";
    private PeriodOption _period;
    private GroupView? _selectedGroup;
    private bool _paused;
    private ListModeOption _listMode;
    private bool _useMask;
    private bool _ipv4Only;
    private string _listText = "";
    private string _listSummary = "";
    private string _summary = "";
    private string _captureStatus = "";
    private string _asnStatus = "";
    private string _error = "";

    public MainViewModel(AppState state)
    {
        _state = state;
        _period = Periods[0];
        _listMode = ListModes[0];
        _useMask = state.Settings.AddressFormat == AddressFormat.Mask;

        Groups.Add(new GroupView("", "Все программы", ""));
        _selectedGroup = Groups[0];

        _autoRefresh = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _autoRefresh.Tick += (_, _) => _ = RefreshAsync();
        _searchDelay = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
        _searchDelay.Tick += (_, _) =>
        {
            _searchDelay.Stop();
            _ = RefreshAsync();
        };

        RefreshCommand = new RelayCommand(() => _ = RefreshAsync());
        ClearSearchCommand = new RelayCommand(() => SearchText = "");
        CopyIpCommand = new RelayCommand(p => CopyLines(Selected(p).Select(r => r.Ip).Distinct()));
        CopyDomainCommand = new RelayCommand(p => CopyLines(Selected(p).SelectMany(r => r.Row.Domains).Distinct()));
        CopyNetworkCommand = new RelayCommand(p => CopyLines(Selected(p).Select(r => r.Network).Where(n => n != "").Distinct()));
        CopyRowCommand = new RelayCommand(p => CopyLines(Selected(p).Select(r => r.ToLine())));
        SearchIpCommand = new RelayCommand(p => SearchFor(Selected(p).FirstOrDefault()?.Ip));
        SearchProcessCommand = new RelayCommand(p => SearchFor(Selected(p).FirstOrDefault()?.Process));
        SearchDomainCommand = new RelayCommand(p => SearchFor(Selected(p).FirstOrDefault()?.Row.Domains.FirstOrDefault()));
        RdapCommand = new RelayCommand(p => _ = RdapAsync(Selected(p).FirstOrDefault()));
        OpenFolderCommand = new RelayCommand(p => OpenFolder(Selected(p).FirstOrDefault()?.Path));
        CopyListCommand = new RelayCommand(() => Copy(ListText));
        SaveListCommand = new RelayCommand(SaveList);
        CopyGroupCommand = new RelayCommand(p => { if (p is GroupView g) Copy(g.Title); });
        CopyGroupIpsCommand = new RelayCommand(p => CopyLines(Analysis.Addresses(RowsOf(p as GroupView)).Select(a => a.ToString())));
        CopyGroupDomainsCommand = new RelayCommand(p => CopyLines(RowsOf(p as GroupView).SelectMany(r => r.Domains).Distinct().Order(StringComparer.OrdinalIgnoreCase)));
        _noticeTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _noticeTimer.Tick += (_, _) =>
        {
            _noticeTimer.Stop();
            Notice = "";
        };
    }

    public void Start()
    {
        UpdateTimer();
        _autoRefresh.Start();
        _ = RefreshAsync();
    }

    // ---- what is on screen ----

    public PeriodOption[] Periods { get; } =
    [
        new("Сейчас (активные)", null, Live: true),
        new("Последние 15 минут", TimeSpan.FromMinutes(15), false),
        new("Последний час", TimeSpan.FromHours(1), false),
        new("Последние 24 часа", TimeSpan.FromDays(1), false),
        new("Последние 7 дней", TimeSpan.FromDays(7), false),
        new("Вся история", null, false),
    ];

    public ListModeOption[] ListModes { get; } =
    [
        new("IP-адреса", ListMode.Addresses),
        new("Домены", ListMode.Domains),
        new("Подсети: только эти адреса", ListMode.Exact),
        new("Подсети: расширить до /24", ListMode.Wide24),
        new("Подсети: расширить до /16", ListMode.Wide16),
        new("Сети владельцев (по базе AS)", ListMode.Owner),
    ];

    public ObservableCollection<GroupView> Groups { get; } = [];
    public ObservableCollection<RowView> Rows { get; } = [];

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (!Set(ref _searchText, value)) return;
            _searchDelay.Stop();
            _searchDelay.Start();
        }
    }

    public PeriodOption Period
    {
        get => _period;
        set
        {
            if (!Set(ref _period, value)) return;
            UpdateTimer();
            _ = RefreshAsync();
        }
    }

    public GroupView? SelectedGroup
    {
        get => _selectedGroup;
        set
        {
            if (!Set(ref _selectedGroup, value)) return;
            ApplyRows();
            UpdateList();
        }
    }

    public bool Paused
    {
        get => _paused;
        set
        {
            if (!Set(ref _paused, value)) return;
            if (value) _autoRefresh.Stop();
            else
            {
                _autoRefresh.Start();
                _ = RefreshAsync();
            }
        }
    }

    public ListModeOption ListModeOption
    {
        get => _listMode;
        set
        {
            if (Set(ref _listMode, value)) UpdateList();
        }
    }

    public bool UseMask
    {
        get => _useMask;
        set
        {
            if (!Set(ref _useMask, value)) return;
            _state.Settings.AddressFormat = value ? AddressFormat.Mask : AddressFormat.Cidr;
            _state.SaveSettings();
            foreach (var r in Rows) r.Update(r.Row, Format);
            UpdateList();
        }
    }

    public bool Ipv4Only
    {
        get => _ipv4Only;
        set
        {
            if (Set(ref _ipv4Only, value)) UpdateList();
        }
    }

    public string ListText { get => _listText; private set => Set(ref _listText, value); }
    public string ListSummary { get => _listSummary; private set => Set(ref _listSummary, value); }
    public string Summary { get => _summary; private set => Set(ref _summary, value); }
    public string CaptureStatus { get => _captureStatus; private set => Set(ref _captureStatus, value); }
    public string AsnStatus { get => _asnStatus; private set => Set(ref _asnStatus, value); }
    public string Error { get => _error; private set => Set(ref _error, value); }
    public string Notice { get => _notice; private set => Set(ref _notice, value); }

    private AddressFormat Format => UseMask ? AddressFormat.Mask : AddressFormat.Cidr;

    // ---- commands ----

    public RelayCommand RefreshCommand { get; }
    public RelayCommand ClearSearchCommand { get; }
    public RelayCommand CopyIpCommand { get; }
    public RelayCommand CopyDomainCommand { get; }
    public RelayCommand CopyNetworkCommand { get; }
    public RelayCommand CopyRowCommand { get; }
    public RelayCommand SearchIpCommand { get; }
    public RelayCommand SearchProcessCommand { get; }
    public RelayCommand SearchDomainCommand { get; }
    public RelayCommand RdapCommand { get; }
    public RelayCommand OpenFolderCommand { get; }
    public RelayCommand CopyListCommand { get; }
    public RelayCommand SaveListCommand { get; }
    public RelayCommand CopyGroupCommand { get; }
    public RelayCommand CopyGroupIpsCommand { get; }
    public RelayCommand CopyGroupDomainsCommand { get; }

    // ---- refresh ----

    private void UpdateTimer()
    {
        var poll = _state.Settings.PollSeconds;
        _autoRefresh.Interval = TimeSpan.FromSeconds(Period.Live ? Math.Max(poll, 2) : 10);
    }

    public void SettingsChanged()
    {
        UpdateTimer();
        _ = RefreshAsync();
    }

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
            var period = Period;
            var words = DestinationRow.SplitQuery(SearchText);
            var asn = _state.Asn;
            var names = _state.Collector.Services.DisplayNames;
            var liveWindow = TimeSpan.FromSeconds(Math.Max(10, _state.Settings.PollSeconds * 3));

            _allRows = await Task.Run(() =>
            {
                var now = DateTimeOffset.Now;
                var from = period.Live ? now - liveWindow
                    : period.Span is { } span ? now - span
                    : DateTimeOffset.FromUnixTimeMilliseconds(0);
                var list = _state.Store.Query(from);
                Analysis.Enrich(list, _state.Dns, asn, names);
                return words.Count == 0 ? list : list.Where(r => r.Matches(words)).ToList();
            });

            ApplyGroups();
            ApplyRows();
            UpdateList();
            UpdateStatus();
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

    private void ApplyGroups()
    {
        var groups = Analysis.Groups(_allRows);
        var all = Groups[0];
        all.Count = _allRows.Select(r => r.RemoteIp).Distinct().Count().ToString();
        all.Subtitle = $"{groups.Count} программ и служб";

        var existing = Groups.Skip(1).ToDictionary(g => g.Key);
        var desired = new List<GroupView>();
        foreach (var g in groups)
        {
            var view = existing.GetValueOrDefault(g.Key) ?? new GroupView(g.Key, g.Process, g.Path);
            view.Subtitle = g.ServicesDisplay != "" ? g.ServicesDisplay : Plural(g.Addresses, "адрес", "адреса", "адресов");
            view.Count = g.Addresses.ToString();
            desired.Add(view);
        }

        // The selected group stays in the list even when nothing matches now, so the selection is not lost.
        if (SelectedGroup is { IsAll: false } sel && !desired.Contains(sel))
        {
            sel.Count = "0";
            desired.Add(sel);
        }

        // Move items in place instead of rebuilding: the list keeps its scroll position.
        for (var i = 0; i < desired.Count; i++)
        {
            var target = i + 1;
            var current = Groups.IndexOf(desired[i]);
            if (current < 0) Groups.Insert(target, desired[i]);
            else if (current != target) Groups.Move(current, target);
        }
        while (Groups.Count > desired.Count + 1) Groups.RemoveAt(Groups.Count - 1);
    }

    private IEnumerable<DestinationRow> VisibleRows => RowsOf(SelectedGroup);

    private void ApplyRows()
    {
        var wanted = VisibleRows.ToDictionary(RowView.KeyOf);
        for (var i = Rows.Count - 1; i >= 0; i--)
            if (!wanted.ContainsKey(Rows[i].Key)) Rows.RemoveAt(i);

        var existing = Rows.ToDictionary(r => r.Key);
        var added = wanted.Keys.Count(k => !existing.ContainsKey(k));
        // Many new rows at once (period switch): sort once at the end instead of on every insert.
        using var defer = added > 200 ? CollectionViewSource.GetDefaultView(Rows).DeferRefresh() : null;
        foreach (var (key, row) in wanted)
        {
            if (existing.TryGetValue(key, out var view)) view.Update(row, Format);
            else Rows.Add(new RowView(row, Format));
        }
    }

    private void UpdateList()
    {
        var rows = VisibleRows.ToList();
        if (Ipv4Only) rows = rows.Where(r => r.RemoteIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
        List<string> lines;
        switch (ListModeOption.Mode)
        {
            case ListMode.Addresses:
                lines = Analysis.Addresses(rows).Select(a => a.ToString()).ToList();
                break;
            case ListMode.Domains:
                lines = rows.SelectMany(r => r.Domains).Distinct().Order(StringComparer.OrdinalIgnoreCase).ToList();
                break;
            default:
                var mode = ListModeOption.Mode switch
                {
                    ListMode.Exact => SubnetMode.Exact,
                    ListMode.Wide24 => SubnetMode.Wide24,
                    ListMode.Wide16 => SubnetMode.Wide16,
                    _ => SubnetMode.Owner,
                };
                lines = Analysis.Subnets(rows, mode, Ipv4Only).Select(c => c.Format(Format)).ToList();
                break;
        }

        var text = string.Join(Environment.NewLine, lines);
        if (text != ListText) ListText = text;
        var addresses = rows.Select(r => r.RemoteIp).Distinct().Count();
        ListSummary = $"{Plural(lines.Count, "строка", "строки", "строк")} из {Plural(addresses, "адреса", "адресов", "адресов")}"
                      + (ListModeOption.Mode == ListMode.Owner && _state.Asn.Count == 0 ? " · база владельцев не скачана, показаны сами адреса" : "");
    }

    public void UpdateStatus()
    {
        var c = _state.Collector;
        CaptureStatus = c.KernelCapture && c.DnsCapture
            ? "Захват: TCP, UDP и DNS"
            : "Захват: только TCP" + (c.CaptureError is { } e ? $" ({e})" : "");
        AsnStatus = _state.AsnStatus;
        var programs = _allRows.Select(r => r.GroupKey).Distinct().Count();
        var addresses = _allRows.Select(r => r.RemoteIp).Distinct().Count();
        Summary = $"{Plural(programs, "программа", "программы", "программ")} · {Plural(addresses, "адрес", "адреса", "адресов")} · журнал {_state.Store.SizeBytes / 1024.0 / 1024.0:0.0} МБ";
        Error = c.LastError is { } err ? "Ошибка сбора: " + err : "";
    }

    // ---- actions ----

    private static List<RowView> Selected(object? parameter) =>
        parameter is IList list ? list.OfType<RowView>().ToList()
        : parameter is RowView r ? [r]
        : [];

    private void CopyLines(IEnumerable<string> lines) => Copy(string.Join(Environment.NewLine, lines));

    /// <summary>Copies and says so in the status bar.</summary>
    public void Copy(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            ShowNotice("Нечего копировать");
            return;
        }
        Clip.SetText(text);
        var lines = text.Split('\n').Length;
        ShowNotice(lines == 1 ? $"Скопировано: {(text.Length > 60 ? text[..60] + "…" : text)}" : $"Скопировано строк: {lines}");
    }

    private void ShowNotice(string text)
    {
        Notice = text;
        _noticeTimer.Stop();
        _noticeTimer.Start();
    }

    private IEnumerable<DestinationRow> RowsOf(GroupView? g) =>
        g is null or { IsAll: true } ? _allRows : _allRows.Where(r => r.GroupKey == g.Key);

    private void SearchFor(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        SelectedGroup = Groups[0];
        SearchText = text;
    }

    private async Task RdapAsync(RowView? row)
    {
        if (row == null || !IpKey.TryParse(row.Ip, out var ip)) return;
        var window = Views.TextWindow.Show($"Сеть {row.Ip}", "Запрос к RDAP (реестр IP-адресов)…");
        try
        {
            var result = await _state.Rdap.LookupAsync(ip);
            var text = $"Адрес: {ip}\n" + result.ToText(Format);
            if (row.Row.Asn is { } asn) text += $"\n\nПо офлайн-базе: {asn.OwnerText}, {asn.NetworkOf(ip).Format(Format)}";
            window.SetText(text);
        }
        catch (Exception e)
        {
            window.SetText($"Не удалось получить данные RDAP: {e.Message}");
        }
    }

    private static void OpenFolder(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
    }

    private void SaveList()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Сохранить список",
            FileName = $"netwatcher-{SafeName(SelectedGroup?.Title)}-{DateTime.Now:yyyyMMdd-HHmm}.txt",
            Filter = "Текст (*.txt)|*.txt|Все файлы (*.*)|*.*",
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            File.WriteAllText(dialog.FileName, ListText + Environment.NewLine);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show("Не удалось сохранить файл: " + e.Message, "NetWatcher", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static string SafeName(string? s)
    {
        if (string.IsNullOrEmpty(s) || s == "Все программы") return "all";
        foreach (var c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
        return s.Replace(' ', '_');
    }

    internal static string Plural(int n, string one, string few, string many)
    {
        var mod100 = n % 100;
        var mod10 = n % 10;
        var word = mod100 is >= 11 and <= 14 ? many : mod10 == 1 ? one : mod10 is >= 2 and <= 4 ? few : many;
        return $"{n} {word}";
    }
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
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is not true;
}
