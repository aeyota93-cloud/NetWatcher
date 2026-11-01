using System.Collections.ObjectModel;
using System.Net;
using System.Windows.Threading;
using NetWatcher.App.Native;
using NetWatcher.Core;
using NetWatcher.Core.Link;

namespace NetWatcher.App.ViewModels;

/// <summary>A server line of the "Связь" tab.</summary>
public sealed record LinkServerView(
    string Title, string Address, string Owner, string Proto, string Level, string State,
    string Latency, string Jitter, string Loss, string LastAnswer, string Traffic, string Reason, bool HasLoss);

/// <summary>A line of the events list: outage start or recovery.</summary>
public sealed record LinkEventView(string Time, string Level, string Text);

/// <summary>A program card of the overview.</summary>
public sealed record LinkCardView(
    string Key, string Title, string Sub, string Level, string State, string Latency, string Loss, string Outages,
    IReadOnlyList<ChartPoint> Chart, NavItem? Nav);

/// <summary>The "Связь" tab: link state per program, from the link monitor.</summary>
internal sealed partial class MainViewModel
{
    private DispatcherTimer? _linkTimer;

    private void StartLink()
    {
        _linkTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _linkTimer.Tick += (_, _) =>
        {
            if (!Paused) ApplyLink();
        };
        _linkTimer.Start();
        SelectProgramCommand = new RelayCommand(p =>
        {
            if (p is string key && Nav.FirstOrDefault(n => n.Key == key) is { } nav) SelectedNav = nav;
        });
        ToggleNotifyCommand = new RelayCommand(ToggleNotify);
        OnPropertyChanged(nameof(SelectProgramCommand));
        OnPropertyChanged(nameof(ToggleNotifyCommand));
    }

    /// <summary>"v0.4.1" in the status bar.</summary>
    public string AppVersion => "v" + AppInfo.Version;

    public RelayCommand? SelectProgramCommand { get; private set; }
    public RelayCommand? ToggleNotifyCommand { get; private set; }

    /// <summary>History kept in memory covers the last hour of this session.</summary>
    private TimeSpan LinkWindow => _period.Live ? TimeSpan.FromMinutes(5)
        : _period.Span is { } s && s < TimeSpan.FromHours(1) ? s
        : TimeSpan.FromHours(1);

    public string LinkWindowText => _period.Live ? "5 минут"
        : _period.Span is { } s && s < TimeSpan.FromHours(1) ? $"{s.TotalMinutes:0} минут"
        : "последний час (история связи хранится, пока NetWatcher запущен)";

    private bool _linkShowAll, _linkHasProgram, _linkNoData;
    public bool LinkShowAll { get => _linkShowAll; private set => Set(ref _linkShowAll, value); }
    public bool LinkHasProgram { get => _linkHasProgram; private set => Set(ref _linkHasProgram, value); }
    public bool LinkNoData { get => _linkNoData; private set => Set(ref _linkNoData, value); }

    private string _linkLevel = "", _linkTitle = "", _linkSubtitle = "";
    private string _linkLatency = "", _linkJitter = "", _linkLoss = "", _linkOutages = "";
    public string LinkLevel { get => _linkLevel; private set => Set(ref _linkLevel, value); }
    public string LinkTitle { get => _linkTitle; private set => Set(ref _linkTitle, value); }
    public string LinkSubtitle { get => _linkSubtitle; private set => Set(ref _linkSubtitle, value); }
    public string LinkLatency { get => _linkLatency; private set => Set(ref _linkLatency, value); }
    public string LinkJitter { get => _linkJitter; private set => Set(ref _linkJitter, value); }
    public string LinkLoss { get => _linkLoss; private set => Set(ref _linkLoss, value); }
    public string LinkOutages { get => _linkOutages; private set => Set(ref _linkOutages, value); }

    private IReadOnlyList<ChartPoint> _linkChart = [];
    public IReadOnlyList<ChartPoint> LinkChart { get => _linkChart; private set => Set(ref _linkChart, value); }

    public ObservableCollection<LinkServerView> LinkServers { get; } = [];
    public ObservableCollection<LinkEventView> LinkEvents { get; } = [];
    public ObservableCollection<string> LinkReasons { get; } = [];
    public ObservableCollection<LinkCardView> LinkCards { get; } = [];

    /// <summary>Programs that talked earlier in the period but are quiet now — a compact line, not big cards.</summary>
    public ObservableCollection<LinkCardView> LinkIdle { get; } = [];

    private bool _hasLinkIdle;
    public bool HasLinkIdle { get => _hasLinkIdle; private set => Set(ref _hasLinkIdle, value); }

    private readonly Dictionary<string, NavItem> _cardAvatars = [];

    /// <summary>The program's list entry, or a stand-in with the same icon and letter when it is not listed for this period.</summary>
    private NavItem AvatarFor(ProgramLink p)
    {
        if (Nav.FirstOrDefault(n => n.Key == p.GroupKey) is { } nav) return nav;
        if (!_cardAvatars.TryGetValue(p.GroupKey, out var item))
            _cardAvatars[p.GroupKey] = item = new NavItem(p.GroupKey, p.Services != "" || p.Process == "System" ? "Службы Windows" : "Приложения", p.Path);
        item.Title = TitleFor(p.GroupKey);
        return item;
    }

    private bool _hasLinkReasons, _hasLinkEvents;
    public bool HasLinkReasons { get => _hasLinkReasons; private set => Set(ref _hasLinkReasons, value); }
    public bool HasLinkEvents { get => _hasLinkEvents; private set => Set(ref _hasLinkEvents, value); }

    public bool NotifyOn => SelectedNav is null or { IsAll: true }
        ? _state.Settings.NotifyAll
        : _state.Settings.NotifyAll || _state.Settings.NotifyPrograms.Contains(SelectedNav.Key);

    public string NotifyText => NotifyOn
        ? "Уведомления включены"
        : SelectedNav is null or { IsAll: true } ? "Уведомлять о пропаже связи у любой программы" : "Уведомлять о пропаже связи";

    private void ToggleNotify()
    {
        var s = _state.Settings;
        if (SelectedNav is null or { IsAll: true }) s.NotifyAll = !s.NotifyAll;
        else if (!s.NotifyPrograms.Remove(SelectedNav.Key)) s.NotifyPrograms.Add(SelectedNav.Key);
        _state.SaveSettings();
        OnPropertyChanged(nameof(NotifyOn));
        OnPropertyChanged(nameof(NotifyText));
    }

    /// <summary>Program title by group key, for notifications.</summary>
    public string TitleFor(string groupKey) => _groupTitles.GetValueOrDefault(groupKey, groupKey.Split(" · ")[0]);

    private void ApplyLink()
    {
        var now = DateTimeOffset.Now;
        var programs = _state.Link.Snapshot(now, LinkWindow, 120);
        OnPropertyChanged(nameof(LinkWindowText));
        OnPropertyChanged(nameof(NotifyOn));
        OnPropertyChanged(nameof(NotifyText));

        // Dots in the program list: the state of the last two minutes.
        var recent = _state.Link.Snapshot(now, TimeSpan.FromMinutes(2), 1).ToDictionary(p => p.GroupKey);
        foreach (var n in Nav.Skip(1))
        {
            if (recent.TryGetValue(n.Key, out var p) && p.Level != Core.Link.LinkLevel.Idle)
            {
                n.LinkLevel = p.Level.ToString();
                n.LinkText = p.Level == Core.Link.LinkLevel.Ok ? (p.LatencyMs is { } ms ? $"{ms:0} мс" : "работает") : p.StateText;
            }
            else
            {
                n.LinkLevel = "";
                n.LinkText = "";
            }
        }

        if (SelectedNav is null or { IsAll: true })
        {
            LinkShowAll = true;
            LinkHasProgram = false;
            LinkNoData = programs.Count == 0;
            ApplyOverview(programs);
            return;
        }

        LinkShowAll = false;
        var program = programs.FirstOrDefault(p => p.GroupKey == SelectedNav.Key);
        LinkHasProgram = program != null;
        LinkNoData = program == null;
        if (program != null) ApplyProgram(program, programs, now);
        else if (!ApplyNoCapture())
        {
            // Not the previous program's summary: there is simply nothing to judge.
            LinkLevel = "Idle";
            LinkTitle = "Нет данных о связи";
            LinkSubtitle = "Связь проверяется, только пока программа что-то отправляет";
        }
    }

    /// <summary>Without the kernel's network events there is nothing to judge: say so instead of "all fine".</summary>
    private bool ApplyNoCapture()
    {
        if (_state.Collector.KernelCapture) return false;
        LinkLevel = "Idle";
        LinkTitle = "Монитор связи не работает";
        LinkSubtitle = _state.Collector.IsElevated
            ? "Windows не отдаёт сетевые события: " + (_state.Collector.CaptureError ?? "причина неизвестна")
            : "Нужны права администратора: без них Windows не сообщает, какие пакеты отправляют и получают программы";
        return true;
    }

    private string ServerName(IPAddress ip, string process) =>
        _state.Dns.Get(ip, process).FirstOrDefault() ?? "";

    private void ApplyProgram(ProgramLink p, List<ProgramLink> all, DateTimeOffset now)
    {
        LinkLevel = p.Level.ToString();
        var activeServers = p.Servers.Count(s => s.Level != Core.Link.LinkLevel.Idle);
        var worst = p.Servers.FirstOrDefault(s => s.Level is Core.Link.LinkLevel.Fail or Core.Link.LinkLevel.Warn);
        var lastOutage = p.OutageList.LastOrDefault(o => o.End != null);
        switch (p.Level)
        {
            case Core.Link.LinkLevel.Fail:
                LinkTitle = "Сервер " + p.StateText.Replace("нет ответа", "не отвечает");
                LinkSubtitle = worst?.Reason ?? "";
                break;
            case Core.Link.LinkLevel.Warn:
                LinkTitle = "Связь с проблемами: " + p.StateText;
                LinkSubtitle = worst?.Reason ?? "";
                break;
            case Core.Link.LinkLevel.Ok:
                LinkTitle = "Связь в порядке";
                LinkSubtitle = TextFormat.Plural(activeServers, "сервер отвечает", "сервера отвечают", "серверов отвечают")
                               + (lastOutage != null
                                   ? $" · последний сбой в {lastOutage.Start.LocalDateTime:HH:mm:ss}, длился {(int)lastOutage.Duration(now).TotalSeconds} с"
                                   : " · сбоев не было");
                break;
            default:
                LinkTitle = "Сейчас программа не обменивается данными";
                LinkSubtitle = "Связь проверяется, только пока программа что-то отправляет";
                break;
        }
        LinkLatency = p.LatencyMs is { } ms ? $"{ms:0} мс" : "—";
        LinkJitter = p.JitterMs is { } j ? $"±{j:0} мс" : "—";
        LinkLoss = p.LossPercent is { } lp ? $"{lp:0}%" : "—";
        LinkOutages = p.Outages.ToString();
        LinkChart = p.Chart;

        Replace(LinkServers, p.Servers.Select(s =>
        {
            var name = ServerName(s.Ip, p.Process);
            var owner = _state.Asn.Lookup(s.Ip) is { } a ? a.OwnerText + (a.Country != "" ? " · " + a.Country : "") : "";
            var addr = s.Ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{s.Ip}]:{s.Port}" : $"{s.Ip}:{s.Port}";
            return new LinkServerView(
                name != "" ? name : "сервер",
                addr,
                owner,
                s.Proto,
                s.Level.ToString(),
                s.StateText,
                s.LatencyMs is { } l ? $"{l:0} мс" : s.Pingable ? "—" : "нет пинга",
                s.JitterMs is { } jj ? $"±{jj:0} мс" : "—",
                s.LossPercent is { } loss ? $"{loss:0}%" : "—",
                s.LastAnswer is { } la ? (now - la < TimeSpan.FromSeconds(5) ? "сейчас" : $"{(int)(now - la).TotalSeconds} с назад") : "—",
                $"{TextFormat.Bytes(s.BytesOut)} / {TextFormat.Bytes(s.BytesIn)}",
                s.Reason != "" ? s.Reason : (s.Pingable ? "" : "Сервер не отвечает на пинг — задержку измерить нельзя, это не ошибка"),
                (s.LossPercent ?? 0) >= 1);
        }));

        // Why: the reasons of problem servers, and whether other programs are fine.
        var reasons = p.Servers
            .Where(s => s.Level is Core.Link.LinkLevel.Fail or Core.Link.LinkLevel.Warn && s.Reason != "")
            .Select(s => $"{(ServerName(s.Ip, p.Process) is { Length: > 0 } n ? n : s.Ip.ToString())}: {s.Reason}")
            .ToList();
        if (reasons.Count > 0)
        {
            var others = all.Where(o => o.GroupKey != p.GroupKey && o.Level == Core.Link.LinkLevel.Ok).Select(o => TitleFor(o.GroupKey)).Take(3).ToList();
            reasons.Add(others.Count > 0
                ? $"Другие программы получают ответы ({string.Join(", ", others)}) — интернет в целом есть"
                : "Другие программы сейчас тоже не получают ответов — возможно, проблема с интернетом");
        }
        Replace(LinkReasons, reasons);
        HasLinkReasons = reasons.Count > 0;

        var events = new List<(DateTimeOffset Time, LinkEventView View)>();
        foreach (var o in p.OutageList)
        {
            var name = ServerName(o.Ip, p.Process) is { Length: > 0 } n ? n : o.Ip.ToString();
            events.Add((o.Start, new LinkEventView(o.Start.LocalDateTime.ToString("HH:mm:ss"), "Fail",
                o.End == null ? $"{name} не отвечает" : $"{name} перестал отвечать")));
            if (o.End is { } end)
                events.Add((end, new LinkEventView(end.LocalDateTime.ToString("HH:mm:ss"), "Ok",
                    $"Связь с {name} восстановилась — простой {(int)o.Duration(now).TotalSeconds} с")));
        }
        Replace(LinkEvents, events.OrderByDescending(e => e.Time).Take(30).Select(e => e.View));
        HasLinkEvents = events.Count > 0;
    }

    private void ApplyOverview(List<ProgramLink> programs)
    {
        var fails = programs.Count(p => p.Level == Core.Link.LinkLevel.Fail);
        var warns = programs.Count(p => p.Level == Core.Link.LinkLevel.Warn);
        var ok = programs.Where(p => p.Level == Core.Link.LinkLevel.Ok).Select(p => TitleFor(p.GroupKey)).ToList();
        LinkLevel = fails > 0 ? "Fail" : warns > 0 ? "Warn" : ok.Count > 0 ? "Ok" : "Idle";
        LinkTitle = fails == 0 && warns == 0
            ? ok.Count > 0 ? "Связь в порядке у всех программ" : "Сейчас программы не обмениваются данными"
            : string.Join(", ", new[]
            {
                fails > 0 ? TextFormat.Plural(fails, "программа без связи", "программы без связи", "программ без связи") : "",
                warns > 0 ? TextFormat.Plural(warns, "программа с потерями", "программы с потерями", "программ с потерями") : "",
            }.Where(x => x != ""));
        LinkSubtitle = ok.Count > 0
            ? $"Интернет в целом работает: отвечают {string.Join(", ", ok.Take(3))}{(ok.Count > 3 ? " и другие" : "")}"
            : fails > 0 ? "Ни одна программа не получает ответов — похоже, проблема с интернетом или сетью" : "";
        ApplyNoCapture();

        LinkCardView Card(ProgramLink p)
        {
            var servers = p.Servers.Count;
            return new LinkCardView(
                p.GroupKey,
                TitleFor(p.GroupKey),
                $"{p.Protocols} · {TextFormat.Plural(servers, "сервер", "сервера", "серверов")}",
                p.Level.ToString(),
                p.Level switch { Core.Link.LinkLevel.Ok => "работает", Core.Link.LinkLevel.Idle => "простаивает", _ => p.StateText },
                p.LatencyMs is { } ms ? $"{ms:0} мс" : "—",
                p.LossPercent is { } cardLoss ? $"{cardLoss:0}%" : "—",
                p.Outages.ToString(),
                p.Chart.Count > 60 ? p.Chart.Skip(p.Chart.Count - 60).ToList() : p.Chart,
                AvatarFor(p));
        }
        Replace(LinkCards, programs.Where(p => p.Level != Core.Link.LinkLevel.Idle).Select(Card));
        Replace(LinkIdle, programs.Where(p => p.Level == Core.Link.LinkLevel.Idle).Select(Card));
        HasLinkIdle = LinkIdle.Count > 0;
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> items)
    {
        var list = items.ToList();
        if (target.SequenceEqual(list)) return;
        target.Clear();
        foreach (var i in list) target.Add(i);
    }
}
