using System.Collections.ObjectModel;
using NetWatcher.Core;
using NetWatcher.Core.Link;

namespace NetWatcher.App.ViewModels;

/// <summary>A line of "Что изменилось": only what really happened, with the program to open.</summary>
public sealed record OverviewEvent(string Time, string Level, string Title, string Detail, string Key);

/// <summary>The "Обзор" page: real figures of the chosen period, no score of our own.</summary>
internal sealed partial class MainViewModel
{
    private string _ovPrograms = "—", _ovProgramsHint = "", _ovTraffic = "—", _ovTrafficHint = "", _ovAddresses = "—", _ovAddressesHint = "";
    private string _ovProblems = "—", _ovProblemsHint = "", _ovLinkLevel = "Idle", _ovLinkText = "";
    private bool _ovHasProblems, _hasOvEvents;
    private IReadOnlyList<ChartPoint> _ovChart = [];

    public string OvPrograms { get => _ovPrograms; private set => Set(ref _ovPrograms, value); }
    public string OvProgramsHint { get => _ovProgramsHint; private set => Set(ref _ovProgramsHint, value); }
    public string OvTraffic { get => _ovTraffic; private set => Set(ref _ovTraffic, value); }
    public string OvTrafficHint { get => _ovTrafficHint; private set => Set(ref _ovTrafficHint, value); }
    public string OvAddresses { get => _ovAddresses; private set => Set(ref _ovAddresses, value); }
    public string OvAddressesHint { get => _ovAddressesHint; private set => Set(ref _ovAddressesHint, value); }
    public string OvProblems { get => _ovProblems; private set => Set(ref _ovProblems, value); }
    public string OvProblemsHint { get => _ovProblemsHint; private set => Set(ref _ovProblemsHint, value); }
    public bool OvHasProblems { get => _ovHasProblems; private set => Set(ref _ovHasProblems, value); }
    public string OvLinkLevel { get => _ovLinkLevel; private set => Set(ref _ovLinkLevel, value); }
    public string OvLinkText { get => _ovLinkText; private set => Set(ref _ovLinkText, value); }
    public IReadOnlyList<ChartPoint> OvChart { get => _ovChart; private set => Set(ref _ovChart, value); }
    public bool HasOvEvents { get => _hasOvEvents; private set => Set(ref _hasOvEvents, value); }
    public ObservableCollection<NavItem> OvTopPrograms { get; } = [];
    public ObservableCollection<OverviewEvent> OvEvents { get; } = [];

    private void ApplyOverviewPage(List<ProgramLink> programs, DateTimeOffset now)
    {
        var navs = Nav.Where(n => !n.IsAll).ToList();
        var services = navs.Count(n => n.Section == ServicesSection);
        OvPrograms = navs.Count.ToString();
        OvProgramsHint = services > 0 ? $"Включая службы Windows: {services}" : "Служб Windows не замечено";

        long bytesIn = _rows.Sum(r => r.BytesIn), bytesOut = _rows.Sum(r => r.BytesOut);
        OvTraffic = bytesIn + bytesOut > 0 ? TextFormat.Bytes(bytesIn + bytesOut) : "—";
        OvTrafficHint = bytesIn + bytesOut > 0 ? TextFormat.Traffic(bytesIn, bytesOut)
            : _state.Collector.KernelCapture ? "Данных не замечено" : "Трафик виден с правами администратора";

        OvAddresses = _rows.Select(r => r.RemoteIp).Distinct().Count().ToString();
        OvAddressesHint = "За выбранный период";

        var problems = _rows.Where(r => r.Health.IsProblem).ToList();
        var titles = problems.Select(r => TitleFor(r.GroupKey)).Distinct().ToList();
        OvProblems = problems.Select(r => r.RemoteIp).Distinct().Count().ToString();
        OvHasProblems = problems.Count > 0;
        OvProblemsHint = titles.Count == 0 ? "Сбоев не видно" : string.Join(", ", titles.Take(2)) + (titles.Count > 2 ? " и другие" : "");

        var fails = programs.Count(p => p.Level == Core.Link.LinkLevel.Fail);
        var warns = programs.Count(p => p.Level == Core.Link.LinkLevel.Warn);
        var working = programs.Count(p => p.Level == Core.Link.LinkLevel.Ok);
        OvLinkLevel = fails > 0 ? "Fail" : warns > 0 ? "Warn" : working > 0 ? "Ok" : "Idle";
        OvLinkText = fails + warns > 0
            ? string.Join(" · ", new[]
            {
                fails > 0 ? $"без ответов: {fails}" : "",
                warns > 0 ? $"с потерями: {warns}" : "",
            }.Where(x => x != ""))
            : working > 0 ? "Сбоев не видно"
            : _state.Collector.KernelCapture ? "Программы сейчас не обмениваются данными" : "Нужны права администратора";

        ApplyQuality();
        OvChart = _state.Quality.InternetChart(now, QualityWindow, 60);

        Replace(OvTopPrograms, navs.OrderByDescending(n => n.Problems > 0).ThenBy(n => Nav.IndexOf(n)).Take(6));

        var events = new List<(DateTimeOffset Time, OverviewEvent View)>();
        foreach (var p in programs)
        {
            var title = TitleFor(p.GroupKey);
            foreach (var o in p.OutageList)
            {
                var server = ServerName(o.Ip, p.Process) is { Length: > 0 } n ? n : o.Ip.ToString();
                events.Add((o.Start, new OverviewEvent(o.Start.LocalDateTime.ToString("HH:mm"), "Fail",
                    o.End == null ? $"{title}: {server} не отвечает" : $"{title}: {server} перестал отвечать", "", p.GroupKey)));
                if (o.End is { } end)
                    events.Add((end, new OverviewEvent(end.LocalDateTime.ToString("HH:mm"), "Ok",
                        $"{title}: связь с {server} восстановилась", $"Простой {(int)o.Duration(now).TotalSeconds} с", p.GroupKey)));
            }
        }
        foreach (var group in _rows.Where(r => r.IsNew).GroupBy(r => r.GroupKey))
        {
            var count = group.Select(r => r.RemoteIp).Distinct().Count();
            events.Add((group.Max(r => r.FirstSeen), new OverviewEvent(group.Max(r => r.FirstSeen).LocalDateTime.ToString("HH:mm"), "New",
                $"{TitleFor(group.Key)}: новые адреса — {count}", "Впервые замечены за последние сутки", group.Key)));
        }
        Replace(OvEvents, events.OrderByDescending(e => e.Time).Take(8).Select(e => e.View));
        HasOvEvents = OvEvents.Count > 0;
    }
}
