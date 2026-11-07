using System.Collections.ObjectModel;
using System.Windows;
using NetWatcher.App.Monitoring;
using NetWatcher.Core;
using NetWatcher.Core.Link;

namespace NetWatcher.App.ViewModels;

/// <summary>A chip of the quality card: "Игры · хорошо".</summary>
public sealed record QualityChip(string Title, string ClassText, string Level, string Tip);

/// <summary>The "Качество подключения" card of the "Связь" tab.</summary>
internal sealed partial class MainViewModel
{
    private static readonly TimeSpan QualityWindow = TimeSpan.FromMinutes(10);

    private string _qGatewayLabel = "До роутера", _qGateway = "—", _qInternetLabel = "До интернета", _qInternet = "—";
    private string _qLoad = "", _qHint = "", _qTest = "", _qProgress = "";
    private bool _qTestBusy;
    private CancellationTokenSource? _testCts;

    public string QualityGatewayLabel { get => _qGatewayLabel; private set => Set(ref _qGatewayLabel, value); }
    public string QualityGateway { get => _qGateway; private set => Set(ref _qGateway, value); }
    public string QualityInternetLabel { get => _qInternetLabel; private set => Set(ref _qInternetLabel, value); }
    public string QualityInternet { get => _qInternet; private set => Set(ref _qInternet, value); }
    public string QualityLoad { get => _qLoad; private set => Set(ref _qLoad, value); }

    /// <summary>The tiles of «Проверки»: the delay large, the spread and losses under it.</summary>
    public string QualityGatewayValue => Split(QualityGateway).Value;
    public string QualityGatewayNote => Split(QualityGateway).Note;
    public string QualityInternetValue => Split(QualityInternet).Value;
    public string QualityInternetNote => Split(QualityInternet).Note;
    public string QualityLoadNote => "Тест под нагрузкой: до 350 МБ трафика, около 20 секунд";

    /// <summary>"42 мс ±3 · потерь нет" → "42 мс" and "±3 · потерь нет"; a text without a delay stays whole.</summary>
    internal static (string Value, string Note) Split(string text)
    {
        var cut = text.IndexOf(" мс", StringComparison.Ordinal);
        if (cut < 0) return (text, "");
        cut += " мс".Length;
        return (text[..cut], text[cut..].TrimStart(' ', '·').Trim());
    }
    public string QualityHint { get => _qHint; private set => Set(ref _qHint, value); }
    public string QualityTest { get => _qTest; private set => Set(ref _qTest, value); }
    public string QualityProgress { get => _qProgress; private set => Set(ref _qProgress, value); }
    public bool QualityOn => _state.Settings.QualityPings;
    public ObservableCollection<QualityChip> QualityChips { get; } = [];

    public bool QualityTestBusy
    {
        get => _qTestBusy;
        private set
        {
            if (Set(ref _qTestBusy, value)) OnPropertyChanged(nameof(QualityTestIdle));
        }
    }

    public bool QualityTestIdle => !_qTestBusy;

    public RelayCommand? RunTestCommand { get; private set; }
    public RelayCommand? CancelTestCommand { get; private set; }

    private void InitQuality()
    {
        RunTestCommand = new RelayCommand(() => _ = RunTestAsync());
        CancelTestCommand = new RelayCommand(() => _testCts?.Cancel());
        OnPropertyChanged(nameof(RunTestCommand));
        OnPropertyChanged(nameof(CancelTestCommand));
    }

    private static string PathText(PathStats s) => s switch
    {
        { Samples: 0 } => "нет данных",
        { LatencyMs: null } => "не отвечает на пинг",
        _ => $"{s.LatencyMs:0} мс" + (s.JitterMs is { } j ? $" ±{j:0}" : "")
             + (s.Loss > 0 ? $" · потери {s.Loss * 100:0.#}%" : " · потерь нет"),
    };

    private void ApplyQuality()
    {
        OnPropertyChanged(nameof(QualityOn));
        var now = DateTimeOffset.Now;
        var test = _state.LastLoadTest is { } t && now - t.Time < TimeSpan.FromHours(1) ? t : null;
        var trafficAvailable = _state.Collector.KernelCapture;
        var r = _state.Quality.Report(now, QualityWindow, test?.DownBps, test?.UpBps, test?.IncreaseMs, trafficAvailable);
        var (gateway, internet) = _state.LinkService.QualityTargets;
        var viaVpn = _state.LinkService.QualityInternetViaVpn;

        QualityGatewayLabel = gateway != null ? $"До роутера ({gateway})" : "До роутера";
        QualityGateway = gateway == null ? "роутер не найден" : PathText(r.Gateway);
        QualityInternetLabel = viaVpn ? $"До интернета через VPN ({internet})" : $"До интернета ({internet})";
        QualityInternet = PathText(r.Internet);
        foreach (var n in new[] { nameof(QualityGatewayValue), nameof(QualityGatewayNote), nameof(QualityInternetValue), nameof(QualityInternetNote) })
            OnPropertyChanged(n);

        var load = r.Load;
        if (!trafficAvailable)
            QualityLoad = _state.Collector.IsElevated
                ? "нагрузка не видна: сетевые события ядра недоступны"
                : "нагрузка не видна без прав администратора";
        else if (test?.IncreaseMs is { } testInc)
            QualityLoad = $"+{testInc:0} мс — {Aim.IncreaseText(testInc)} (тест в {test.Time.LocalDateTime:HH:mm})";
        else if (load.IncreaseMs is { } inc)
        {
            var dir = load.DownLoadedMs != null && (load.UpLoadedMs == null || load.DownLoadedMs >= load.UpLoadedMs)
                ? $"при скачивании до {LoadTestMath.Mbps(load.PeakInBps)}"
                : $"при отправке до {LoadTestMath.Mbps(load.PeakOutBps)}";
            QualityLoad = $"+{inc:0} мс {dir} — {Aim.IncreaseText(inc)}";
        }
        else
            QualityLoad = load.PeakInBps < QualityMonitor.MinDownLoadBps && load.PeakOutBps < QualityMonitor.MinUpLoadBps
                ? "за 10 минут сильной нагрузки не было — проверьте тестом"
                : "мало данных";

        Replace(QualityChips, r.Scores.Select(s => new QualityChip(
            s.Title, s.ClassText,
            s.Class >= AimClass.Good ? "Ok" : s.Class == AimClass.Average ? "Warn" : "Fail",
            $"Баллы AIM: {s.Points} из {MaxPoints(s.Experience)}"
            + "\nМетодика Cloudflare AIM: задержка, разброс, потери, рост задержки под нагрузкой, скорость")));

        QualityHint = Hint(r, test);
        if (viaVpn) QualityHint = "Задержка до интернета включает VPN." + (QualityHint.Length > 0 ? " " + QualityHint : "");
        QualityTest = test == null ? "" :
            $"Тест в {test.Time.LocalDateTime:HH:mm}: ↓ {Speed(test.DownBps)}, ↑ {Speed(test.UpBps)}; задержка {Ms(test.Idle.LatencyMs)}, "
            + $"при скачивании {Ms(test.DownLoaded.LatencyMs)}, при отправке {Ms(test.UpLoaded.LatencyMs)} · {test.Server}";
    }

    private static string Speed(double? bps) => bps is { } b ? LoadTestMath.Mbps(b) : "—";
    private static string Ms(double? ms) => ms is { } m ? $"{m:0} мс" : "—";

    private static int MaxPoints(string experience) => experience switch
    {
        "gaming" => 50,
        "rtc" => 60,
        _ => 80,
    };

    /// <summary>Where the trouble is: the home network (router, Wi-Fi), the way out, or queues under load.</summary>
    private static string Hint(QualityReport r, LoadTestResult? test)
    {
        var g = r.Gateway;
        // A gateway that never answers ping (often a VPN adapter) says nothing about Wi-Fi.
        if (g.Samples >= 10 && g.LatencyMs != null && (g.Loss >= 0.03 || g.LatencyMs >= 20 || g.JitterMs >= 15))
            return "Задержка или потери видны уже до роутера — для домашней сети это много. Так бывает с Wi-Fi: далеко от роутера, стены, помехи. Попробуйте подключиться по кабелю.";
        var i = r.Internet;
        if (i.Samples >= 10 && (i.Loss >= 0.02 || i.LatencyMs is null))
            return g.Samples >= 10 && g.LatencyMs != null
                ? "До роутера потерь не видно, а до внешнего сервера они есть. Причина может быть на пути или в ограничении ответов."
                : "Потери на пути к интернету.";
        var inc = test?.IncreaseMs ?? r.Load.IncreaseMs;
        if (inc >= 50)
            return "Когда линия загружена, задержка сильно растёт (bufferbloat): игры и звонки могут прерываться, пока что-то качается. "
                   + "Помогает управление очередями на роутере (SQM: CAKE или FQ-CoDel) или ограничение скорости чуть ниже тарифа.";
        return "";
    }

    private async Task RunTestAsync()
    {
        var owner = Application.Current.MainWindow;
        var question = $"Тест около 20 секунд нагружает линию: скачивает до {LoadTester.MaxDownBytes / 1_000_000} МБ и отправляет до "
                       + $"{LoadTester.MaxUpBytes / 1_000_000} МБ через серверы теста скорости Cloudflare ({LoadTester.Host}) и всё это время измеряет задержку. "
                       + "Результаты никуда не отправляются.\n\nНа мобильном интернете это расход трафика. Запустить?";
        if (MessageBox.Show(owner, question, "Проверить под нагрузкой", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

        QualityTestBusy = true;
        _testCts = new CancellationTokenSource();
        var progress = new Progress<string>(s => QualityProgress = s);
        try
        {
            _state.LastLoadTest = await LoadTester.RunAsync(progress, _testCts.Token);
            QualityProgress = "";
        }
        catch (OperationCanceledException)
        {
            QualityProgress = "Тест остановлен.";
        }
        catch (Exception e) when (e is System.Net.Http.HttpRequestException or System.Net.Sockets.SocketException or InvalidOperationException or IOException)
        {
            QualityProgress = "Тест не удался: " + e.Message;
        }
        finally
        {
            QualityTestBusy = false;
            _testCts.Dispose();
            _testCts = null;
            ApplyQuality();
        }
    }
}
