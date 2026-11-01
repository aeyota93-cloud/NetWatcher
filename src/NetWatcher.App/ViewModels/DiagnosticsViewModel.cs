using System.Collections.ObjectModel;
using System.Windows;
using NetWatcher.Core;
using NetWatcher.Core.Diagnostics;

namespace NetWatcher.App.ViewModels;

/// <summary>A line of the check: status mark, title and what was found.</summary>
public sealed class StepView(string id, string title) : ObservableObject
{
    private StepStatus _status = StepStatus.Waiting;
    private string _text = "";

    public string Id { get; } = id;
    public string Title { get; } = title;
    public StepStatus Status { get => _status; set => Set(ref _status, value); }
    public string Text { get => _text; set => Set(ref _text, value); }
}

/// <summary>A line of the MTR-style table.</summary>
public sealed record HopView(int Ttl, string Address, string Loss, string Avg, string Best, string Worst, string Owner, bool Silent, bool Reached, bool HasLoss)
{
    public static HopView From(HopInfo h)
    {
        static string Ms(double? v) => v is { } x ? $"{x:0}" : "";
        return new HopView(
            h.Ttl,
            h.Address == null ? "*" : h.Address + (h.Balanced ? $" (+{h.Addresses.Count - 1})" : ""),
            h.Answered ? $"{h.LossPercent:0}%" : "",
            Ms(h.AvgMs), Ms(h.BestMs), Ms(h.WorstMs),
            h.OwnerText,
            !h.Answered,
            h.Reached,
            h.Answered && h.LossPercent > 0);
    }
}

/// <summary>The "Проверка соединения" side panel.</summary>
internal sealed class DiagnosticsViewModel : ObservableObject
{
    private readonly AppState _state;
    private readonly Action<string, string> _copy;
    private CancellationTokenSource? _cts;
    private CheckReport? _report;

    public DiagnosticsViewModel(AppState state, Action<string, string> copy)
    {
        _state = state;
        _copy = copy;
        RunCommand = new RelayCommand(_ => _ = RunAsync(), _ => !IsRunning);
        StopCommand = new RelayCommand(() => _cts?.Cancel());
        CopyCommand = new RelayCommand(() =>
        {
            if (_report != null) _copy(_report.ToText(), "отчёт о проверке");
        });
        CloseCommand = new RelayCommand(() =>
        {
            _cts?.Cancel();
            IsOpen = false;
        });
    }

    private bool _isOpen;
    public bool IsOpen { get => _isOpen; set => Set(ref _isOpen, value); }

    private string _target = "";
    public string Target { get => _target; set => Set(ref _target, value); }

    private bool _isRunning;
    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (Set(ref _isRunning, value)) CommandManagerHelper.Refresh();
        }
    }

    private string _error = "";
    public string Error { get => _error; private set => Set(ref _error, value); }

    private bool _hasVerdict;
    public bool HasVerdict { get => _hasVerdict; private set => Set(ref _hasVerdict, value); }
    private VerdictLevel _level;
    public VerdictLevel Level { get => _level; private set => Set(ref _level, value); }
    private string _verdictTitle = "";
    public string VerdictTitle { get => _verdictTitle; private set => Set(ref _verdictTitle, value); }
    private string _verdictText = "";
    public string VerdictText { get => _verdictText; private set => Set(ref _verdictText, value); }

    private string _vpnNote = "";

    /// <summary>Why the check counts as going through a VPN; empty when it does not.</summary>
    public string VpnNote
    {
        get => _vpnNote;
        private set
        {
            if (Set(ref _vpnNote, value)) OnPropertyChanged(nameof(HasVpn));
        }
    }

    public bool HasVpn => VpnNote != "";

    public ObservableCollection<StepView> Steps { get; } = [];
    public ObservableCollection<HopView> Hops { get; } = [];
    public bool HasHops => Hops.Count > 0;

    public RelayCommand RunCommand { get; }
    public RelayCommand StopCommand { get; }
    public RelayCommand CopyCommand { get; }
    public RelayCommand CloseCommand { get; }

    /// <summary>Refreshes the route table; called after every round of the trace.</summary>
    private void ShowHops(IReadOnlyList<HopInfo> hops)
    {
        Hops.Clear();
        foreach (var h in hops) Hops.Add(HopView.From(h));
        Rounds = hops.Count > 0 ? hops.Max(h => h.Sent) : 0;
        OnPropertyChanged(nameof(HasHops));
    }

    private int _rounds;

    /// <summary>Probes sent per hop so far.</summary>
    public int Rounds { get => _rounds; private set => Set(ref _rounds, value); }

    /// <summary>Opens the panel; with a target the check starts at once.</summary>
    public void Open(string? target)
    {
        IsOpen = true;
        if (!string.IsNullOrWhiteSpace(target))
        {
            Target = target;
            _ = RunAsync();
        }
    }

    public async Task RunAsync()
    {
        if (IsRunning) return;
        var target = CheckTarget.Parse(Target);
        if (target == null)
        {
            Error = "Введите сайт или адрес: example.com, 1.2.3.4, example.com:8443 или udp://1.2.3.4:27015";
            return;
        }

        Error = "";
        HasVerdict = false;
        VpnNote = "";
        Hops.Clear();
        OnPropertyChanged(nameof(HasHops));
        Steps.Clear();
        foreach (var (id, title) in new[]
                 {
                     ("dns", "DNS"), ("dnsint", "Проверка подмены DNS"), ("tcp", "Подключение"), ("tls", "Защищённое соединение"),
                     ("quic", "HTTP/3 (QUIC, UDP 443)"), ("ping", "Задержка"), ("trace", "Трасса"), ("mtu", "Размер пакетов (MTU)"),
                 })
            Steps.Add(new StepView(id, title));

        _cts = new CancellationTokenSource();
        IsRunning = true;
        var ui = Application.Current.Dispatcher;
        try
        {
            _report = await Checker.RunAsync(target, _state.Probe, _state.Asn, step => ui.Invoke(() =>
                {
                    var view = Steps.FirstOrDefault(s => s.Id == step.Id);
                    if (view == null)
                    {
                        // Steps that appear only when needed (the SNI test) go right after TLS.
                        view = new StepView(step.Id, step.Title);
                        var tls = Steps.ToList().FindIndex(s => s.Id == "tls");
                        Steps.Insert(tls >= 0 ? tls + 1 : Steps.Count, view);
                    }
                    view.Status = step.Status;
                    view.Text = step.Text;
                }),
                _cts.Token,
                hops => ui.Invoke(() => ShowHops(hops)));

            ShowHops(_report.Hops);

            if (_report.Verdict is { } v)
            {
                Level = v.Level;
                VerdictTitle = v.Title;
                VerdictText = v.Text;
                HasVerdict = true;
            }
            VpnNote = _report.Tunnel is { } tunnel
                ? $"Проверка идёт через VPN: {tunnel}. Задержка, трасса и доступность описывают VPN, а не путь через вашего провайдера."
                : "";
        }
        catch (OperationCanceledException)
        {
            Error = "Проверка остановлена";
        }
        catch (Exception e)
        {
            Error = "Проверка не удалась: " + e.Message;
        }
        finally
        {
            IsRunning = false;
        }
    }
}

internal static class CommandManagerHelper
{
    public static void Refresh() => System.Windows.Input.CommandManager.InvalidateRequerySuggested();
}
