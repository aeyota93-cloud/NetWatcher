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

public sealed record HopView(int Ttl, string Address, string Time, string Loss, string Owner, bool Silent, bool Reached);

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

    public ObservableCollection<StepView> Steps { get; } = [];
    public ObservableCollection<HopView> Hops { get; } = [];
    public bool HasHops => Hops.Count > 0;

    public RelayCommand RunCommand { get; }
    public RelayCommand StopCommand { get; }
    public RelayCommand CopyCommand { get; }
    public RelayCommand CloseCommand { get; }

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
            Error = "Введите сайт или адрес: example.com, 1.2.3.4 или example.com:8443";
            return;
        }

        Error = "";
        HasVerdict = false;
        Hops.Clear();
        OnPropertyChanged(nameof(HasHops));
        Steps.Clear();
        foreach (var (id, title) in new[] { ("dns", "DNS"), ("tcp", "Подключение"), ("tls", "Защищённое соединение"), ("ping", "Задержка"), ("trace", "Трасса") })
            Steps.Add(new StepView(id, title));

        _cts = new CancellationTokenSource();
        IsRunning = true;
        var ui = Application.Current.Dispatcher;
        try
        {
            _report = await Checker.RunAsync(target, _state.Probe, _state.Asn, step => ui.Invoke(() =>
            {
                var view = Steps.FirstOrDefault(s => s.Id == step.Id);
                if (view == null) return;
                view.Status = step.Status;
                view.Text = step.Text;
            }), _cts.Token);

            foreach (var h in _report.Hops)
                Hops.Add(new HopView(
                    h.Ttl,
                    h.Address?.ToString() ?? "*",
                    h.AvgMs is { } ms ? $"{ms:0} мс" : "",
                    h.Answered && h.LossPercent > 0 ? $"{h.LossPercent:0}%" : "",
                    h.OwnerText,
                    !h.Answered,
                    h.Reached));
            OnPropertyChanged(nameof(HasHops));

            if (_report.Verdict is { } v)
            {
                Level = v.Level;
                VerdictTitle = v.Title;
                VerdictText = v.Text;
                HasVerdict = true;
            }
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
