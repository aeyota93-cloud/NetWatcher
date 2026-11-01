using System.Net.Http;
using System.Windows;
using NetWatcher.App.Native;
using NetWatcher.App.Update;
using NetWatcher.Core.Update;

namespace NetWatcher.App.ViewModels;

/// <summary>New versions from the GitHub releases: a quiet check, then download and install on request.</summary>
internal sealed partial class MainViewModel
{
    private static readonly TimeSpan UpdateCheckEvery = TimeSpan.FromHours(24);

    private UpdateRelease? _release;
    private CancellationTokenSource? _updateCts;
    private bool _updateAvailable, _updateBusy;
    private string _updateText = "", _updateMessage = "";

    /// <summary>A newer version is published: the banner over the table.</summary>
    public bool UpdateAvailable { get => _updateAvailable; private set => Set(ref _updateAvailable, value); }

    public bool UpdateBusy
    {
        get => _updateBusy;
        private set
        {
            if (Set(ref _updateBusy, value)) CommandManagerHelper.Refresh();
        }
    }

    /// <summary>"Доступна версия 0.8.0".</summary>
    public string UpdateText { get => _updateText; private set => Set(ref _updateText, value); }

    /// <summary>Progress or the reason it failed; also the answer to a manual check in the settings.</summary>
    public string UpdateMessage { get => _updateMessage; private set => Set(ref _updateMessage, value); }

    public RelayCommand? InstallUpdateCommand { get; private set; }
    public RelayCommand? CheckUpdatesCommand { get; private set; }
    public RelayCommand? DismissUpdateCommand { get; private set; }

    private void InitUpdates()
    {
        InstallUpdateCommand = new RelayCommand(_ => _ = InstallUpdateAsync(), _ => _release != null && !UpdateBusy);
        CheckUpdatesCommand = new RelayCommand(_ => _ = CheckUpdatesAsync(true), _ => !UpdateBusy);
        DismissUpdateCommand = new RelayCommand(() => UpdateAvailable = false);
        // Created after the window bound to them (see StartLink): tell the buttons.
        OnPropertyChanged(nameof(InstallUpdateCommand));
        OnPropertyChanged(nameof(CheckUpdatesCommand));
        OnPropertyChanged(nameof(DismissUpdateCommand));
        _ = UpdateLoopAsync();
    }

    /// <summary>A quiet check a little after the start and then once a day, unless turned off in the settings.</summary>
    private async Task UpdateLoopAsync()
    {
        await Task.Delay(TimeSpan.FromSeconds(20));
        while (true)
        {
            if (_state.Settings.CheckUpdates) await CheckUpdatesAsync(false);
            await Task.Delay(UpdateCheckEvery);
        }
    }

    /// <summary>The "Проверить обновления" button in the settings: the answer in words.</summary>
    public async Task<string> CheckUpdatesNowAsync()
    {
        await CheckUpdatesAsync(true);
        return UpdateMessage;
    }

    private async Task CheckUpdatesAsync(bool manual)
    {
        if (UpdateBusy) return;
        if (manual) UpdateMessage = "Проверка…";
        try
        {
            var result = await new UpdateClient(AppPaths.Http).CheckAsync(AppInfo.Version);
            _release = result.IsUpdateAvailable ? result.Release : null;
            UpdateText = _release != null ? $"Доступна версия {_release.Version}" : "";
            UpdateAvailable = _release != null;
            if (manual) UpdateMessage = _release != null ? UpdateText : $"Установлена последняя версия {AppInfo.Version}";
        }
        catch (Exception e) when (e is UpdateException or HttpRequestException or OperationCanceledException)
        {
            // A quiet check fails quietly: no internet is not worth a message.
            if (manual) UpdateMessage = "Не удалось проверить: " + (e is OperationCanceledException ? "нет ответа" : e.Message);
        }
        CommandManagerHelper.Refresh();
    }

    private async Task InstallUpdateAsync()
    {
        if (_release is not { } release || UpdateBusy) return;
        var ok = MessageBox.Show(
            $"Скачать и установить NetWatcher {release.Version}? Программа перезапустится. Журнал, настройки и блокировки сохранятся.",
            "Обновление", MessageBoxButton.OKCancel, MessageBoxImage.Question);
        if (ok != MessageBoxResult.OK) return;

        UpdateBusy = true;
        _updateCts = new CancellationTokenSource();
        PreparedUpdate? package = null;
        try
        {
            UpdateMessage = "Скачивание…";
            var progress = new Progress<UpdateProgress>(p =>
                UpdateMessage = p.TotalBytes > 0 ? $"Скачивание {100 * p.BytesReceived / p.TotalBytes}%" : "Скачивание…");
            package = await new UpdateClient(AppPaths.Http).DownloadAsync(release, progress, _updateCts.Token);
            UpdateMessage = "Установка…";
            // The installer owns the package from here on, success or failure.
            var installing = package;
            package = null;
            await UpdateInstaller.InstallAndRestartAsync(installing, () => Application.Current.Shutdown(), _updateCts.Token);
        }
        catch (OperationCanceledException)
        {
            UpdateMessage = "Обновление отменено";
        }
        catch (Exception e) when (e is UpdateException or HttpRequestException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            UpdateMessage = "Не удалось обновить: " + e.Message;
        }
        finally
        {
            package?.Dispose();
            UpdateBusy = false;
        }
    }
}
