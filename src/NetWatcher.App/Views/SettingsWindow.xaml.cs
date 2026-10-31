using System.Diagnostics;
using System.Windows;
using NetWatcher.Core.Asn;

namespace NetWatcher.App.Views;

internal partial class SettingsWindow : Window
{
    private readonly AppState _state;

    public SettingsWindow(AppState state)
    {
        InitializeComponent();
        _state = state;
        Retention.Text = state.Settings.RetentionDays.ToString();
        Poll.Text = state.Settings.PollSeconds.ToString();
        HideLoopback.IsChecked = state.Settings.HideLoopback;
        (state.Settings.Theme switch
        {
            "Light" => ThemeLight,
            "Dark" => ThemeDark,
            _ => ThemeSystem,
        }).IsChecked = true;
        AsnInfo.Text = state.AsnStatus;
        AsnButton.Content = state.Asn.Count > 0 ? "Обновить базу" : "Скачать базу";
        ShowDbInfo();
    }

    private void ShowDbInfo() =>
        DbInfo.Text = $"Журнал занимает {_state.Store.SizeBytes / 1024.0 / 1024.0:0.0} МБ";

    private void OnSave(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(Retention.Text.Trim(), out var days) || days is < 1 or > 365)
        {
            MessageBox.Show(this, "Срок хранения — целое число дней от 1 до 365.", "Настройки", MessageBoxButton.OK, MessageBoxImage.Warning);
            Retention.Focus();
            return;
        }
        if (!int.TryParse(Poll.Text.Trim(), out var poll) || poll is < 1 or > 60)
        {
            MessageBox.Show(this, "Интервал опроса — целое число секунд от 1 до 60.", "Настройки", MessageBoxButton.OK, MessageBoxImage.Warning);
            Poll.Focus();
            return;
        }

        var s = _state.Settings;
        var shorter = days < s.RetentionDays;
        s.RetentionDays = days;
        s.PollSeconds = poll;
        s.HideLoopback = HideLoopback.IsChecked == true;
        s.Theme = ThemeLight.IsChecked == true ? "Light" : ThemeDark.IsChecked == true ? "Dark" : "System";
        _state.SaveSettings();
        ThemeService.Apply(s.Theme);
        if (shorter) _state.Collector.PurgeSoon();
        DialogResult = true;
    }

    private void OnOpenFolder(object sender, RoutedEventArgs e) =>
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{AppPaths.DataDir}\"") { UseShellExecute = true });

    private void OnClear(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Удалить всю историю соединений и DNS? Это нельзя отменить.", "Очистить историю",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        _state.Store.Clear();
        ShowDbInfo();
    }

    private async void OnDownloadAsn(object sender, RoutedEventArgs e)
    {
        AsnButton.IsEnabled = false;
        AsnInfo.Text = "Скачивается…";
        try
        {
            _state.Asn = await AsnUpdater.DownloadAsync(AppPaths.Http, AppPaths.AsnDatabase);
            _state.SetAsnLoaded();
            AsnInfo.Text = _state.AsnStatus;
            AsnButton.Content = "Обновить базу";
        }
        catch (Exception ex)
        {
            AsnInfo.Text = "Не удалось скачать: " + ex.Message;
        }
        finally
        {
            AsnButton.IsEnabled = true;
        }
    }
}
