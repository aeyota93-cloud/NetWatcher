using System.Diagnostics;
using System.Windows;
using NetWatcher.App.Native;
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
        AlertProgram.IsChecked = state.Settings.AlertNewProgram;
        AlertCountry.IsChecked = state.Settings.AlertNewCountry;
        AlertNetwork.IsChecked = state.Settings.AlertNewNetwork;
        AlertSkipBrowsers.IsChecked = state.Settings.AlertSkipBrowsers;
        (state.Settings.Theme switch
        {
            "Light" => ThemeLight,
            "Dark" => ThemeDark,
            _ => ThemeSystem,
        }).IsChecked = true;
        AsnInfo.Text = state.AsnStatus;
        AsnButton.Content = state.Asn.Count > 0 ? "Обновить базу" : "Скачать базу";
        GeoInfo.Text = state.GeoStatus;
        CatalogInfo.Text = state.CatalogStatus;
        GeoButton.Content = state.Geo.Count > 0 ? "Обновить базу" : "Скачать базу";
        ShowDbInfo();
        VersionText.Text = "NetWatcher " + AppInfo.Version;
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
        s.AlertNewProgram = AlertProgram.IsChecked == true;
        s.AlertNewCountry = AlertCountry.IsChecked == true;
        s.AlertNewNetwork = AlertNetwork.IsChecked == true;
        s.AlertSkipBrowsers = AlertSkipBrowsers.IsChecked == true;
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
        _state.Alerts.Reset();
        ShowDbInfo();
    }

    private void OnImportAsn(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Файл базы владельцев IP",
            Filter = "База iptoasn (ip2asn-combined.tsv.gz)|*.gz;*.tsv|Все файлы (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            _state.Asn = AsnUpdater.Import(dialog.FileName, AppPaths.AsnDatabase);
            _state.SetAsnLoaded();
            AsnInfo.Text = _state.AsnStatus;
            AsnButton.Content = "Обновить базу";
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            AsnInfo.Text = "Файл не подошёл: " + ex.Message;
        }
    }

    private void OnLink(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }

    private void OnImportGeo(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Файл базы стран DB-IP",
            Filter = "DB-IP IP to Country Lite (*.csv.gz, *.csv)|*.gz;*.csv|Все файлы (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            _state.Geo = Core.Geo.GeoUpdater.Import(dialog.FileName, AppPaths.GeoDatabase);
            _state.SetGeoLoaded();
            GeoInfo.Text = _state.GeoStatus;
            GeoButton.Content = "Обновить базу";
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            GeoInfo.Text = "Файл не подошёл: " + ex.Message;
        }
    }

    private async void OnDownloadCatalog(object sender, RoutedEventArgs e)
    {
        CatalogButton.IsEnabled = false;
        CatalogInfo.Text = "Скачивается…";
        try
        {
            _state.Catalog = await Core.Catalog.CatalogUpdater.DownloadAsync(AppPaths.Http, AppPaths.Catalog);
            _state.SetCatalogLoaded();
            CatalogInfo.Text = _state.CatalogStatus;
        }
        catch (Exception ex)
        {
            CatalogInfo.Text = "Не удалось скачать: " + ex.Message;
        }
        finally
        {
            CatalogButton.IsEnabled = true;
        }
    }

    private async void OnDownloadGeo(object sender, RoutedEventArgs e)
    {
        GeoButton.IsEnabled = false;
        GeoInfo.Text = "Скачивается…";
        try
        {
            _state.Geo = await Core.Geo.GeoUpdater.DownloadAsync(AppPaths.Http, AppPaths.GeoDatabase);
            _state.SetGeoLoaded();
            GeoInfo.Text = _state.GeoStatus;
            GeoButton.Content = "Обновить базу";
        }
        catch (Exception ex)
        {
            GeoInfo.Text = "Не удалось скачать: " + ex.Message;
        }
        finally
        {
            GeoButton.IsEnabled = true;
        }
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
