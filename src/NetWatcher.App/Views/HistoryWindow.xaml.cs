using System.Windows;
using System.Windows.Controls;
using NetWatcher.App.Native;
using NetWatcher.Core;

namespace NetWatcher.App.Views;

/// <summary>Traffic per application for the last day, week or 30 days, as Windows counts it.</summary>
internal partial class HistoryWindow : Window
{
    public sealed record Line(string Name, string Id, long Received, long Sent)
    {
        public long Total => Received + Sent;
        public string ReceivedText => TextFormat.Bytes(Received);
        public string SentText => TextFormat.Bytes(Sent);
        public string TotalText => TextFormat.Bytes(Total);
    }

    private const string AllNetworks = "Все сети";
    private WindowsUsage.Result? _result;
    private int _loading;

    public HistoryWindow()
    {
        InitializeComponent();
        Network.ItemsSource = new[] { AllNetworks };
        Network.SelectedIndex = 0;
        Loaded += (_, _) => _ = LoadAsync();
    }

    private void OnFilter(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded) _ = LoadAsync();
    }

    private void OnNetwork(object sender, SelectionChangedEventArgs e) => ShowUsage();

    private async Task LoadAsync()
    {
        var days = int.Parse((string)((ComboBoxItem)Period.SelectedItem).Tag);
        var ticket = ++_loading;
        Status.Text = "Запрашиваю у Windows…";
        var now = DateTimeOffset.Now;
        try
        {
            var result = await WindowsUsage.ReadAsync(now.AddDays(-days), now);
            if (ticket != _loading) return;
            _result = result;
            var selected = Network.SelectedItem as string ?? AllNetworks;
            Network.ItemsSource = new[] { AllNetworks }.Concat(result.Networks).ToList();
            Network.SelectedItem = result.Networks.Contains(selected) ? selected : AllNetworks;
            ShowUsage();
        }
        catch (Exception e)
        {
            if (ticket == _loading) Status.Text = "Не удалось получить историю: " + e.Message;
        }
    }

    private void ShowUsage()
    {
        if (_result == null) return;
        var network = Network.SelectedItem as string ?? AllNetworks;
        var lines = _result.Usage
            .Where(u => network == AllNetworks || u.Network == network)
            .GroupBy(u => u.Id == "" ? "\0system" : u.Id, StringComparer.OrdinalIgnoreCase)
            .Select(g => new Line(g.First().Name, g.Key, g.Sum(u => u.Received), g.Sum(u => u.Sent)))
            .Where(l => l.Total > 0)
            .OrderByDescending(l => l.Total)
            .ToList();
        Grid.ItemsSource = lines;
        Total.Text = lines.Count == 0 ? "" : $"Всего ↓ {TextFormat.Bytes(lines.Sum(l => l.Received))}  ↑ {TextFormat.Bytes(lines.Sum(l => l.Sent))} · {TextFormat.Plural(lines.Count, "приложение", "приложения", "приложений")}";
        Status.Text = _result.Errors.Count > 0
            ? string.Join("; ", _result.Errors.Distinct().Take(3)) + ". Эти же данные можно посмотреть в Параметрах: Сеть и Интернет → Использование данных."
            : lines.Count == 0 ? "Windows не вернула данных за этот период." : "";
    }

    private void OnCopy(object sender, RoutedEventArgs e)
    {
        if (Grid.ItemsSource is not IEnumerable<Line> lines) return;
        var chosen = Grid.SelectedItems.Count > 0 ? Grid.SelectedItems.Cast<Line>() : lines;
        Clipboard.SetText(string.Join(Environment.NewLine, chosen.Select(l => $"{l.Name}\t{l.Received}\t{l.Sent}\t{l.Total}")));
        Status.Text = "Скопировано (байты, через табуляцию — для таблицы).";
    }
}
