using System.Windows;
using NetWatcher.App.Monitoring;
using NetWatcher.Core;
using NetWatcher.Core.Blocking;

namespace NetWatcher.App.Views;

/// <summary>The list of blocks made from NetWatcher, with "Снять" for each and for all.</summary>
internal partial class BlocksWindow : Window
{
    public sealed record Line(BlockRule Rule, string Title, string Detail, string Problem);

    private readonly AppState _state;

    public BlocksWindow(AppState state)
    {
        InitializeComponent();
        _state = state;
        Fill();
    }

    private void Fill()
    {
        var rules = _state.Blocks.Rules.OrderByDescending(r => r.Created).ToList();
        List.ItemsSource = rules.Select(r => new Line(
            r,
            r.Describe(),
            $"с {r.Created.LocalDateTime:dd.MM.yyyy HH:mm}"
            + (r.Kind == BlockKind.Domain ? $" · {TextFormat.Plural(r.Addresses.Count, "адрес", "адреса", "адресов")}" : "")
            + $" · правило «{r.RuleName}»",
            _state.Blocks.IsMissing(r) ? "Правило удалено в брандмауэре — блокировка не действует. «Снять» уберёт её из списка." : "")).ToList();
        Empty.Visibility = rules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        RemoveAllButton.IsEnabled = rules.Count > 0;
        if (BlockService.FirewallOn() == false && rules.Count > 0)
            Status.Text = "Брандмауэр Windows выключен — правила сейчас не действуют.";
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: BlockRule rule }) return;
        var (ok, message) = _state.Blocks.Remove(rule);
        Status.Text = ok ? $"Снято: {rule.Describe()}" : message;
        Fill();
    }

    private void OnRemoveAll(object sender, RoutedEventArgs e)
    {
        var rules = _state.Blocks.Rules;
        if (MessageBox.Show(this, $"Снять все блокировки ({rules.Count})?", "Блокировки", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        var failed = rules.Select(r => _state.Blocks.Remove(r)).Count(r => !r.Ok);
        Status.Text = failed == 0 ? "Все блокировки сняты." : $"Не удалось снять: {failed}.";
        Fill();
    }
}
