using System.Windows;
using NetWatcher.App.Monitoring;
using NetWatcher.Core;
using NetWatcher.Core.Blocking;

namespace NetWatcher.App.Views;

/// <summary>The list of blocks made from NetWatcher, with "Снять" for each and for all.</summary>
internal partial class BlocksPage : System.Windows.Controls.UserControl
{
    public sealed record Line(BlockRule Rule, string Title, string Detail, string Problem);

    private AppState _state = null!;

    public BlocksPage()
    {
        InitializeComponent();
        IsVisibleChanged += (_, e) =>
        {
            if (e.NewValue is true && _state != null) Fill();
        };
    }

    public void Init(AppState state)
    {
        _state = state;
        // A block made from a row while this page is on screen must show up at once.
        state.Blocks.Changed += () => Dispatcher.BeginInvoke(() =>
        {
            if (IsVisible) Fill();
        });
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
        Status.Text = "";
        if (BlockService.FirewallOn() == false && rules.Count > 0)
            Status.Text = "Брандмауэр Windows выключен — правила сейчас не действуют.";
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: BlockRule rule }) return;
        var (ok, message) = _state.Blocks.Remove(rule);
        Fill();
        Status.Text = ok ? $"Снято: {rule.Describe()}" : message;
    }

    private void OnRemoveAll(object sender, RoutedEventArgs e)
    {
        var rules = _state.Blocks.Rules;
        if (MessageBox.Show(Window.GetWindow(this)!, $"Снять все блокировки ({rules.Count})?", "Блокировки", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        var failed = rules.Select(r => _state.Blocks.Remove(r)).Count(r => !r.Ok);
        Fill();
        Status.Text = failed == 0 ? "Все блокировки сняты." : $"Не удалось снять: {failed}.";
    }
}
