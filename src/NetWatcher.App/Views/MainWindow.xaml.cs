using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using NetWatcher.App.ViewModels;

namespace NetWatcher.App.Views;

internal partial class MainWindow : Window
{
    private readonly AppState _state;
    private readonly MainViewModel _vm;
    private Native.TrayIcon? _tray;

    public MainWindow(AppState state)
    {
        InitializeComponent();
        _state = state;
        _vm = new MainViewModel(state);
        DataContext = _vm;

        // Programs list: "Приложения" and "Службы Windows" sections.
        var nav = CollectionViewSource.GetDefaultView(_vm.Nav);
        nav.GroupDescriptions.Add(new PropertyGroupDescription(nameof(NavItem.Section)));

        // The domain tree has its own order; drop any column sort when going back to it.
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName != nameof(MainViewModel.IsDomainsTab) || !_vm.IsDomainsTab) return;
            CollectionViewSource.GetDefaultView(_vm.Table).SortDescriptions.Clear();
            foreach (var c in Grid.Columns) c.SortDirection = null;
        };

        // Panel sizes the user dragged last time; clamped in case the screen got smaller.
        NavColumn.Width = new GridLength(Math.Clamp(state.Settings.NavWidth, NavColumn.MinWidth, NavColumn.MaxWidth));
        DetailsRow.Height = new GridLength(Math.Clamp(state.Settings.DetailsHeight, DetailsRow.MinHeight, 600));

        Loaded += (_, _) =>
        {
            _vm.Start();
            SearchBox.Focus();
            // Notification-area icon for "связь пропала / восстановилась" notifications.
            _tray = new Native.TrayIcon(this);
            _tray.Attach();
            state.LinkService.TitleOf = key => Dispatcher.Invoke(() => _vm.TitleFor(key));
            state.LinkService.Notify = (title, text, warning) => Dispatcher.BeginInvoke(() => _tray.Show(title, text, warning));
            state.Alerts.TitleOf = key => Dispatcher.Invoke(() => _vm.TitleFor(key));
            state.Alerts.Notify = (title, text, warning) => Dispatcher.BeginInvoke(() => _tray.Show(title, text, warning));
        };
        Closed += (_, _) => _tray?.Dispose();
        PreviewKeyDown += OnKey;
        _vm.Diagnostics.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(DiagnosticsViewModel.IsOpen) && _vm.Diagnostics.IsOpen) FocusCheckBox();
        };
    }

    private void OnPanelsResized(object sender, System.Windows.Controls.Primitives.DragCompletedEventArgs e)
    {
        _state.Settings.NavWidth = Math.Round(NavColumn.ActualWidth);
        _state.Settings.DetailsHeight = Math.Round(DetailsRow.ActualHeight);
        _state.SaveSettings();
    }

    private void OnKey(object sender, KeyEventArgs e)
    {
        var ctrl = Keyboard.Modifiers.HasFlag(ModifierKeys.Control);
        var shift = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift);

        if (ctrl && e.Key == Key.F)
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
        }
        else if (e.Key == Key.Escape)
        {
            _vm.Escape();
        }
        else if (e.Key == Key.F5)
        {
            _vm.RefreshCommand.Execute(null);
        }
        else if (ctrl && e.Key == Key.D)
        {
            // The selected row, or an empty form to type a site in.
            if (ServerList.IsKeyboardFocusWithin && ServerList.SelectedItem is LinkServerView server) _vm.OpenCheckCommand.Execute(server);
            else if (Grid.SelectedItems.Count > 0) _vm.OpenCheckCommand.Execute(Grid.SelectedItems);
            else _vm.OpenEmptyCheckCommand.Execute(null);
            FocusCheckBox();
        }
        else if (ctrl && e.Key == Key.E)
        {
            _vm.OpenExportCommand.Execute(null);
        }
        else if (ctrl && e.Key == Key.Enter && _vm.Export.IsOpen)
        {
            _vm.Export.CopyCommand.Execute(null);
        }
        else if (ctrl && e.Key == Key.C && Grid.IsKeyboardFocusWithin && Keyboard.FocusedElement is not TextBox { SelectionLength: > 0 })
        {
            // Ctrl+C — whole rows, Ctrl+Shift+C — only the addresses.
            (shift ? _vm.CopyIpCommand : _vm.CopyRowCommand).Execute(Grid.SelectedItems);
        }
        else if (e.Key is Key.Space or Key.Right or Key.Left && Grid.IsKeyboardFocusWithin && Grid.SelectedItem is TableItem { IsGroup: true } g)
        {
            // Keyboard users open and close domain groups like a tree.
            if (e.Key == Key.Space || (e.Key == Key.Right) != g.IsExpanded) _vm.ToggleCommand.Execute(g);
        }
        else
        {
            return;
        }
        e.Handled = true;
    }

    private void OnRowDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject d && ItemsControl.ContainerFromElement(Grid, d) is not DataGridRow) return;
        if (Grid.SelectedItem is not TableItem item) return;
        if (item.IsGroup) _vm.ToggleCommand.Execute(item);
        else _vm.CopyIpCommand.Execute(item);
    }

    private void OnTableMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject source ||
            ItemsControl.ContainerFromElement(Grid, source) is not DataGridRow row) return;
        if (e.ChangedButton == MouseButton.Right)
        {
            if (!row.IsSelected) Grid.SelectedItem = row.Item;
            return;
        }
        if (e.ChangedButton != MouseButton.Left || FindTextBox(source) == null) return;
        // Select before TextBox handles the click; leave it free to capture a drag and select text.
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) && Grid.SelectedItem != null)
        {
            var anchor = Grid.Items.IndexOf(Grid.SelectedItem);
            var target = Grid.Items.IndexOf(row.Item);
            if (!Keyboard.Modifiers.HasFlag(ModifierKeys.Control)) Grid.SelectedItems.Clear();
            for (var i = Math.Min(anchor, target); i <= Math.Max(anchor, target); i++)
                if (!Grid.SelectedItems.Contains(Grid.Items[i])) Grid.SelectedItems.Add(Grid.Items[i]);
        }
        else if (Keyboard.Modifiers.HasFlag(ModifierKeys.Control)) row.IsSelected = !row.IsSelected;
        else Grid.SelectedItem = row.Item;
    }

    private void OnServerMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton is not (MouseButton.Left or MouseButton.Right) ||
            e.OriginalSource is not DependencyObject source ||
            ItemsControl.ContainerFromElement(ServerList, source) is not ListBoxItem row) return;
        row.IsSelected = true;
    }

    private static TextBox? FindTextBox(DependencyObject source)
    {
        for (DependencyObject? current = source; current != null; current = System.Windows.Media.VisualTreeHelper.GetParent(current))
            if (current is TextBox text) return text;
        return null;
    }

    private void OnRowMore(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: TableItem item } button) return;
        if (!Grid.SelectedItems.Contains(item))
        {
            Grid.SelectedItems.Clear();
            Grid.SelectedItem = item;
        }
        var menu = Grid.ContextMenu;
        menu.PlacementTarget = Grid;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.HorizontalOffset = button.TranslatePoint(new Point(0, 0), Grid).X;
        menu.VerticalOffset = button.TranslatePoint(new Point(0, button.ActualHeight), Grid).Y - Grid.ActualHeight;
        menu.IsOpen = true;
    }

    private void OnCloseDetails(object sender, RoutedEventArgs e)
    {
        Grid.SelectedItems.Clear();
        _vm.SelectedItem = null;
    }

    private void OnScrimClick(object sender, MouseButtonEventArgs e) => _vm.Export.IsOpen = false;

    private void OnCheckScrimClick(object sender, MouseButtonEventArgs e) => _vm.Diagnostics.CloseCommand.Execute(null);

    private void FocusCheckBox() =>
        Dispatcher.BeginInvoke(() =>
        {
            if (!_vm.Diagnostics.IsOpen || _vm.Diagnostics.IsRunning) return;
            CheckBox.Focus();
            CheckBox.SelectAll();
        }, System.Windows.Threading.DispatcherPriority.Input);

    /// <summary>The theme button opens its menu on a normal click, under the button.</summary>
    private void OnSettings(object sender, RoutedEventArgs e)
    {
        var window = new SettingsWindow(_state, _vm.CheckUpdatesNowAsync) { Owner = this };
        if (window.ShowDialog() == true) _vm.SettingsChanged();
        _vm.UpdateStatus();
    }
}
