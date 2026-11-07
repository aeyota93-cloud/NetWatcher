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
        nav.Filter = o => o is NavItem item && (item.IsAll || item.Matches(_vm.ProgramSearch));
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName != nameof(MainViewModel.ProgramSearch)) return;
            nav.Refresh();
            // A filtered-out program loses its highlight in the list; it comes back with the program.
            NavList.SelectedItem = _vm.SelectedNav;
        };

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
        ApplyProgramList();
        BlocksView.Init(state);
        SettingsView.Init(state, _vm.CheckUpdatesNowAsync);
        SettingsView.Saved += () =>
        {
            _vm.SettingsChanged();
            _vm.UpdateStatus();
            _vm.ShowPage(AppPage.Main);
        };
        SettingsView.Cancelled += () => _vm.ShowPage(AppPage.Main);
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.IsProgramListVisible)) ApplyProgramList();
        };

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

    /// <summary>The list gives its place to the table in "Все соединения" and when the user hides it.</summary>
    private void ApplyProgramList()
    {
        var show = _vm.IsProgramListVisible;
        ProgramPanel.Visibility = ProgramSplitter.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        NavColumn.MinWidth = show ? 200 : 0;
        NavColumn.Width = new GridLength(show ? Math.Clamp(_state.Settings.NavWidth, 200, NavColumn.MaxWidth) : 0);
    }

    private void OnProgramActions(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { ContextMenu: { } menu } button) return;
        menu.PlacementTarget = button;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.IsOpen = true;
    }

    private void OnNarrowList(object sender, RoutedEventArgs e) => StepList(-30);

    private void OnWidenList(object sender, RoutedEventArgs e) => StepList(30);

    /// <summary>The list width without dragging: these buttons work from the keyboard.</summary>
    private void StepList(double by)
    {
        NavColumn.Width = new GridLength(Math.Clamp(NavColumn.ActualWidth + by, NavColumn.MinWidth, NavColumn.MaxWidth));
        _state.Settings.NavWidth = NavColumn.Width.Value;
        _state.SaveSettings();
    }

    private void OnPanelsResized(object sender, System.Windows.Controls.Primitives.DragCompletedEventArgs e)
    {
        if (_vm.IsProgramListVisible) _state.Settings.NavWidth = Math.Round(NavColumn.ActualWidth);
        _state.Settings.DetailsHeight = Math.Round(DetailsRow.ActualHeight);
        _state.SaveSettings();
    }

    private void OnKey(object sender, KeyEventArgs e)
    {
        var ctrl = Keyboard.Modifiers.HasFlag(ModifierKeys.Control);
        var shift = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift);

        if (ctrl && e.Key == Key.F)
        {
            // A program's "Связь" has no search box: its text filter does that job there.
            var box = ServerFilterBox.IsVisible ? ServerFilterBox : SearchBox;
            box.Focus();
            box.SelectAll();
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
        else if (ctrl && e.Key == Key.C && ServerList.IsKeyboardFocusWithin && ServerList.SelectedItem is LinkServerView server
                 && Keyboard.FocusedElement is not TextBox { SelectionLength: > 0 })
        {
            // As in the table: Ctrl+C — the line (domain, IP:port, protocol), Ctrl+Shift+C — only the IP.
            if (shift) _vm.CopyServerIpCommand?.Execute(server);
            else _vm.Copy(string.Join('\t', new[] { server.Name, server.Address, server.Proto }.Where(x => x != "")), "строку");
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

    // The server rows are rebuilt every refresh; rebuilding the row under an open menu would close it.
    private void OnServerMenuOpening(object sender, ContextMenuEventArgs e) => _vm.HoldServerList = true;

    private void OnServerMenuClosing(object sender, ContextMenuEventArgs e) => _vm.HoldServerList = false;

    private static TextBox? FindTextBox(DependencyObject source) => FindParent<TextBox>(source);

    private static T? FindParent<T>(DependencyObject source) where T : DependencyObject
    {
        for (DependencyObject? current = source; current != null; current = System.Windows.Media.VisualTreeHelper.GetParent(current))
            if (current is T found) return found;
        return null;
    }

    private void OnTableSelectionChanged(object sender, SelectionChangedEventArgs e) => _vm.SelectedCount = Grid.SelectedItems.Count;

    private void OnClearSelection(object sender, RoutedEventArgs e) => Grid.UnselectAll();

    // «⋯» moves the shared row menu under itself; a right-click must open it at the mouse again.
    private void OnTableMenuOpening(object sender, ContextMenuEventArgs e)
    {
        var menu = Grid.ContextMenu;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint;
        menu.HorizontalOffset = 0;
        menu.VerticalOffset = 0;
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
        _vm.SelectedLinkServer = null;
        _vm.SelectedItem = null;
    }

    private void OnScrimClick(object sender, MouseButtonEventArgs e) => _vm.Export.IsOpen = false;

    private void FocusCheckBox() =>
        Dispatcher.BeginInvoke(() =>
        {
            if (!_vm.Diagnostics.IsOpen || _vm.Diagnostics.IsRunning) return;
            CheckBox.Focus();
            CheckBox.SelectAll();
        }, System.Windows.Threading.DispatcherPriority.Input);

    private void OnSettings(object sender, RoutedEventArgs e) => _vm.ShowPage(AppPage.Settings);
}
