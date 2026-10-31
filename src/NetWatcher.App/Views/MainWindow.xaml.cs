using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using NetWatcher.App.ViewModels;

namespace NetWatcher.App.Views;

internal partial class MainWindow : Window
{
    private readonly AppState _state;
    private readonly MainViewModel _vm;

    public MainWindow(AppState state)
    {
        InitializeComponent();
        _state = state;
        _vm = new MainViewModel(state);
        DataContext = _vm;

        // Default order: by program, then by address.
        var view = CollectionViewSource.GetDefaultView(_vm.Rows);
        view.SortDescriptions.Add(new SortDescription(nameof(RowView.Process), ListSortDirection.Ascending));
        view.SortDescriptions.Add(new SortDescription(nameof(RowView.IpSort), ListSortDirection.Ascending));

        Loaded += (_, _) =>
        {
            _vm.Start();
            SearchBox.Focus();
        };
        PreviewKeyDown += OnKey;
    }

    private void OnKey(object sender, KeyEventArgs e)
    {
        var ctrl = Keyboard.Modifiers.HasFlag(ModifierKeys.Control);
        var shift = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift);

        if (ctrl && e.Key == Key.F)
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && SearchBox.IsKeyboardFocusWithin)
        {
            _vm.SearchText = "";
            e.Handled = true;
        }
        else if (ctrl && e.Key == Key.C && Grid.IsKeyboardFocusWithin)
        {
            // Ctrl+C — whole rows, Ctrl+Shift+C — only the addresses.
            var cmd = shift ? _vm.CopyIpCommand : _vm.CopyRowCommand;
            cmd.Execute(Grid.SelectedItems);
            e.Handled = true;
        }
    }

    private void OnRowDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (Grid.SelectedItem is RowView row) _vm.Copy(row.Ip);
    }

    private void OnSettings(object sender, RoutedEventArgs e)
    {
        var window = new SettingsWindow(_state) { Owner = this };
        if (window.ShowDialog() == true) _vm.SettingsChanged();
        _vm.UpdateStatus();
    }
}
