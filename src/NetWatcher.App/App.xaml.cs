using System.Windows;
using System.Windows.Threading;
using NetWatcher.App.Views;

namespace NetWatcher.App;

public partial class App : Application
{
    private Mutex? _single;
    private AppState? _state;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Two copies would fight over the same system event sessions.
        _single = new Mutex(true, @"Global\NetWatcher-SingleInstance", out var first);
        if (!first)
        {
            MessageBox.Show("NetWatcher уже запущен.", "NetWatcher", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandled;

        try
        {
            _state = new AppState();
            _state.Start();
        }
        catch (Exception ex)
        {
            MessageBox.Show("Не удалось запустить NetWatcher:\n\n" + ex.Message, "NetWatcher", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        ThemeService.Init(_state.Settings.Theme);
        MainWindow = new MainWindow(_state);
        MainWindow.Show();
    }

    private static void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show("Непредвиденная ошибка:\n\n" + e.Exception.Message, "NetWatcher", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _state?.Dispose();
        if (_single != null)
        {
            try
            {
                _single.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // Not owned: this copy was the second one.
            }
            _single.Dispose();
        }
        base.OnExit(e);
    }
}
