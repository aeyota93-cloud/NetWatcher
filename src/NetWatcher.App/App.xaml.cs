using System.Windows;
using System.Windows.Threading;
using NetWatcher.App.Views;

namespace NetWatcher.App;

public partial class App : Application
{
    private Mutex? _single;
    private AppState? _state;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Two copies would fight over the same system event sessions.
        _single = new Mutex(true, @"Global\NetWatcher-SingleInstance", out var first);
        if (!first && e.Args.Contains("--after-update", StringComparer.Ordinal))
        {
            var deadline = System.Diagnostics.Stopwatch.StartNew();
            while (deadline.Elapsed < TimeSpan.FromSeconds(15))
            {
                try { first = _single.WaitOne(0); }
                catch (AbandonedMutexException) { first = true; }
                if (first) break;
                // Resume on the dispatcher: mutex ownership belongs to this thread.
                await Task.Delay(100);
            }
        }
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
        _ = DeleteOldExecutableAsync();
    }

    private static async Task DeleteOldExecutableAsync()
    {
        await Task.Delay(TimeSpan.FromSeconds(30));
        await Task.Run(() =>
        {
            try
            {
                if (Environment.ProcessPath is { } path)
                    File.Delete(path + ".old");
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        });
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
