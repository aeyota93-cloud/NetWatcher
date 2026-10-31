using System.Windows;
using Microsoft.Win32;

namespace NetWatcher.App;

/// <summary>
/// Light and dark themes. Our own colours live in Themes/Light.xaml and Themes/Dark.xaml;
/// standard controls (scroll bars, menus, lists) get the built-in Windows 11 (Fluent) look.
/// </summary>
internal static class ThemeService
{
    private static string _mode = "System";

    public static bool IsDark { get; private set; }

    public static event Action? Changed;

    public static void Init(string mode)
    {
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (e.Category == UserPreferenceCategory.General && _mode == "System")
                Application.Current?.Dispatcher.Invoke(() => Apply(_mode));
        };
        Apply(mode);
    }

    public static void Apply(string mode)
    {
        _mode = mode;
        var dark = mode switch
        {
            "Dark" => true,
            "Light" => false,
            _ => SystemIsDark(),
        };
        IsDark = dark;
        var app = Application.Current;
        if (app == null) return;

        try
        {
#pragma warning disable WPF0001 // Fluent theme is marked experimental in WPF.
            app.ThemeMode = dark ? ThemeMode.Dark : ThemeMode.Light;
#pragma warning restore WPF0001
        }
        catch (Exception e) when (e is InvalidOperationException or NotSupportedException)
        {
            // Older systems: keep classic controls, our own colours still switch.
        }

        var dicts = app.Resources.MergedDictionaries;
        var old = dicts.FirstOrDefault(d => d.Source?.OriginalString is { } s && (s.EndsWith("Light.xaml") || s.EndsWith("Dark.xaml")));
        var fresh = new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/NetWatcher;component/Themes/{(dark ? "Dark" : "Light")}.xaml"),
        };
        if (old != null) dicts[dicts.IndexOf(old)] = fresh;
        else dicts.Insert(0, fresh);
        Changed?.Invoke();
    }

    private static bool SystemIsDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }
}
