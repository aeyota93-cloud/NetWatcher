using System.Collections.Concurrent;
using System.Diagnostics;
using System.Windows.Media;

namespace NetWatcher.App.Native;

/// <summary>Human names and placeholder colours for programs.</summary>
internal static class AppInfo
{
    private static readonly ConcurrentDictionary<string, string> Names = new(StringComparer.OrdinalIgnoreCase);

    // Calm, readable colours for letter avatars when a program has no icon.
    private static readonly Brush[] Palette =
    [
        Freeze("#0F6CBD"), Freeze("#C239B3"), Freeze("#CA5010"), Freeze("#498205"), Freeze("#8764B8"),
        Freeze("#038387"), Freeze("#986F0B"), Freeze("#4F6BED"), Freeze("#E3008C"), Freeze("#6B7280"),
    ];

    /// <summary>"Google Chrome" for chrome.exe, read from the file description.</summary>
    public static string FriendlyName(string process, string path)
    {
        var fallback = process.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? process[..^4] : process;
        if (string.IsNullOrEmpty(path)) return fallback;
        return Names.GetOrAdd(path, p =>
        {
            try
            {
                var d = FileVersionInfo.GetVersionInfo(p).FileDescription?.Trim();
                return string.IsNullOrEmpty(d) || d.Length > 48 ? fallback : d;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
            {
                return fallback;
            }
        });
    }

    public static Brush ColorFor(string key)
    {
        var h = 0;
        foreach (var c in key.ToLowerInvariant()) h = h * 31 + c;
        return Palette[(h & 0x7FFFFFFF) % Palette.Length];
    }

    public static string LetterFor(string title) =>
        title.FirstOrDefault(char.IsLetterOrDigit) is var c and not '\0' ? char.ToUpperInvariant(c).ToString() : "?";

    private static Brush Freeze(string hex)
    {
        var b = (Brush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
