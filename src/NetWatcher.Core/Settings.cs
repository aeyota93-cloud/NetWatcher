using System.Text.Json;
using NetWatcher.Core.Net;

namespace NetWatcher.Core;

/// <summary>User settings, kept as JSON next to the log.</summary>
public sealed class Settings
{
    /// <summary>How many days of history to keep.</summary>
    public int RetentionDays { get; set; } = 7;

    /// <summary>How often to read the connection table, in seconds.</summary>
    public int PollSeconds { get; set; } = 2;

    /// <summary>Hide 127.0.0.1 and ::1: programs talking to themselves.</summary>
    public bool HideLoopback { get; set; } = true;

    public AddressFormat AddressFormat { get; set; } = AddressFormat.Cidr;

    /// <summary>"System", "Light" or "Dark".</summary>
    public string Theme { get; set; } = "System";

    /// <summary>Width of the programs list, as the user dragged it.</summary>
    public double NavWidth { get; set; } = 280;

    /// <summary>Height of the details panel under the table, as the user dragged it.</summary>
    public double DetailsHeight { get; set; } = 240;

    /// <summary>Look for a new version at start and once a day; installing always waits for the user.</summary>
    public bool CheckUpdates { get; set; } = true;

    /// <summary>Windows notification when any program loses its link.</summary>
    public bool NotifyAll { get; set; }

    /// <summary>Programs left out while <see cref="NotifyAll"/> is on.</summary>
    public List<string> NotifyExcept { get; set; } = [];

    /// <summary>Whether to notify about this program losing its link.</summary>
    public bool NotifyFor(string groupKey) => NotifyAll ? !NotifyExcept.Contains(groupKey) : NotifyPrograms.Contains(groupKey);

    /// <summary>Programs (group keys) to notify about when their link is lost.</summary>
    public List<string> NotifyPrograms { get; set; } = [];

    /// <summary>Program list order: by activity (true) or by name.</summary>
    public bool SortByActivity { get; set; } = true;

    /// <summary>Program list order: by data sent and received; wins over <see cref="SortByActivity"/>.</summary>
    public bool SortByTraffic { get; set; }

    /// <summary>Notify when a program goes online for the first time.</summary>
    public bool AlertNewProgram { get; set; } = true;

    /// <summary>Notify when a program reaches a server in a new country.</summary>
    public bool AlertNewCountry { get; set; } = true;

    /// <summary>Notify when a program reaches a new network (AS); noisy, off by default.</summary>
    public bool AlertNewNetwork { get; set; }

    /// <summary>Browsers visit new countries and networks with every site: only their first start is news.</summary>
    public bool AlertSkipBrowsers { get; set; } = true;

    /// <summary>Ping the router and an internet reference point every 2 s, for connection quality.</summary>
    public bool QualityPings { get; set; } = true;

    /// <summary>When NetWatcher started learning what is normal; alerts start a day later.</summary>
    public DateTimeOffset? LearningSince { get; set; }

    public void Normalize()
    {
        RetentionDays = Math.Clamp(RetentionDays, 1, 365);
        PollSeconds = Math.Clamp(PollSeconds, 1, 60);
        if (Theme is not ("System" or "Light" or "Dark")) Theme = "System";
    }

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static Settings Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var s = JsonSerializer.Deserialize<Settings>(File.ReadAllText(path)) ?? new Settings();
                s.Normalize();
                return s;
            }
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            // A broken file must not stop the program; fall back to defaults.
        }
        return new Settings();
    }

    public void Save(string path)
    {
        Normalize();
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, path, overwrite: true);
    }
}
