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

    /// <summary>Program list order: by activity (true) or by name.</summary>
    public bool SortByActivity { get; set; } = true;

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
