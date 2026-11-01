using System.Net;
using System.Text.Json;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Blocking;

public enum BlockKind
{
    /// <summary>The whole program (or one Windows service inside svchost).</summary>
    Program,

    /// <summary>Addresses or networks.</summary>
    Address,

    /// <summary>A domain: its addresses as DNS answers them, updated when new answers come.</summary>
    Domain,
}

/// <summary>
/// One block made by NetWatcher. It lives as an outbound "block" rule of the Windows firewall named
/// "NetWatcher: …", so it works while NetWatcher is closed and is visible in the firewall console.
/// </summary>
public sealed class BlockRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public BlockKind Kind { get; set; }

    /// <summary>What is blocked, as people read it: "Steam", "149.154.164.0/22", "ads.example.com".</summary>
    public string Title { get; set; } = "";

    /// <summary>Full path of the program the rule is limited to; "" — every program.</summary>
    public string ProgramPath { get; set; } = "";

    /// <summary>Short name of a Windows service inside svchost.exe ("wuauserv"), or "".</summary>
    public string Service { get; set; } = "";

    /// <summary>The program's readable name, for the list of blocks.</summary>
    public string ProgramTitle { get; set; } = "";

    /// <summary>Addresses and networks (CIDR). Never empty for Address and Domain rules.</summary>
    public List<string> Addresses { get; set; } = [];

    public string Domain { get; set; } = "";
    public DateTimeOffset Created { get; set; } = DateTimeOffset.Now;

    public string RuleName => $"NetWatcher: {Clean(Title)}{(ProgramTitle != "" && Kind != BlockKind.Program ? " — " + Clean(ProgramTitle) : "")} ({Id})";

    /// <summary>"Программа Steam", "Домен ads.example.com для Chrome"…</summary>
    public string Describe() => Kind switch
    {
        BlockKind.Program => Service != "" ? $"Служба {Title}" : $"Программа {Title}",
        BlockKind.Domain => $"Домен {Domain}" + For(),
        _ => (Addresses.Count == 1 ? $"Адрес {Addresses[0]}" : $"Адреса: {Title}") + For(),
    };

    private string For() => ProgramTitle != "" ? $" для {ProgramTitle}" : " для всех программ";

    private static string Clean(string s) => s.Replace("\"", "").Replace("\r", " ").Replace("\n", " ");

    /// <summary>Does the rule stop this destination of this program?</summary>
    public bool Covers(DestinationRow row)
    {
        if (ProgramPath != "" && !string.Equals(ProgramPath, row.Path, StringComparison.OrdinalIgnoreCase)) return false;
        if (Service != "" && !row.Services.Split(',').Contains(Service, StringComparer.OrdinalIgnoreCase)) return false;
        if (Kind == BlockKind.Program) return true;
        if (Kind == BlockKind.Domain && row.Domains.Contains(Domain, StringComparer.OrdinalIgnoreCase)) return true;
        return Addresses.Any(a => Cidr.TryParse(a, out var net) && net.Contains(row.RemoteIp));
    }
}

/// <summary>Builds the netsh commands for block rules and keeps the list on disk.</summary>
public static class BlockRules
{
    /// <summary>The firewall takes at most this many addresses in a rule; the newest are kept.</summary>
    public const int MaxAddresses = 1000;

    /// <summary>
    /// "netsh advfirewall firewall add rule …": outbound, block, every profile, any protocol.
    /// A rule for addresses must have addresses: an empty list would block the program everywhere.
    /// </summary>
    public static string AddArguments(BlockRule r)
    {
        Check(r);
        var args = $"advfirewall firewall add rule name=\"{r.RuleName}\" dir=out action=block profile=any enable=yes"
                   + $" description=\"{Description(r)}\"";
        if (r.ProgramPath != "") args += $" program=\"{r.ProgramPath}\"";
        if (r.Service != "") args += $" service=\"{r.Service}\"";
        if (r.Kind != BlockKind.Program) args += $" remoteip={string.Join(",", r.Addresses)}";
        return args;
    }

    /// <summary>New addresses for a domain rule ("set rule … new remoteip=…").</summary>
    public static string UpdateArguments(BlockRule r)
    {
        Check(r);
        return $"advfirewall firewall set rule name=\"{r.RuleName}\" new remoteip={string.Join(",", r.Addresses)}";
    }

    public static string DeleteArguments(BlockRule r) => $"advfirewall firewall delete rule name=\"{r.RuleName}\"";

    public static string ShowArguments(BlockRule r) => $"advfirewall firewall show rule name=\"{r.RuleName}\"";

    private static string Description(BlockRule r) => $"Создано NetWatcher {r.Created:dd.MM.yyyy HH:mm}: {r.Describe()}".Replace("\"", "");

    private static void Check(BlockRule r)
    {
        if (r.Kind == BlockKind.Program && r.ProgramPath == "" && r.Service == "")
            throw new InvalidOperationException("Не указана программа: такое правило заблокировало бы всё.");
        if (r.Kind != BlockKind.Program && r.Addresses.Count == 0)
            throw new InvalidOperationException("Нет адресов: такое правило заблокировало бы программе весь интернет.");
        foreach (var a in r.Addresses)
            if (!Cidr.TryParse(a, out _)) throw new InvalidOperationException($"Не адрес и не сеть: {a}");
    }

    /// <summary>Adds addresses to a domain rule; true when something new was added.</summary>
    public static bool AddAddresses(BlockRule r, IEnumerable<IPAddress> ips)
    {
        var changed = false;
        foreach (var ip in ips)
        {
            var text = Cidr.Of(IpKey.Normalize(ip), IpKey.Normalize(ip).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128).ToString();
            if (r.Addresses.Contains(text)) continue;
            r.Addresses.Add(text);
            changed = true;
        }
        if (r.Addresses.Count > MaxAddresses) r.Addresses.RemoveRange(0, r.Addresses.Count - MaxAddresses);
        return changed;
    }

    /// <summary>
    /// Blocking these breaks Windows itself (updates, sign-in, time, name lookups, the network as such):
    /// the user is warned before.
    /// </summary>
    public static bool IsSystem(string path, string services, string process)
    {
        if (process is "System" or "lsass.exe" or "services.exe" or "svchost.exe" && services == "") return true;
        if (services != "") return true;
        var windows = Environment.GetEnvironmentVariable("SystemRoot") is { Length: > 0 } root ? root : @"C:\Windows";
        return path.StartsWith(windows + "\\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Networks that serve many unrelated sites from the same addresses (CDNs and clouds): Cloudflare,
    /// Akamai, Amazon, Google, Fastly, Microsoft. Blocking such an address blocks other sites too.
    /// </summary>
    public static readonly HashSet<int> SharedHostingAsns = [13335, 20940, 16625, 16509, 14618, 15169, 396982, 54113, 8075];

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static List<BlockRule> Load(string path)
    {
        try
        {
            if (File.Exists(path)) return JsonSerializer.Deserialize<List<BlockRule>>(File.ReadAllText(path)) ?? [];
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            // A broken list must not stop the program; the firewall rules stay as they are.
        }
        return [];
    }

    public static void Save(string path, IEnumerable<BlockRule> rules)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(rules.ToList(), Json));
        File.Move(tmp, path, overwrite: true);
    }
}
