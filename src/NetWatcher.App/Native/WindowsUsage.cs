using Windows.Networking.Connectivity;

namespace NetWatcher.App.Native;

/// <summary>
/// Traffic per application as Windows itself counts it (the same data as Settings → Network → Data usage):
/// ConnectionProfile.GetAttributedNetworkUsageAsync for every network the computer knows. Covers the time
/// before NetWatcher was installed; the API gives at most 60 days back.
/// </summary>
internal static class WindowsUsage
{
    public sealed record AppUsage(string Id, string Name, string Network, long Received, long Sent)
    {
        public long Total => Received + Sent;
    }

    public sealed record Result(List<AppUsage> Usage, List<string> Networks, List<string> Errors);

    public static async Task<Result> ReadAsync(DateTimeOffset from, DateTimeOffset to)
    {
        var usage = new List<AppUsage>();
        var networks = new List<string>();
        var errors = new List<string>();
        IReadOnlyList<ConnectionProfile> profiles;
        try
        {
            profiles = NetworkInformation.GetConnectionProfiles();
        }
        catch (Exception e)
        {
            return new Result(usage, networks, [Describe(e)]);
        }

        foreach (var profile in profiles)
        {
            var network = string.IsNullOrWhiteSpace(profile.ProfileName) ? "сеть без имени" : profile.ProfileName;
            try
            {
                // DoNotCare for roaming and shared: all traffic.
                var list = await profile.GetAttributedNetworkUsageAsync(from, to, new NetworkUsageStates());
                var any = false;
                foreach (var u in list)
                {
                    var id = u.AttributionId ?? "";
                    var name = string.IsNullOrWhiteSpace(u.AttributionName) ? (id == "" ? "Система Windows" : Path.GetFileName(id.TrimEnd('\\'))) : u.AttributionName;
                    usage.Add(new AppUsage(id, name, network, (long)u.BytesReceived, (long)u.BytesSent));
                    any = true;
                }
                if (any && !networks.Contains(network)) networks.Add(network);
            }
            catch (Exception e)
            {
                errors.Add($"{network}: {Describe(e)}");
            }
        }
        return new Result(usage, networks, errors);
    }

    private static string Describe(Exception e) => e switch
    {
        UnauthorizedAccessException => "Windows не дала доступ к истории трафика",
        _ => e.Message,
    };
}
