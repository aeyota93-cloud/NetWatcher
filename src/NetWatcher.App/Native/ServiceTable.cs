using System.Runtime.InteropServices;

namespace NetWatcher.App.Native;

/// <summary>
/// Windows services and the processes they live in. Many services share one
/// svchost.exe, so this is how "svchost" becomes "Windows Update".
/// </summary>
internal sealed class ServiceTable
{
    private readonly Lock _lock = new();
    private Dictionary<int, string> _byPid = [];
    private Dictionary<string, string> _displayNames = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Short service names running in the process, comma separated, or "".</summary>
    public string ForPid(int pid)
    {
        lock (_lock) return _byPid.GetValueOrDefault(pid, "");
    }

    /// <summary>Short name → display name for every known service, running or not.</summary>
    public IReadOnlyDictionary<string, string> DisplayNames
    {
        get
        {
            lock (_lock) return _displayNames;
        }
    }

    public void Refresh()
    {
        var list = Enumerate(NativeMethods.SERVICE_WIN32 | NativeMethods.SERVICE_USER_SERVICES)
                   ?? Enumerate(NativeMethods.SERVICE_WIN32)
                   ?? [];

        var byPid = list
            .Where(s => s.Pid != 0)
            .GroupBy(s => s.Pid)
            .ToDictionary(g => g.Key, g => string.Join(",", g.Select(s => s.Name).Order(StringComparer.OrdinalIgnoreCase)));
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in list) names[s.Name] = s.Display;

        lock (_lock)
        {
            _byPid = byPid;
            // Keep names of services that are gone, so old log rows still read well.
            foreach (var (k, v) in _displayNames) names.TryAdd(k, v);
            _displayNames = names;
        }
    }

    private static List<(string Name, string Display, int Pid)>? Enumerate(uint types)
    {
        var scm = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ENUMERATE_SERVICE);
        if (scm == 0) return null;
        try
        {
            var result = new List<(string, string, int)>();
            var resume = 0;
            var size = 256 * 1024;
            var itemSize = Marshal.SizeOf<NativeMethods.ENUM_SERVICE_STATUS_PROCESS>();
            while (true)
            {
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    var ok = NativeMethods.EnumServicesStatusEx(scm, NativeMethods.SC_ENUM_PROCESS_INFO, types,
                        NativeMethods.SERVICE_STATE_ALL, buffer, size, out var needed, out var count, ref resume, null);
                    var error = ok ? 0 : Marshal.GetLastPInvokeError();
                    if (!ok && error != NativeMethods.ERROR_MORE_DATA) return null;

                    for (var i = 0; i < count; i++)
                    {
                        var item = Marshal.PtrToStructure<NativeMethods.ENUM_SERVICE_STATUS_PROCESS>(buffer + i * itemSize);
                        var name = Marshal.PtrToStringUni(item.ServiceName) ?? "";
                        var display = Marshal.PtrToStringUni(item.DisplayName) ?? name;
                        if (name != "") result.Add((name, display, (int)item.ProcessId));
                    }

                    if (ok) return result;
                    size = Math.Max(size, needed + 4096);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        finally
        {
            NativeMethods.CloseServiceHandle(scm);
        }
    }
}
