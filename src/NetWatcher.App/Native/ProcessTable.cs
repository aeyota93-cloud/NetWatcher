using System.Collections.Concurrent;
using System.Diagnostics;

namespace NetWatcher.App.Native;

internal readonly record struct ProcessInfo(string Name, string Path);

/// <summary>Process id → program name and path, cached for a minute.</summary>
internal sealed class ProcessTable
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(60);
    private readonly ConcurrentDictionary<int, (ProcessInfo Info, DateTime At)> _cache = new();

    /// <summary>Program names learnt from process start events, for processes already gone.</summary>
    private readonly ConcurrentDictionary<int, string> _started = new();

    public void NoteStarted(int pid, string imageName)
    {
        if (!string.IsNullOrWhiteSpace(imageName)) _started[pid] = imageName;
        _cache.TryRemove(pid, out _); // the id may have been reused
    }

    public ProcessInfo Get(int pid)
    {
        var now = DateTime.UtcNow;
        if (_cache.TryGetValue(pid, out var c) && now - c.At < Ttl) return c.Info;
        var info = Query(pid);
        _cache[pid] = (info, now);
        return info;
    }

    public void Trim()
    {
        var now = DateTime.UtcNow;
        foreach (var (pid, c) in _cache)
            if (now - c.At > Ttl * 5) _cache.TryRemove(pid, out _);
        if (_started.Count > 5000) _started.Clear();
    }

    private ProcessInfo Query(int pid)
    {
        if (pid == 0) return new ProcessInfo("System Idle Process", "");
        if (pid == 4) return new ProcessInfo("System", "");

        var path = ImagePath(pid);
        if (path != "") return new ProcessInfo(System.IO.Path.GetFileName(path), path);

        try
        {
            using var p = Process.GetProcessById(pid);
            return new ProcessInfo(p.ProcessName + ".exe", "");
        }
        catch (ArgumentException)
        {
            // Already exited.
        }
        catch (InvalidOperationException)
        {
        }

        return _started.TryGetValue(pid, out var name)
            ? new ProcessInfo(System.IO.Path.GetFileName(name), "")
            : new ProcessInfo($"PID {pid}", "");
    }

    private static unsafe string ImagePath(int pid)
    {
        var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == 0) return "";
        try
        {
            var buffer = stackalloc char[1024];
            var size = 1024;
            return NativeMethods.QueryFullProcessImageName(handle, 0, buffer, ref size) ? new string(buffer, 0, size) : "";
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }
}
