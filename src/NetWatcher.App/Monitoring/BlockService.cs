using System.Diagnostics;
using System.Globalization;
using System.Text;
using Microsoft.Win32;
using NetWatcher.Core;
using NetWatcher.Core.Blocking;

namespace NetWatcher.App.Monitoring;

/// <summary>
/// Blocks made from NetWatcher: outbound "block" rules of the Windows firewall, created and removed with
/// netsh advfirewall. The list is kept in blocks.json; domain rules get the new addresses of their domain
/// as DNS answers arrive.
/// </summary>
internal sealed class BlockService
{
    private readonly Lock _lock = new();
    private readonly List<BlockRule> _rules;
    private readonly HashSet<string> _missing = [];
    private readonly HashSet<string> _pendingUpdate = [];
    private bool _updating;

    public BlockService() => _rules = BlockRules.Load(AppPaths.Blocks);

    /// <summary>The list changed: a rule added or removed, or found missing from the firewall.</summary>
    public event Action? Changed;

    public List<BlockRule> Rules
    {
        get
        {
            lock (_lock) return _rules.ToList();
        }
    }

    /// <summary>Rules deleted outside NetWatcher (in the firewall console): they no longer block.</summary>
    public bool IsMissing(BlockRule r)
    {
        lock (_lock) return _missing.Contains(r.Id);
    }

    public (bool Ok, string Message) Add(BlockRule rule)
    {
        string args;
        try
        {
            args = BlockRules.AddArguments(rule);
        }
        catch (InvalidOperationException e)
        {
            return (false, e.Message);
        }
        var (code, output) = Netsh(args);
        if (code != 0) return (false, $"Брандмауэр Windows не принял правило (код {code}). {output}".Trim());
        lock (_lock)
        {
            _rules.Add(rule);
            Save();
        }
        Changed?.Invoke();
        return (true, "");
    }

    public (bool Ok, string Message) Remove(BlockRule rule)
    {
        bool missing;
        lock (_lock) missing = _missing.Contains(rule.Id);
        if (!missing)
        {
            var (code, output) = Netsh(BlockRules.DeleteArguments(rule));
            // Exit code 1 also when there is no such rule any more: then it is gone anyway.
            if (code != 0 && Netsh(BlockRules.ShowArguments(rule)).Code == 0)
                return (false, $"Не удалось удалить правило (код {code}). {output}".Trim());
        }
        lock (_lock)
        {
            _rules.RemoveAll(r => r.Id == rule.Id);
            _missing.Remove(rule.Id);
            Save();
        }
        Changed?.Invoke();
        return (true, "");
    }

    /// <summary>At start: which of our rules are still in the firewall.</summary>
    public void Verify()
    {
        foreach (var r in Rules)
        {
            var exists = Netsh(BlockRules.ShowArguments(r)).Code == 0;
            lock (_lock)
            {
                if (exists) _missing.Remove(r.Id);
                else _missing.Add(r.Id);
            }
        }
        Changed?.Invoke();
    }

    /// <summary>New DNS answers: domain rules take the new addresses (first connection may still go through).</summary>
    public void OnDns(IReadOnlyCollection<DnsObservation> answers)
    {
        if (answers.Count == 0) return;
        lock (_lock)
        {
            foreach (var rule in _rules.Where(r => r.Kind == BlockKind.Domain && !_missing.Contains(r.Id)))
            {
                var ips = answers.Where(a => string.Equals(a.Domain.TrimEnd('.'), rule.Domain, StringComparison.OrdinalIgnoreCase)).Select(a => a.Ip);
                if (BlockRules.AddAddresses(rule, ips)) _pendingUpdate.Add(rule.Id);
            }
            if (_pendingUpdate.Count == 0 || _updating) return;
            _updating = true;
        }
        _ = Task.Run(FlushUpdates);
    }

    private void FlushUpdates()
    {
        while (true)
        {
            List<BlockRule> rules;
            lock (_lock)
            {
                rules = _rules.Where(r => _pendingUpdate.Contains(r.Id)).ToList();
                _pendingUpdate.Clear();
                if (rules.Count == 0)
                {
                    _updating = false;
                    return;
                }
                Save();
            }
            foreach (var r in rules)
            {
                try
                {
                    Netsh(BlockRules.UpdateArguments(r));
                }
                catch (InvalidOperationException)
                {
                    // An empty list cannot happen for a domain rule once created; skip if it does.
                }
            }
        }
    }

    private void Save()
    {
        try
        {
            BlockRules.Save(AppPaths.Blocks, _rules);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The firewall rules are what blocks; the list is only our memory of them.
        }
    }

    /// <summary>
    /// Whether the Windows firewall is on: rules do nothing when it is off or replaced by another firewall.
    /// Group policy wins over local settings. Null — could not tell.
    /// </summary>
    public static bool? FirewallOn()
    {
        try
        {
            string[] local = ["DomainProfile", "StandardProfile", "PublicProfile"];
            string[] policy = ["DomainProfile", "PrivateProfile", "PublicProfile"];
            var anyOn = false;
            for (var i = 0; i < 3; i++)
            {
                var value = Registry.GetValue($@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\{policy[i]}", "EnableFirewall", null)
                            ?? Registry.GetValue($@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{local[i]}", "EnableFirewall", null);
                if (value is int on && on != 0) anyOn = true;
            }
            return anyOn;
        }
        catch (Exception e) when (e is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static Encoding? _oem;

    /// <summary>Runs netsh; its messages come in the console code page (866 in Russian Windows).</summary>
    private static (int Code, string Output) Netsh(string args)
    {
        if (_oem == null)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            try
            {
                _oem = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
            }
            catch (ArgumentException)
            {
                _oem = Encoding.UTF8;
            }
        }
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"), args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = _oem,
            StandardErrorEncoding = _oem,
        };
        try
        {
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEndAsync();
            var error = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(20_000))
            {
                p.Kill();
                return (-1, "netsh не ответил за 20 секунд");
            }
            return (p.ExitCode, (output.Result + " " + error.Result).Trim());
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return (-1, "Не удалось запустить netsh: " + e.Message);
        }
    }
}
