using NetWatcher.App.Monitoring;
using NetWatcher.Core;
using NetWatcher.Core.Asn;
using NetWatcher.Core.Dns;
using NetWatcher.Core.Storage;

namespace NetWatcher.App;

/// <summary>Everything the program holds while it runs.</summary>
internal sealed class AppState : IDisposable
{
    public Settings Settings { get; }
    public LogStore Store { get; }
    public DnsIndex Dns { get; } = new();

    /// <summary>Link quality per program for the last hour, in memory.</summary>
    public Core.Link.LinkMonitor Link { get; } = new(TimeSpan.FromHours(1));

    public LinkService LinkService { get; }
    public Collector Collector { get; }
    public RdapClient Rdap { get; } = new(AppPaths.Http);
    public PeeringDbClient PeeringDb { get; } = new(AppPaths.Http, AppPaths.PeeringDbCache);
    public Core.Diagnostics.NetProbe Probe { get; } = new(AppPaths.Http);

    private volatile AsnDatabase _asn = AsnDatabase.Empty;
    public AsnDatabase Asn { get => _asn; set => _asn = value; }

    public string AsnStatus { get; set; } = "";

    /// <summary>The owner database is being read from disk at start.</summary>
    public bool AsnLoading { get; private set; } = true;

    public AppState()
    {
        Settings = Settings.Load(AppPaths.Settings);
        Store = new LogStore(AppPaths.Database);
        Collector = new Collector(Store, Dns, Link, () => Settings);
        LinkService = new LinkService(this);
    }

    public void Start()
    {
        Collector.Start();
        LinkService.Start();
        Task.Run(() =>
        {
            Store.Purge(DateTimeOffset.Now.AddDays(-Settings.RetentionDays));
            Store.LoadDns(Dns);
        });
        Task.Run(LoadAsn);
    }

    private void LoadAsn()
    {
        try
        {
            AsnStatus = "Загружается база владельцев IP…";
            // A copy is built into the program: use it on first start, and when it is newer
            // than the one on disk (a newer release of NetWatcher).
            if (EmbeddedAsnIsNewer()) ExtractEmbeddedAsn();
            if (!File.Exists(AppPaths.AsnDatabase))
            {
                AsnStatus = "База владельцев IP не скачана";
                return;
            }
            Asn = AsnDatabase.LoadFile(AppPaths.AsnDatabase);
            SetAsnLoaded();
        }
        catch (Exception e)
        {
            AsnStatus = "База владельцев IP не читается: " + e.Message;
        }
        finally
        {
            AsnLoading = false;
        }
    }

    private const string EmbeddedAsnName = "ip2asn-combined.tsv.gz";

    private static bool EmbeddedAsnIsNewer()
    {
        if (typeof(AppState).Assembly.GetManifestResourceInfo(EmbeddedAsnName) == null) return false;
        if (!File.Exists(AppPaths.AsnDatabase)) return true;
        var built = Environment.ProcessPath is { } exe ? File.GetLastWriteTimeUtc(exe) : DateTime.MinValue;
        return File.GetLastWriteTimeUtc(AppPaths.AsnDatabase) < built;
    }

    private static void ExtractEmbeddedAsn()
    {
        using var res = typeof(AppState).Assembly.GetManifestResourceStream(EmbeddedAsnName);
        if (res == null) return;
        Directory.CreateDirectory(AppPaths.DataDir);
        var tmp = AppPaths.AsnDatabase + ".embedded";
        using (var file = File.Create(tmp)) res.CopyTo(file);
        File.Move(tmp, AppPaths.AsnDatabase, overwrite: true);
    }

    public void SetAsnLoaded()
    {
        var date = File.GetLastWriteTime(AppPaths.AsnDatabase);
        AsnStatus = $"База владельцев IP от {date:dd.MM.yyyy}";
    }

    public void SaveSettings() => Settings.Save(AppPaths.Settings);

    public void Dispose()
    {
        LinkService.Dispose();
        Collector.Dispose();
        Store.Dispose();
    }
}
