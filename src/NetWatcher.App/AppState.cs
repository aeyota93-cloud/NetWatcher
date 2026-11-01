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
    public AlertService Alerts { get; }
    public BlockService Blocks { get; } = new();
    public Collector Collector { get; }
    public RdapClient Rdap { get; } = new(AppPaths.Http);
    public PeeringDbClient PeeringDb { get; } = new(AppPaths.Http, AppPaths.PeeringDbCache);
    public Core.Diagnostics.NetProbe Probe { get; } = new(AppPaths.Http);

    private volatile AsnDatabase _asn = AsnDatabase.Empty;
    public AsnDatabase Asn { get => _asn; set => _asn = value; }

    public string AsnStatus { get; set; } = "";

    private volatile Core.Geo.GeoDatabase _geo = Core.Geo.GeoDatabase.Empty;

    /// <summary>Country of the server by address (DB-IP).</summary>
    public Core.Geo.GeoDatabase Geo { get => _geo; set => _geo = value; }

    public string GeoStatus { get; set; } = "";

    /// <summary>The country database is being read from disk at start.</summary>
    public bool GeoLoading { get; private set; } = true;

    private volatile Core.Catalog.DomainCatalog _catalog = Core.Catalog.DomainCatalog.Empty;

    /// <summary>Owner company and purpose of known domains.</summary>
    public Core.Catalog.DomainCatalog Catalog { get => _catalog; set => _catalog = value; }

    public string CatalogStatus { get; set; } = "";

    /// <summary>The owner database is being read from disk at start.</summary>
    public bool AsnLoading { get; private set; } = true;

    public AppState()
    {
        Settings = Settings.Load(AppPaths.Settings);
        Store = new LogStore(AppPaths.Database);
        Collector = new Collector(Store, Dns, Link, () => Settings);
        LinkService = new LinkService(this);
        Alerts = new AlertService(this);
        Collector.DnsAnswers += Blocks.OnDns;
    }

    public void Start()
    {
        Collector.Start();
        LinkService.Start();
        Alerts.Start();
        Task.Run(() =>
        {
            Store.Purge(DateTimeOffset.Now.AddDays(-Settings.RetentionDays));
            Store.LoadDns(Dns);
        });
        Task.Run(LoadAsn);
        Task.Run(LoadGeo);
        Task.Run(LoadCatalog);
        Task.Run(Blocks.Verify);
    }

    private void LoadAsn()
    {
        try
        {
            AsnStatus = "Загружается база владельцев IP…";
            if (EmbeddedIsNewer(EmbeddedAsnName, AppPaths.AsnDatabase)) ExtractEmbedded(EmbeddedAsnName, AppPaths.AsnDatabase);
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
    private const string EmbeddedGeoName = "dbip-country-lite.csv.gz";
    private const string EmbeddedCatalogName = "domain-catalog.tsv.gz";

    private void LoadCatalog()
    {
        try
        {
            if (EmbeddedIsNewer(EmbeddedCatalogName, AppPaths.Catalog)) ExtractEmbedded(EmbeddedCatalogName, AppPaths.Catalog);
            if (!File.Exists(AppPaths.Catalog))
            {
                CatalogStatus = "Каталог доменов не скачан";
                return;
            }
            Catalog = Core.Catalog.DomainCatalog.LoadFile(AppPaths.Catalog);
            SetCatalogLoaded();
        }
        catch (Exception e)
        {
            CatalogStatus = "Каталог доменов не читается: " + e.Message;
        }
    }

    public void SetCatalogLoaded() =>
        CatalogStatus = $"Каталог от {File.GetLastWriteTime(AppPaths.Catalog):dd.MM.yyyy}: {Catalog.Count} доменов";

    private void LoadGeo()
    {
        try
        {
            if (EmbeddedIsNewer(EmbeddedGeoName, AppPaths.GeoDatabase)) ExtractEmbedded(EmbeddedGeoName, AppPaths.GeoDatabase);
            if (!File.Exists(AppPaths.GeoDatabase))
            {
                GeoStatus = "База стран не скачана: страна берётся по месту регистрации сети";
                return;
            }
            Geo = Core.Geo.GeoDatabase.LoadFile(AppPaths.GeoDatabase);
            SetGeoLoaded();
        }
        catch (Exception e)
        {
            GeoStatus = "База стран не читается: " + e.Message;
        }
        finally
        {
            GeoLoading = false;
        }
    }

    public void SetGeoLoaded() => GeoStatus = $"База стран от {File.GetLastWriteTime(AppPaths.GeoDatabase):dd.MM.yyyy}";

    /// <summary>
    /// A copy of each database is built into the program: it is used on first start, and when it is
    /// newer than the one on disk (a newer release of NetWatcher).
    /// </summary>
    private static bool EmbeddedIsNewer(string resource, string path)
    {
        if (typeof(AppState).Assembly.GetManifestResourceInfo(resource) == null) return false;
        if (!File.Exists(path)) return true;
        var built = Environment.ProcessPath is { } exe ? File.GetLastWriteTimeUtc(exe) : DateTime.MinValue;
        return File.GetLastWriteTimeUtc(path) < built;
    }

    private static void ExtractEmbedded(string resource, string path)
    {
        using var res = typeof(AppState).Assembly.GetManifestResourceStream(resource);
        if (res == null) return;
        Directory.CreateDirectory(AppPaths.DataDir);
        var tmp = path + ".embedded";
        using (var file = File.Create(tmp)) res.CopyTo(file);
        File.Move(tmp, path, overwrite: true);
    }

    public void SetAsnLoaded()
    {
        var date = File.GetLastWriteTime(AppPaths.AsnDatabase);
        AsnStatus = $"База владельцев IP от {date:dd.MM.yyyy}";
    }

    public void SaveSettings() => Settings.Save(AppPaths.Settings);

    public void Dispose()
    {
        Alerts.Dispose();
        LinkService.Dispose();
        Collector.Dispose();
        Store.Dispose();
    }
}
