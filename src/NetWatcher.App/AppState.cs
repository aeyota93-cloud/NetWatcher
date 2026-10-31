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
        Collector = new Collector(Store, Dns, () => Settings);
    }

    public void Start()
    {
        Collector.Start();
        Task.Run(() =>
        {
            Store.Purge(DateTimeOffset.Now.AddDays(-Settings.RetentionDays));
            Store.LoadDns(Dns);
        });
        Task.Run(LoadAsn);
    }

    private void LoadAsn()
    {
        if (!File.Exists(AppPaths.AsnDatabase))
        {
            AsnStatus = "База владельцев IP не скачана";
            AsnLoading = false;
            return;
        }
        try
        {
            AsnStatus = "Загружается база владельцев IP…";
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

    public void SetAsnLoaded()
    {
        var date = File.GetLastWriteTime(AppPaths.AsnDatabase);
        AsnStatus = $"База владельцев IP от {date:dd.MM.yyyy}";
    }

    public void SaveSettings() => Settings.Save(AppPaths.Settings);

    public void Dispose()
    {
        Collector.Dispose();
        Store.Dispose();
    }
}
