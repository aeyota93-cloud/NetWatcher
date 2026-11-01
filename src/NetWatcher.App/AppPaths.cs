using System.Net.Http;

namespace NetWatcher.App;

internal static class AppPaths
{
    public static string DataDir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetWatcher");

    public static string Database => Path.Combine(DataDir, "log.db");
    public static string Settings => Path.Combine(DataDir, "settings.json");
    public static string AsnDatabase => Path.Combine(DataDir, Core.Asn.AsnDatabase.FileName);
    public static string GeoDatabase => Path.Combine(DataDir, Core.Geo.GeoDatabase.FileName);
    public static string Catalog => Path.Combine(DataDir, Core.Catalog.DomainCatalog.FileName);
    public static string PeeringDbCache => Path.Combine(DataDir, "peeringdb.json");

    public static HttpClient Http { get; } = CreateHttp();

    private static HttpClient CreateHttp()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("NetWatcher/0.1");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json, application/json, */*");
        return http;
    }
}
