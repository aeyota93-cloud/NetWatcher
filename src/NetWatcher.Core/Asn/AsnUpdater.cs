using NetWatcher.Core.Data;

namespace NetWatcher.Core.Asn;

/// <summary>
/// Fresh owner database: a copy kept on GitHub first (it is reachable wherever the program itself
/// was downloaded), then the original site iptoasn.com.
/// </summary>
public static class AsnUpdater
{
    /// <summary>Weekly copy published by the repository's "data-mirror" workflow.</summary>
    public const string MirrorUrl = "https://github.com/aeyota93-cloud/NetWatcher/releases/download/asn-db/ip2asn-combined.tsv.gz";

    public static readonly string[] Sources = [MirrorUrl, AsnDatabase.DownloadUrl];

    private const string Hint = "Можно скачать файл ip2asn-combined.tsv.gz браузером и указать его кнопкой «Загрузить из файла».";

    public static Task<AsnDatabase> DownloadAsync(HttpClient http, string destination, CancellationToken ct = default) =>
        DataUpdater.DownloadAsync(http, Sources, destination, AsnDatabase.LoadFile, d => d.Count, 1000, Hint, ct);

    public static AsnDatabase Import(string source, string destination) =>
        DataUpdater.Import(source, destination, AsnDatabase.LoadFile, d => d.Count, 1000);
}
