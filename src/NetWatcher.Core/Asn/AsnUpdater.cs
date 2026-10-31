using System.Net;

namespace NetWatcher.Core.Asn;

/// <summary>
/// Gets a fresh owner database and swaps it in only if it reads well. Tries a copy kept on
/// GitHub first (it is reachable wherever the program itself was downloaded), then the
/// original site iptoasn.com.
/// </summary>
public static class AsnUpdater
{
    /// <summary>Weekly copy published by the repository's "asn-db" workflow.</summary>
    public const string MirrorUrl = "https://github.com/aeyota93-cloud/NetWatcher/releases/download/asn-db/ip2asn-combined.tsv.gz";

    public static readonly string[] Sources = [MirrorUrl, AsnDatabase.DownloadUrl];

    public static async Task<AsnDatabase> DownloadAsync(HttpClient http, string destination, CancellationToken ct = default)
    {
        var errors = new List<string>();
        foreach (var url in Sources)
        {
            var host = new Uri(url).Host;
            var tmp = destination + ".download";
            try
            {
                using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    cts.CancelAfter(TimeSpan.FromMinutes(2));
                    using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                    if (!response.IsSuccessStatusCode)
                    {
                        errors.Add($"{host}: ответ {(int)response.StatusCode} {response.ReasonPhrase}");
                        continue;
                    }
                    await using var file = File.Create(tmp);
                    await response.Content.CopyToAsync(file, cts.Token).ConfigureAwait(false);
                }
                return Install(tmp, destination);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                errors.Add($"{host}: не ответил за 2 минуты");
            }
            catch (HttpRequestException e)
            {
                errors.Add($"{host}: {Describe(e)}");
            }
            catch (InvalidDataException e)
            {
                errors.Add($"{host}: {e.Message}");
            }
            finally
            {
                if (File.Exists(tmp)) File.Delete(tmp);
            }
        }
        throw new InvalidOperationException(
            "Не удалось скачать базу. " + string.Join("; ", errors) +
            ". Можно скачать файл ip2asn-combined.tsv.gz браузером и указать его кнопкой «Загрузить из файла».");
    }

    /// <summary>Checks a file the user downloaded by hand and puts it in place.</summary>
    public static AsnDatabase Import(string source, string destination)
    {
        var tmp = destination + ".import";
        File.Copy(source, tmp, overwrite: true);
        try
        {
            return Install(tmp, destination);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    private static AsnDatabase Install(string tmp, string destination)
    {
        var db = AsnDatabase.LoadFile(tmp);
        if (db.Count < 1000)
            throw new InvalidDataException("файл не похож на базу владельцев" + (File.Exists(destination) ? ", прежняя база оставлена" : ""));
        File.Move(tmp, destination, overwrite: true);
        // Mark the moment of installation, so a newer release does not replace a fresher download.
        File.SetLastWriteTimeUtc(destination, DateTime.UtcNow);
        return db;
    }

    private static string Describe(HttpRequestException e) => e.InnerException switch
    {
        System.Net.Sockets.SocketException s => s.SocketErrorCode switch
        {
            System.Net.Sockets.SocketError.HostNotFound => "адрес не найден в DNS",
            System.Net.Sockets.SocketError.ConnectionRefused => "подключение отклонено",
            System.Net.Sockets.SocketError.TimedOut => "сервер не ответил",
            _ => s.Message,
        },
        System.Security.Authentication.AuthenticationException => "ошибка защищённого соединения (возможна подмена или блокировка)",
        _ => e.StatusCode is { } code ? $"ответ {(int)code}" : e.Message,
    };
}
