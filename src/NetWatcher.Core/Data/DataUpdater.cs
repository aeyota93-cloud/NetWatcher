using System.IO.Compression;
using System.Net;

namespace NetWatcher.Core.Data;

/// <summary>
/// Reference data the program keeps next to the log (owners of addresses, countries, domain catalog):
/// downloads a fresh copy from the first source that answers and swaps it in only if it reads well.
/// </summary>
public static class DataUpdater
{
    /// <summary>
    /// Opens a data file whether it is gzip or plain text: decided by content, not by name,
    /// because a download in progress has no .gz extension.
    /// </summary>
    public static Stream OpenText(string path)
    {
        var file = File.OpenRead(path);
        try
        {
            Span<byte> head = stackalloc byte[2];
            var read = file.Read(head);
            file.Position = 0;
            if (read == 2 && head[0] == 0x1F && head[1] == 0x8B) return new GZipStream(file, CompressionMode.Decompress);
            if (read > 0 && head[0] == (byte)'<')
                throw new InvalidDataException("Сервер вернул веб-страницу вместо базы. Попробуйте позже или скачайте файл вручную.");
            return file;
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    public static async Task<T> DownloadAsync<T>(
        HttpClient http,
        IReadOnlyList<string> sources,
        string destination,
        Func<string, T> load,
        Func<T, int> count,
        int minCount,
        string manualHint,
        CancellationToken ct = default)
    {
        var errors = new List<string>();
        foreach (var url in sources)
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
                return Install(tmp, destination, load, count, minCount);
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
        throw new InvalidOperationException("Не удалось скачать базу. " + string.Join("; ", errors) + ". " + manualHint);
    }

    /// <summary>Checks a file the user downloaded by hand and puts it in place.</summary>
    public static T Import<T>(string source, string destination, Func<string, T> load, Func<T, int> count, int minCount)
    {
        var tmp = destination + ".import";
        File.Copy(source, tmp, overwrite: true);
        try
        {
            return Install(tmp, destination, load, count, minCount);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    private static T Install<T>(string tmp, string destination, Func<string, T> load, Func<T, int> count, int minCount)
    {
        var db = load(tmp);
        if (count(db) < minCount)
            throw new InvalidDataException("файл не похож на нужную базу" + (File.Exists(destination) ? ", прежняя база оставлена" : ""));
        File.Move(tmp, destination, overwrite: true);
        // Mark the moment of installation, so a newer release does not replace a fresher download.
        File.SetLastWriteTimeUtc(destination, DateTime.UtcNow);
        return db;
    }

    public static string Describe(HttpRequestException e) => e.InnerException switch
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
