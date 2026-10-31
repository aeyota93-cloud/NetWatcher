namespace NetWatcher.Core.Asn;

/// <summary>Downloads a fresh owner database and swaps it in only if it reads well.</summary>
public static class AsnUpdater
{
    public static async Task<AsnDatabase> DownloadAsync(HttpClient http, string destination, CancellationToken ct = default)
    {
        var tmp = destination + ".download";
        try
        {
            using (var response = await http.GetAsync(AsnDatabase.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                response.EnsureSuccessStatusCode();
                await using var file = File.Create(tmp);
                await response.Content.CopyToAsync(file, ct);
            }

            var db = await Task.Run(() => AsnDatabase.LoadFile(tmp), ct);
            if (db.Count < 1000)
                throw new InvalidDataException("Скачанная база слишком мала, похоже, файл повреждён. Старая база оставлена.");

            File.Move(tmp, destination, overwrite: true);
            return db;
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }
}
