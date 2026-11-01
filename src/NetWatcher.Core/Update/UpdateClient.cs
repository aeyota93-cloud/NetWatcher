using System.Globalization;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetWatcher.Core.Update;

public sealed class UpdateClient(HttpClient http)
{
    public const string ArchiveName = "NetWatcher-win-x64.zip";
    public const string HashName = ArchiveName + ".sha256";
    public const long MaximumExecutableSize = 300L * 1024 * 1024;
    public const long MaximumArchiveSize = 350L * 1024 * 1024;
    private const string Repository = "https://github.com/aeyota93-cloud/NetWatcher";
    private const string LatestUrl = "https://api.github.com/repos/aeyota93-cloud/NetWatcher/releases/latest";
    private static readonly string[] ExpectedFiles = ["NetWatcher.exe", "README.md", "THIRD-PARTY-NOTICES.md"];

    public static Version ParseVersion(string value)
    {
        var numeric = value.Trim().TrimStart('v', 'V').Split(['+', '-'], 2)[0];
        var parts = numeric.Split('.');
        if (parts.Length != 3 || parts.Any(p => p.Length == 0 || p.Any(c => c is < '0' or > '9')) ||
            !Version.TryParse(numeric, out var version))
            throw new UpdateException("Не удалось определить версию обновления.");
        return version;
    }

    public static int CompareVersions(string current, string available) =>
        ParseVersion(current).CompareTo(ParseVersion(available));

    public static UpdateRelease? ParseRelease(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.GetProperty("draft").GetBoolean() || root.GetProperty("prerelease").GetBoolean())
                return null;
            var tag = root.GetProperty("tag_name").GetString()
                ?? throw new UpdateException("В релизе не указана версия.");
            var version = ParseVersion(tag);
            var assets = root.GetProperty("assets").EnumerateArray().ToArray();
            var archive = assets.SingleOrDefault(a => a.GetProperty("name").GetString() == ArchiveName);
            var hash = assets.SingleOrDefault(a => a.GetProperty("name").GetString() == HashName);
            if (archive.ValueKind == JsonValueKind.Undefined)
                throw new UpdateException("В релизе нет архива NetWatcher.");
            if (hash.ValueKind == JsonValueKind.Undefined)
                throw new UpdateException("В релизе нет файла SHA-256. Установка запрещена.");
            var size = archive.GetProperty("size").GetInt64();
            if (size <= 0 || size > MaximumArchiveSize)
                throw new UpdateException("Недопустимый размер архива обновления.");
            var archiveUrl = AssetUri(archive.GetProperty("browser_download_url").GetString()!, tag, ArchiveName);
            var hashUrl = AssetUri(hash.GetProperty("browser_download_url").GetString()!, tag, HashName);
            var htmlUrl = new Uri(root.GetProperty("html_url").GetString()!);
            ValidateRepositoryUri(htmlUrl, "/releases/tag/");
            DateTimeOffset? date = root.TryGetProperty("published_at", out var published) &&
                published.ValueKind == JsonValueKind.String
                ? DateTimeOffset.Parse(published.GetString()!, CultureInfo.InvariantCulture) : null;
            return new UpdateRelease(version, tag, root.GetProperty("name").GetString() ?? tag,
                archiveUrl, hashUrl, size, root.GetProperty("body").GetString() ?? "", date, htmlUrl);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException
            or FormatException or ArgumentException or OverflowException)
        {
            throw new UpdateException("Не удалось прочитать сведения о релизе.", ex);
        }
    }

    public async Task<UpdateCheckResult> CheckAsync(string currentVersion, CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var response = await http.GetAsync(LatestUrl, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return new UpdateCheckResult(false, null);
        response.EnsureSuccessStatusCode();
        ValidateResponseUri(response, true);
        var json = await ReadLimitedAsync(response.Content, 2 * 1024 * 1024, timeout.Token).ConfigureAwait(false);
        var release = ParseRelease(json);
        return new UpdateCheckResult(release != null && ParseVersion(currentVersion) < release.Version, release);
    }

    public async Task<PreparedUpdate> DownloadAsync(UpdateRelease release, IProgress<UpdateProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(release);
        AssetUri(release.ArchiveUrl.AbsoluteUri, release.Tag, ArchiveName);
        AssetUri(release.HashUrl.AbsoluteUri, release.Tag, HashName);
        var directory = Path.Combine(Path.GetTempPath(), "NetWatcher-update", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMinutes(10));
            var token = timeout.Token;
            string hash;
            using (var response = await http.GetAsync(release.HashUrl, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                ValidateResponseUri(response, false);
                hash = await ReadLimitedAsync(response.Content, 4096, token).ConfigureAwait(false);
            }
            var archivePath = Path.Combine(directory, ArchiveName);
            using (var response = await http.GetAsync(release.ArchiveUrl, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                ValidateResponseUri(response, false);
                if (response.Content.Headers.ContentLength is long length && length != release.ArchiveSize)
                    throw new UpdateException("Размер архива не совпадает с размером в релизе.");
                await using var input = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
                await using var output = new FileStream(archivePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true);
                await CopyLimitedAsync(input, output, release.ArchiveSize, progress, token).ConfigureAwait(false);
                if (output.Length != release.ArchiveSize)
                    throw new UpdateException("Архив обновления скачан не полностью.");
            }
            await VerifyHashAsync(archivePath, hash, token).ConfigureAwait(false);
            var staging = Path.Combine(directory, "files");
            await ExtractAsync(archivePath, staging, token).ConfigureAwait(false);
            File.Delete(archivePath);
            // The parent also belongs to this package and is removed by Dispose.
            foreach (var name in ExpectedFiles)
                if (File.Exists(Path.Combine(staging, name)))
                    File.Move(Path.Combine(staging, name), Path.Combine(directory, name));
            Directory.Delete(staging);
            return new PreparedUpdate(directory, release);
        }
        catch
        {
            TryDeleteDirectory(directory);
            throw;
        }
    }

    public static async Task VerifyHashAsync(string archivePath, string hashFile, CancellationToken cancellationToken = default)
    {
        var parts = hashFile.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length is < 1 or > 2 || parts[0].Length != 64 || !parts[0].All(Uri.IsHexDigit) ||
            (parts.Length == 2 && parts[1] != ArchiveName))
            throw new UpdateException("Некорректный файл SHA-256. Установка запрещена.");
        await using var input = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        var actual = await SHA256.HashDataAsync(input, cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(actual, Convert.FromHexString(parts[0])))
            throw new UpdateException("SHA-256 архива не совпадает. Установка запрещена.");
    }

    public static async Task ExtractAsync(string archivePath, string destination, CancellationToken cancellationToken = default)
    {
        // A private, new directory avoids overwriting files or following pre-existing links.
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new UpdateException("Папка подготовки обновления уже существует.");
        Directory.CreateDirectory(destination);
        try
        {
            await using var input = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
            using var archive = new ZipArchive(input, ZipArchiveMode.Read);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var name = ExpectedFiles.FirstOrDefault(n => string.Equals(n, entry.FullName, StringComparison.OrdinalIgnoreCase));
                if (name == null)
                    continue;
                if (!seen.Add(name))
                    throw new UpdateException("В архиве есть повторяющиеся файлы.");
                var limit = name == "NetWatcher.exe" ? MaximumExecutableSize : 5L * 1024 * 1024;
                if ((name == "NetWatcher.exe" && entry.Length == 0) || entry.Length > limit)
                    throw new UpdateException("Недопустимый размер файла в архиве обновления.");
                await using var source = entry.Open();
                await using var target = new FileStream(Path.Combine(destination, name), FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true);
                await CopyLimitedAsync(source, target, limit, null, cancellationToken).ConfigureAwait(false);
                if (target.Length != entry.Length)
                    throw new UpdateException("Файл в архиве обновления повреждён.");
            }
            if (!seen.Contains("NetWatcher.exe"))
                throw new UpdateException("В архиве нет NetWatcher.exe.");
        }
        catch
        {
            TryDeleteDirectory(destination);
            throw;
        }
    }

    private static async Task CopyLimitedAsync(Stream input, Stream output, long limit,
        IProgress<UpdateProgress>? progress, CancellationToken token)
    {
        var buffer = new byte[81920];
        long total = 0;
        progress?.Report(new UpdateProgress(0, limit));
        int count;
        while ((count = await input.ReadAsync(buffer, token).ConfigureAwait(false)) != 0)
        {
            total += count;
            if (total > limit)
                throw new UpdateException("Размер обновления превышает допустимый.");
            await output.WriteAsync(buffer.AsMemory(0, count), token).ConfigureAwait(false);
            progress?.Report(new UpdateProgress(total, limit));
        }
    }

    private static async Task<string> ReadLimitedAsync(HttpContent content, int limit, CancellationToken token)
    {
        await using var source = await content.ReadAsStreamAsync(token).ConfigureAwait(false);
        using var target = new MemoryStream();
        await CopyLimitedAsync(source, target, limit, null, token).ConfigureAwait(false);
        return Encoding.UTF8.GetString(target.ToArray());
    }

    private static Uri AssetUri(string value, string tag, string name)
    {
        var uri = new Uri(value);
        ValidateRepositoryUri(uri, "/releases/download/");
        if (uri.AbsolutePath != new Uri($"{Repository}/releases/download/{Uri.EscapeDataString(tag)}/{name}").AbsolutePath)
            throw new UpdateException("Ссылка на обновление не относится к этому релизу.");
        return uri;
    }

    private static void ValidateRepositoryUri(Uri uri, string suffix)
    {
        if (uri.Scheme != Uri.UriSchemeHttps || uri.Host != "github.com" || !uri.IsDefaultPort ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            !uri.AbsolutePath.StartsWith("/aeyota93-cloud/NetWatcher" + suffix, StringComparison.Ordinal))
            throw new UpdateException("Недопустимая ссылка на обновление.");
    }

    private static void ValidateResponseUri(HttpResponseMessage response, bool api)
    {
        var uri = response.RequestMessage?.RequestUri;
        if (uri == null || uri.Scheme != Uri.UriSchemeHttps || !uri.IsDefaultPort || uri.UserInfo.Length != 0 ||
            (api ? uri.AbsoluteUri != LatestUrl : uri.Host != "github.com" && uri.Host != "release-assets.githubusercontent.com" && uri.Host != "objects.githubusercontent.com"))
            throw new UpdateException("Недопустимый адрес загрузки обновления.");
        if (!api && uri.Host == "github.com")
            ValidateRepositoryUri(uri, "/releases/download/");
    }

    internal static void TryDeleteDirectory(string path)
    {
        try { Directory.Delete(path, true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
