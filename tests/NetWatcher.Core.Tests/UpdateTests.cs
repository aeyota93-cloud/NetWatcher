using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NetWatcher.Core.Update;

namespace NetWatcher.Core.Tests;

public sealed class UpdateTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "NetWatcher-update-tests", Guid.NewGuid().ToString("N"));

    public UpdateTests() => Directory.CreateDirectory(_directory);

    private static string ReleaseJson(bool draft = false, bool prerelease = false, bool hash = true,
        long size = 1234, string repository = "aeyota93-cloud/NetWatcher") => JsonSerializer.Serialize(new
    {
        tag_name = "v0.8.0",
        name = "NetWatcher 0.8.0",
        body = "Исправления и улучшения",
        draft,
        prerelease,
        published_at = "2026-10-30T12:00:00Z",
        html_url = $"https://github.com/{repository}/releases/tag/v0.8.0",
        assets = new[]
        {
            new { name = UpdateClient.ArchiveName, browser_download_url = $"https://github.com/{repository}/releases/download/v0.8.0/{UpdateClient.ArchiveName}", size },
            new { name = hash ? UpdateClient.HashName : "other.txt", browser_download_url = $"https://github.com/{repository}/releases/download/v0.8.0/{UpdateClient.HashName}", size = 100L }
        }
    });

    [Fact]
    public void Release_fields_are_parsed()
    {
        var release = Assert.IsType<UpdateRelease>(UpdateClient.ParseRelease(ReleaseJson()));
        Assert.Equal(new Version(0, 8, 0), release.Version);
        Assert.Equal("v0.8.0", release.Tag);
        Assert.Equal("NetWatcher 0.8.0", release.Name);
        Assert.Equal("Исправления и улучшения", release.Changes);
        Assert.Equal(DateTimeOffset.Parse("2026-10-30T12:00:00Z"), release.PublishedAt);
        Assert.Equal(1234, release.ArchiveSize);
        Assert.EndsWith(UpdateClient.ArchiveName, release.ArchiveUrl.AbsoluteUri);
        Assert.EndsWith(UpdateClient.HashName, release.HashUrl.AbsoluteUri);
        Assert.EndsWith("/releases/tag/v0.8.0", release.HtmlUrl.AbsoluteUri);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void Unpublished_releases_are_ignored(bool draft, bool prerelease) =>
        Assert.Null(UpdateClient.ParseRelease(ReleaseJson(draft, prerelease)));

    [Fact]
    public void Missing_hash_prohibits_update() =>
        Assert.Contains("SHA-256", Assert.Throws<UpdateException>(() => UpdateClient.ParseRelease(ReleaseJson(hash: false))).Message);

    [Theory]
    [InlineData("https://github.com/aeyota93-cloud/NetWatcher", "http://github.com/aeyota93-cloud/NetWatcher")]
    [InlineData("https://github.com/aeyota93-cloud/NetWatcher", "https://github.com/other/NetWatcher")]
    [InlineData("releases/download/v0.8.0/", "releases/download/v0.9.0/")]
    [InlineData("https://github.com/", "https://github.com.evil.example/")]
    public void Foreign_or_insecure_asset_urls_are_rejected(string from, string to) =>
        Assert.Throws<UpdateException>(() => UpdateClient.ParseRelease(ReleaseJson().Replace(from, to, StringComparison.Ordinal)));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(UpdateClient.MaximumArchiveSize + 1)]
    public void Invalid_archive_sizes_are_rejected(long size) =>
        Assert.Throws<UpdateException>(() => UpdateClient.ParseRelease(ReleaseJson(size: size)));

    [Theory]
    [InlineData("0.7.1", "v0.7.1", 0)]
    [InlineData("0.7.1+abc", "v0.8.0", -1)]
    [InlineData("0.10.0", "v0.9.9", 1)]
    [InlineData("1.0.0-beta+abc", "v1.0.0+def", 0)]
    [InlineData("2.0.0", "v1.99.99", 1)]
    [InlineData("0.8.0", "v0.8.1-rc.1", -1)]
    public void Versions_are_compared_numerically(string current, string available, int expected) =>
        Assert.Equal(expected, Math.Sign(UpdateClient.CompareVersions(current, available)));

    [Theory]
    [InlineData("0.8")]
    [InlineData("1.2.3.4")]
    [InlineData("x.1.2")]
    public void Invalid_versions_are_rejected(string version) =>
        Assert.Throws<UpdateException>(() => UpdateClient.ParseVersion(version));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Hash_accepts_both_formats_and_case(bool withName)
    {
        var path = Path.Combine(_directory, "archive.zip");
        await File.WriteAllTextAsync(path, "archive contents");
        var hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path)));
        await UpdateClient.VerifyHashAsync(path, withName ? hash.ToLowerInvariant() + "  " + UpdateClient.ArchiveName + "\r\n" : hash);
    }

    [Theory]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("")]
    [InlineData("bad hash")]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000000  other.zip")]
    public async Task Wrong_or_missing_hash_is_rejected(string hash)
    {
        var path = Path.Combine(_directory, "archive.zip");
        await File.WriteAllTextAsync(path, "archive contents");
        await Assert.ThrowsAsync<UpdateException>(() => UpdateClient.VerifyHashAsync(path, hash));
    }

    private byte[] Archive(params (string Name, string Content)[] entries)
    {
        using var memory = new MemoryStream();
        using (var zip = new ZipArchive(memory, ZipArchiveMode.Create, true))
            foreach (var (name, content) in entries)
            {
                using var writer = new StreamWriter(zip.CreateEntry(name).Open());
                writer.Write(content);
            }
        return memory.ToArray();
    }

    [Fact]
    public async Task Extraction_allows_only_expected_root_files()
    {
        var archive = Path.Combine(_directory, "test.zip");
        await File.WriteAllBytesAsync(archive, Archive(("NetWatcher.exe", "new exe"), ("README.md", "readme"),
            ("THIRD-PARTY-NOTICES.md", "notices"), ("../outside.txt", "attack"), ("sub/NetWatcher.exe", "attack"),
            ("..\\outside.txt", "attack"), ("C:/outside.txt", "attack"), ("settings.json", "attack")));
        var destination = Path.Combine(_directory, "extracted");
        await UpdateClient.ExtractAsync(archive, destination);
        Assert.Equal(3, Directory.GetFiles(destination).Length);
        Assert.Equal("new exe", await File.ReadAllTextAsync(Path.Combine(destination, "NetWatcher.exe")));
        Assert.Equal("readme", await File.ReadAllTextAsync(Path.Combine(destination, "README.md")));
        Assert.Equal("notices", await File.ReadAllTextAsync(Path.Combine(destination, "THIRD-PARTY-NOTICES.md")));
        Assert.False(File.Exists(Path.Combine(_directory, "outside.txt")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Missing_or_duplicate_executable_is_rejected_and_cleaned(bool duplicate)
    {
        var archive = Path.Combine(_directory, "test.zip");
        await File.WriteAllBytesAsync(archive, duplicate
            ? Archive(("NetWatcher.exe", "exe"), ("netwatcher.exe", "duplicate"))
            : Archive(("sub/NetWatcher.exe", "exe")));
        var destination = Path.Combine(_directory, "extracted");
        await Assert.ThrowsAsync<UpdateException>(() => UpdateClient.ExtractAsync(archive, destination));
        Assert.False(Directory.Exists(destination));
    }

    [Fact]
    public async Task Oversized_executable_is_rejected_without_extracting()
    {
        var bytes = Archive(("NetWatcher.exe", "exe"));
        // Set the declared uncompressed size in the central directory without allocating 300 MB.
        var signature = new byte[] { 0x50, 0x4b, 0x01, 0x02 };
        var offset = Enumerable.Range(0, bytes.Length - 3).Single(i => bytes.AsSpan(i, 4).SequenceEqual(signature));
        BitConverter.GetBytes((uint)(UpdateClient.MaximumExecutableSize + 1)).CopyTo(bytes, offset + 24);
        var path = Path.Combine(_directory, "large.zip");
        await File.WriteAllBytesAsync(path, bytes);
        var destination = Path.Combine(_directory, "extracted");
        await Assert.ThrowsAsync<UpdateException>(() => UpdateClient.ExtractAsync(path, destination));
        Assert.False(Directory.Exists(destination));
    }

    [Theory]
    [InlineData("0.7.1+abc", true)]
    [InlineData("0.8.0", false)]
    [InlineData("0.9.0", false)]
    public async Task Check_reports_availability(string version, bool expected)
    {
        using var http = new HttpClient(new Handler(_ => new StringContent(ReleaseJson())));
        var result = await new UpdateClient(http).CheckAsync(version);
        Assert.Equal(expected, result.IsUpdateAvailable);
    }

    [Fact]
    public async Task Check_honors_cancellation()
    {
        using var http = new HttpClient(new Handler(_ => new StringContent(ReleaseJson())));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new UpdateClient(http).CheckAsync("0.7.1", cancelled.Token));
    }

    [Theory]
    [InlineData("success")]
    [InlineData("hash")]
    [InlineData("short")]
    [InlineData("long")]
    [InlineData("cancel")]
    public async Task Download_validates_size_hash_and_cancellation_and_cleans_up(string mode)
    {
        var bytes = Archive(("NetWatcher.exe", "exe"), ("README.md", "readme"));
        var release = UpdateClient.ParseRelease(ReleaseJson(size: bytes.Length))!;
        using var cancelled = new CancellationTokenSource();
        string? tempDirectory = null;
        var progress = new ProgressSink(p =>
        {
            Assert.InRange(p.BytesReceived, 0, bytes.Length);
            // Observe the unique directory while it exists, for failure cleanup assertions.
            tempDirectory ??= Directory.GetDirectories(Path.Combine(Path.GetTempPath(), "NetWatcher-update"))
                .Single(d => File.Exists(Path.Combine(d, UpdateClient.ArchiveName)));
            if (mode == "cancel") cancelled.Cancel();
        });
        using var http = new HttpClient(new Handler(uri => uri.AbsolutePath.EndsWith(".sha256", StringComparison.Ordinal)
            ? new StringContent(mode == "hash" ? new string('0', 64) : Convert.ToHexString(SHA256.HashData(bytes)))
            : new UnknownLengthContent(mode == "short" ? bytes[..^1] : mode == "long" ? [.. bytes, 0] : bytes)));
        var client = new UpdateClient(http);
        if (mode == "success")
        {
            var prepared = await client.DownloadAsync(release, progress, cancelled.Token);
            Assert.Equal("exe", await File.ReadAllTextAsync(prepared.ExecutablePath));
            Assert.False(File.Exists(Path.Combine(prepared.DirectoryPath, UpdateClient.ArchiveName)));
            tempDirectory = prepared.DirectoryPath;
            prepared.Dispose();
        }
        else if (mode == "cancel")
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.DownloadAsync(release, progress, cancelled.Token));
        else
            await Assert.ThrowsAsync<UpdateException>(() => client.DownloadAsync(release, progress, cancelled.Token));
        if (tempDirectory != null) Assert.False(Directory.Exists(tempDirectory));
    }

    private sealed class ProgressSink(Action<UpdateProgress> report) : IProgress<UpdateProgress>
    {
        public void Report(UpdateProgress value) => report(value);
    }

    private sealed class UnknownLengthContent(byte[] bytes) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(bytes).AsTask();

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class Handler(Func<Uri, HttpContent> content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = content(request.RequestUri!)
            });
        }
    }

    public void Dispose() => Directory.Delete(_directory, true);
}
