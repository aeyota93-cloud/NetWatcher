namespace NetWatcher.Core.Update;

public sealed class UpdateException(string message, Exception? innerException = null)
    : Exception(message, innerException);

public sealed record UpdateRelease
{
    internal UpdateRelease(Version version, string tag, string name, Uri archiveUrl, Uri hashUrl,
        long archiveSize, string changes, DateTimeOffset? publishedAt, Uri htmlUrl)
    {
        Version = version;
        Tag = tag;
        Name = name;
        ArchiveUrl = archiveUrl;
        HashUrl = hashUrl;
        ArchiveSize = archiveSize;
        Changes = changes;
        PublishedAt = publishedAt;
        HtmlUrl = htmlUrl;
    }

    public Version Version { get; }
    public string Tag { get; }
    public string Name { get; }
    public Uri ArchiveUrl { get; }
    public Uri HashUrl { get; }
    public long ArchiveSize { get; }
    public string Changes { get; }
    public DateTimeOffset? PublishedAt { get; }
    public Uri HtmlUrl { get; }
}

public sealed record UpdateCheckResult(bool IsUpdateAvailable, UpdateRelease? Release);

public sealed record UpdateProgress(long BytesReceived, long TotalBytes)
{
    public double Percent => TotalBytes == 0 ? 0 : 100.0 * BytesReceived / TotalBytes;
}

// Keep this object alive until installation finishes; disposing it removes the staging files.
public sealed class PreparedUpdate : IDisposable
{
    internal PreparedUpdate(string directoryPath, UpdateRelease release)
    {
        DirectoryPath = directoryPath;
        Release = release;
    }

    public string DirectoryPath { get; }
    public string ExecutablePath => Path.Combine(DirectoryPath, "NetWatcher.exe");
    public UpdateRelease Release { get; }

    public void Dispose() => UpdateClient.TryDeleteDirectory(DirectoryPath);
}
