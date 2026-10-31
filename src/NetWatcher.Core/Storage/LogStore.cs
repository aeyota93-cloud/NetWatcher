using System.Net;
using Microsoft.Data.Sqlite;
using NetWatcher.Core.Dns;
using NetWatcher.Core.Net;

namespace NetWatcher.Core.Storage;

/// <summary>
/// History in one SQLite file. Sightings are folded per hour: one row per
/// (hour, process, services, protocol, address, port) with first/last time and a counter.
/// This keeps a week of a busy computer at a few megabytes.
/// </summary>
public sealed class LogStore : IDisposable
{
    private readonly SqliteConnection _db;
    private readonly Lock _lock = new();

    public string Path { get; }

    public LogStore(string path)
    {
        Path = path;
        var dir = System.IO.Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        _db.Open();
        Exec("PRAGMA journal_mode=WAL;");
        Exec("PRAGMA synchronous=NORMAL;");
        Exec("""
            CREATE TABLE IF NOT EXISTS seen(
              bucket      INTEGER NOT NULL,
              process     TEXT    NOT NULL,
              services    TEXT    NOT NULL,
              proto       TEXT    NOT NULL,
              remote_ip   TEXT    NOT NULL,
              remote_port INTEGER NOT NULL,
              path        TEXT    NOT NULL,
              first_seen  INTEGER NOT NULL,
              last_seen   INTEGER NOT NULL,
              hits        INTEGER NOT NULL,
              PRIMARY KEY(bucket, process, services, proto, remote_ip, remote_port)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS seen_last ON seen(last_seen);
            CREATE TABLE IF NOT EXISTS dns(
              ip         TEXT    NOT NULL,
              domain     TEXT    NOT NULL,
              process    TEXT    NOT NULL,
              first_seen INTEGER NOT NULL,
              last_seen  INTEGER NOT NULL,
              PRIMARY KEY(ip, domain, process)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS dns_last ON dns(last_seen);
            """);
    }

    public void Write(IReadOnlyCollection<Observation> seen, IReadOnlyCollection<DnsObservation> dns)
    {
        if (seen.Count == 0 && dns.Count == 0) return;
        lock (_lock)
        {
            using var tx = _db.BeginTransaction();

            using (var cmd = _db.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO seen(bucket, process, services, proto, remote_ip, remote_port, path, first_seen, last_seen, hits)
                    VALUES($b, $p, $s, $pr, $ip, $port, $path, $t, $t, 1)
                    ON CONFLICT(bucket, process, services, proto, remote_ip, remote_port) DO UPDATE SET
                      last_seen = max(last_seen, excluded.last_seen),
                      first_seen = min(first_seen, excluded.first_seen),
                      hits = hits + 1,
                      path = CASE WHEN excluded.path <> '' THEN excluded.path ELSE path END;
                    """;
                var b = cmd.Parameters.Add("$b", SqliteType.Integer);
                var p = cmd.Parameters.Add("$p", SqliteType.Text);
                var s = cmd.Parameters.Add("$s", SqliteType.Text);
                var pr = cmd.Parameters.Add("$pr", SqliteType.Text);
                var ip = cmd.Parameters.Add("$ip", SqliteType.Text);
                var port = cmd.Parameters.Add("$port", SqliteType.Integer);
                var path = cmd.Parameters.Add("$path", SqliteType.Text);
                var t = cmd.Parameters.Add("$t", SqliteType.Integer);
                foreach (var o in seen)
                {
                    var ms = o.Time.ToUnixTimeMilliseconds();
                    b.Value = ms / 3_600_000;
                    p.Value = o.Process;
                    s.Value = o.Services;
                    pr.Value = o.Proto;
                    ip.Value = IpKey.Normalize(o.RemoteIp).ToString();
                    port.Value = o.RemotePort;
                    path.Value = o.Path;
                    t.Value = ms;
                    cmd.ExecuteNonQuery();
                }
            }

            using (var cmd = _db.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO dns(ip, domain, process, first_seen, last_seen) VALUES($ip, $d, $p, $t, $t)
                    ON CONFLICT(ip, domain, process) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen);
                    """;
                var ip = cmd.Parameters.Add("$ip", SqliteType.Text);
                var d = cmd.Parameters.Add("$d", SqliteType.Text);
                var p = cmd.Parameters.Add("$p", SqliteType.Text);
                var t = cmd.Parameters.Add("$t", SqliteType.Integer);
                foreach (var o in dns)
                {
                    ip.Value = IpKey.Normalize(o.Ip).ToString();
                    d.Value = DnsResultParser.NormalizeName(o.Domain);
                    p.Value = o.Process;
                    t.Value = o.Time.ToUnixTimeMilliseconds();
                    cmd.ExecuteNonQuery();
                }
            }

            tx.Commit();
        }
    }

    /// <summary>Destinations seen since <paramref name="from"/>, folded over the whole period.</summary>
    public List<DestinationRow> Query(DateTimeOffset from)
    {
        var rows = new List<DestinationRow>();
        lock (_lock)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = """
                SELECT process, services, proto, remote_ip, remote_port, max(path),
                       min(first_seen), max(last_seen), sum(hits)
                FROM seen
                WHERE last_seen >= $from
                GROUP BY process, services, proto, remote_ip, remote_port
                """;
            cmd.Parameters.AddWithValue("$from", from.ToUnixTimeMilliseconds());
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                if (!IpKey.TryParse(r.GetString(3), out var ip)) continue;
                rows.Add(new DestinationRow
                {
                    Process = r.GetString(0),
                    Services = r.GetString(1),
                    Proto = r.GetString(2),
                    RemoteIp = ip,
                    RemotePort = r.GetInt32(4),
                    Path = r.IsDBNull(5) ? "" : r.GetString(5),
                    FirstSeen = DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(6)).ToLocalTime(),
                    LastSeen = DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(7)).ToLocalTime(),
                    Hits = r.GetInt64(8),
                });
            }
        }
        return rows;
    }

    /// <summary>When each destination (by <see cref="DestinationRow.Key"/>) was first seen, over the whole log.</summary>
    public Dictionary<string, DateTimeOffset> FirstSeenByRow()
    {
        var result = new Dictionary<string, DateTimeOffset>();
        lock (_lock)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = """
                SELECT process, services, proto, remote_ip, remote_port, min(first_seen)
                FROM seen GROUP BY process, services, proto, remote_ip, remote_port
                """;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var group = r.GetString(1) == "" ? r.GetString(0) : $"{r.GetString(0)} · {r.GetString(1)}";
                result[$"{group}|{r.GetString(2)}|{r.GetString(3)}|{r.GetInt32(4)}"] = DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(5));
            }
        }
        return result;
    }

    /// <summary>The oldest moment in the log, or null when it is empty.</summary>
    public DateTimeOffset? LogStart()
    {
        lock (_lock)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "SELECT min(first_seen) FROM seen";
            return cmd.ExecuteScalar() is long ms ? DateTimeOffset.FromUnixTimeMilliseconds(ms) : null;
        }
    }

    /// <summary>
    /// Activity per group for the last <paramref name="hours"/> hours: how many destinations
    /// were active in each hour, oldest hour first.
    /// </summary>
    public Dictionary<string, int[]> Activity(DateTimeOffset now, int hours)
    {
        var result = new Dictionary<string, int[]>();
        var last = now.ToUnixTimeMilliseconds() / 3_600_000;
        var first = last - hours + 1;
        lock (_lock)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = """
                SELECT process, services, bucket, count(*) FROM seen
                WHERE bucket >= $b GROUP BY process, services, bucket
                """;
            cmd.Parameters.AddWithValue("$b", first);
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var group = r.GetString(1) == "" ? r.GetString(0) : $"{r.GetString(0)} · {r.GetString(1)}";
                if (!result.TryGetValue(group, out var bars)) result[group] = bars = new int[hours];
                var i = (int)(r.GetInt64(2) - first);
                if (i >= 0 && i < hours) bars[i] = r.GetInt32(3);
            }
        }
        return result;
    }

    /// <summary>Fills an index with every stored DNS answer, so domains survive a restart.</summary>
    public void LoadDns(DnsIndex index)
    {
        lock (_lock)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "SELECT ip, domain, process, last_seen FROM dns";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                if (IpKey.TryParse(r.GetString(0), out var ip))
                    index.Add(ip, r.GetString(1), r.GetString(2), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(3)));
            }
        }
    }

    /// <summary>Deletes everything last seen before the cutoff. Returns the number of rows removed.</summary>
    public int Purge(DateTimeOffset cutoff)
    {
        lock (_lock)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "DELETE FROM seen WHERE last_seen < $c; DELETE FROM dns WHERE last_seen < $c;";
            cmd.Parameters.AddWithValue("$c", cutoff.ToUnixTimeMilliseconds());
            var n = cmd.ExecuteNonQuery();
            if (n > 0) Exec("PRAGMA wal_checkpoint(TRUNCATE);");
            return n;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            Exec("DELETE FROM seen; DELETE FROM dns;");
            Exec("VACUUM;");
        }
    }

    public long SizeBytes
    {
        get
        {
            long size = 0;
            foreach (var f in new[] { Path, Path + "-wal" })
                if (File.Exists(f)) size += new FileInfo(f).Length;
            return size;
        }
    }

    private void Exec(string sql)
    {
        using var cmd = _db.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    public void Dispose()
    {
        lock (_lock) _db.Dispose();
    }
}
