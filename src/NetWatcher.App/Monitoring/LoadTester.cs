using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetWatcher.Core.Link;

namespace NetWatcher.App.Monitoring;

/// <summary>
/// The active quality test: ping with the line idle, then download and upload as fast as possible for a few
/// seconds each while pinging. Load comes from Cloudflare's speed test servers (speed.cloudflare.com — the
/// same endpoints its open source test uses); results are not sent anywhere.
/// </summary>
internal static class LoadTester
{
    public const string Host = "speed.cloudflare.com";
    public static readonly TimeSpan PhaseTime = TimeSpan.FromSeconds(8);
    public const long MaxDownBytes = 250_000_000, MaxUpBytes = 100_000_000;
    private const int Streams = 4;
    private const int DownChunk = 25_000_000, UpChunk = 10_000_000;

    public static async Task<LoadTestResult> RunAsync(IProgress<string> progress, CancellationToken ct)
    {
        progress.Report("Ищу сервер…");
        var addresses = await Dns.GetHostAddressesAsync(Host, ct).ConfigureAwait(false);
        var target = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault()
                     ?? throw new InvalidOperationException("Не удалось узнать адрес " + Host);

        using var http = new HttpClient(new SocketsHttpHandler
        {
            MaxConnectionsPerServer = Streams * 2,
            AutomaticDecompression = DecompressionMethods.None,
            PooledConnectionLifetime = TimeSpan.FromMinutes(1),
        })
        { Timeout = Timeout.InfiniteTimeSpan };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("NetWatcher/" + Native.AppInfo.Version);

        progress.Report("Задержка без нагрузки…");
        var idle = new List<double?>();
        for (var i = 0; i < 20; i++)
        {
            idle.Add(await PingAsync(target, ct).ConfigureAwait(false));
            await Task.Delay(250, ct).ConfigureAwait(false);
        }

        progress.Report("Скачивание: нагружаю линию…");
        var (downRate, downBytes, downPings) = await Phase(target, ct, async (count, stop) =>
        {
            while (!stop.IsCancellationRequested && Interlocked.Read(ref count.Value) < MaxDownBytes)
            {
                using var response = await http.GetAsync($"https://{Host}/__down?bytes={DownChunk}", HttpCompletionOption.ResponseHeadersRead, stop).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                await using var stream = await response.Content.ReadAsStreamAsync(stop).ConfigureAwait(false);
                var buffer = new byte[64 * 1024];
                int n;
                while ((n = await stream.ReadAsync(buffer, stop).ConfigureAwait(false)) > 0)
                {
                    if (Interlocked.Add(ref count.Value, n) >= MaxDownBytes) return;
                }
            }
        }).ConfigureAwait(false);

        progress.Report("Отправка: нагружаю линию…");
        var (upRate, upBytes, upPings) = await Phase(target, ct, async (count, stop) =>
        {
            while (!stop.IsCancellationRequested && Interlocked.Read(ref count.Value) < MaxUpBytes)
            {
                using var content = new CountingContent(UpChunk, n => Interlocked.Add(ref count.Value, n));
                using var response = await http.PostAsync($"https://{Host}/__up", content, stop).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
            }
        }).ConfigureAwait(false);

        return new LoadTestResult(DateTimeOffset.Now, $"{Host} ({target})", LoadTestMath.Stats(idle),
            downRate, upRate, LoadTestMath.Stats(downPings), LoadTestMath.Stats(upPings), downBytes, upBytes);
    }

    private sealed class Counter
    {
        public long Value;
    }

    /// <summary>Runs the transfer in several streams for the phase time while pinging every 400 ms (as Cloudflare's test does).</summary>
    private static async Task<(double? Rate, long Bytes, List<double?> Pings)> Phase(IPAddress target, CancellationToken ct, Func<Counter, CancellationToken, Task> transfer)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        stop.CancelAfter(PhaseTime);
        var count = new Counter();
        var samples = new List<(double Seconds, long Bytes)>();
        var pings = new List<double?>();
        var clock = Stopwatch.StartNew();
        var errors = new List<Exception>();

        async Task Stream()
        {
            try
            {
                await transfer(count, stop.Token).ConfigureAwait(false);
            }
            catch (Exception) when (stop.IsCancellationRequested)
            {
                // The phase is over: requests in flight are cut off.
            }
            catch (Exception e) when (e is HttpRequestException or IOException)
            {
                lock (errors) errors.Add(e);
            }
        }

        async Task Sample()
        {
            while (!stop.IsCancellationRequested)
            {
                samples.Add((clock.Elapsed.TotalSeconds, Interlocked.Read(ref count.Value)));
                try
                {
                    await Task.Delay(200, stop.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
            samples.Add((clock.Elapsed.TotalSeconds, Interlocked.Read(ref count.Value)));
        }

        async Task Ping()
        {
            // Let the queues fill first.
            try
            {
                await Task.Delay(1000, stop.Token).ConfigureAwait(false);
                while (!stop.IsCancellationRequested)
                {
                    pings.Add(await PingAsync(target, stop.Token).ConfigureAwait(false));
                    await Task.Delay(400, stop.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // The phase is over.
            }
        }

        var streams = Enumerable.Range(0, Streams).Select(_ => Stream()).ToList();
        var sampler = Sample();
        var pinger = Ping();
        await Task.WhenAll(streams).ConfigureAwait(false);
        // All streams may end early (byte limit or errors): stop sampling and pinging then.
        stop.Cancel();
        await Task.WhenAll(sampler, pinger).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (count.Value == 0 && errors.Count > 0) throw new HttpRequestException("Сервер теста не ответил: " + errors[0].Message, errors[0]);
        return (LoadTestMath.Rate(samples, 2), count.Value, pings);
    }

    private static async Task<double?> PingAsync(IPAddress target, CancellationToken ct)
    {
        using var ping = new Ping();
        try
        {
            var r = await ping.SendPingAsync(target, TimeSpan.FromSeconds(1), new byte[32], null, ct).ConfigureAwait(false);
            return r.Status == IPStatus.Success ? r.RoundtripTime : null;
        }
        catch (PingException)
        {
            return null;
        }
    }

    /// <summary>
    /// Upload body of zeros (as Cloudflare's test sends) that counts what was handed to the network. The byte
    /// limit is checked between requests: a body cut short would not match its declared length.
    /// </summary>
    private sealed class CountingContent(long size, Action<int> written) : HttpContent
    {
        private static readonly byte[] Zeros = new byte[64 * 1024];

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            long sent = 0;
            while (sent < size)
            {
                var n = (int)Math.Min(Zeros.Length, size - sent);
                await stream.WriteAsync(Zeros.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                sent += n;
                written(n);
            }
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override bool TryComputeLength(out long length)
        {
            length = size;
            return true;
        }
    }
}
