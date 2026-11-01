using NetWatcher.Core;
using NetWatcher.Core.Alerts;

namespace NetWatcher.App.Monitoring;

/// <summary>
/// Every few seconds looks at what programs did lately and tells the user, through a Windows notification,
/// when a program does something for the first time: goes online, reaches a new country or network.
/// Several events in a row are folded into one notification.
/// </summary>
internal sealed class AlertService(AppState state) : IDisposable
{
    private static readonly TimeSpan CheckEvery = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan NotifyEvery = TimeSpan.FromSeconds(30);

    private readonly CancellationTokenSource _stop = new();
    private readonly Lock _lock = new();
    private readonly List<Novelty> _pending = [];
    private NoveltyDetector? _detector;
    private DateTime _notifiedAt = DateTime.MinValue;
    private DateTimeOffset _checkedUpTo;
    private (int Asn, int Geo) _databases;

    /// <summary>Shows a Windows notification; set by the main window once it has a tray icon.</summary>
    public Action<string, string, bool>? Notify { get; set; }

    /// <summary>Program title for notifications ("Counter-Strike 2" rather than cs2.exe).</summary>
    public Func<string, string>? TitleOf { get; set; }

    public void Start() => _ = Task.Run(() => Loop(_stop.Token));

    /// <summary>After the history is cleared: forget everything and learn again for a day.</summary>
    public void Reset()
    {
        lock (_lock)
        {
            _detector = new NoveltyDetector([]);
            _pending.Clear();
            state.Settings.LearningSince = DateTimeOffset.Now;
            state.SaveSettings();
        }
    }

    private async Task Loop(CancellationToken ct)
    {
        try
        {
            // Countries and networks need their databases; without waiting, every country would look new.
            for (var i = 0; i < 120 && (state.AsnLoading || state.GeoLoading); i++) await Task.Delay(1000, ct).ConfigureAwait(false);
            Prepare();
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            return; // No alerts this run; the rest of the program goes on.
        }

        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(CheckEvery, ct).ConfigureAwait(false);
            try
            {
                Check(DateTimeOffset.Now);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // A failed round is skipped.
            }
        }
    }

    private void Prepare()
    {
        var now = DateTimeOffset.Now;
        var detector = new NoveltyDetector(state.Store.LoadKnown());
        if (detector.KnownCount == 0)
        {
            // First run of this version: learn from the whole log, silently.
            var rows = state.Store.Query(DateTimeOffset.FromUnixTimeMilliseconds(0));
            Analysis.Enrich(rows, state.Dns, state.Asn, new Dictionary<string, string>(), state.Geo);
            detector.Check(rows, AlertOptions.From(state.Settings), false, state.Geo.Count > 0, state.Asn.Count > 0);
            state.Store.AddKnown(detector.TakeAdded(), now);
        }
        if (state.Settings.LearningSince == null)
        {
            // A log older than a day has already shown what is normal.
            state.Settings.LearningSince = state.Store.LogStart() ?? now;
            state.SaveSettings();
        }
        lock (_lock)
        {
            _detector = detector;
            _checkedUpTo = now.AddMinutes(-2);
            _databases = (state.Asn.Count, state.Geo.Count);
        }
    }

    private void Check(DateTimeOffset now)
    {
        List<Novelty>? send = null;
        lock (_lock)
        {
            if (_detector == null) return;
            var rows = state.Store.Query(_checkedUpTo.AddSeconds(-30));
            var asn = state.Asn;
            var geo = state.Geo;
            Analysis.Enrich(rows, state.Dns, asn, new Dictionary<string, string>(), geo);

            // A database just appeared or was updated: learn this round without telling, or every
            // country would be "new".
            var databases = (asn.Count, geo.Count);
            var stable = databases == _databases;
            _databases = databases;

            var learning = state.Settings.LearningSince is { } since && now - since < NoveltyDetector.LearningPeriod;
            var news = _detector.Check(rows, AlertOptions.From(state.Settings), stable && !learning, geo.Count > 0, asn.Count > 0);
            state.Store.AddKnown(_detector.TakeAdded(), now);
            _checkedUpTo = now;

            _pending.AddRange(news);
            if (_pending.Count == 0 || DateTime.UtcNow - _notifiedAt < NotifyEvery || Notify == null) return;
            send = _pending.ToList();
            _pending.Clear();
            _notifiedAt = DateTime.UtcNow;
        }

        // Outside the lock: the title comes from the window's thread, which may be waiting for Reset().
        var (title, text) = NoveltyDetector.Compose(send, key => TitleOf?.Invoke(key) ?? key);
        Notify?.Invoke(title, text, false);
    }

    public void Dispose() => _stop.Cancel();
}
