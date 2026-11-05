using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using NetWatcher.Core.Link;

namespace NetWatcher.App.Views;

/// <summary>
/// Latency line, loss bars and red bands where the link was down. The compact variant is a narrow strip with
/// only the top of the scale; the mini variant (for cards) draws only bars. Hovering shows the moment's numbers.
/// </summary>
public sealed class LinkChart : FrameworkElement
{
    public static readonly DependencyProperty PointsProperty = DependencyProperty.Register(
        nameof(Points), typeof(IReadOnlyList<ChartPoint>), typeof(LinkChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MiniProperty = DependencyProperty.Register(
        nameof(Mini), typeof(bool), typeof(LinkChart),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public IReadOnlyList<ChartPoint>? Points
    {
        get => (IReadOnlyList<ChartPoint>?)GetValue(PointsProperty);
        set => SetValue(PointsProperty, value);
    }

    public bool Mini
    {
        get => (bool)GetValue(MiniProperty);
        set => SetValue(MiniProperty, value);
    }

    public static readonly DependencyProperty CompactProperty = DependencyProperty.Register(
        nameof(Compact), typeof(bool), typeof(LinkChart),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>A narrow strip: no axes, the top of the scale written inside the plot.</summary>
    public bool Compact
    {
        get => (bool)GetValue(CompactProperty);
        set => SetValue(CompactProperty, value);
    }

    private readonly ToolTip _tip = new();

    // Plot margins of the full and compact layouts; the hover maths uses the same ones.
    private (double Left, double Right, double Top, double Bottom) Margins => Compact ? (4, 4, 3, 3) : (64, 40, 8, 26);

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var pts = Points;
        if (Mini || pts == null || pts.Count == 0) return;
        if (ToolTip == null)
        {
            ToolTip = _tip;
            ToolTipService.SetInitialShowDelay(this, 150);
        }
        var (left, right, _, _) = Margins;
        var plotW = ActualWidth - left - right;
        if (plotW <= 0) return;
        var i = (int)Math.Round((e.GetPosition(this).X - left) / plotW * Math.Max(1, pts.Count - 1));
        var p = pts[Math.Clamp(i, 0, pts.Count - 1)];
        var parts = new List<string> { p.Time.LocalDateTime.ToString("HH:mm:ss") };
        parts.Add(p.Down ? "нет связи" : p.LatencyMs is { } ms ? $"задержка {ms:0} мс" : "задержка не измерена");
        if (p.LossPercent > 0) parts.Add($"потери {p.LossPercent:0}%");
        _tip.Content = string.Join(" · ", parts);
    }

    private Brush Res(string key, string fallback) =>
        TryFindResource(key) as Brush ?? (Brush)new BrushConverter().ConvertFromString(fallback)!;

    protected override void OnRender(DrawingContext dc)
    {
        var pts = Points;
        var w = ActualWidth;
        var h = ActualHeight;
        if (pts == null || pts.Count == 0 || w < 20 || h < 10) return;
        // A transparent fill catches the mouse everywhere, not only over the drawn lines (for the hover tooltip).
        if (!Mini) dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));

        var accent = Res("AccentBrush", "#0F6CBD");
        var warn = Res("LossBrush", "#C27C0E");
        var danger = Res("DangerBrush", "#C42B1C");
        var grid = Res("StrokeBrush", "#E5E5E5");
        var text = Res("Text3Brush", "#8A8A8A");
        var dip = VisualTreeHelper.GetDpi(this).PixelsPerDip;

        if (Mini)
        {
            RenderMini(dc, pts, w, h, accent, warn, danger);
            return;
        }

        var (left, right, top, bottom) = Margins;
        var compact = Compact;
        var plotW = w - left - right;
        var plotH = h - bottom - top;
        if (plotW <= 0 || plotH <= 0) return;
        var max = pts.Where(p => p.LatencyMs != null).Select(p => p.LatencyMs!.Value).DefaultIfEmpty(0).Max();
        var scale = Math.Max(100, Math.Ceiling(max / 50) * 50);
        double X(int i) => left + i * plotW / Math.Max(1, pts.Count - 1);
        double Y(double v) => top + plotH - v / scale * plotH;

        FormattedText Label(string s) => new(s, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
            new Typeface("Segoe UI"), 10, text, dip);

        // Grid and scale: the full chart has axes; the strip only a baseline.
        var pen = new Pen(grid, 1);
        if (compact)
        {
            var y0 = Math.Round(Y(0)) + 0.5;
            dc.DrawLine(pen, new Point(left, y0), new Point(w - right, y0));
        }
        else
        {
            for (var v = 0.0; v <= scale; v += scale / 3)
            {
                var y = Math.Round(Y(v)) + 0.5;
                dc.DrawLine(pen, new Point(left, y), new Point(w - right, y));
                var l = Label($"{v:0} мс");
                dc.DrawText(l, new Point(left - 6 - l.Width, y - l.Height / 2));
            }

            // Loss scale uses the full plot height, independently of latency.
            for (var loss = 0; loss <= 100; loss += 50)
            {
                var l = Label($"{loss}%");
                l.SetForegroundBrush(warn);
                var y = top + plotH - loss / 100.0 * plotH;
                dc.DrawText(l, new Point(w - right + 6, y - l.Height / 2));
            }
        }

        dc.PushClip(new RectangleGeometry(new Rect(left, top, plotW, plotH)));

        // Bands where the link was down.
        var band = danger.Clone();
        band.Opacity = 0.16;
        for (var i = 0; i < pts.Count; i++)
        {
            if (!pts[i].Down) continue;
            var x0 = X(i) - plotW / pts.Count / 2;
            dc.DrawRectangle(band, null, new Rect(x0, top, plotW / pts.Count + 0.5, plotH));
        }

        // Loss bars (100% fills the plot height).
        var barW = Math.Max(2, plotW / pts.Count * 0.6);
        for (var i = 0; i < pts.Count; i++)
        {
            if (pts[i].LossPercent <= 0) continue;
            var bh = Math.Min(plotH, pts[i].LossPercent / 100 * plotH);
            dc.DrawRectangle(warn, null, new Rect(X(i) - barW / 2, top + plotH - bh, barW, bh));
        }

        // Latency line, broken where there is no data.
        var line = new Pen(accent, 1.8) { LineJoin = PenLineJoin.Round };
        Point? prev = null;
        for (var i = 0; i < pts.Count; i++)
        {
            if (pts[i].LatencyMs is not { } ms || pts[i].Down)
            {
                prev = null;
                continue;
            }
            var p = new Point(X(i), Y(ms));
            if (prev is { } a) dc.DrawLine(line, a, p);
            else dc.DrawEllipse(accent, null, p, 1.2, 1.2);
            prev = p;
        }

        dc.Pop();

        if (compact)
        {
            // The top of the scale, so the line's height means something; the time span is in the title.
            var topLabel = Label($"до {scale:0} мс");
            dc.DrawText(topLabel, new Point(w - right - topLabel.Width - 2, top));
            return;
        }

        // Time axis.
        var span = pts[^1].Time - pts[0].Time;
        var first = Label($"−{Math.Round(span.TotalMinutes)} мин");
        dc.DrawText(first, new Point(left, h - first.Height));
        var lastL = Label("сейчас");
        dc.DrawText(lastL, new Point(w - right - lastL.Width, h - lastL.Height));
    }

    /// <summary>
    /// Card chart: a bar only where there was traffic. Height follows latency when the server
    /// answers ping, otherwise the amount of traffic; amber for loss, red where the link was down.
    /// </summary>
    private static void RenderMini(DrawingContext dc, IReadOnlyList<ChartPoint> pts, double w, double h, Brush accent, Brush loss, Brush danger)
    {
        var maxLat = pts.Where(p => p.LatencyMs != null).Select(p => p.LatencyMs!.Value).DefaultIfEmpty(0).Max();
        var maxPk = Math.Log10(1 + pts.Select(p => p.Packets).DefaultIfEmpty(0).Max());
        var step = w / pts.Count;
        var bar = Math.Max(1.5, step * 0.62);
        var normal = accent.Clone();
        normal.Opacity = 0.7;
        var down = danger.Clone();
        down.Opacity = 0.45;
        for (var i = 0; i < pts.Count; i++)
        {
            var p = pts[i];
            if (p.Packets == 0 && !p.Down) continue;
            Brush brush = normal;
            double bh;
            if (p.Down)
            {
                brush = down;
                bh = h;
            }
            else if (p.LatencyMs is { } ms && maxLat > 0)
                bh = h * (0.3 + 0.7 * ms / maxLat);
            else
                bh = maxPk > 0 ? h * (0.25 + 0.75 * Math.Log10(1 + p.Packets) / maxPk) : h * 0.4;
            if (!p.Down && p.LossPercent >= 5) brush = loss;
            dc.DrawRectangle(brush, null, new Rect(i * step, h - bh, bar, bh));
        }
    }
}
