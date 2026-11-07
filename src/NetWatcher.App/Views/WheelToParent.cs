using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace NetWatcher.App.Views;

/// <summary>
/// A list that does not scroll by itself still takes the mouse wheel, so the page around it stays still.
/// With <c>Enabled</c> on, the wheel goes on to the parent and the page scrolls.
/// </summary>
public static class WheelToParent
{
    public static readonly DependencyProperty EnabledProperty = DependencyProperty.RegisterAttached(
        "Enabled", typeof(bool), typeof(WheelToParent), new PropertyMetadata(false, OnEnabledChanged));

    public static bool GetEnabled(DependencyObject element) => (bool)element.GetValue(EnabledProperty);

    public static void SetEnabled(DependencyObject element, bool value) => element.SetValue(EnabledProperty, value);

    private static void OnEnabledChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not UIElement ui) return;
        ui.PreviewMouseWheel -= OnWheel;
        if (e.NewValue is true) ui.PreviewMouseWheel += OnWheel;
    }

    private static void OnWheel(object sender, MouseWheelEventArgs e)
    {
        if (e.Handled || sender is not DependencyObject element || VisualTreeHelper.GetParent(element) is not UIElement parent) return;
        e.Handled = true;
        parent.RaiseEvent(new MouseWheelEventArgs(e.MouseDevice, e.Timestamp, e.Delta)
        {
            RoutedEvent = UIElement.MouseWheelEvent,
            Source = element,
        });
    }
}
