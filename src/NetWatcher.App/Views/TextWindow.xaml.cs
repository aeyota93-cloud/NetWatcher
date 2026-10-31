using System.Windows;
using NetWatcher.App.ViewModels;

namespace NetWatcher.App.Views;

/// <summary>A small window with text that can be selected and copied.</summary>
internal partial class TextWindow : Window
{
    public TextWindow() => InitializeComponent();

    public static TextWindow Show(string title, string text)
    {
        var w = new TextWindow { Title = title, Owner = Application.Current.MainWindow };
        w.SetText(text);
        w.Show();
        return w;
    }

    public void SetText(string text) => Body.Text = text;

    private void OnCopy(object sender, RoutedEventArgs e) => ViewModels.Clip.SetText(Body.Text);

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
