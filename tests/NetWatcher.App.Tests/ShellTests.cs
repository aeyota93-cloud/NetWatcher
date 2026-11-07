using System.IO;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetWatcher.App.Views;
using NetWatcher.App.Update;
using NetWatcher.App.ViewModels;
using NetWatcher.Core;
using Xunit;

namespace NetWatcher.App.Tests;

public sealed class ShellTests
{
    private static NavItem Item(string key) => new(key, "Приложения", "");

    // The view model is internal: reach the rule through reflection, as UpdateBindingTests does.
    private static NavItem? ProgramToShow(IEnumerable<NavItem> nav, NavItem? last) =>
        (NavItem?)typeof(UpdateInstaller).Assembly.GetType("NetWatcher.App.ViewModels.MainViewModel", true)!
            .GetMethod("ProgramToShow", BindingFlags.Static | BindingFlags.NonPublic)!
            .Invoke(null, [nav, last]);

    [Fact]
    public void ProgramsSectionReturnsToTheProgramSeenLast()
    {
        var all = new NavItem("", "", "");
        var first = Item("first");
        var second = Item("second");
        var nav = new[] { all, first, second };
        Assert.True(all.IsAll);

        Assert.Same(second, ProgramToShow(nav, second));
        Assert.Same(first, ProgramToShow(nav, null));
        // The program has gone from the list, or the last item was "Все": take the first program.
        Assert.Same(first, ProgramToShow(nav, Item("gone")));
        Assert.Same(first, ProgramToShow(nav, all));
        Assert.Null(ProgramToShow([all], null));
    }

    [Fact]
    public void WheelOverANestedListReachesThePageAroundIt()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var list = new ListBox();
                var page = new Border { Child = list };
                var received = 0;
                page.AddHandler(UIElement.MouseWheelEvent, new MouseWheelEventHandler((_, _) => received++));
                WheelToParent.SetEnabled(list, true);

                list.RaiseEvent(new MouseWheelEventArgs(Mouse.PrimaryDevice, 0, -120) { RoutedEvent = UIElement.PreviewMouseWheelEvent });
                Assert.Equal(1, received);

                WheelToParent.SetEnabled(list, false);
                list.RaiseEvent(new MouseWheelEventArgs(Mouse.PrimaryDevice, 0, -120) { RoutedEvent = UIElement.PreviewMouseWheelEvent });
                Assert.Equal(1, received);
            }
            catch (Exception e)
            {
                failure = e;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure != null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    [Fact]
    public void ProgramSearchLooksAtNameAndPath()
    {
        var item = new NavItem("telegram", "Приложения", @"C:\Apps\Telegram.exe") { Title = "Telegram Desktop" };
        Assert.True(item.Matches(""));
        Assert.True(item.Matches("  "));
        Assert.True(item.Matches("telegram d"));
        Assert.True(item.Matches("APPS"));
        Assert.False(item.Matches("discord"));
    }

    [Fact]
    public void QualityTileShowsTheDelayLarge()
    {
        var split = typeof(UpdateInstaller).Assembly.GetType("NetWatcher.App.ViewModels.MainViewModel", true)!
            .GetMethod("Split", BindingFlags.Static | BindingFlags.NonPublic)!;
        (string, string) Run(string s) => ((string, string))split.Invoke(null, [s])!;
        Assert.Equal(("42 мс", "±3 · потерь нет"), Run("42 мс ±3 · потерь нет"));
        Assert.Equal(("0 мс", "потерь нет"), Run("0 мс · потерь нет"));
        Assert.Equal(("не отвечает на пинг", ""), Run("не отвечает на пинг"));
    }

    [Fact]
    public void LinkColumnSaysOnlyWhatIsKnown()
    {
        Assert.Equal("нет ответа", TableItem.LinkWords(HealthLevel.Fail, "нет ответа", false));
        Assert.Equal("повторы", TableItem.LinkWords(HealthLevel.Warn, "повторы", false));
        Assert.Equal("сбоев не видно", TableItem.LinkWords(HealthLevel.Ok, "", false));
        // UDP has no acknowledgements: no verdict either way.
        Assert.Equal("UDP: подтверждений нет", TableItem.LinkWords(HealthLevel.Unknown, "", true));
        Assert.Equal("нет данных", TableItem.LinkWords(HealthLevel.Unknown, "", false));
    }

    [Fact]
    public void PortsAreOrderedAndShortened()
    {
        Assert.Equal("443", TableItem.PortWords([443, 443]));
        Assert.Equal("80, 443", TableItem.PortWords([443, 80]));
        Assert.Equal("53, 80, 443, …", TableItem.PortWords([443, 80, 53, 8443]));
    }

    [Fact]
    public void SettingsOfTheFrameSurviveARestart()
    {
        var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        try
        {
            new Settings { MenuExpanded = true, ProgramListHidden = true }.Save(path);
            var loaded = Settings.Load(path);
            Assert.True(loaded.MenuExpanded);
            Assert.True(loaded.ProgramListHidden);
            // A settings file of an older version keeps the approved defaults.
            Assert.False(new Settings().MenuExpanded);
            Assert.False(new Settings().ProgramListHidden);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
