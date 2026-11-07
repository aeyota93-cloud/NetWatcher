using System.IO;
using System.Reflection;
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
