using System.Net;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Windows.Controls;
using System.Windows.Data;
using NetWatcher.App.Update;
using NetWatcher.App.ViewModels;
using NetWatcher.Core;
using NetWatcher.Core.Link;
using Xunit;

namespace NetWatcher.App.Tests;

public sealed class LinkFilterBindingTests
{
    private static void RunSta(Action body)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                body();
            }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "WPF test timed out.");
        if (failure != null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    [Fact]
    public void CopyButtonsGetCommandsAndColumnFiltersFollowQuickFilters()
    {
        RunSta(() =>
        {
            var type = typeof(UpdateInstaller).Assembly.GetType("NetWatcher.App.ViewModels.MainViewModel", true)!;
            // No monitoring, disk or timers: only the filter state and the commands.
            var vm = RuntimeHelpers.GetUninitializedObject(type);
            var chips = new[]
            {
                new FilterChip("TCP", QuickFilter.Tcp, ""), new FilterChip("UDP", QuickFilter.Udp, ""),
                new FilterChip("С доменом", QuickFilter.WithDomain, ""), new FilterChip("Без домена", QuickFilter.NoDomain, ""),
                new FilterChip("Проблемные", QuickFilter.Problems, ""), new FilterChip("Трекеры", QuickFilter.Trackers, ""),
            };
            type.GetField("<Chips>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(vm, chips);

            var names = new[]
            {
                "CopyServerIpCommand", "CopyServerDomainCommand", "CopyServerAddressCommand", "CopyShownIpsCommand",
                "CopyShownDomainsCommand", "ResetServerFiltersCommand", "ToggleLinkChartCommand",
            };
            var buttons = names.Select(name =>
            {
                var button = new Button();
                BindingOperations.SetBinding(button, Button.CommandProperty, new Binding(name) { Source = vm });
                Assert.Null(button.Command);
                return button;
            }).ToArray();
            type.GetMethod("InitServerFilter", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(vm, null);
            for (var i = 0; i < names.Length; i++) Assert.NotNull(buttons[i].Command);

            object? Get(string p) => type.GetProperty(p)!.GetValue(vm);
            void Put(string p, object v) => type.GetProperty(p)!.SetValue(vm, v);

            // Wire the quick filters as the window does, without refreshing anything else.
            var toColumns = type.GetMethod("QuickFilterToColumns", BindingFlags.Instance | BindingFlags.NonPublic)!;
            foreach (var c in chips)
            {
                var chip = c;
                chip.Changed = () => toColumns.Invoke(vm, [chip]);
            }
            Put("HoldServerList", true); // no list rebuild: only the filter state is checked

            // A column narrows only the "Связь" table: no quick filter changes, so the program list stays as it is.
            Assert.Equal(false, Get("LinkFilterActive"));
            Put("LinkFilterProto", 2);
            Put("LinkFilterAddress", 2);
            Put("LinkFilterState", (int)StateFilter.Problems);
            Assert.All(chips, c => Assert.False(c.IsOn));
            Assert.Equal(true, Get("LinkColumnFilterActive"));

            // "Сбросить фильтры" resets the columns only.
            chips[5].IsOn = true;
            buttons[Array.IndexOf(names, "ResetServerFiltersCommand")].Command.Execute(null);
            Assert.Equal(0, Get("LinkFilterProto"));
            Assert.Equal(false, Get("LinkColumnFilterActive"));
            Assert.True(chips[5].IsOn);
            Assert.Equal(true, Get("LinkFilterActive")); // «Трекеры» above still narrows the servers
            chips[5].IsOn = false;

            // A quick filter sets its column.
            chips[1].IsOn = true;
            Assert.Equal(2, Get("LinkFilterProto"));
            chips[0].IsOn = true; // both on — "either"
            Assert.Equal(0, Get("LinkFilterProto"));
            chips[3].IsOn = true;
            Assert.Equal(2, Get("LinkFilterAddress"));
            chips[4].IsOn = true;
            Assert.Equal((int)StateFilter.Problems, Get("LinkFilterState"));
            chips[4].IsOn = false;
            Assert.Equal((int)StateFilter.All, Get("LinkFilterState"));

            foreach (var button in buttons) BindingOperations.ClearAllBindings(button);
        });
    }

    [Fact]
    public void ServerLineCopiesIpWithoutPort()
    {
        var row = new DestinationRow { Process = "Telegram.exe", Services = "", Proto = "UDP", RemoteIp = IPAddress.Parse("149.154.167.51"), RemotePort = 443 };
        var server = new LinkServerView("сервер", "149.154.167.51:443", "AS62041 · Telegram", "UDP", "Ok", "работает",
            "—", "—", "—", "сейчас", "1 КБ / 2 КБ", "", false)
        {
            Row = row,
            Facts = new ServerFacts("", "149.154.167.51:443", "AS62041 · Telegram", "UDP", LinkLevel.Ok, false, null, null, null, 1, 3000),
        };
        Assert.Equal("149.154.167.51", server.Ip);
        Assert.False(server.HasName);
        Assert.False(server.IsTcp);
        Assert.Equal(row.Key, server.Key);
    }
}
