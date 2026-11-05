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

            // The protocol column sets the TCP/UDP quick filters, and the quick filters show in the column.
            Assert.Equal(false, Get("LinkFilterActive"));
            Put("LinkFilterProto", 2);
            Assert.True(chips[1].IsOn);
            Assert.False(chips[0].IsOn);
            Assert.Equal(2, Get("LinkFilterProto"));
            chips[0].IsOn = true; // both on — "either"
            Assert.Equal(0, Get("LinkFilterProto"));

            Put("LinkFilterAddress", 1);
            Assert.True(chips[2].IsOn);
            Assert.Equal(1, Get("LinkFilterAddress"));

            Put("LinkFilterState", (int)StateFilter.Problems);
            Assert.True(chips[4].IsOn);
            Assert.Equal((int)StateFilter.Problems, Get("LinkFilterState"));

            // A quick filter without a column still narrows the servers.
            chips[0].IsOn = chips[1].IsOn = chips[2].IsOn = chips[4].IsOn = false;
            Assert.Equal(false, Get("LinkFilterActive"));
            chips[5].IsOn = true;
            Assert.Equal(true, Get("LinkFilterActive"));

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
