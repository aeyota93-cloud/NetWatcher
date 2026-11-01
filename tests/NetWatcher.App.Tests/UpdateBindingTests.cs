using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using NetWatcher.App.Update;
using NetWatcher.Core.Update;
using Xunit;

namespace NetWatcher.App.Tests;

public sealed class UpdateBindingTests
{
    [Fact]
    public void ButtonsBoundBeforeStartupReceiveCommandsAndRespectUpdateState()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                var type = typeof(UpdateInstaller).Assembly.GetType("NetWatcher.App.ViewModels.MainViewModel", true)!;
                // Isolate command initialization from network monitoring, disk state and background timers.
                var vm = RuntimeHelpers.GetUninitializedObject(type);
                var names = new[] { "InstallUpdateCommand", "CheckUpdatesCommand", "DismissUpdateCommand" };
                var buttons = names.Select(name =>
                {
                    var button = new Button();
                    BindingOperations.SetBinding(button, Button.CommandProperty, new Binding(name) { Source = vm });
                    Assert.Null(button.Command);
                    return button;
                }).ToArray();

                type.GetMethod("InitUpdates", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(vm, null);
                for (var i = 0; i < names.Length; i++)
                {
                    Assert.NotNull(buttons[i].Command);
                    Assert.Same(type.GetProperty(names[i])!.GetValue(vm), buttons[i].Command);
                }
                Assert.False(buttons[0].Command.CanExecute(null));
                Assert.True(buttons[1].Command.CanExecute(null));

                // Only presence is needed by CanExecute; no download or installation is performed.
                type.GetField("_release", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .SetValue(vm, RuntimeHelpers.GetUninitializedObject(typeof(UpdateRelease)));
                Assert.True(buttons[0].Command.CanExecute(null));
                type.GetProperty("UpdateBusy")!.SetValue(vm, true);
                Assert.False(buttons[0].Command.CanExecute(null));
                Assert.False(buttons[1].Command.CanExecute(null));
                type.GetProperty("UpdateBusy")!.SetValue(vm, false);
                Assert.True(buttons[0].Command.CanExecute(null));

                type.GetProperty("UpdateAvailable")!.SetValue(vm, true);
                buttons[2].Command.Execute(null);
                Assert.Equal(false, type.GetProperty("UpdateAvailable")!.GetValue(vm));
                foreach (var button in buttons) BindingOperations.ClearAllBindings(button);
            }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "WPF command binding test timed out.");
        if (failure != null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
