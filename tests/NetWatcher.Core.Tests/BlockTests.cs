using System.Net;
using NetWatcher.Core.Blocking;

namespace NetWatcher.Core.Tests;

public class BlockTests
{
    private static DestinationRow Row(string process, string path, string ip, string domain = "", string services = "") => new()
    {
        Process = process, Services = services, Path = path, Proto = "TCP", RemoteIp = IPAddress.Parse(ip), RemotePort = 443,
        Domains = domain == "" ? [] : [domain],
    };

    [Fact]
    public void Program_rule_command()
    {
        var r = new BlockRule { Id = "abc12345", Kind = BlockKind.Program, Title = "Steam", ProgramPath = @"C:\Program Files (x86)\Steam\steam.exe", ProgramTitle = "Steam" };
        var args = BlockRules.AddArguments(r);
        Assert.StartsWith("advfirewall firewall add rule name=\"NetWatcher: Steam (abc12345)\" dir=out action=block profile=any enable=yes", args);
        Assert.Contains("program=\"C:\\Program Files (x86)\\Steam\\steam.exe\"", args);
        Assert.DoesNotContain("remoteip", args);
        Assert.Equal("advfirewall firewall delete rule name=\"NetWatcher: Steam (abc12345)\"", BlockRules.DeleteArguments(r));
    }

    [Fact]
    public void Address_and_service_rule_commands()
    {
        var r = new BlockRule
        {
            Id = "1", Kind = BlockKind.Address, Title = "149.154.164.0/22", Addresses = ["149.154.164.0/22", "2001:67c:4e8::/48"],
            ProgramPath = @"C:\Windows\System32\svchost.exe", Service = "wuauserv", ProgramTitle = "Центр обновления",
        };
        var args = BlockRules.AddArguments(r);
        Assert.Contains("service=\"wuauserv\"", args);
        Assert.Contains("remoteip=149.154.164.0/22,2001:67c:4e8::/48", args);
        Assert.Contains("name=\"NetWatcher: 149.154.164.0/22 — Центр обновления (1)\"", args);
        Assert.Equal("advfirewall firewall set rule name=\"NetWatcher: 149.154.164.0/22 — Центр обновления (1)\" new remoteip=149.154.164.0/22,2001:67c:4e8::/48",
            BlockRules.UpdateArguments(r));
    }

    [Fact]
    public void Dangerous_rules_are_refused()
    {
        // No addresses would mean "block everything" for the program.
        Assert.Throws<InvalidOperationException>(() => BlockRules.AddArguments(new BlockRule { Kind = BlockKind.Domain, Domain = "x.com", ProgramPath = @"C:\a.exe" }));
        // No program would mean "block everything".
        Assert.Throws<InvalidOperationException>(() => BlockRules.AddArguments(new BlockRule { Kind = BlockKind.Program, Title = "?" }));
        // Junk instead of an address.
        Assert.Throws<InvalidOperationException>(() => BlockRules.AddArguments(new BlockRule { Kind = BlockKind.Address, Addresses = ["1.2.3.4 delete rule all"] }));
        // Quotes in a title cannot break the command.
        var r = new BlockRule { Id = "q", Kind = BlockKind.Address, Title = "a\" dir=in \"b", Addresses = ["1.2.3.4/32"] };
        Assert.Contains("name=\"NetWatcher: a dir=in b (q)\"", BlockRules.AddArguments(r));
    }

    [Fact]
    public void Coverage_of_rows()
    {
        var steam = @"C:\Steam\steam.exe";
        var program = new BlockRule { Kind = BlockKind.Program, ProgramPath = steam };
        Assert.True(program.Covers(Row("steam.exe", steam, "1.1.1.1")));
        Assert.False(program.Covers(Row("steam.exe", @"D:\other\steam.exe", "1.1.1.1")));

        var net = new BlockRule { Kind = BlockKind.Address, Addresses = ["149.154.164.0/22"] };
        Assert.True(net.Covers(Row("Telegram.exe", @"C:\tg.exe", "149.154.167.51")));
        Assert.False(net.Covers(Row("Telegram.exe", @"C:\tg.exe", "149.154.168.1")));

        var domain = new BlockRule { Kind = BlockKind.Domain, Domain = "ads.example.com", Addresses = ["5.5.5.5/32"], ProgramPath = @"C:\chrome.exe" };
        Assert.True(domain.Covers(Row("chrome.exe", @"C:\chrome.exe", "6.6.6.6", "ads.example.com")));
        Assert.True(domain.Covers(Row("chrome.exe", @"C:\chrome.exe", "5.5.5.5")));
        Assert.False(domain.Covers(Row("firefox.exe", @"C:\firefox.exe", "5.5.5.5", "ads.example.com")));

        var service = new BlockRule { Kind = BlockKind.Program, ProgramPath = @"C:\Windows\System32\svchost.exe", Service = "BITS" };
        Assert.True(service.Covers(Row("svchost.exe", @"C:\Windows\System32\svchost.exe", "1.1.1.1", services: "BITS")));
        Assert.False(service.Covers(Row("svchost.exe", @"C:\Windows\System32\svchost.exe", "1.1.1.1", services: "wuauserv")));
    }

    [Fact]
    public void Domain_rule_takes_new_addresses_once()
    {
        var r = new BlockRule { Kind = BlockKind.Domain, Domain = "x.com" };
        Assert.True(BlockRules.AddAddresses(r, [IPAddress.Parse("1.1.1.1"), IPAddress.Parse("::ffff:1.1.1.1"), IPAddress.Parse("2001:db8::1")]));
        Assert.Equal(["1.1.1.1/32", "2001:db8::1/128"], r.Addresses);
        Assert.False(BlockRules.AddAddresses(r, [IPAddress.Parse("1.1.1.1")]));
    }

    [Fact]
    public void System_components_and_saving()
    {
        Assert.True(BlockRules.IsSystem(@"C:\Windows\System32\svchost.exe", "wuauserv", "svchost.exe"));
        Assert.True(BlockRules.IsSystem("", "", "System"));
        Assert.False(BlockRules.IsSystem(@"C:\Program Files\Steam\steam.exe", "", "steam.exe"));

        var dir = Directory.CreateTempSubdirectory("netwatcher-blocks").FullName;
        try
        {
            var path = Path.Combine(dir, "blocks.json");
            BlockRules.Save(path, [new BlockRule { Kind = BlockKind.Domain, Domain = "x.com", Addresses = ["1.1.1.1/32"] }]);
            var back = Assert.Single(BlockRules.Load(path));
            Assert.Equal(BlockKind.Domain, back.Kind);
            Assert.Equal(["1.1.1.1/32"], back.Addresses);
            File.WriteAllText(path, "{ broken");
            Assert.Empty(BlockRules.Load(path));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
