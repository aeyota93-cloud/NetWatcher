using System.Net;
using System.Windows;
using System.Windows.Controls;
using NetWatcher.App.Monitoring;
using NetWatcher.Core;
using NetWatcher.Core.Blocking;
using NetWatcher.Core.Net;

namespace NetWatcher.App.Views;

/// <summary>"Заблокировать…": what to block (program, addresses, owner networks, domain) and for whom.</summary>
internal partial class BlockWindow : Window
{
    private sealed record Choice(string Title, string Detail, BlockKind Kind, Func<BlockRule> Make, bool Shared);

    private readonly AppState _state;
    private readonly List<Choice> _choices = [];
    private readonly string _programPath;
    private readonly string _programTitle;
    private readonly bool _system;
    private Choice? _chosen;

    /// <summary>The rule that was created, when the window closes with OK.</summary>
    public BlockRule? Created { get; private set; }

    public BlockWindow(AppState state, IReadOnlyList<DestinationRow> rows, Func<DestinationRow, string> titleOf)
    {
        InitializeComponent();
        _state = state;
        var programs = rows.Select(r => r.GroupKey).Distinct().ToList();
        var first = rows[0];
        var single = programs.Count == 1;
        _programPath = single ? rows.Select(r => r.Path).FirstOrDefault(p => p != "") ?? "" : "";
        _programTitle = single ? titleOf(first) : "";
        _system = single && BlockRules.IsSystem(_programPath, first.Services, first.Process);
        Heading.Text = single ? $"Заблокировать для {_programTitle}" : $"Заблокировать ({programs.Count} программ)";

        // The program as a whole, or one Windows service inside svchost.
        if (single && first.Services != "")
        {
            foreach (var service in first.Services.Split(',').Take(3))
            {
                var name = state.Collector.Services.DisplayNames.TryGetValue(service, out var d) ? $"{d} ({service})" : service;
                _choices.Add(new Choice($"Службу «{name}» целиком", "Все её соединения, с любыми адресами", BlockKind.Program,
                    () => new BlockRule { Kind = BlockKind.Program, Title = name, ProgramPath = _programPath, Service = service, ProgramTitle = name }, false));
            }
        }
        else if (single && _programPath != "")
        {
            _choices.Add(new Choice($"Программу «{_programTitle}» целиком", _programPath, BlockKind.Program,
                () => new BlockRule { Kind = BlockKind.Program, Title = _programTitle, ProgramPath = _programPath, ProgramTitle = _programTitle }, false));
        }

        var shared = rows.Any(r => r.Asn != null && BlockRules.SharedHostingAsns.Contains(r.Asn.Asn));
        var ips = Analysis.Addresses(rows);
        _choices.Add(new Choice(
            ips.Count == 1 ? $"Адрес {ips[0]}" : $"Адреса ({ips.Count})",
            string.Join(", ", ips.Take(6)) + (ips.Count > 6 ? $" и ещё {ips.Count - 6}" : ""),
            BlockKind.Address,
            () => new BlockRule
            {
                Kind = BlockKind.Address,
                Title = ips.Count == 1 ? ips[0].ToString() : $"{ips.Count} адресов",
                Addresses = ips.Select(ip => Cidr.Of(ip, ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128).ToString()).ToList(),
            },
            shared));

        var networks = Analysis.Subnets(rows, SubnetMode.Owner, false);
        if (networks.Count > 0 && rows.Any(r => r.Asn != null))
        {
            var owners = string.Join(", ", rows.Where(r => r.Asn != null).Select(r => r.Asn!.OwnerText).Distinct().Take(3));
            _choices.Add(new Choice(
                networks.Count == 1 ? $"Сеть владельца {networks[0]}" : $"Сети владельца ({networks.Count})",
                owners + " · " + string.Join(", ", networks.Take(4)) + (networks.Count > 4 ? "…" : ""),
                BlockKind.Address,
                () => new BlockRule
                {
                    Kind = BlockKind.Address,
                    Title = networks.Count == 1 ? networks[0].ToString() : $"{networks.Count} сетей {owners}",
                    Addresses = networks.Select(n => n.ToString()).ToList(),
                },
                shared));
        }

        var domains = rows.Select(r => r.PrimaryDomain).Where(d => d != "").Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (domains.Count == 1)
        {
            var domain = domains[0];
            _choices.Add(new Choice($"Домен {domain}",
                "Все его известные адреса; новые добавляются в правило, как только Windows их узнаёт",
                BlockKind.Domain,
                () =>
                {
                    var rule = new BlockRule { Kind = BlockKind.Domain, Title = domain, Domain = domain };
                    var known = _state.Dns.Answers(null, DateTimeOffset.MinValue)
                        .Where(a => string.Equals(a.Domain, domain, StringComparison.OrdinalIgnoreCase))
                        .SelectMany(a => a.Addresses)
                        .Concat(rows.Where(r => r.Domains.Contains(domain, StringComparer.OrdinalIgnoreCase)).Select(r => r.RemoteIp));
                    BlockRules.AddAddresses(rule, known);
                    return rule;
                },
                shared));
        }

        foreach (var c in _choices)
        {
            var radio = new RadioButton { GroupName = "what", Margin = new Thickness(0, 4, 0, 4), Tag = c };
            radio.Content = new StackPanel
            {
                Children =
                {
                    new TextBlock { Text = c.Title, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap },
                    new TextBlock { Text = c.Detail, Style = (Style)FindResource("Muted"), FontSize = 12, TextWrapping = TextWrapping.Wrap, MaxWidth = 500 },
                },
            };
            radio.Checked += (_, _) =>
            {
                _chosen = c;
                Update();
            };
            Choices.Children.Add(radio);
        }

        OnlyProgram.Content = single ? $"Только для «{_programTitle}» — другие программы будут ходить туда как раньше" : "Только для этой программы";
        OnlyProgram.IsEnabled = single && _programPath != "";
        OnlyProgram.IsChecked = OnlyProgram.IsEnabled;
        // Start from the safest choice: the address(es), not the whole program.
        ((RadioButton)Choices.Children[_choices.FindIndex(c => c.Kind != BlockKind.Program)]).IsChecked = true;
    }

    private void OnChanged(object sender, RoutedEventArgs e) => Update();

    private BlockRule? Build()
    {
        if (_chosen == null) return null;
        var rule = _chosen.Make();
        if (rule.Kind != BlockKind.Program && OnlyProgram.IsChecked == true && _programPath != "")
        {
            rule.ProgramPath = _programPath;
            rule.ProgramTitle = _programTitle;
        }
        return rule;
    }

    private void Update()
    {
        if (!IsInitialized || _chosen == null) return;
        OnlyProgram.Visibility = _chosen.Kind == BlockKind.Program ? Visibility.Collapsed : Visibility.Visible;
        var rule = Build();
        var warnings = new List<string>();
        if (BlockService.FirewallOn() == false)
            warnings.Add("Брандмауэр Windows выключен — правило создастся, но действовать не будет, пока его не включить.");
        if (_system && (_chosen.Kind == BlockKind.Program || OnlyProgram.IsChecked == true))
            warnings.Add("Это компонент Windows. Блокировка может сломать обновления, вход в учётную запись, проверку сертификатов или саму сеть.");
        if (_chosen.Shared && _chosen.Kind != BlockKind.Program)
            warnings.Add(OnlyProgram.IsChecked == true
                ? "Адреса принадлежат CDN или облаку: на них работают и другие сайты. В этой программе они тоже перестанут открываться."
                : "Адреса принадлежат CDN или облаку: на них работают и другие сайты. Они перестанут открываться во всех программах.");
        if (_chosen.Kind == BlockKind.Domain)
            warnings.Add("Новые адреса домена добавляются в правило через несколько секунд после ответа DNS — первое соединение может успеть пройти. Если программа спрашивает DNS сама (DNS через HTTPS), новые адреса не будут видны.");
        if (rule is { Kind: not BlockKind.Program, Addresses.Count: 0 })
            warnings.Add("Адреса неизвестны — блокировать нечего.");
        Warning.Text = string.Join("\n\n", warnings);
        WarningBox.Visibility = warnings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        try
        {
            Command.Text = rule == null ? "" : "netsh " + BlockRules.AddArguments(rule);
            BlockButton.IsEnabled = rule != null;
        }
        catch (InvalidOperationException e)
        {
            Command.Text = e.Message;
            BlockButton.IsEnabled = false;
        }
    }

    private void OnBlock(object sender, RoutedEventArgs e)
    {
        if (Build() is not { } rule) return;
        BlockButton.IsEnabled = false;
        var (ok, message) = _state.Blocks.Add(rule);
        if (!ok)
        {
            Error.Text = message;
            BlockButton.IsEnabled = true;
            return;
        }
        Created = rule;
        DialogResult = true;
    }
}
