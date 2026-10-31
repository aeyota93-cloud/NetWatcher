using System.Windows;
using Microsoft.Win32;
using NetWatcher.Core;

namespace NetWatcher.App.ViewModels;

/// <summary>The side panel that turns what is on screen into a list for VPN, firewall or a router.</summary>
internal sealed class ExportViewModel : ObservableObject
{
    private readonly Func<IReadOnlyCollection<DestinationRow>> _rows;
    private readonly Action<string, string> _copy;
    private bool _isOpen;
    private ExportWhat _what = ExportWhat.Subnets;
    private int _width = 2;
    private ExportTarget _target = ExportTarget.Lines;
    private bool _ipv4Only = true;
    private bool _comments;
    private string _preview = "";
    private string _summary = "";
    private string _context = "";

    public ExportViewModel(Func<IReadOnlyCollection<DestinationRow>> rows, Action<string, string> copy)
    {
        _rows = rows;
        _copy = copy;
        CopyCommand = new RelayCommand(() =>
        {
            _copy(Preview, Summary);
            IsOpen = false;
        });
        SaveCommand = new RelayCommand(Save);
        CloseCommand = new RelayCommand(() => IsOpen = false);
    }

    public bool IsOpen { get => _isOpen; set => Set(ref _isOpen, value); }

    /// <summary>"Google Chrome · 24 часа".</summary>
    public string Context { get => _context; private set => Set(ref _context, value); }

    public void Open(string context, ExportWhat? what = null)
    {
        Context = context;
        if (what is { } w) What = w;
        Rebuild();
        IsOpen = true;
    }

    public ExportWhat What
    {
        get => _what;
        set
        {
            if (!Set(ref _what, value)) return;
            OnPropertyChanged(nameof(WidthEnabled));
            OnPropertyChanged(nameof(TargetEnabled));
            OnPropertyChanged(nameof(CommentsEnabled));
            foreach (var n in new[] { nameof(IsAddresses), nameof(IsDomains), nameof(IsSubnets), nameof(IsOwners) }) OnPropertyChanged(n);
            Rebuild();
        }
    }

    // Two-way bindable flags for the segmented control.
    public bool IsAddresses { get => What == ExportWhat.Addresses; set { if (value) What = ExportWhat.Addresses; } }
    public bool IsDomains { get => What == ExportWhat.Domains; set { if (value) What = ExportWhat.Domains; } }
    public bool IsSubnets { get => What == ExportWhat.Subnets; set { if (value) What = ExportWhat.Subnets; } }
    public bool IsOwners { get => What == ExportWhat.OwnerNetworks; set { if (value) What = ExportWhat.OwnerNetworks; } }

    /// <summary>Slider position 0..4: /32, /28, /24, /20, /16.</summary>
    public double Width
    {
        get => _width;
        set
        {
            var v = (int)Math.Round(value);
            if (Set(ref _width, v))
            {
                OnPropertyChanged(nameof(WidthText));
                Rebuild();
            }
        }
    }

    public string WidthText => _width == 0 ? "точно, только эти адреса" : $"до /{Export.Widths[_width].V4} (IPv6 до /{Export.Widths[_width].V6})";
    public bool WidthEnabled => What == ExportWhat.Subnets;
    public bool TargetEnabled => What != ExportWhat.Domains;
    public bool CommentsEnabled => TargetEnabled && Target is ExportTarget.Lines or ExportTarget.Mask;

    public ExportTarget Target
    {
        get => _target;
        set
        {
            if (!Set(ref _target, value)) return;
            foreach (var n in new[] { nameof(IsLines), nameof(IsWireGuard), nameof(IsFirewall), nameof(IsMask), nameof(CommentsEnabled) }) OnPropertyChanged(n);
            Rebuild();
        }
    }

    public bool IsLines { get => Target == ExportTarget.Lines; set { if (value) Target = ExportTarget.Lines; } }
    public bool IsWireGuard { get => Target == ExportTarget.WireGuard; set { if (value) Target = ExportTarget.WireGuard; } }
    public bool IsFirewall { get => Target == ExportTarget.WindowsFirewall; set { if (value) Target = ExportTarget.WindowsFirewall; } }
    public bool IsMask { get => Target == ExportTarget.Mask; set { if (value) Target = ExportTarget.Mask; } }

    public bool Ipv4Only
    {
        get => _ipv4Only;
        set
        {
            if (Set(ref _ipv4Only, value)) Rebuild();
        }
    }

    public bool Comments
    {
        get => _comments;
        set
        {
            if (Set(ref _comments, value)) Rebuild();
        }
    }

    public string Preview { get => _preview; private set => Set(ref _preview, value); }
    public string Summary { get => _summary; private set => Set(ref _summary, value); }

    public RelayCommand CopyCommand { get; }
    public RelayCommand SaveCommand { get; }
    public RelayCommand CloseCommand { get; }

    /// <summary>Called when the data on screen changes while the panel is open.</summary>
    public void Rebuild()
    {
        var rows = _rows();
        var r = Export.Build(rows, What, _width, Target, Ipv4Only, Comments && CommentsEnabled);
        Preview = r.Text;
        var items = What switch
        {
            ExportWhat.Addresses => TextFormat.Plural(r.Items, "адрес", "адреса", "адресов"),
            ExportWhat.Domains => TextFormat.Plural(r.Items, "домен", "домена", "доменов"),
            _ => TextFormat.Plural(r.Items, "сеть", "сети", "сетей"),
        };
        Summary = What == ExportWhat.Addresses || What == ExportWhat.Domains
            ? items
            : $"{items} из {TextFormat.Plural(r.Addresses, "адреса", "адресов", "адресов")}";
    }

    private void Save()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Сохранить список",
            FileName = $"netwatcher-{DateTime.Now:yyyyMMdd-HHmm}.txt",
            Filter = "Текст (*.txt)|*.txt|Все файлы (*.*)|*.*",
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            File.WriteAllText(dialog.FileName, Preview + Environment.NewLine);
            IsOpen = false;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show("Не удалось сохранить файл: " + e.Message, "NetWatcher", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
