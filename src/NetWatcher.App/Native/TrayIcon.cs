using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace NetWatcher.App.Native;

/// <summary>
/// A notification-area icon used to show Windows notifications (balloon tips, which
/// Windows 10 and 11 display as toasts). A click on the icon or the notification opens the window.
/// </summary>
internal sealed class TrayIcon : IDisposable
{
    private const int NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2;
    private const int NIF_MESSAGE = 0x1, NIF_ICON = 0x2, NIF_TIP = 0x4, NIF_INFO = 0x10;
    private const int NIIF_INFO = 0x1, NIIF_WARNING = 0x2;
    private const int WM_APP = 0x8000, CallbackMessage = WM_APP + 17;
    private const int WM_LBUTTONUP = 0x0202, NIN_BALLOONUSERCLICK = 0x0405;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public int cbSize;
        public nint hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public nint hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public int uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public int dwInfoFlags;
        public Guid guidItem;
        public nint hBalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(int message, ref NOTIFYICONDATAW data);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int ExtractIconEx(string file, int index, out nint large, out nint small, int count);

    private readonly Window _window;
    private HwndSource? _source;
    private nint _icon;
    private bool _added;

    public TrayIcon(Window window) => _window = window;

    private NOTIFYICONDATAW Data(int flags) => new()
    {
        cbSize = Marshal.SizeOf<NOTIFYICONDATAW>(),
        hWnd = _source?.Handle ?? 0,
        uID = 1,
        uFlags = flags,
        uCallbackMessage = CallbackMessage,
        hIcon = _icon,
        szTip = "NetWatcher",
        szInfo = "",
        szInfoTitle = "",
    };

    /// <summary>Adds the icon once the window has a handle.</summary>
    public void Attach()
    {
        if (_added) return;
        var handle = new WindowInteropHelper(_window).Handle;
        if (handle == 0) return;
        _source = HwndSource.FromHwnd(handle);
        _source?.AddHook(Hook);
        if (Environment.ProcessPath is { } exe) ExtractIconEx(exe, 0, out _, out _icon, 1);
        var data = Data(NIF_MESSAGE | NIF_ICON | NIF_TIP);
        _added = Shell_NotifyIcon(NIM_ADD, ref data);
    }

    public void Show(string title, string text, bool warning)
    {
        if (!_added) Attach();
        if (!_added) return;
        var data = Data(NIF_INFO);
        data.szInfoTitle = title.Length > 63 ? title[..63] : title;
        data.szInfo = text.Length > 255 ? text[..255] : text;
        data.dwInfoFlags = warning ? NIIF_WARNING : NIIF_INFO;
        Shell_NotifyIcon(NIM_MODIFY, ref data);
    }

    private nint Hook(nint hwnd, int msg, nint wParam, nint lParam, ref bool handled)
    {
        if (msg == CallbackMessage && (lParam.ToInt32() & 0xFFFF) is WM_LBUTTONUP or NIN_BALLOONUSERCLICK)
        {
            if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
            _window.Show();
            _window.Activate();
            handled = true;
        }
        return 0;
    }

    public void Dispose()
    {
        if (_added)
        {
            var data = Data(0);
            Shell_NotifyIcon(NIM_DELETE, ref data);
            _added = false;
        }
        _source?.RemoveHook(Hook);
        if (_icon != 0) NativeMethods.DestroyIcon(_icon);
    }
}
