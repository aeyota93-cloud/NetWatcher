using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace NetWatcher.App.Native;

/// <summary>Small program icons for the list, read once per path.</summary>
internal static class IconCache
{
    private static readonly ConcurrentDictionary<string, ImageSource?> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static ImageSource? Get(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        return Cache.GetOrAdd(path, Load);
    }

    private static ImageSource? Load(string path)
    {
        try
        {
            var info = new NativeMethods.SHFILEINFO();
            var r = NativeMethods.SHGetFileInfo(path, 0, ref info, (uint)Marshal.SizeOf(info),
                NativeMethods.SHGFI_ICON | NativeMethods.SHGFI_SMALLICON);
            if (r == 0 || info.hIcon == 0) return null;
            try
            {
                var image = Imaging.CreateBitmapSourceFromHIcon(info.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                image.Freeze();
                return image;
            }
            finally
            {
                NativeMethods.DestroyIcon(info.hIcon);
            }
        }
        catch (Exception e) when (e is COMException or ArgumentException or ExternalException)
        {
            return null;
        }
    }
}
