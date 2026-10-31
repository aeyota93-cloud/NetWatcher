using System.Runtime.InteropServices;
using NetWatcher.Core.Net;

namespace NetWatcher.App.Native;

/// <summary>The same list netstat -ano shows: every TCP connection with its process id.</summary>
internal static class TcpTable
{
    public static List<TcpRow> Read()
    {
        var rows = Read(NativeMethods.AF_INET, ipv6: false);
        rows.AddRange(Read(NativeMethods.AF_INET6, ipv6: true));
        return rows;
    }

    private static List<TcpRow> Read(int family, bool ipv6)
    {
        var size = 64 * 1024;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var result = NativeMethods.GetExtendedTcpTable(buffer, ref size, false, family, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
                if (result == NativeMethods.ERROR_INSUFFICIENT_BUFFER)
                {
                    size += 16 * 1024; // the table may grow between calls
                    continue;
                }
                if (result != 0) return [];
                var bytes = new byte[size];
                Marshal.Copy(buffer, bytes, 0, size);
                return TcpTableParser.Parse(bytes, ipv6);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return [];
    }
}
