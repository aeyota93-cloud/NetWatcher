using System.Net;

namespace NetWatcher.Core.Net;

public enum AddressFormat
{
    /// <summary>1.2.3.0/24</summary>
    Cidr,

    /// <summary>1.2.3.0 255.255.255.0</summary>
    Mask,
}

/// <summary>A network block such as 1.2.3.0/24 or 2a00:1450::/32.</summary>
public readonly record struct Cidr
{
    /// <summary>First address as an <see cref="IpKey"/> number.</summary>
    public UInt128 Start { get; }

    /// <summary>Prefix length in its own family: 0–32 for IPv4, 0–128 for IPv6.</summary>
    public int Prefix { get; }

    public bool IsV4 { get; }

    public Cidr(UInt128 start, int prefix, bool isV4)
    {
        var bits = isV4 ? 32 : 128;
        if (prefix < 0 || prefix > bits) throw new ArgumentOutOfRangeException(nameof(prefix));
        IsV4 = isV4;
        Prefix = prefix;
        Start = start & MaskOf(FullPrefix(prefix, isV4));
    }

    public static Cidr Of(IPAddress ip, int prefix)
    {
        var key = IpKey.From(ip);
        return new Cidr(key, prefix, IpKey.IsV4(key));
    }

    public static bool TryParse(string text, out Cidr cidr)
    {
        cidr = default;
        var parts = text.Trim().Split('/');
        if (parts.Length is < 1 or > 2 || !IpKey.TryParse(parts[0], out var ip)) return false;
        var key = IpKey.From(ip);
        var v4 = IpKey.IsV4(key);
        var prefix = v4 ? 32 : 128;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > (v4 ? 32 : 128)))
            return false;
        cidr = new Cidr(key, prefix, v4);
        return true;
    }

    /// <summary>Prefix length counted over the whole 128-bit key.</summary>
    internal int KeyPrefix => FullPrefix(Prefix, IsV4);

    public UInt128 End => Start | ~MaskOf(KeyPrefix);

    public IPAddress Network => IpKey.ToAddress(Start);

    public bool Contains(IPAddress ip)
    {
        var key = IpKey.From(ip);
        return key >= Start && key <= End;
    }

    /// <summary>Dotted mask for IPv4 (255.255.255.0). IPv6 has no masks in practice, so it gets /N.</summary>
    public string MaskText
    {
        get
        {
            if (!IsV4) return "/" + Prefix;
            var m = Prefix == 0 ? 0u : uint.MaxValue << (32 - Prefix);
            return $"{m >> 24}.{(m >> 16) & 0xFF}.{(m >> 8) & 0xFF}.{m & 0xFF}";
        }
    }

    public string Format(AddressFormat format) =>
        format == AddressFormat.Mask && IsV4 ? $"{Network} {MaskText}" : ToString();

    public override string ToString() => $"{Network}/{Prefix}";

    internal static int FullPrefix(int prefix, bool isV4) => isV4 ? prefix + 96 : prefix;

    internal static UInt128 MaskOf(int keyPrefix) =>
        keyPrefix == 0 ? UInt128.Zero : UInt128.MaxValue << (128 - keyPrefix);
}
