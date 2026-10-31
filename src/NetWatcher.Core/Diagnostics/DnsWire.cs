using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NetWatcher.Core.Diagnostics;

/// <summary>
/// The smallest DNS client that is enough for diagnostics (RFC 1035): one question,
/// answers of type A, AAAA and TXT. Used to ask a chosen server directly, past the
/// system resolver, over UDP and over TCP.
/// </summary>
public static class DnsWire
{
    public const ushort TypeA = 1;
    public const ushort TypeTxt = 16;
    public const ushort TypeAaaa = 28;

    public sealed record Answer(ushort Type, string Text, IPAddress? Address);

    public sealed record Response(ushort Id, int RCode, IReadOnlyList<Answer> Answers);

    public static byte[] BuildQuery(ushort id, string name, ushort type)
    {
        var labels = name.TrimEnd('.').Split('.');
        var size = 12 + labels.Sum(l => 1 + Encoding.ASCII.GetByteCount(l)) + 1 + 4;
        var buf = new byte[size];
        BinaryPrimitives.WriteUInt16BigEndian(buf, id);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), 0x0100); // standard query, recursion desired
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(4), 1);      // one question
        var p = 12;
        foreach (var label in labels)
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63) throw new ArgumentException("Неправильное имя: " + name);
            buf[p++] = (byte)bytes.Length;
            bytes.CopyTo(buf, p);
            p += bytes.Length;
        }
        buf[p++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(p), type);
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(p + 2), 1); // class IN
        return buf;
    }

    public static Response Parse(ReadOnlySpan<byte> msg)
    {
        if (msg.Length < 12) throw new FormatException("Ответ DNS слишком короткий");
        var id = BinaryPrimitives.ReadUInt16BigEndian(msg);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(msg[2..]);
        var qd = BinaryPrimitives.ReadUInt16BigEndian(msg[4..]);
        var an = BinaryPrimitives.ReadUInt16BigEndian(msg[6..]);
        var p = 12;
        for (var i = 0; i < qd; i++)
        {
            p = SkipName(msg, p);
            p += 4;
        }

        var answers = new List<Answer>();
        for (var i = 0; i < an; i++)
        {
            p = SkipName(msg, p);
            if (p + 10 > msg.Length) throw new FormatException("Обрезанная запись DNS");
            var type = BinaryPrimitives.ReadUInt16BigEndian(msg[p..]);
            var len = BinaryPrimitives.ReadUInt16BigEndian(msg[(p + 8)..]);
            p += 10;
            if (p + len > msg.Length) throw new FormatException("Обрезанные данные DNS");
            var data = msg.Slice(p, len);
            switch (type)
            {
                case TypeA when len == 4:
                case TypeAaaa when len == 16:
                    var ip = new IPAddress(data);
                    answers.Add(new Answer(type, ip.ToString(), ip));
                    break;
                case TypeTxt:
                    // One or more <length><text> strings.
                    var sb = new StringBuilder();
                    for (var q = 0; q < data.Length;)
                    {
                        var n = data[q++];
                        if (q + n > data.Length) break;
                        sb.Append(Encoding.ASCII.GetString(data.Slice(q, n)));
                        q += n;
                    }
                    answers.Add(new Answer(type, sb.ToString(), null));
                    break;
            }
            p += len;
        }
        return new Response(id, flags & 0x000F, answers);
    }

    private static int SkipName(ReadOnlySpan<byte> msg, int p)
    {
        while (p < msg.Length)
        {
            var len = msg[p];
            if (len == 0) return p + 1;
            if ((len & 0xC0) == 0xC0) return p + 2; // compression pointer ends the name
            p += len + 1;
        }
        throw new FormatException("Обрезанное имя в ответе DNS");
    }
}
