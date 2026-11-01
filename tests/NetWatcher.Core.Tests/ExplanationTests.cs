using NetWatcher.Core.Catalog;

namespace NetWatcher.Core.Tests;

public class ExplanationTests
{
    [Fact]
    public void Builtin_catalog_loads_and_every_entry_is_complete()
    {
        var e = Explanations.Builtin;
        Assert.True(e.Count >= 100);
        using var stream = typeof(Explanations).Assembly.GetManifestResourceStream("explanations.json")!;
        using var doc = System.Text.Json.JsonDocument.Parse(stream);
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            var keys = new[] { "service", "process", "domain", "prefix" }.Count(k => item.TryGetProperty(k, out _));
            Assert.Equal(1, keys);
            Assert.False(string.IsNullOrWhiteSpace(item.GetProperty("title").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(item.GetProperty("what").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(item.GetProperty("block").GetString()));
        }
    }

    [Fact]
    public void Services_programs_and_domains()
    {
        var e = Explanations.Builtin;
        Assert.Equal("Центр обновления Windows", e.ForProgram("svchost.exe", "wuauserv")!.Title);
        // A group of several services: the first one the catalog knows.
        Assert.Equal("Фоновая интеллектуальная служба передачи (BITS)", e.ForProgram("svchost.exe", "Unknown1, BITS")!.Title);
        Assert.Equal("Telegram", e.ForProgram("telegram.exe", "")!.Title);
        Assert.Null(e.ForProgram("my-own-tool.exe", ""));

        Assert.Equal("Видео YouTube", e.ForDomain("rr3---sn-4g5e6nsz.googlevideo.com")!.Title);
        Assert.Equal("Яндекс Метрика", e.ForDomain("mc.yandex.ru")!.Title);
        Assert.Equal("Проверка подключения Windows", e.ForDomain("www.msftconnecttest.com.")!.Title);
        Assert.Equal("Проверка отзыва сертификата (OCSP)", e.ForDomain("ocsp.digicert.com")!.Title);
        Assert.Null(e.ForDomain("example.org"));
        Assert.Null(e.ForDomain(""));
    }
}
