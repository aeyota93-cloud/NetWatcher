using System.Globalization;

namespace NetWatcher.Core.Geo;

/// <summary>Country names in the user's language and the wording "server here, network registered there".</summary>
public static class Countries
{
    /// <summary>"Германия (DE)", or the code itself when Windows does not know it.</summary>
    public static string Name(string code)
    {
        if (code == "") return "";
        try
        {
            return $"{new RegionInfo(code).DisplayName} ({code})";
        }
        catch (ArgumentException)
        {
            return code;
        }
    }

    /// <summary>
    /// "Сервер: Германия (DE)\nСеть зарегистрирована: США (US)". Large networks (Cloudflare, Google, Amazon)
    /// are registered in one country and have servers all over the world.
    /// </summary>
    public static string Tip(string server, string registered)
    {
        if (server == "" && registered == "") return "";
        if (server == "") return $"Сеть зарегистрирована: {Name(registered)}\nГде стоит сервер — неизвестно (нет базы стран)";
        if (registered == "" || registered == server) return $"Сервер: {Name(server)}";
        return $"Сервер: {Name(server)}\nСеть зарегистрирована: {Name(registered)}";
    }

    /// <summary>One line for the details pane.</summary>
    public static string Describe(string server, string registered)
    {
        if (server == "" && registered == "") return "—";
        if (server == "") return $"{Name(registered)} — где зарегистрирована сеть";
        if (registered == "" || registered == server) return Name(server);
        return $"{Name(server)}; сеть зарегистрирована: {Name(registered)}";
    }
}
