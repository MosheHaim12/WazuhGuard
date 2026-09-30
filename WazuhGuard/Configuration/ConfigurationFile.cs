using System.Text.Json;
using System.Text.Json.Serialization;
using WazuhGuard.Core;

namespace WazuhGuard.Configuration;

public static class ConfigurationFile
{
    public static string DataDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WazuhGuard");
    public static string ConfigPath => Path.Combine(DataDirectory, "appsettings.json");

    public static GuardOptions Read(string path)
    {
        var json = File.ReadAllText(path);
        using var document = JsonDocument.Parse(json);
        RejectDuplicates(document.RootElement);
        var config = JsonSerializer.Deserialize<Root>(json, new JsonSerializerOptions
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        }) ?? throw new InvalidDataException("Configuration is null.");
        if (config.WazuhGuard is null) throw new InvalidDataException("WazuhGuard configuration section is required.");
        config.WazuhGuard.Validate();
        return config.WazuhGuard;
    }

    private static void RejectDuplicates(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) return;
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in value.EnumerateObject())
        {
            if (!keys.Add(property.Name)) throw new InvalidDataException($"Duplicate configuration property: {property.Name}");
            RejectDuplicates(property.Value);
        }
    }

    private sealed record Root
    {
        public required GuardOptions WazuhGuard { get; init; }
    }
}
