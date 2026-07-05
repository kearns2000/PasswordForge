using System.Text.Json;
using PasswordForge.Configuration;
using PasswordForge.Policies;

namespace PasswordForge.McpServer.Internal;

internal static class PolicyJson
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static PasswordPolicy ParsePolicy(string policyJson)
    {
        if (string.IsNullOrWhiteSpace(policyJson))
            throw new ArgumentException("Policy JSON is required.", nameof(policyJson));

        var options = JsonSerializer.Deserialize<PasswordPolicyOptions>(policyJson, SerializerOptions)
            ?? throw new ArgumentException("Policy JSON could not be parsed.", nameof(policyJson));

        return options.ToPolicy();
    }
}
