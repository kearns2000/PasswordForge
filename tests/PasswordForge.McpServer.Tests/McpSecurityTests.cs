using PasswordForge.McpServer.Tools;
using PasswordForge.Policies;
using Xunit;

namespace PasswordForge.McpServer.Tests;

public class McpSecurityTests
{
  private const string StandardPolicyJson = """
        {
          "MinLength": 12,
          "MaxLength": 32,
          "RequireUppercase": true,
          "RequireLowercase": true,
          "RequireDigit": true,
          "RequireSymbol": true,
          "AllowedSymbols": "@#$%!"
        }
        """;

    [Fact]
    public void GeneratePasswordMetadata_never_returns_password_value()
    {
        var json = PasswordForgeMcpTools.GeneratePasswordMetadata(StandardPolicyJson);

        Assert.DoesNotContain("\"Value\"", json, StringComparison.Ordinal);
        Assert.Contains("SecurityNotice", json, StringComparison.Ordinal);
        Assert.Contains("\"Success\": true", json, StringComparison.Ordinal);
    }

    [Fact]
    public void GenerateHumanReadableMetadata_never_returns_password_value()
    {
        var json = PasswordForgeMcpTools.GenerateHumanReadableMetadata(StandardPolicyJson);

        Assert.DoesNotContain("\"Value\"", json, StringComparison.Ordinal);
        Assert.Contains("human-readable", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GenerateTestSetSummary_never_returns_sample_values()
    {
        var json = PasswordForgeMcpTools.GenerateTestSetSummary(StandardPolicyJson, validCount: 3);

        Assert.Contains("ValueRedacted", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Value\":", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidatePassword_does_not_echo_password_in_response()
    {
        const string password = "SuperSecretExample1!";
        var json = PasswordForgeMcpTools.ValidatePassword(password, StandardPolicyJson);

        Assert.DoesNotContain(password, json, StringComparison.Ordinal);
        Assert.Contains("\"IsValid\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ReviewPolicy_returns_score_and_findings()
    {
        var json = PasswordForgeMcpTools.ReviewPolicy(StandardPolicyJson);

        Assert.Contains("\"Score\"", json, StringComparison.Ordinal);
        Assert.Contains("Findings", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ImportPolicyFromRegex_maps_common_pattern()
    {
        var json = PasswordForgeMcpTools.ImportPolicyFromRegex(@"^(?=.*[A-Z])(?=.*\d).{12,32}$");

        Assert.Contains("\"Success\": true", json, StringComparison.Ordinal);
        Assert.Contains("\"MinLength\": 12", json, StringComparison.Ordinal);
    }
}
