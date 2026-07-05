using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using PasswordForge.McpServer.Internal;
using PasswordForge.Policies;
using PasswordForge.Reviews;
using PasswordForge.Validation;

namespace PasswordForge.McpServer.Tools;

/// <summary>
/// MCP tools for PasswordForge. Responses never include generated password values.
/// </summary>
[McpServerToolType]
public sealed class PasswordForgeMcpTools
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    [McpServerTool]
    [Description("Validates a password against a PasswordForge policy. Returns rule results and entropy. The password is not echoed in the response.")]
    public static string ValidatePassword(
        [Description("Password to validate")] string password,
        [Description("PasswordForge policy as JSON (PasswordPolicyOptions shape)")] string policyJson)
    {
        var policy = PolicyJson.ParsePolicy(policyJson);
        var report = PasswordValidator.Validate(password, policy);
        return JsonSerializer.Serialize(SecureResponseBuilder.Validation(report), JsonOptions);
    }

    [McpServerTool]
    [Description("Reviews a password policy against common modern guidance. Returns score, findings, and suggestions.")]
    public static string ReviewPolicy(
        [Description("PasswordForge policy as JSON (PasswordPolicyOptions shape)")] string policyJson)
    {
        var policy = PolicyJson.ParsePolicy(policyJson);
        var review = PasswordPolicyReviewer.Review(policy);
        return JsonSerializer.Serialize(SecureResponseBuilder.PolicyReview(review), JsonOptions);
    }

    [McpServerTool]
    [Description("Checks whether a policy can generate passwords. Returns diagnostics and warnings without generating or returning a password.")]
    public static string AnalysePolicyConfiguration(
        [Description("PasswordForge policy as JSON (PasswordPolicyOptions shape)")] string policyJson)
    {
        var policy = PolicyJson.ParsePolicy(policyJson);
        var result = global::PasswordForge.PasswordForge.TryGenerate(policy);
        return JsonSerializer.Serialize(SecureResponseBuilder.GenerationMetadata(result), JsonOptions);
    }

    [McpServerTool]
    [Description("Generates a password for the policy but returns only metadata (entropy, warnings, validation). The password value is never returned.")]
    public static string GeneratePasswordMetadata(
        [Description("PasswordForge policy as JSON (PasswordPolicyOptions shape)")] string policyJson,
        [Description("Optional generation options JSON with preferredLength, maxAttempts, humanReadableFallback, avoidStartingWithSymbol, avoidEndingWithSymbol")] string? optionsJson = null)
    {
        var policy = PolicyJson.ParsePolicy(policyJson);
        var options = ParseGenerationOptions(optionsJson);
        var result = global::PasswordForge.PasswordForge.Generate(policy, options);
        return JsonSerializer.Serialize(SecureResponseBuilder.GenerationMetadata(result), JsonOptions);
    }

    [McpServerTool]
    [Description("Generates a human-readable password but returns only metadata. The password value is never returned.")]
    public static string GenerateHumanReadableMetadata(
        [Description("PasswordForge policy as JSON (PasswordPolicyOptions shape)")] string policyJson)
    {
        var policy = PolicyJson.ParsePolicy(policyJson);
        var result = global::PasswordForge.PasswordForge.GenerateHumanReadable(policy);
        return JsonSerializer.Serialize(SecureResponseBuilder.GenerationMetadata(result), JsonOptions);
    }

    [McpServerTool]
    [Description("Builds valid and invalid password test scenarios for a policy. Returns scenario metadata only; sample password values are never returned.")]
    public static string GenerateTestSetSummary(
        [Description("PasswordForge policy as JSON (PasswordPolicyOptions shape)")] string policyJson,
        [Description("Number of valid samples to generate")] int validCount = 5,
        [Description("Number of too-short invalid samples")] int invalidTooShortCount = 2,
        [Description("Number of missing-digit invalid samples")] int invalidMissingDigitCount = 2,
        [Description("Include edge cases")] bool includeEdgeCases = true)
    {
        var policy = PolicyJson.ParsePolicy(policyJson);
        var builder = global::PasswordForge.PasswordForge.TestSet(policy)
            .Valid(Math.Max(0, validCount))
            .InvalidTooShort(Math.Max(0, invalidTooShortCount))
            .InvalidMissingDigit(Math.Max(0, invalidMissingDigitCount));

        if (includeEdgeCases)
            builder.EdgeCases();

        var result = builder.Generate();
        return JsonSerializer.Serialize(SecureResponseBuilder.TestSet(result), JsonOptions);
    }

    [McpServerTool]
    [Description("Imports a password policy from a regular expression pattern. Returns the mapped policy and any unsupported features.")]
    public static string ImportPolicyFromRegex(
        [Description("Regular expression pattern")] string pattern)
    {
        var result = PasswordPolicy.FromRegex(pattern);
        return JsonSerializer.Serialize(SecureResponseBuilder.RegexImport(result), JsonOptions);
    }

    private static Generation.PasswordGenerationOptions ParseGenerationOptions(string? optionsJson)
    {
        if (string.IsNullOrWhiteSpace(optionsJson))
            return Generation.PasswordGenerationOptions.Default;

        var parsed = JsonSerializer.Deserialize<GenerationOptionsDto>(optionsJson, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        }) ?? new GenerationOptionsDto();

        return new Generation.PasswordGenerationOptions
        {
            PreferredLength = parsed.PreferredLength,
            MaxAttempts = parsed.MaxAttempts ?? 100,
            EntropyTargetBits = parsed.EntropyTargetBits,
            HumanReadableFallback = parsed.HumanReadableFallback ?? false,
            AvoidStartingWithSymbol = parsed.AvoidStartingWithSymbol ?? false,
            AvoidEndingWithSymbol = parsed.AvoidEndingWithSymbol ?? false
        };
    }

    private sealed class GenerationOptionsDto
    {
        public int? PreferredLength { get; set; }
        public int? MaxAttempts { get; set; }
        public double? EntropyTargetBits { get; set; }
        public bool? HumanReadableFallback { get; set; }
        public bool? AvoidStartingWithSymbol { get; set; }
        public bool? AvoidEndingWithSymbol { get; set; }
    }
}
