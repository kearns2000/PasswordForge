using PasswordForge.Generation;
using PasswordForge.Reports;
using PasswordForge.Reviews;
using PasswordForge.TestSets;

namespace PasswordForge.McpServer.Internal;

/// <summary>
/// Builds MCP tool responses that never include password values.
/// </summary>
internal static class SecureResponseBuilder
{
    public static object Validation(PasswordValidationReport report) => new
    {
        report.IsValid,
        report.EntropyBits,
        report.NormalisedLength,
        report.Warnings,
        MatchedRules = report.MatchedRules.Select(ToRule).ToList(),
        FailedRules = report.FailedRules.Select(ToRule).ToList(),
        CharacterBreakdown = new
        {
            report.CharacterClassBreakdown.UppercaseCount,
            report.CharacterClassBreakdown.LowercaseCount,
            report.CharacterClassBreakdown.DigitCount,
            report.CharacterClassBreakdown.SymbolCount,
            report.CharacterClassBreakdown.WhitespaceCount,
            report.CharacterClassBreakdown.OtherCount
        },
        report.EntropyEstimate.Method,
        EntropyEstimateBits = report.EntropyEstimate.EntropyBits,
        report.EntropyEstimate.Note
    };

    public static object PolicyReview(PasswordPolicyReview review) => new
    {
        review.Score,
        review.EstimatedStrength,
        review.Warnings,
        review.SuggestedChanges,
        Findings = review.Findings.Select(f => new
        {
            f.Id,
            f.Message,
            Severity = f.Severity.ToString(),
            Category = f.Category.ToString()
        }).ToList()
    };

    public static object GenerationMetadata(PasswordGenerationResult result) => new
    {
        result.Success,
        result.EntropyBits,
        result.Warnings,
        result.Diagnostics,
        Generation = result.GenerationReport is null ? null : new
        {
            result.GenerationReport.AttemptCount,
            result.GenerationReport.TargetLength,
            result.GenerationReport.EffectivePoolSize,
            result.GenerationReport.GenerationMethod,
            AppliedRules = result.GenerationReport.AppliedRules.ToList()
        },
        Validation = result.ValidationReport is null ? null : Validation(result.ValidationReport),
        SecurityNotice = "Generated password values are intentionally omitted from MCP responses."
    };

    public static object TestSet(PasswordTestSetResult result) => new
    {
        result.Diagnostics,
        Items = result.Items.Select(item => new
        {
            Scenario = item.Scenario.ToString(),
            item.ExpectedValid,
            item.ExpectedFailedRules,
            item.Description,
            item.Skipped,
            item.SkipReason,
            ValueRedacted = true
        }).ToList(),
        SecurityNotice = "Test sample values are intentionally omitted from MCP responses."
    };

    public static object RegexImport(Regex.RegexPolicyImportResult result) => new
    {
        result.Success,
        UnsupportedFeatures = result.UnsupportedFeatures.ToList(),
        Policy = result.Policy is null ? null : new
        {
            result.Policy.MinLength,
            result.Policy.MaxLength,
            result.Policy.RequireUppercase,
            result.Policy.RequireLowercase,
            result.Policy.RequireDigit,
            result.Policy.RequireSymbol,
            UnicodeMode = result.Policy.UnicodeMode.ToString()
        }
    };

    private static object ToRule(PasswordRuleResult rule) => new
    {
        rule.RuleId,
        rule.Message,
        rule.Passed
    };
}
