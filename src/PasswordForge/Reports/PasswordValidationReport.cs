namespace PasswordForge.Reports;

/// <summary>
/// Report from validating a password against a policy.
/// </summary>
public sealed record PasswordValidationReport(
    bool IsValid,
    IReadOnlyList<PasswordRuleResult> MatchedRules,
    IReadOnlyList<PasswordRuleResult> FailedRules,
    IReadOnlyList<string> Warnings,
    double EntropyBits,
    int NormalisedLength,
    PasswordCharacterBreakdown CharacterClassBreakdown,
    PasswordEntropyEstimate EntropyEstimate);
