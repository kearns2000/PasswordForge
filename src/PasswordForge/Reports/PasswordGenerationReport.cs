namespace PasswordForge.Reports;

/// <summary>
/// Report describing how a password was generated.
/// </summary>
public sealed record PasswordGenerationReport(
    int AttemptCount,
    int TargetLength,
    int EffectivePoolSize,
    IReadOnlyList<string> AppliedRules,
    string GenerationMethod);
