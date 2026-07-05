namespace PasswordForge.Reviews;

/// <summary>
/// Severity of a policy review finding.
/// </summary>
public enum PasswordPolicyFindingSeverity
{
    /// <summary>Informational finding.</summary>
    Info,

    /// <summary>Warning-level finding.</summary>
    Warning,

    /// <summary>High severity finding.</summary>
    High
}

/// <summary>
/// Category of a policy review finding.
/// </summary>
public enum PasswordPolicyFindingCategory
{
    /// <summary>Length-related finding.</summary>
    Length,

    /// <summary>Character set finding.</summary>
    CharacterSet,

    /// <summary>Composition rule finding.</summary>
    Composition,

    /// <summary>Usability finding.</summary>
    Usability,

    /// <summary>Legacy compatibility finding.</summary>
    LegacyCompatibility,

    /// <summary>Entropy-related finding.</summary>
    Entropy,

    /// <summary>Temporary credential suitability finding.</summary>
    TemporaryCredential,

    /// <summary>Modern guidance alignment finding.</summary>
    ModernGuidance
}

/// <summary>
/// A single finding from a password policy review.
/// </summary>
public sealed record PasswordPolicyFinding(
    string Id,
    string Message,
    PasswordPolicyFindingSeverity Severity,
    PasswordPolicyFindingCategory Category);

/// <summary>
/// Result of reviewing a password policy against common modern guidance.
/// </summary>
public sealed record PasswordPolicyReview(
    int Score,
    IReadOnlyList<PasswordPolicyFinding> Findings,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> SuggestedChanges,
    string EstimatedStrength);
