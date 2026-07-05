namespace PasswordForge.Reports;

/// <summary>
/// Result of a single password rule evaluation.
/// </summary>
public sealed record PasswordRuleResult(
    string RuleId,
    string Message,
    bool Passed,
    Reports.PasswordRuleSeverity Severity = PasswordRuleSeverity.Error);

/// <summary>
/// Severity of a password rule result.
/// </summary>
public enum PasswordRuleSeverity
{
    /// <summary>Informational result.</summary>
    Info,

    /// <summary>Warning-level result.</summary>
    Warning,

    /// <summary>Error-level result indicating validation failure.</summary>
    Error
}
