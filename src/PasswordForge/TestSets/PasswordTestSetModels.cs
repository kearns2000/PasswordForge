namespace PasswordForge.TestSets;

/// <summary>
/// Strongly typed test scenario identifiers.
/// </summary>
public enum PasswordTestScenario
{
    /// <summary>Valid password scenario.</summary>
    Valid,

    /// <summary>Password that is too short.</summary>
    InvalidTooShort,

    /// <summary>Password that is too long.</summary>
    InvalidTooLong,

    /// <summary>Password missing an uppercase letter.</summary>
    InvalidMissingUppercase,

    /// <summary>Password missing a lowercase letter.</summary>
    InvalidMissingLowercase,

    /// <summary>Password missing a digit.</summary>
    InvalidMissingDigit,

    /// <summary>Password missing a symbol.</summary>
    InvalidMissingSymbol,

    /// <summary>Password with excessive repeated characters.</summary>
    InvalidRepeatedCharacters,

    /// <summary>Password with sequential characters.</summary>
    InvalidSequentialCharacters,

    /// <summary>Common password scenario.</summary>
    InvalidCommonPassword,

    /// <summary>Edge case scenario.</summary>
    EdgeCase
}

/// <summary>
/// A single item in a generated password test set.
/// </summary>
public sealed record PasswordTestSetItem(
    string Value,
    bool ExpectedValid,
    PasswordTestScenario Scenario,
    IReadOnlyList<string> ExpectedFailedRules,
    string Description,
    bool Skipped = false,
    string? SkipReason = null);

/// <summary>
/// Result of generating a password test set.
/// </summary>
public sealed record PasswordTestSetResult(
    IReadOnlyList<PasswordTestSetItem> Items,
    IReadOnlyList<string> Diagnostics);
