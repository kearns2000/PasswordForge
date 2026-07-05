namespace PasswordForge.Reports;

/// <summary>
/// Breakdown of character classes in a password.
/// </summary>
public sealed record PasswordCharacterBreakdown(
    int UppercaseCount,
    int LowercaseCount,
    int DigitCount,
    int SymbolCount,
    int WhitespaceCount,
    int OtherCount,
    int TotalLength);
