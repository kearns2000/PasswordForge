namespace PasswordForge.Reports;

/// <summary>
/// Estimated password entropy. This is an approximation, not a guarantee of strength.
/// </summary>
public sealed record PasswordEntropyEstimate(
    double EntropyBits,
    string Method,
    string? Note);
