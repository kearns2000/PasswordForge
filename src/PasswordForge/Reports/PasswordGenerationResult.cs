namespace PasswordForge.Reports;

/// <summary>
/// Result of a password generation attempt.
/// </summary>
public sealed record PasswordGenerationResult(
    bool Success,
    string? Value,
    double EntropyBits,
    Policies.PasswordPolicy Policy,
    PasswordValidationReport? ValidationReport,
    PasswordGenerationReport? GenerationReport,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Diagnostics)
{
    /// <summary>
    /// Returns the generated password or throws if generation failed.
    /// Password values are never included in exception messages.
    /// </summary>
    public string GenerateOrThrow()
    {
        if (Success && Value is not null)
            return Value;

        var message = Diagnostics.Count > 0
            ? string.Join(" ", Diagnostics)
            : "Password generation failed.";
        throw new InvalidOperationException(message);
    }
}
