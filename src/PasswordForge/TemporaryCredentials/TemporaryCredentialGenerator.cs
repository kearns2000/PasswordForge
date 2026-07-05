namespace PasswordForge.TemporaryCredentials;

/// <summary>
/// Generates temporary credentials with expiry metadata.
/// </summary>
internal sealed class TemporaryCredentialGenerator
{
    private readonly Generation.PasswordGenerator _generator;

    public TemporaryCredentialGenerator(Generation.PasswordGenerator generator)
    {
        _generator = generator;
    }

    public TemporaryCredentialResult Generate(
        Policies.PasswordPolicy policy,
        TemporaryCredentialOptions options,
        Generation.PasswordGenerationOptions? generationOptions = null)
    {
        var result = _generator.Generate(policy, generationOptions);

        if (!result.Success || result.Value is null)
        {
            throw new InvalidOperationException(
                result.Diagnostics.Count > 0
                    ? string.Join(" ", result.Diagnostics)
                    : "Temporary credential generation failed.");
        }

        var now = options.Clock.UtcNow;
        var expiresAt = now.Add(options.ExpiresAfter);

        var safeDisplay = BuildSafeDisplayText(options, now, expiresAt);

        return new TemporaryCredentialResult(
            result.Value,
            expiresAt,
            options.RequireResetOnFirstUse,
            now,
            options.DeliveryHint,
            safeDisplay,
            result);
    }

    /// <summary>
    /// Builds display text for one-time credential presentation.
    /// The password is included because the purpose is one-time display.
    /// This text must not be written to logs.
    /// </summary>
    private static string BuildSafeDisplayText(
        TemporaryCredentialOptions options,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        var resetNote = options.RequireResetOnFirstUse
            ? " Reset required on first sign-in."
            : string.Empty;

        return $"Temporary credential created at {createdAt:u}. Expires at {expiresAt:u}.{resetNote} Do not log or store this value.";
    }
}
