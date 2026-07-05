namespace PasswordForge.Abstractions;

/// <summary>
/// Generates passwords that satisfy a <see cref="Policies.PasswordPolicy"/>.
/// </summary>
public interface IPasswordForge
{
    /// <summary>
    /// Generates a password using the named policy from configuration.
    /// </summary>
    /// <param name="policyName">The registered policy name.</param>
    /// <param name="options">Optional generation options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The generation result.</returns>
    ValueTask<Reports.PasswordGenerationResult> GenerateAsync(
        string policyName,
        Generation.PasswordGenerationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a password from the supplied policy.
    /// </summary>
    ValueTask<Reports.PasswordGenerationResult> GenerateAsync(
        Policies.PasswordPolicy policy,
        Generation.PasswordGenerationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Attempts to generate a password without throwing for impossible policies.
    /// </summary>
    ValueTask<Reports.PasswordGenerationResult> TryGenerateAsync(
        Policies.PasswordPolicy policy,
        Generation.PasswordGenerationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a human-readable password that satisfies the policy.
    /// </summary>
    ValueTask<Reports.PasswordGenerationResult> GenerateHumanReadableAsync(
        Policies.PasswordPolicy policy,
        HumanReadable.HumanReadablePasswordOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a temporary credential with expiry metadata.
    /// </summary>
    ValueTask<TemporaryCredentials.TemporaryCredentialResult> GenerateTemporaryCredentialAsync(
        Policies.PasswordPolicy policy,
        TemporaryCredentials.TemporaryCredentialOptions options,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a test set builder for the supplied policy.
    /// </summary>
    TestSets.PasswordTestSetBuilder TestSet(Policies.PasswordPolicy policy);
}
