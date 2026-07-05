namespace PasswordForge;

/// <summary>
/// Static entry point for password generation, validation, and policy tooling.
/// </summary>
public static class PasswordForge
{
    private static readonly Internal.CryptographicRandomSource DefaultRandom = new();
    private static readonly Internal.BuiltInCommonPasswordProvider DefaultCommonPasswordProvider = new();

    /// <summary>
    /// Generates a password that satisfies the policy. Returns a result object; does not throw for policy failures.
    /// </summary>
    public static Reports.PasswordGenerationResult Generate(
        Policies.PasswordPolicy policy,
        Generation.PasswordGenerationOptions? options = null)
    {
        var generator = new Generation.PasswordGenerator(DefaultRandom, DefaultCommonPasswordProvider);
        return generator.Generate(policy, options);
    }

    /// <summary>
    /// Attempts to generate a password without throwing for impossible policies.
    /// </summary>
    public static Reports.PasswordGenerationResult TryGenerate(
        Policies.PasswordPolicy policy,
        Generation.PasswordGenerationOptions? options = null) =>
        Generate(policy, options);

    /// <summary>
    /// Generates a password or throws if generation failed. Password values are never included in exceptions.
    /// </summary>
    public static string GenerateOrThrow(
        Policies.PasswordPolicy policy,
        Generation.PasswordGenerationOptions? options = null) =>
        Generate(policy, options).GenerateOrThrow();

    /// <summary>
    /// Generates a human-readable password that satisfies the policy.
    /// </summary>
    public static Reports.PasswordGenerationResult GenerateHumanReadable(
        Policies.PasswordPolicy policy,
        HumanReadable.HumanReadablePasswordOptions? options = null)
    {
        var generator = new HumanReadable.HumanReadablePasswordGenerator(DefaultRandom, DefaultCommonPasswordProvider);
        return generator.Generate(policy, options);
    }

    /// <summary>
    /// Generates a temporary credential with expiry metadata.
    /// </summary>
    public static TemporaryCredentials.TemporaryCredentialResult GenerateTemporaryCredential(
        Policies.PasswordPolicy policy,
        TemporaryCredentials.TemporaryCredentialOptions options)
    {
        var generator = new Generation.PasswordGenerator(DefaultRandom, DefaultCommonPasswordProvider);
        var tempGen = new TemporaryCredentials.TemporaryCredentialGenerator(generator);
        return tempGen.Generate(policy, options);
    }

    /// <summary>
    /// Creates a test set builder for the supplied policy.
    /// </summary>
    public static TestSets.PasswordTestSetBuilder TestSet(Policies.PasswordPolicy policy) =>
        new(policy, DefaultRandom, DefaultCommonPasswordProvider);
}
