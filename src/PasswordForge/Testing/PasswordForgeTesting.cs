namespace PasswordForge.Testing;

/// <summary>
/// Deterministic random source for unit tests only.
/// Do not use in production. This source is predictable and unsuitable for real credentials.
/// </summary>
internal sealed class DeterministicRandomSource : Internal.IRandomSource
{
    private readonly Random _random;

    public DeterministicRandomSource(int seed)
    {
        _random = new Random(seed);
    }

    public int NextInt32(int maxExclusive) => _random.Next(maxExclusive);

    public void Shuffle(Span<char> buffer)
    {
        for (var i = buffer.Length - 1; i > 0; i--)
        {
            var j = _random.Next(i + 1);
            (buffer[i], buffer[j]) = (buffer[j], buffer[i]);
        }
    }
}

/// <summary>
/// Test-only password forge with deterministic generation.
/// WARNING: This API is for unit tests only. Never use in production.
/// </summary>
public sealed class DeterministicPasswordForge : Abstractions.IPasswordForge
{
    private readonly PasswordForgeService _inner;

    private DeterministicPasswordForge(int seed)
    {
        var provider = new Configuration.PasswordPolicyProvider(new Dictionary<string, Policies.PasswordPolicy>());
        _inner = new PasswordForgeService(provider, new DeterministicRandomSource(seed), new Internal.BuiltInCommonPasswordProvider());
    }

    /// <summary>
    /// Creates a deterministic password forge for unit testing.
    /// WARNING: Do not use in production. Output is predictable from the seed.
    /// </summary>
    public static DeterministicPasswordForge CreateDeterministic(int seed) => new(seed);

    /// <inheritdoc />
    public ValueTask<Reports.PasswordGenerationResult> GenerateAsync(
        string policyName,
        Generation.PasswordGenerationOptions? options = null,
        CancellationToken cancellationToken = default) =>
        _inner.GenerateAsync(policyName, options, cancellationToken);

    /// <inheritdoc />
    public ValueTask<Reports.PasswordGenerationResult> GenerateAsync(
        Policies.PasswordPolicy policy,
        Generation.PasswordGenerationOptions? options = null,
        CancellationToken cancellationToken = default) =>
        _inner.GenerateAsync(policy, options, cancellationToken);

    /// <inheritdoc />
    public ValueTask<Reports.PasswordGenerationResult> TryGenerateAsync(
        Policies.PasswordPolicy policy,
        Generation.PasswordGenerationOptions? options = null,
        CancellationToken cancellationToken = default) =>
        _inner.TryGenerateAsync(policy, options, cancellationToken);

    /// <inheritdoc />
    public ValueTask<Reports.PasswordGenerationResult> GenerateHumanReadableAsync(
        Policies.PasswordPolicy policy,
        HumanReadable.HumanReadablePasswordOptions? options = null,
        CancellationToken cancellationToken = default) =>
        _inner.GenerateHumanReadableAsync(policy, options, cancellationToken);

    /// <inheritdoc />
    public ValueTask<TemporaryCredentials.TemporaryCredentialResult> GenerateTemporaryCredentialAsync(
        Policies.PasswordPolicy policy,
        TemporaryCredentials.TemporaryCredentialOptions options,
        CancellationToken cancellationToken = default) =>
        _inner.GenerateTemporaryCredentialAsync(policy, options, cancellationToken);

    /// <inheritdoc />
    public TestSets.PasswordTestSetBuilder TestSet(Policies.PasswordPolicy policy) =>
        _inner.TestSet(policy);

    /// <summary>
    /// Generates a password synchronously using the deterministic source.
    /// </summary>
    public Reports.PasswordGenerationResult Generate(Policies.PasswordPolicy policy) =>
        GenerateAsync(policy).AsTask().GetAwaiter().GetResult();
}

/// <summary>
/// Factory for test-only PasswordForge instances.
/// WARNING: This entire namespace is for unit tests only. Never use in production.
/// </summary>
public static class PasswordForgeTesting
{
    /// <summary>
    /// Creates a deterministic password forge for unit testing.
    /// WARNING: Do not use in production.
    /// </summary>
    public static DeterministicPasswordForge CreateDeterministic(int seed) =>
        DeterministicPasswordForge.CreateDeterministic(seed);
}
