namespace PasswordForge;

/// <summary>
/// DI-backed password forge service implementation.
/// </summary>
internal sealed class PasswordForgeService : Abstractions.IPasswordForge
{
    private readonly Abstractions.IPasswordPolicyProvider _policyProvider;
    private readonly Internal.IRandomSource _random;
    private readonly Abstractions.ICommonPasswordProvider _commonPasswordProvider;

    public PasswordForgeService(Abstractions.IPasswordPolicyProvider policyProvider)
        : this(policyProvider, new Internal.CryptographicRandomSource(), new Internal.BuiltInCommonPasswordProvider())
    {
    }

    internal PasswordForgeService(
        Abstractions.IPasswordPolicyProvider policyProvider,
        Internal.IRandomSource random,
        Abstractions.ICommonPasswordProvider commonPasswordProvider)
    {
        _policyProvider = policyProvider;
        _random = random;
        _commonPasswordProvider = commonPasswordProvider;
    }

    public ValueTask<Reports.PasswordGenerationResult> GenerateAsync(
        string policyName,
        Generation.PasswordGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var policy = _policyProvider.GetPolicy(policyName);
        return GenerateAsync(policy, options, cancellationToken);
    }

    public ValueTask<Reports.PasswordGenerationResult> GenerateAsync(
        Policies.PasswordPolicy policy,
        Generation.PasswordGenerationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var generator = new Generation.PasswordGenerator(_random, _commonPasswordProvider);
        return ValueTask.FromResult(generator.Generate(policy, options));
    }

    public ValueTask<Reports.PasswordGenerationResult> TryGenerateAsync(
        Policies.PasswordPolicy policy,
        Generation.PasswordGenerationOptions? options = null,
        CancellationToken cancellationToken = default) =>
        GenerateAsync(policy, options, cancellationToken);

    public ValueTask<Reports.PasswordGenerationResult> GenerateHumanReadableAsync(
        Policies.PasswordPolicy policy,
        HumanReadable.HumanReadablePasswordOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var generator = new HumanReadable.HumanReadablePasswordGenerator(_random, _commonPasswordProvider);
        return ValueTask.FromResult(generator.Generate(policy, options));
    }

    public ValueTask<TemporaryCredentials.TemporaryCredentialResult> GenerateTemporaryCredentialAsync(
        Policies.PasswordPolicy policy,
        TemporaryCredentials.TemporaryCredentialOptions options,
        CancellationToken cancellationToken = default)
    {
        var generator = new Generation.PasswordGenerator(_random, _commonPasswordProvider);
        var tempGen = new TemporaryCredentials.TemporaryCredentialGenerator(generator);
        return ValueTask.FromResult(tempGen.Generate(policy, options));
    }

    public TestSets.PasswordTestSetBuilder TestSet(Policies.PasswordPolicy policy) =>
        new(policy, _random, _commonPasswordProvider);
}
