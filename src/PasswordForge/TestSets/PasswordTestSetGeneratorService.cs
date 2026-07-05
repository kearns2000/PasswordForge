namespace PasswordForge.TestSets;

/// <summary>
/// Service implementation for test set generation.
/// </summary>
internal sealed class PasswordTestSetGeneratorService : Abstractions.IPasswordTestSetGenerator
{
    public PasswordTestSetBuilder CreateBuilder(Policies.PasswordPolicy policy)
    {
        var random = new Internal.CryptographicRandomSource();
        var commonPasswordProvider = new Internal.BuiltInCommonPasswordProvider();
        return new PasswordTestSetBuilder(policy, random, commonPasswordProvider);
    }
}
