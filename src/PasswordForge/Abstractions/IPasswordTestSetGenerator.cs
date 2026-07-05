namespace PasswordForge.Abstractions;

/// <summary>
/// Generates structured valid and invalid password test sets.
/// </summary>
public interface IPasswordTestSetGenerator
{
    /// <summary>
    /// Creates a test set builder for the supplied policy.
    /// </summary>
    TestSets.PasswordTestSetBuilder CreateBuilder(Policies.PasswordPolicy policy);
}
