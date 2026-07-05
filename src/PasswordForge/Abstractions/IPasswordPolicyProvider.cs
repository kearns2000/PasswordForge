namespace PasswordForge.Abstractions;

/// <summary>
/// Provides named password policies for dependency injection.
/// </summary>
public interface IPasswordPolicyProvider
{
    /// <summary>
    /// Gets a policy by name.
    /// </summary>
    /// <param name="name">The policy name.</param>
    /// <returns>The policy if found.</returns>
    /// <exception cref="InvalidOperationException">When the policy name is not registered.</exception>
    Policies.PasswordPolicy GetPolicy(string name);

    /// <summary>
    /// Attempts to get a policy by name.
    /// </summary>
    bool TryGetPolicy(string name, out Policies.PasswordPolicy? policy);

    /// <summary>
    /// Gets all registered policy names.
    /// </summary>
    IReadOnlyCollection<string> PolicyNames { get; }
}
