namespace PasswordForge.Configuration;

/// <summary>
/// Default implementation of named policy provider.
/// </summary>
internal sealed class PasswordPolicyProvider : Abstractions.IPasswordPolicyProvider
{
    private readonly IReadOnlyDictionary<string, Policies.PasswordPolicy> _policies;

    public PasswordPolicyProvider(IReadOnlyDictionary<string, Policies.PasswordPolicy> policies)
    {
        _policies = policies;
    }

    public IReadOnlyCollection<string> PolicyNames => _policies.Keys.ToList();

    public Policies.PasswordPolicy GetPolicy(string name)
    {
        if (TryGetPolicy(name, out var policy) && policy is not null)
            return policy;

        throw new InvalidOperationException(
            $"Password policy '{name}' is not registered. Available policies: {string.Join(", ", _policies.Keys)}.");
    }

    public bool TryGetPolicy(string name, out Policies.PasswordPolicy? policy)
    {
        if (_policies.TryGetValue(name, out var found))
        {
            policy = found;
            return true;
        }

        policy = null;
        return false;
    }
}
