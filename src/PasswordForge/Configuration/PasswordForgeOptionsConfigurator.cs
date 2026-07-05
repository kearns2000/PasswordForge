namespace PasswordForge.Configuration;

/// <summary>
/// Configures named password policies for dependency injection.
/// </summary>
public sealed class PasswordForgeOptionsConfigurator
{
    private readonly PasswordForgeOptions _options;

    internal PasswordForgeOptionsConfigurator(PasswordForgeOptions options)
    {
        _options = options;
    }

    /// <summary>
    /// Registers a named policy.
    /// </summary>
    public PasswordForgeOptionsConfigurator AddPolicy(string name, Policies.PasswordPolicy policy)
    {
        _options.Policies[name] = MapPolicy(policy);
        return this;
    }

    /// <summary>
    /// Registers a named policy using the fluent builder.
    /// </summary>
    public PasswordForgeOptionsConfigurator AddPolicy(string name, Action<Policies.PasswordPolicyBuilder> configure)
    {
        var builder = Policies.PasswordPolicy.Create();
        configure(builder);
        return AddPolicy(name, builder.Build());
    }

    private static PasswordPolicyOptions MapPolicy(Policies.PasswordPolicy policy) =>
        new()
        {
            MinLength = policy.MinLength,
            MaxLength = policy.MaxLength,
            RequireUppercase = policy.RequireUppercase,
            RequireLowercase = policy.RequireLowercase,
            RequireDigit = policy.RequireDigit,
            RequireSymbol = policy.RequireSymbol,
            RequireWhitespace = policy.RequireWhitespace,
            AllowWhitespace = policy.AllowWhitespace,
            DisallowWhitespace = policy.DisallowWhitespace,
            AllowedSymbols = policy.AllowedSymbols,
            AllowedCharacters = policy.AllowedCharacters,
            DisallowedCharacters = policy.DisallowedCharacters,
            AvoidAmbiguousCharacters = policy.AvoidAmbiguousCharacters,
            MaxRepeatedCharacterRun = policy.MaxRepeatedCharacterRun,
            DisallowSequentialCharacters = policy.DisallowSequentialCharacters,
            DisallowKeyboardSequences = policy.DisallowKeyboardSequences,
            DisallowCommonPasswords = policy.DisallowCommonPasswords,
            DisallowUsername = policy.DisallowUsername,
            DisallowEmailParts = policy.DisallowEmailParts,
            Username = policy.Username,
            Email = policy.Email,
            DisallowedContextValues = policy.DisallowedContextValues.ToList(),
            RequireAtLeastOneFrom = policy.RequireAtLeastOneFrom.Select(r => r.SetName).ToList(),
            RequireCountFrom = policy.RequireCountFrom.ToDictionary(
                r => r.SetName,
                r => r.MinimumCount,
                StringComparer.OrdinalIgnoreCase),
            MinimumEntropyBits = policy.MinimumEntropyBits,
            UnicodeMode = policy.UnicodeMode.ToString()
        };
}
