namespace PasswordForge.Configuration;

/// <summary>
/// Options for binding password policies from configuration.
/// </summary>
public class PasswordPolicyOptions
{
    /// <summary>Minimum password length.</summary>
    public int MinLength { get; set; } = 16;

    /// <summary>Maximum password length.</summary>
    public int MaxLength { get; set; } = 64;

    /// <summary>Requires uppercase letters.</summary>
    public bool RequireUppercase { get; set; }

    /// <summary>Requires lowercase letters.</summary>
    public bool RequireLowercase { get; set; }

    /// <summary>Requires digits.</summary>
    public bool RequireDigit { get; set; }

    /// <summary>Requires symbols.</summary>
    public bool RequireSymbol { get; set; }

    /// <summary>Requires whitespace.</summary>
    public bool RequireWhitespace { get; set; }

    /// <summary>Allows whitespace.</summary>
    public bool AllowWhitespace { get; set; }

    /// <summary>Disallows whitespace.</summary>
    public bool DisallowWhitespace { get; set; } = true;

    /// <summary>Allowed symbol characters.</summary>
    public string? AllowedSymbols { get; set; }

    /// <summary>Allowed characters.</summary>
    public string? AllowedCharacters { get; set; }

    /// <summary>Disallowed characters.</summary>
    public string? DisallowedCharacters { get; set; }

    /// <summary>Avoids ambiguous characters.</summary>
    public bool AvoidAmbiguousCharacters { get; set; }

    /// <summary>Maximum repeated character run length.</summary>
    public int? MaxRepeatedCharacterRun { get; set; }

    /// <summary>Disallows sequential characters.</summary>
    public bool DisallowSequentialCharacters { get; set; }

    /// <summary>Disallows keyboard sequences.</summary>
    public bool DisallowKeyboardSequences { get; set; }

    /// <summary>Disallows common passwords.</summary>
    public bool DisallowCommonPasswords { get; set; }

    /// <summary>Disallows username in password.</summary>
    public bool DisallowUsername { get; set; }

    /// <summary>Username value used when disallowing username in password.</summary>
    public string? Username { get; set; }

    /// <summary>Disallows email parts in password.</summary>
    public bool DisallowEmailParts { get; set; }

    /// <summary>Email value used when disallowing email parts in password.</summary>
    public string? Email { get; set; }

    /// <summary>Context values that must not appear in the password.</summary>
    public List<string> DisallowedContextValues { get; set; } = [];

    /// <summary>Named character sets that require at least one matching character.</summary>
    public List<string> RequireAtLeastOneFrom { get; set; } = [];

    /// <summary>Named character sets that require a minimum count of matching characters.</summary>
    public Dictionary<string, int> RequireCountFrom { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Minimum entropy bits.</summary>
    public double? MinimumEntropyBits { get; set; }

    /// <summary>Unicode mode as string (AsciiOnly, AllowUnicode, AllowUnicodeLettersOnly).</summary>
    public string UnicodeMode { get; set; } = "AsciiOnly";

    /// <summary>Converts options to an immutable policy.</summary>
    public Policies.PasswordPolicy ToPolicy()
    {
        var builder = Policies.PasswordPolicy.Create()
            .MinLength(MinLength)
            .MaxLength(MaxLength);

        if (RequireUppercase) builder.RequireUppercase();
        if (RequireLowercase) builder.RequireLowercase();
        if (RequireDigit) builder.RequireDigit();
        if (RequireSymbol) builder.RequireSymbol();
        if (RequireWhitespace) builder.RequireWhitespace();
        if (AllowWhitespace) builder.AllowWhitespace();
        if (DisallowWhitespace) builder.DisallowWhitespace();
        if (AllowedSymbols is not null) builder.AllowedSymbols(AllowedSymbols);
        if (AllowedCharacters is not null) builder.AllowedCharacters(AllowedCharacters);
        if (DisallowedCharacters is not null) builder.DisallowedCharacters(DisallowedCharacters);
        if (AvoidAmbiguousCharacters) builder.AvoidAmbiguousCharacters();
        if (MaxRepeatedCharacterRun is not null) builder.DisallowRepeatedCharacters(MaxRepeatedCharacterRun.Value);
        if (DisallowSequentialCharacters) builder.DisallowSequentialCharacters();
        if (DisallowKeyboardSequences) builder.DisallowKeyboardSequences();
        if (DisallowCommonPasswords) builder.DisallowCommonPasswords();
        if (DisallowUsername) builder.DisallowUsername(Username);
        if (DisallowEmailParts) builder.DisallowEmailParts(Email);
        if (MinimumEntropyBits is not null) builder.MinimumEntropyBits(MinimumEntropyBits.Value);

        if (DisallowedContextValues.Count > 0)
            builder.DisallowContextValues([.. DisallowedContextValues]);

        foreach (var setName in RequireAtLeastOneFrom)
            builder.RequireAtLeastOneFrom(setName);

        foreach (var (setName, count) in RequireCountFrom)
            builder.RequireCountFrom(setName, count);

        if (Enum.TryParse<Policies.UnicodeMode>(UnicodeMode, true, out var unicodeMode))
            builder.UnicodeMode(unicodeMode);

        return builder.Build();
    }
}

/// <summary>
/// Root configuration options for PasswordForge.
/// </summary>
public sealed class PasswordForgeOptions
{
    /// <summary>Named policies loaded from configuration.</summary>
    public Dictionary<string, PasswordPolicyOptions> Policies { get; set; } = new();

    internal Dictionary<string, Policies.PasswordPolicy> BuildPolicyDictionary()
    {
        return Policies.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value.ToPolicy(),
            StringComparer.OrdinalIgnoreCase);
    }
}
