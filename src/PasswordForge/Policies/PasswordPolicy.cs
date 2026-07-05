namespace PasswordForge.Policies;

/// <summary>
/// Represents a requirement to include characters from a named set.
/// </summary>
public sealed record NamedCharacterSetRequirement(string SetName, int MinimumCount);

/// <summary>
/// Immutable password policy describing length, character, and composition rules.
/// </summary>
public sealed class PasswordPolicy
{
    internal PasswordPolicy(PasswordPolicyBuilder builder)
    {
        MinLength = builder.MinLengthValue;
        MaxLength = builder.MaxLengthValue;
        RequireUppercase = builder.RequireUppercaseValue;
        RequireLowercase = builder.RequireLowercaseValue;
        RequireDigit = builder.RequireDigitValue;
        RequireSymbol = builder.RequireSymbolValue;
        RequireWhitespace = builder.RequireWhitespaceValue;
        AllowWhitespace = builder.AllowWhitespaceValue;
        DisallowWhitespace = builder.DisallowWhitespaceValue;
        AllowedSymbols = builder.AllowedSymbolsValue;
        AllowedCharacters = builder.AllowedCharactersValue;
        DisallowedCharacters = builder.DisallowedCharactersValue;
        AvoidAmbiguousCharacters = builder.AvoidAmbiguousCharactersValue;
        AmbiguousCharacters = builder.AmbiguousCharactersValue;
        MaxRepeatedCharacterRun = builder.MaxRepeatedCharacterRunValue;
        DisallowSequentialCharacters = builder.DisallowSequentialCharactersValue;
        DisallowKeyboardSequences = builder.DisallowKeyboardSequencesValue;
        DisallowCommonPasswords = builder.DisallowCommonPasswordsValue;
        DisallowUsername = builder.DisallowUsernameValue;
        DisallowEmailParts = builder.DisallowEmailPartsValue;
        DisallowedContextValues = builder.DisallowedContextValuesList.ToList();
        MinimumEntropyBits = builder.MinimumEntropyBitsValue;
        RequireAtLeastOneFrom = builder.RequireAtLeastOneFromList.ToList();
        RequireCountFrom = builder.RequireCountFromList.ToList();
        UnicodeMode = builder.UnicodeModeValue;
        Username = builder.UsernameValue;
        Email = builder.EmailValue;
    }

    /// <summary>Minimum password length.</summary>
    public int MinLength { get; }

    /// <summary>Maximum password length.</summary>
    public int MaxLength { get; }

    /// <summary>Requires at least one uppercase letter.</summary>
    public bool RequireUppercase { get; }

    /// <summary>Requires at least one lowercase letter.</summary>
    public bool RequireLowercase { get; }

    /// <summary>Requires at least one digit.</summary>
    public bool RequireDigit { get; }

    /// <summary>Requires at least one symbol.</summary>
    public bool RequireSymbol { get; }

    /// <summary>Requires at least one whitespace character.</summary>
    public bool RequireWhitespace { get; }

    /// <summary>Allows whitespace characters.</summary>
    public bool AllowWhitespace { get; }

    /// <summary>Disallows whitespace characters.</summary>
    public bool DisallowWhitespace { get; }

    /// <summary>Allowed symbol characters when symbols are required or permitted.</summary>
    public string? AllowedSymbols { get; }

    /// <summary>Explicit allowed character set. When set, overrides default pools.</summary>
    public string? AllowedCharacters { get; }

    /// <summary>Characters that must not appear in the password.</summary>
    public string? DisallowedCharacters { get; }

    /// <summary>Excludes ambiguous characters such as 0, O, and l.</summary>
    public bool AvoidAmbiguousCharacters { get; }

    /// <summary>Ambiguous characters to avoid when enabled.</summary>
    public string AmbiguousCharacters { get; }

    /// <summary>Maximum run length for repeated characters. Null means no limit.</summary>
    public int? MaxRepeatedCharacterRun { get; }

    /// <summary>Disallows sequential characters such as abc or 123.</summary>
    public bool DisallowSequentialCharacters { get; }

    /// <summary>Disallows common keyboard sequences such as qwerty.</summary>
    public bool DisallowKeyboardSequences { get; }

    /// <summary>Disallows common passwords from the built-in or custom list.</summary>
    public bool DisallowCommonPasswords { get; }

    /// <summary>Disallows the username appearing in the password.</summary>
    public bool DisallowUsername { get; }

    /// <summary>Disallows parts of the email address appearing in the password.</summary>
    public bool DisallowEmailParts { get; }

    /// <summary>Additional context values that must not appear in the password.</summary>
    public IReadOnlyList<string> DisallowedContextValues { get; }

    /// <summary>Minimum estimated entropy in bits. Null means no minimum.</summary>
    public double? MinimumEntropyBits { get; }

    /// <summary>Requires at least one character from each named set.</summary>
    public IReadOnlyList<NamedCharacterSetRequirement> RequireAtLeastOneFrom { get; }

    /// <summary>Requires a minimum count from each named set.</summary>
    public IReadOnlyList<NamedCharacterSetRequirement> RequireCountFrom { get; }

    /// <summary>Controls Unicode character support.</summary>
    public UnicodeMode UnicodeMode { get; }

    /// <summary>Username used for disallow-username validation.</summary>
    public string? Username { get; }

    /// <summary>Email used for disallow-email-parts validation.</summary>
    public string? Email { get; }

    /// <summary>Creates a new fluent policy builder.</summary>
    public static PasswordPolicyBuilder Create() => new();

    /// <summary>Builds a policy from the builder state.</summary>
    public static PasswordPolicy Build(Action<PasswordPolicyBuilder> configure)
    {
        var builder = Create();
        configure(builder);
        return builder.Build();
    }

    /// <summary>
    /// Attempts to import a policy from a regular expression pattern.
    /// </summary>
    public static Regex.RegexPolicyImportResult FromRegex(string pattern) =>
        Regex.RegexPasswordPolicyImporter.FromRegex(pattern);

    /// <summary>
    /// Creates a policy from ASP.NET Identity PasswordOptions.
    /// </summary>
    public static PasswordPolicy FromAspNetIdentity(Microsoft.AspNetCore.Identity.PasswordOptions options) =>
        Identity.AspNetIdentityPasswordPolicyAdapter.FromAspNetIdentity(options);
}
