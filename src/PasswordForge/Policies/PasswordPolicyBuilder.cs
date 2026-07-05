namespace PasswordForge.Policies;

/// <summary>
/// Fluent builder for <see cref="PasswordPolicy"/>.
/// </summary>
public sealed class PasswordPolicyBuilder
{
    internal int MinLengthValue { get; private set; } = 16;
    internal int MaxLengthValue { get; private set; } = 64;
    internal bool RequireUppercaseValue { get; private set; }
    internal bool RequireLowercaseValue { get; private set; }
    internal bool RequireDigitValue { get; private set; }
    internal bool RequireSymbolValue { get; private set; }
    internal bool RequireWhitespaceValue { get; private set; }
    internal bool AllowWhitespaceValue { get; private set; }
    internal bool DisallowWhitespaceValue { get; private set; } = true;
    internal string? AllowedSymbolsValue { get; private set; }
    internal string? AllowedCharactersValue { get; private set; }
    internal string? DisallowedCharactersValue { get; private set; }
    internal bool AvoidAmbiguousCharactersValue { get; private set; }
    internal string AmbiguousCharactersValue { get; private set; } = Internal.CharacterSets.DefaultAmbiguous;
    internal int? MaxRepeatedCharacterRunValue { get; private set; }
    internal bool DisallowSequentialCharactersValue { get; private set; }
    internal bool DisallowKeyboardSequencesValue { get; private set; }
    internal bool DisallowCommonPasswordsValue { get; private set; }
    internal bool DisallowUsernameValue { get; private set; }
    internal bool DisallowEmailPartsValue { get; private set; }
    internal List<string> DisallowedContextValuesList { get; } = [];
    internal double? MinimumEntropyBitsValue { get; private set; }
    internal List<NamedCharacterSetRequirement> RequireAtLeastOneFromList { get; } = [];
    internal List<NamedCharacterSetRequirement> RequireCountFromList { get; } = [];
    internal Policies.UnicodeMode UnicodeModeValue { get; private set; } = Policies.UnicodeMode.AsciiOnly;
    internal string? UsernameValue { get; private set; }
    internal string? EmailValue { get; private set; }

    /// <summary>Sets the minimum password length.</summary>
    public PasswordPolicyBuilder MinLength(int length)
    {
        MinLengthValue = length;
        return this;
    }

    /// <summary>Sets the maximum password length.</summary>
    public PasswordPolicyBuilder MaxLength(int length)
    {
        MaxLengthValue = length;
        return this;
    }

    /// <summary>Requires at least one uppercase letter.</summary>
    public PasswordPolicyBuilder RequireUppercase()
    {
        RequireUppercaseValue = true;
        return this;
    }

    /// <summary>Requires at least one lowercase letter.</summary>
    public PasswordPolicyBuilder RequireLowercase()
    {
        RequireLowercaseValue = true;
        return this;
    }

    /// <summary>Requires at least one digit.</summary>
    public PasswordPolicyBuilder RequireDigit()
    {
        RequireDigitValue = true;
        return this;
    }

    /// <summary>Requires at least one symbol.</summary>
    public PasswordPolicyBuilder RequireSymbol()
    {
        RequireSymbolValue = true;
        return this;
    }

    /// <summary>Requires at least one whitespace character.</summary>
    public PasswordPolicyBuilder RequireWhitespace()
    {
        RequireWhitespaceValue = true;
        AllowWhitespaceValue = true;
        DisallowWhitespaceValue = false;
        return this;
    }

    /// <summary>Allows whitespace characters.</summary>
    public PasswordPolicyBuilder AllowWhitespace()
    {
        AllowWhitespaceValue = true;
        DisallowWhitespaceValue = false;
        return this;
    }

    /// <summary>Disallows whitespace characters.</summary>
    public PasswordPolicyBuilder DisallowWhitespace()
    {
        DisallowWhitespaceValue = true;
        AllowWhitespaceValue = false;
        RequireWhitespaceValue = false;
        return this;
    }

    /// <summary>Sets the allowed symbol characters.</summary>
    public PasswordPolicyBuilder AllowedSymbols(string symbols)
    {
        AllowedSymbolsValue = symbols;
        return this;
    }

    /// <summary>Sets an explicit allowed character set.</summary>
    public PasswordPolicyBuilder AllowedCharacters(string characters)
    {
        AllowedCharactersValue = characters;
        return this;
    }

    /// <summary>Sets characters that must not appear.</summary>
    public PasswordPolicyBuilder DisallowedCharacters(string characters)
    {
        DisallowedCharactersValue = characters;
        return this;
    }

    /// <summary>Excludes ambiguous characters from generation.</summary>
    public PasswordPolicyBuilder AvoidAmbiguousCharacters()
    {
        AvoidAmbiguousCharactersValue = true;
        return this;
    }

    /// <summary>Sets custom ambiguous characters to avoid.</summary>
    public PasswordPolicyBuilder AmbiguousCharacters(string characters)
    {
        AmbiguousCharactersValue = characters;
        return this;
    }

    /// <summary>Disallows repeated character runs exceeding the limit.</summary>
    public PasswordPolicyBuilder DisallowRepeatedCharacters(int maxRunLength)
    {
        MaxRepeatedCharacterRunValue = maxRunLength;
        return this;
    }

    /// <summary>Disallows sequential character runs.</summary>
    public PasswordPolicyBuilder DisallowSequentialCharacters()
    {
        DisallowSequentialCharactersValue = true;
        return this;
    }

    /// <summary>Disallows common keyboard sequences.</summary>
    public PasswordPolicyBuilder DisallowKeyboardSequences()
    {
        DisallowKeyboardSequencesValue = true;
        return this;
    }

    /// <summary>Disallows common passwords.</summary>
    public PasswordPolicyBuilder DisallowCommonPasswords()
    {
        DisallowCommonPasswordsValue = true;
        return this;
    }

    /// <summary>Disallows the username appearing in the password.</summary>
    public PasswordPolicyBuilder DisallowUsername(string? username = null)
    {
        DisallowUsernameValue = true;
        if (username is not null)
            UsernameValue = username;
        return this;
    }

    /// <summary>Disallows email address parts appearing in the password.</summary>
    public PasswordPolicyBuilder DisallowEmailParts(string? email = null)
    {
        DisallowEmailPartsValue = true;
        if (email is not null)
            EmailValue = email;
        return this;
    }

    /// <summary>Disallows additional context values in the password.</summary>
    public PasswordPolicyBuilder DisallowContextValues(params string[] values)
    {
        DisallowedContextValuesList.AddRange(values);
        return this;
    }

    /// <summary>Sets a minimum estimated entropy requirement.</summary>
    public PasswordPolicyBuilder MinimumEntropyBits(double bits)
    {
        MinimumEntropyBitsValue = bits;
        return this;
    }

    /// <summary>Requires at least one character from a named set.</summary>
    public PasswordPolicyBuilder RequireAtLeastOneFrom(string setName)
    {
        RequireAtLeastOneFromList.Add(new NamedCharacterSetRequirement(setName, 1));
        return this;
    }

    /// <summary>Requires a minimum count from a named character set.</summary>
    public PasswordPolicyBuilder RequireCountFrom(string setName, int count)
    {
        RequireCountFromList.Add(new NamedCharacterSetRequirement(setName, count));
        return this;
    }

    /// <summary>Sets the Unicode mode.</summary>
    public PasswordPolicyBuilder UnicodeMode(UnicodeMode mode)
    {
        UnicodeModeValue = mode;
        return this;
    }

    /// <summary>Builds the immutable policy.</summary>
    public PasswordPolicy Build() => new(this);
}
