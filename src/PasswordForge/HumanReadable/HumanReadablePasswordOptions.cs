namespace PasswordForge.HumanReadable;

/// <summary>
/// Capitalisation mode for human-readable passwords.
/// </summary>
public enum CapitalisationMode
{
    /// <summary>First letter of each word is uppercase.</summary>
    TitleCase,

    /// <summary>All words are lowercase.</summary>
    LowerCase,

    /// <summary>All words are uppercase.</summary>
    UpperCase,

    /// <summary>Random capitalisation per word.</summary>
    Random
}

/// <summary>
/// Options for human-readable password generation.
/// </summary>
public sealed class HumanReadablePasswordOptions
{
    /// <summary>Default human-readable options.</summary>
    public static HumanReadablePasswordOptions Default { get; } = new();

    /// <summary>Number of words in the passphrase.</summary>
    public int WordCount { get; init; } = 3;

    /// <summary>Separator between words. Prefer a character from the policy allowed symbol set when symbols are required.</summary>
    public string Separator { get; init; } = "#";

    /// <summary>Capitalisation mode for words.</summary>
    public CapitalisationMode CapitalisationMode { get; init; } = CapitalisationMode.TitleCase;

    /// <summary>When true, appends a random number.</summary>
    public bool AppendNumber { get; init; } = true;

    /// <summary>When true, appends a random symbol.</summary>
    public bool AppendSymbol { get; init; } = true;

    /// <summary>Custom word list. When null, the built-in list is used.</summary>
    public IReadOnlyList<string>? CustomWordList { get; init; }

    /// <summary>Maximum generation attempts.</summary>
    public int MaxAttempts { get; init; } = 100;
}
