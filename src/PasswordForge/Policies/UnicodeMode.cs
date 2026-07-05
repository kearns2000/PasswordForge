namespace PasswordForge.Policies;

/// <summary>
/// Controls which Unicode characters are permitted in generated passwords.
/// </summary>
public enum UnicodeMode
{
    /// <summary>
    /// Only ASCII characters are permitted.
    /// </summary>
    AsciiOnly,

    /// <summary>
    /// Full Unicode is permitted where the policy allows.
    /// </summary>
    AllowUnicode,

    /// <summary>
    /// Only Unicode letter characters are permitted in addition to ASCII.
    /// </summary>
    AllowUnicodeLettersOnly
}
