namespace PasswordForge.Abstractions;

/// <summary>
/// Provides a list of common passwords for policy validation.
/// </summary>
public interface ICommonPasswordProvider
{
    /// <summary>
    /// Determines whether the password appears in the common password list.
    /// </summary>
    bool IsCommonPassword(string password);
}
