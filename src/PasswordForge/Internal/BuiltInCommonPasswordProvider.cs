namespace PasswordForge.Internal;

/// <summary>
/// Built-in common password list for v1. Production systems should use a larger external check.
/// </summary>
internal sealed class BuiltInCommonPasswordProvider : Abstractions.ICommonPasswordProvider
{
    private static readonly HashSet<string> Passwords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password1", "password123", "123456", "12345678", "123456789",
        "qwerty", "qwerty123", "letmein", "welcome", "admin", "administrator",
        "passw0rd", "iloveyou", "monkey", "dragon", "master", "login",
        "abc123", "football", "shadow", "sunshine", "princess", "baseball",
        "trustno1", "superman", "batman", "changeme", "secret", "test",
        "guest", "root", "toor", "pass", "pass123", "welcome1"
    };

    public bool IsCommonPassword(string password) =>
        Passwords.Contains(password);
}
