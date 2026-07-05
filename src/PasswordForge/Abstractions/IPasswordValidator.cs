namespace PasswordForge.Abstractions;

/// <summary>
/// Validates passwords against a <see cref="Policies.PasswordPolicy"/>.
/// </summary>
public interface IPasswordValidator
{
    /// <summary>
    /// Validates a password against the supplied policy.
    /// </summary>
    Reports.PasswordValidationReport Validate(string password, Policies.PasswordPolicy policy);

    /// <summary>
    /// Validates a password against a named policy.
    /// </summary>
    Reports.PasswordValidationReport Validate(string password, string policyName);
}
