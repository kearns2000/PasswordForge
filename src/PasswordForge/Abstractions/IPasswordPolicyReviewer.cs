namespace PasswordForge.Abstractions;

/// <summary>
/// Reviews password policies against common modern guidance.
/// </summary>
public interface IPasswordPolicyReviewer
{
    /// <summary>
    /// Reviews the supplied policy and returns findings and suggestions.
    /// </summary>
    Reviews.PasswordPolicyReview Review(Policies.PasswordPolicy policy);
}
