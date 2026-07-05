namespace PasswordForge.Reviews;

/// <summary>
/// Reviews password policies and provides practical guidance checks.
/// </summary>
public static class PasswordPolicyReviewer
{
    /// <summary>
    /// Reviews a policy and returns findings and suggestions.
    /// </summary>
    public static PasswordPolicyReview Review(Policies.PasswordPolicy policy) =>
        ReviewInternal(policy);

    internal static PasswordPolicyReview ReviewInternal(Policies.PasswordPolicy policy)
    {
        var findings = new List<PasswordPolicyFinding>();
        var warnings = new List<string>();
        var suggestions = new List<string>();
        var score = 100;

        if (policy.MaxLength < 64)
        {
            findings.Add(new PasswordPolicyFinding(
                "max-length-low",
                "Maximum length is below 64 characters. This may conflict with common modern guidance favouring longer passwords.",
                PasswordPolicyFindingSeverity.Info,
                PasswordPolicyFindingCategory.Length));
            score -= 5;
        }

        if (policy.MinLength < 12)
        {
            findings.Add(new PasswordPolicyFinding(
                "min-length-low",
                $"Policy allows fewer than 12 characters (minimum: {policy.MinLength}). This may conflict with common modern guidance.",
                PasswordPolicyFindingSeverity.Warning,
                PasswordPolicyFindingCategory.Length));
            score -= 15;
            suggestions.Add("Consider increasing the minimum length to at least 12 characters.");
        }
        else if (policy.MinLength >= 16)
        {
            findings.Add(new PasswordPolicyFinding(
                "min-length-good",
                "Minimum length aligns with common modern guidance.",
                PasswordPolicyFindingSeverity.Info,
                PasswordPolicyFindingCategory.ModernGuidance));
        }

        var hasComposition = policy.RequireUppercase || policy.RequireLowercase ||
                             policy.RequireDigit || policy.RequireSymbol;
        if (hasComposition)
        {
            findings.Add(new PasswordPolicyFinding(
                "composition-rules",
                "Policy requires composition rules. This may reduce usability compared with length-focused policies.",
                PasswordPolicyFindingSeverity.Info,
                PasswordPolicyFindingCategory.Composition));
            score -= 5;
        }

        if (policy.DisallowWhitespace)
        {
            findings.Add(new PasswordPolicyFinding(
                "blocks-whitespace",
                "Policy blocks whitespace, which can make passphrases harder to use.",
                PasswordPolicyFindingSeverity.Info,
                PasswordPolicyFindingCategory.Usability));
        }

        var pool = Internal.CharacterSets.BuildAllowedPool(policy, out _);
        if (pool.Length < 20)
        {
            findings.Add(new PasswordPolicyFinding(
                "small-pool",
                "Policy allows a very small character pool, which may reduce effective entropy.",
                PasswordPolicyFindingSeverity.Warning,
                PasswordPolicyFindingCategory.CharacterSet));
            score -= 10;
        }

        if (policy.RequireSymbol)
        {
            var symbols = policy.AllowedSymbols ?? Internal.CharacterSets.CommonSymbols;
            if (symbols.Length <= 1)
            {
                findings.Add(new PasswordPolicyFinding(
                    "single-symbol",
                    "Policy requires symbols but only allows one symbol character.",
                    PasswordPolicyFindingSeverity.Warning,
                    PasswordPolicyFindingCategory.CharacterSet));
                score -= 10;
            }
        }

        if (policy.MinLength >= 20 && policy.MaxLength <= 32 && hasComposition)
        {
            findings.Add(new PasswordPolicyFinding(
                "temporary-suitable",
                "Policy appears suitable for a temporary password.",
                PasswordPolicyFindingSeverity.Info,
                PasswordPolicyFindingCategory.TemporaryCredential));
        }

        if (policy.MinLength < 16 && !hasComposition)
        {
            findings.Add(new PasswordPolicyFinding(
                "weak-bootstrap",
                "Policy is probably too weak for service account bootstrap.",
                PasswordPolicyFindingSeverity.High,
                PasswordPolicyFindingCategory.ModernGuidance));
            score -= 20;
            warnings.Add("Consider stronger requirements for service account bootstrap scenarios.");
        }

        if (policy.DisallowCommonPasswords)
        {
            findings.Add(new PasswordPolicyFinding(
                "common-password-check",
                "Policy includes a common password check. Note that production systems should use a larger compromised-password list externally.",
                PasswordPolicyFindingSeverity.Info,
                PasswordPolicyFindingCategory.ModernGuidance));
        }

        score = Math.Clamp(score, 0, 100);
        var strength = score switch
        {
            >= 80 => "Strong",
            >= 60 => "Moderate",
            >= 40 => "Weak",
            _ => "Very weak"
        };

        return new PasswordPolicyReview(
            score,
            findings,
            warnings,
            suggestions,
            strength);
    }
}

/// <summary>
/// Dependency injection adapter for password policy review.
/// </summary>
public sealed class DefaultPasswordPolicyReviewer : Abstractions.IPasswordPolicyReviewer
{
    /// <inheritdoc />
    public PasswordPolicyReview Review(Policies.PasswordPolicy policy) =>
        PasswordPolicyReviewer.ReviewInternal(policy);
}
