namespace PasswordForge.Validation;

/// <summary>
/// Validates passwords against password policies using a shared rule engine.
/// </summary>
public static class PasswordValidator
{
    private static readonly Internal.BuiltInCommonPasswordProvider DefaultCommonPasswordProvider = new();

    /// <summary>
    /// Validates a password against the supplied policy.
    /// </summary>
    public static Reports.PasswordValidationReport Validate(string password, Policies.PasswordPolicy policy) =>
        Validate(password, policy, DefaultCommonPasswordProvider);

    /// <summary>
    /// Validates a password against the supplied policy with a custom common password provider.
    /// </summary>
    public static Reports.PasswordValidationReport Validate(
        string password,
        Policies.PasswordPolicy policy,
        Abstractions.ICommonPasswordProvider commonPasswordProvider) =>
        ValidateInternal(password, policy, commonPasswordProvider);

    internal static Reports.PasswordValidationReport ValidateInternal(
        string password,
        Policies.PasswordPolicy policy,
        Abstractions.ICommonPasswordProvider commonPasswordProvider)
    {
        var matched = new List<Reports.PasswordRuleResult>();
        var failed = new List<Reports.PasswordRuleResult>();
        var warnings = new List<string>();

        EvaluatePolicyConfiguration(policy, warnings);
        EvaluateLength(password, policy, matched, failed);
        EvaluateUppercase(password, policy, matched, failed);
        EvaluateLowercase(password, policy, matched, failed);
        EvaluateDigit(password, policy, matched, failed);
        EvaluateSymbol(password, policy, matched, failed);
        EvaluateWhitespace(password, policy, matched, failed);
        EvaluateAllowedCharacters(password, policy, matched, failed);
        EvaluateDisallowedCharacters(password, policy, matched, failed);
        EvaluateAmbiguous(password, policy, matched, failed);
        EvaluateRepeatedCharacters(password, policy, matched, failed);
        EvaluateSequentialCharacters(password, policy, matched, failed);
        EvaluateKeyboardSequences(password, policy, matched, failed);
        EvaluateCommonPassword(password, policy, matched, failed, commonPasswordProvider);
        EvaluateUsername(password, policy, matched, failed);
        EvaluateEmailParts(password, policy, matched, failed);
        EvaluateContextValues(password, policy, matched, failed);
        EvaluateNamedCharacterSets(password, policy, matched, failed);

        var breakdown = PasswordCharacterAnalyser.Analyse(password);
        var poolSize = PasswordEntropyEstimator.ComputeEffectivePoolSize(policy);
        var entropy = PasswordEntropyEstimator.EstimateRandom(password, poolSize);

        if (policy.MinimumEntropyBits is not null && entropy.EntropyBits < policy.MinimumEntropyBits)
        {
            failed.Add(new Reports.PasswordRuleResult(
                "minimum-entropy",
                $"Estimated entropy ({entropy.EntropyBits:F1} bits) is below the required minimum ({policy.MinimumEntropyBits:F1} bits).",
                false));
        }
        else if (policy.MinimumEntropyBits is not null)
        {
            matched.Add(new Reports.PasswordRuleResult(
                "minimum-entropy",
                "Estimated entropy meets the minimum requirement.",
                true));
        }

        return new Reports.PasswordValidationReport(
            failed.Count == 0,
            matched,
            failed,
            warnings,
            entropy.EntropyBits,
            PasswordCharacterAnalyser.NormalisedLength(password),
            breakdown,
            entropy);
    }

    private static void EvaluatePolicyConfiguration(Policies.PasswordPolicy policy, List<string> warnings)
    {
        if (policy.DisallowUsername && string.IsNullOrWhiteSpace(policy.Username))
        {
            warnings.Add("DisallowUsername is enabled but no username was configured on the policy.");
        }

        if (policy.DisallowEmailParts && string.IsNullOrWhiteSpace(policy.Email))
        {
            warnings.Add("DisallowEmailParts is enabled but no email was configured on the policy.");
        }
    }

    private static void EvaluateNamedCharacterSets(
        string password,
        Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched,
        List<Reports.PasswordRuleResult> failed)
    {
        foreach (var requirement in policy.RequireAtLeastOneFrom)
        {
            EvaluateNamedSetRequirement(password, policy, requirement.SetName, 1, "require-at-least-one-from", matched, failed);
        }

        foreach (var requirement in policy.RequireCountFrom)
        {
            EvaluateNamedSetRequirement(
                password,
                policy,
                requirement.SetName,
                requirement.MinimumCount,
                "require-count-from",
                matched,
                failed);
        }
    }

    private static void EvaluateNamedSetRequirement(
        string password,
        Policies.PasswordPolicy policy,
        string setName,
        int minimumCount,
        string rulePrefix,
        List<Reports.PasswordRuleResult> matched,
        List<Reports.PasswordRuleResult> failed)
    {
        if (!Internal.NamedCharacterSetResolver.IsKnownSetName(setName))
        {
            failed.Add(new Reports.PasswordRuleResult(
                $"{rulePrefix}-{setName}",
                $"Named character set '{setName}' is not recognised.",
                false));
            return;
        }

        var count = Internal.NamedCharacterSetResolver.CountMatchingCharacters(password, setName, policy);
        if (count >= minimumCount)
        {
            matched.Add(new Reports.PasswordRuleResult(
                $"{rulePrefix}-{setName}",
                $"Password contains at least {minimumCount} character(s) from set '{setName}'.",
                true));
        }
        else
        {
            failed.Add(new Reports.PasswordRuleResult(
                $"{rulePrefix}-{setName}",
                $"Password must contain at least {minimumCount} character(s) from set '{setName}'.",
                false));
        }
    }

    private static void EvaluateLength(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (password.Length < policy.MinLength)
        {
            failed.Add(new Reports.PasswordRuleResult(
                "min-length",
                $"Password must be at least {policy.MinLength} characters.",
                false));
        }
        else
        {
            matched.Add(new Reports.PasswordRuleResult(
                "min-length",
                $"Password meets the minimum length of {policy.MinLength}.",
                true));
        }

        if (password.Length > policy.MaxLength)
        {
            failed.Add(new Reports.PasswordRuleResult(
                "max-length",
                $"Password must not exceed {policy.MaxLength} characters.",
                false));
        }
        else
        {
            matched.Add(new Reports.PasswordRuleResult(
                "max-length",
                $"Password is within the maximum length of {policy.MaxLength}.",
                true));
        }
    }

    private static void EvaluateUppercase(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (!policy.RequireUppercase) return;

        if (password.Any(char.IsUpper))
            matched.Add(new Reports.PasswordRuleResult("require-uppercase", "Password contains an uppercase letter.", true));
        else
            failed.Add(new Reports.PasswordRuleResult("require-uppercase", "Password must contain an uppercase letter.", false));
    }

    private static void EvaluateLowercase(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (!policy.RequireLowercase) return;

        if (password.Any(char.IsLower))
            matched.Add(new Reports.PasswordRuleResult("require-lowercase", "Password contains a lowercase letter.", true));
        else
            failed.Add(new Reports.PasswordRuleResult("require-lowercase", "Password must contain a lowercase letter.", false));
    }

    private static void EvaluateDigit(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (!policy.RequireDigit) return;

        if (password.Any(char.IsDigit))
            matched.Add(new Reports.PasswordRuleResult("require-digit", "Password contains a digit.", true));
        else
            failed.Add(new Reports.PasswordRuleResult("require-digit", "Password must contain a digit.", false));
    }

    private static void EvaluateSymbol(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (!policy.RequireSymbol) return;

        var symbols = policy.AllowedSymbols ?? Internal.CharacterSets.CommonSymbols;
        if (password.Any(c => symbols.Contains(c)))
            matched.Add(new Reports.PasswordRuleResult("require-symbol", "Password contains an allowed symbol.", true));
        else
            failed.Add(new Reports.PasswordRuleResult("require-symbol", "Password must contain an allowed symbol.", false));
    }

    private static void EvaluateWhitespace(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        var hasWhitespace = password.Any(char.IsWhiteSpace);

        if (policy.DisallowWhitespace && hasWhitespace)
            failed.Add(new Reports.PasswordRuleResult("disallow-whitespace", "Password must not contain whitespace.", false));
        else if (policy.DisallowWhitespace)
            matched.Add(new Reports.PasswordRuleResult("disallow-whitespace", "Password contains no whitespace.", true));

        if (policy.RequireWhitespace && !hasWhitespace)
            failed.Add(new Reports.PasswordRuleResult("require-whitespace", "Password must contain whitespace.", false));
        else if (policy.RequireWhitespace)
            matched.Add(new Reports.PasswordRuleResult("require-whitespace", "Password contains whitespace.", true));
    }

    private static void EvaluateAllowedCharacters(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (policy.AllowedCharacters is null && policy.UnicodeMode == Policies.UnicodeMode.AsciiOnly)
        {
            if (password.All(c => c <= 127))
                matched.Add(new Reports.PasswordRuleResult("ascii-only", "Password uses ASCII characters only.", true));
            else
                failed.Add(new Reports.PasswordRuleResult("ascii-only", "Password must use ASCII characters only.", false));
        }

        if (policy.UnicodeMode == Policies.UnicodeMode.AllowUnicodeLettersOnly)
        {
            if (password.All(c => c <= 127 || char.IsLetter(c)))
                matched.Add(new Reports.PasswordRuleResult("unicode-letters-only", "Password uses only ASCII and Unicode letter characters.", true));
            else
                failed.Add(new Reports.PasswordRuleResult("unicode-letters-only", "Password must use only ASCII and Unicode letter characters beyond ASCII.", false));
        }

        if (policy.AllowedCharacters is not null)
        {
            var allowed = policy.AllowedCharacters.ToHashSet();
            if (password.All(c => allowed.Contains(c)))
                matched.Add(new Reports.PasswordRuleResult("allowed-characters", "Password uses only allowed characters.", true));
            else
                failed.Add(new Reports.PasswordRuleResult("allowed-characters", "Password contains characters outside the allowed set.", false));
        }

        if (policy.AllowedSymbols is not null && policy.RequireSymbol)
        {
            var invalidSymbols = password.Where(c =>
                !char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c) &&
                !policy.AllowedSymbols.Contains(c)).ToList();

            if (invalidSymbols.Count > 0)
                failed.Add(new Reports.PasswordRuleResult("allowed-symbols", "Password contains symbols outside the allowed set.", false));
            else
                matched.Add(new Reports.PasswordRuleResult("allowed-symbols", "Password symbols are within the allowed set.", true));
        }
        else if (policy.AllowedSymbols is not null)
        {
            var invalidSymbols = password.Where(c =>
                !char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c) &&
                !policy.AllowedSymbols.Contains(c)).ToList();

            if (invalidSymbols.Count > 0)
                failed.Add(new Reports.PasswordRuleResult("allowed-symbols", "Password contains symbols outside the allowed set.", false));
        }
    }

    private static void EvaluateDisallowedCharacters(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (policy.DisallowedCharacters is null) return;

        var disallowed = policy.DisallowedCharacters.ToHashSet();
        if (password.Any(c => disallowed.Contains(c)))
            failed.Add(new Reports.PasswordRuleResult("disallowed-characters", "Password contains disallowed characters.", false));
        else
            matched.Add(new Reports.PasswordRuleResult("disallowed-characters", "Password contains no disallowed characters.", true));
    }

    private static void EvaluateAmbiguous(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (!policy.AvoidAmbiguousCharacters) return;

        if (password.Any(c => policy.AmbiguousCharacters.Contains(c)))
            failed.Add(new Reports.PasswordRuleResult("avoid-ambiguous", "Password contains ambiguous characters.", false));
        else
            matched.Add(new Reports.PasswordRuleResult("avoid-ambiguous", "Password avoids ambiguous characters.", true));
    }

    private static void EvaluateRepeatedCharacters(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (policy.MaxRepeatedCharacterRun is null) return;

        var maxRun = 1;
        var currentRun = 1;
        for (var i = 1; i < password.Length; i++)
        {
            if (password[i] == password[i - 1])
            {
                currentRun++;
                maxRun = Math.Max(maxRun, currentRun);
            }
            else
            {
                currentRun = 1;
            }
        }

        if (maxRun > policy.MaxRepeatedCharacterRun)
            failed.Add(new Reports.PasswordRuleResult(
                "disallow-repeated",
                $"Password contains a run of {maxRun} repeated characters (maximum allowed: {policy.MaxRepeatedCharacterRun}).",
                false));
        else
            matched.Add(new Reports.PasswordRuleResult("disallow-repeated", "Password avoids excessive repeated characters.", true));
    }

    private static void EvaluateSequentialCharacters(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (!policy.DisallowSequentialCharacters) return;

        if (ContainsSequentialRun(password, 3))
            failed.Add(new Reports.PasswordRuleResult("disallow-sequential", "Password contains sequential characters.", false));
        else
            matched.Add(new Reports.PasswordRuleResult("disallow-sequential", "Password avoids sequential characters.", true));
    }

    private static void EvaluateKeyboardSequences(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (!policy.DisallowKeyboardSequences) return;

        var lower = password.ToLowerInvariant();
        var sequences = new[] { "qwerty", "asdf", "zxcv", "1234", "abcd" };
        if (sequences.Any(s => lower.Contains(s)))
            failed.Add(new Reports.PasswordRuleResult("disallow-keyboard", "Password contains a keyboard sequence.", false));
        else
            matched.Add(new Reports.PasswordRuleResult("disallow-keyboard", "Password avoids keyboard sequences.", true));
    }

    private static void EvaluateCommonPassword(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed,
        Abstractions.ICommonPasswordProvider commonPasswordProvider)
    {
        if (!policy.DisallowCommonPasswords) return;

        if (commonPasswordProvider.IsCommonPassword(password))
            failed.Add(new Reports.PasswordRuleResult("disallow-common", "Password is a commonly used password.", false));
        else
            matched.Add(new Reports.PasswordRuleResult("disallow-common", "Password is not in the common password list.", true));
    }

    private static void EvaluateUsername(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (!policy.DisallowUsername) return;

        if (string.IsNullOrEmpty(policy.Username))
            return;

        if (password.Contains(policy.Username, StringComparison.OrdinalIgnoreCase))
            failed.Add(new Reports.PasswordRuleResult("disallow-username", "Password must not contain the username.", false));
        else
            matched.Add(new Reports.PasswordRuleResult("disallow-username", "Password does not contain the username.", true));
    }

    private static void EvaluateEmailParts(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (!policy.DisallowEmailParts) return;

        if (string.IsNullOrEmpty(policy.Email))
            return;

        var parts = policy.Email.Split('@', StringSplitOptions.RemoveEmptyEntries);
        var emailFragments = new List<string>();
        foreach (var part in parts)
        {
            emailFragments.Add(part);
            emailFragments.AddRange(part.Split('.', StringSplitOptions.RemoveEmptyEntries));
        }

        if (emailFragments.Any(p => p.Length >= 3 && password.Contains(p, StringComparison.OrdinalIgnoreCase)))
            failed.Add(new Reports.PasswordRuleResult("disallow-email", "Password must not contain parts of the email address.", false));
        else
            matched.Add(new Reports.PasswordRuleResult("disallow-email", "Password does not contain email address parts.", true));
    }

    private static void EvaluateContextValues(string password, Policies.PasswordPolicy policy,
        List<Reports.PasswordRuleResult> matched, List<Reports.PasswordRuleResult> failed)
    {
        if (policy.DisallowedContextValues.Count == 0) return;

        var found = policy.DisallowedContextValues
            .Where(v => v.Length >= 3 && password.Contains(v, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (found.Count > 0)
            failed.Add(new Reports.PasswordRuleResult("disallow-context", "Password contains disallowed context values.", false));
        else
            matched.Add(new Reports.PasswordRuleResult("disallow-context", "Password contains no disallowed context values.", true));
    }

    private static bool ContainsSequentialRun(string password, int minLength)
    {
        if (password.Length < minLength) return false;

        for (var i = 0; i <= password.Length - minLength; i++)
        {
            var ascending = true;
            var descending = true;
            for (var j = 1; j < minLength; j++)
            {
                if (password[i + j] != password[i + j - 1] + 1) ascending = false;
                if (password[i + j] != password[i + j - 1] - 1) descending = false;
            }

            if (ascending || descending) return true;
        }

        return false;
    }
}

/// <summary>
/// Dependency injection adapter for password validation.
/// </summary>
public sealed class DefaultPasswordValidator : Abstractions.IPasswordValidator
{
    private readonly Abstractions.ICommonPasswordProvider _commonPasswordProvider;
    private readonly Abstractions.IPasswordPolicyProvider? _policyProvider;

    /// <summary>
    /// Creates a validator with the supplied dependencies.
    /// </summary>
    public DefaultPasswordValidator(
        Abstractions.ICommonPasswordProvider commonPasswordProvider,
        Abstractions.IPasswordPolicyProvider? policyProvider = null)
    {
        _commonPasswordProvider = commonPasswordProvider;
        _policyProvider = policyProvider;
    }

    /// <inheritdoc />
    public Reports.PasswordValidationReport Validate(string password, Policies.PasswordPolicy policy) =>
        PasswordValidator.ValidateInternal(password, policy, _commonPasswordProvider);

    /// <inheritdoc />
    public Reports.PasswordValidationReport Validate(string password, string policyName)
    {
        if (_policyProvider is null)
            throw new InvalidOperationException("Named policy validation requires IPasswordPolicyProvider.");

        var policy = _policyProvider.GetPolicy(policyName);
        return Validate(password, policy);
    }
}
