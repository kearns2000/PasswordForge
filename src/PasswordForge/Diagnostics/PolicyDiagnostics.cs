namespace PasswordForge.Diagnostics;

/// <summary>
/// Validates a policy for internal consistency before generation.
/// </summary>
internal static class PolicyDiagnostics
{
    public static IReadOnlyList<string> Analyse(Policies.PasswordPolicy policy)
    {
        var diagnostics = new List<string>();

        if (policy.MinLength > policy.MaxLength)
        {
            diagnostics.Add(
                $"Cannot generate a password because the minimum length ({policy.MinLength}) is greater than the maximum length ({policy.MaxLength}).");
        }

        var mandatoryChars = CountMandatoryCharacters(policy);
        if (mandatoryChars > policy.MaxLength)
        {
            diagnostics.Add(
                $"Cannot generate a password because the policy requires at least {mandatoryChars} mandatory characters, but the maximum length is {policy.MaxLength}.");
        }

        if (policy.MinLength > policy.MaxLength)
            return diagnostics;

        if (policy.DisallowUsername && string.IsNullOrWhiteSpace(policy.Username))
        {
            diagnostics.Add(
                "DisallowUsername is enabled but no username was configured on the policy. Set Username on the policy or pass a value to DisallowUsername().");
        }

        if (policy.DisallowEmailParts && string.IsNullOrWhiteSpace(policy.Email))
        {
            diagnostics.Add(
                "DisallowEmailParts is enabled but no email was configured on the policy. Set Email on the policy or pass a value to DisallowEmailParts().");
        }

        foreach (var req in policy.RequireAtLeastOneFrom.Concat(policy.RequireCountFrom))
        {
            if (!Internal.NamedCharacterSetResolver.IsKnownSetName(req.SetName))
            {
                diagnostics.Add(
                    $"Cannot generate a password because named character set '{req.SetName}' is not recognised. Supported sets: lowercase, uppercase, digit, symbol, whitespace.");
            }
            else if (!Internal.NamedCharacterSetResolver.TryGetPool(req.SetName, policy, out var setPool) || setPool.Length == 0)
            {
                diagnostics.Add(
                    $"Cannot generate a password because named character set '{req.SetName}' has no available characters for this policy.");
            }
        }

        var pool = Internal.CharacterSets.BuildAllowedPool(policy, out var classCount);

        if (pool.Length == 0)
        {
            diagnostics.Add("Cannot generate a password because the allowed character set is empty.");
        }

        if (policy.RequireSymbol)
        {
            var symbols = policy.AllowedSymbols ?? Internal.CharacterSets.CommonSymbols;
            if (policy.AvoidAmbiguousCharacters)
                symbols = Internal.CharacterSets.RemoveAmbiguous(symbols, policy.AmbiguousCharacters);

            if (string.IsNullOrEmpty(symbols))
            {
                diagnostics.Add("Cannot generate a password because symbols are required but no symbols are allowed.");
            }
        }

        if (policy.RequireWhitespace && policy.DisallowWhitespace)
        {
            diagnostics.Add("Cannot generate a password because whitespace is required but whitespace is disallowed.");
        }

        if (policy.UnicodeMode == Policies.UnicodeMode.AsciiOnly &&
            policy.AllowedCharacters is not null &&
            policy.AllowedCharacters.Any(c => c > 127))
        {
            diagnostics.Add("Cannot generate a password because ASCII-only mode is enabled but only Unicode characters are allowed.");
        }

        var requiredClasses = CountRequiredClasses(policy);
        if (pool.Length > 0 && requiredClasses > classCount && policy.AllowedCharacters is null)
        {
            diagnostics.Add(
                $"Cannot generate a password because the policy requires {requiredClasses} distinct character classes, but the allowed pool can only satisfy {classCount}.");
        }

        foreach (var req in policy.RequireCountFrom)
        {
            if (req.MinimumCount > policy.MaxLength)
            {
                diagnostics.Add(
                    $"Cannot generate a password because set '{req.SetName}' requires {req.MinimumCount} characters, exceeding the maximum length of {policy.MaxLength}.");
            }
        }

        return diagnostics;
    }

    private static int CountMandatoryCharacters(Policies.PasswordPolicy policy)
    {
        var count = 0;
        if (policy.RequireUppercase) count++;
        if (policy.RequireLowercase) count++;
        if (policy.RequireDigit) count++;
        if (policy.RequireSymbol) count++;
        if (policy.RequireWhitespace) count++;
        count += policy.RequireAtLeastOneFrom.Count;
        count += policy.RequireCountFrom.Sum(r => r.MinimumCount);
        return count;
    }

    private static int CountRequiredClasses(Policies.PasswordPolicy policy)
    {
        var count = 0;
        if (policy.RequireUppercase) count++;
        if (policy.RequireLowercase) count++;
        if (policy.RequireDigit) count++;
        if (policy.RequireSymbol) count++;
        if (policy.RequireWhitespace) count++;
        return count;
    }
}
