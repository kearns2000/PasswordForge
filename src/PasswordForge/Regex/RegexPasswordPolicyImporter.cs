namespace PasswordForge.Regex;

/// <summary>
/// Result of importing a password policy from a regular expression.
/// </summary>
public sealed record RegexPolicyImportResult(
    bool Success,
    Policies.PasswordPolicy? Policy,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> UnsupportedFeatures);

/// <summary>
/// Imports password policies from common regular expression patterns.
/// </summary>
public static class RegexPasswordPolicyImporter
{
    /// <summary>
    /// Attempts to import a policy from a regex pattern.
    /// Only common patterns are supported. Complex regexes return unsupported feature warnings.
    /// </summary>
    public static RegexPolicyImportResult FromRegex(string pattern)
    {
        var warnings = new List<string>();
        var unsupported = new List<string>();

        if (string.IsNullOrWhiteSpace(pattern))
        {
            return new RegexPolicyImportResult(
                false, null, warnings,
                ["Pattern is empty."]);
        }

        var builder = Policies.PasswordPolicy.Create();
        var supported = false;

        var lengthMatch = System.Text.RegularExpressions.Regex.Match(pattern, @"\.\{(\d+)(?:,(\d+))?\}");
        if (lengthMatch.Success)
        {
            supported = true;
            var min = int.Parse(lengthMatch.Groups[1].Value);
            builder.MinLength(min);
            if (lengthMatch.Groups[2].Success)
                builder.MaxLength(int.Parse(lengthMatch.Groups[2].Value));
            else
                builder.MaxLength(Math.Max(min, 64));
        }

        if (pattern.Contains(@"(?=.*[A-Z])", StringComparison.Ordinal))
        {
            supported = true;
            builder.RequireUppercase();
        }

        if (pattern.Contains(@"(?=.*[a-z])", StringComparison.Ordinal))
        {
            supported = true;
            builder.RequireLowercase();
        }

        if (pattern.Contains(@"(?=.*\d)", StringComparison.Ordinal) ||
            pattern.Contains(@"(?=.*[0-9])", StringComparison.Ordinal))
        {
            supported = true;
            builder.RequireDigit();
        }

        var symbolMatch = System.Text.RegularExpressions.Regex.Match(
            pattern, @"\(\?=\.\*\[@#\$%[^\]]*\]\)");
        if (symbolMatch.Success)
        {
            supported = true;
            builder.RequireSymbol();
            var symbolGroup = System.Text.RegularExpressions.Regex.Match(pattern, @"\[@#\$%[^\]]*\]");
            if (symbolGroup.Success)
            {
                var inner = symbolGroup.Value.Trim('[', ']');
                builder.AllowedSymbols(inner);
            }
        }
        else if (pattern.Contains(@"(?=.*[@#$%])", StringComparison.Ordinal) ||
                 pattern.Contains(@"(?=.*\W)", StringComparison.Ordinal))
        {
            supported = true;
            builder.RequireSymbol();
            warnings.Add("Symbol requirement detected but specific allowed symbols could not be determined. Using default symbols.");
        }

        if (pattern.Contains(@"(?!.*\s)", StringComparison.Ordinal) ||
            pattern.Contains(@"\S", StringComparison.Ordinal))
        {
            supported = true;
            builder.DisallowWhitespace();
        }

        if (pattern.Contains("(?=") && !IsSimpleLookaheadPattern(pattern))
        {
            unsupported.Add("Complex lookahead assertions are not fully supported.");
        }

        if (pattern.Contains("|"))
            unsupported.Add("Alternation is not supported.");

        if (pattern.Contains("\\b"))
            unsupported.Add("Word boundary assertions are not supported.");

        if (!supported)
        {
            unsupported.Add("No recognised password policy patterns were found in the regex.");
            return new RegexPolicyImportResult(false, null, warnings, unsupported);
        }

        if (unsupported.Count > 0)
            warnings.Add("Policy was partially imported. Review unsupported features before use.");

        return new RegexPolicyImportResult(true, builder.Build(), warnings, unsupported);
    }

    private static bool IsSimpleLookaheadPattern(string pattern)
    {
        var simplePatterns = new[]
        {
            @"(?=.*[A-Z])", @"(?=.*[a-z])", @"(?=.*\d)", @"(?=.*[0-9])",
            @"(?=.*[@#$%])", @"(?!.*\s)"
        };
        return simplePatterns.Any(p => pattern.Contains(p, StringComparison.Ordinal));
    }
}
