namespace PasswordForge.Internal;

/// <summary>
/// Resolves named character set requirements used by policy rules.
/// </summary>
internal static class NamedCharacterSetResolver
{
    public static bool TryGetPool(string setName, Policies.PasswordPolicy policy, out string pool)
    {
        pool = ResolvePool(setName, policy);
        return pool.Length > 0;
    }

    public static bool IsKnownSetName(string setName) =>
        ResolveKind(setName) != SetKind.Unknown;

    public static int CountMatchingCharacters(string password, string setName, Policies.PasswordPolicy policy)
    {
        var pool = ResolvePool(setName, policy);
        if (pool.Length == 0)
            return 0;

        var allowed = pool.ToHashSet();
        return password.Count(c => allowed.Contains(c));
    }

    public static string ResolvePool(string setName, Policies.PasswordPolicy policy)
    {
        return ResolveKind(setName) switch
        {
            SetKind.Lowercase => FilterPool(GetLowercasePool(policy), policy),
            SetKind.Uppercase => FilterPool(GetUppercasePool(policy), policy),
            SetKind.Digit => FilterPool(GetDigitPool(policy), policy),
            SetKind.Symbol => FilterPool(GetSymbolPool(policy), policy),
            SetKind.Whitespace => CharacterSets.Whitespace,
            _ => string.Empty
        };
    }

    private static string FilterPool(string source, Policies.PasswordPolicy policy)
    {
        if (policy.AvoidAmbiguousCharacters)
            source = CharacterSets.RemoveAmbiguous(source, policy.AmbiguousCharacters);
        return source;
    }

    private static string GetLowercasePool(Policies.PasswordPolicy policy)
    {
        var pool = new HashSet<char>(CharacterSets.LowercaseAscii);
        if (policy.UnicodeMode != Policies.UnicodeMode.AsciiOnly)
            CharacterSets.AddUnicodeLetters(pool, upper: false, lower: true);
        return new string(pool.OrderBy(c => c).ToArray());
    }

    private static string GetUppercasePool(Policies.PasswordPolicy policy)
    {
        var pool = new HashSet<char>(CharacterSets.UppercaseAscii);
        if (policy.UnicodeMode != Policies.UnicodeMode.AsciiOnly)
            CharacterSets.AddUnicodeLetters(pool, upper: true, lower: false);
        return new string(pool.OrderBy(c => c).ToArray());
    }

    private static string GetDigitPool(Policies.PasswordPolicy policy) => CharacterSets.Digits;

    private static string GetSymbolPool(Policies.PasswordPolicy policy) =>
        policy.AllowedSymbols ?? CharacterSets.CommonSymbols;

    private static SetKind ResolveKind(string setName) =>
        setName.Trim().ToLowerInvariant() switch
        {
            "lowercase" or "lower" => SetKind.Lowercase,
            "uppercase" or "upper" => SetKind.Uppercase,
            "digit" or "digits" or "number" or "numbers" => SetKind.Digit,
            "symbol" or "symbols" => SetKind.Symbol,
            "whitespace" or "space" => SetKind.Whitespace,
            _ => SetKind.Unknown
        };

    private enum SetKind
    {
        Unknown,
        Lowercase,
        Uppercase,
        Digit,
        Symbol,
        Whitespace
    }
}
