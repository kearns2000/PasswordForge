namespace PasswordForge.Internal;

/// <summary>
/// Central character set definitions used by generation and validation.
/// </summary>
internal static class CharacterSets
{
    public const string LowercaseAscii = "abcdefghijklmnopqrstuvwxyz";
    public const string UppercaseAscii = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string Digits = "0123456789";
    public const string CommonSymbols = "@#$%!&*+-=?";
    public const string ExtendedSymbols = "@#$%!&*+-=?^~_.,:;<>[]{}()/\\|";
    public const string Whitespace = " \t";
    public const string DefaultAmbiguous = "0Oo1lI5S8B";

    public static string GetSymbols(bool extended) =>
        extended ? ExtendedSymbols : CommonSymbols;

    public static string RemoveAmbiguous(string source, string ambiguous) =>
        new string(source.Where(c => !ambiguous.Contains(c)).ToArray());

    public static void AddUnicodeLetters(HashSet<char> pool, bool upper, bool lower)
    {
        for (var c = '\u00C0'; c <= '\u024F'; c++)
        {
            if (!char.IsLetter(c))
                continue;

            if (upper && char.IsUpper(c))
                pool.Add(c);
            else if (lower && char.IsLower(c))
                pool.Add(c);
        }
    }

    public static string BuildAllowedPool(
        Policies.PasswordPolicy policy,
        out int classCount)
    {
        classCount = 0;
        var pool = new HashSet<char>();

        if (policy.AllowedCharacters is not null)
        {
            foreach (var c in policy.AllowedCharacters)
                pool.Add(c);

            ApplyDisallowedAndUnicodeFilters(pool, policy);
            classCount = CountDistinctClasses(pool, policy);
            return new string(pool.OrderBy(c => c).ToArray());
        }

        if (policy.RequireLowercase || policy.AllowedCharacters is null)
            AddClass(pool, BuildLowercasePool(policy), ref classCount);

        if (policy.RequireUppercase || policy.AllowedCharacters is null)
            AddClass(pool, BuildUppercasePool(policy), ref classCount);

        if (policy.RequireDigit || policy.AllowedCharacters is null)
            AddClass(pool, BuildDigitPool(policy), ref classCount);

        if (policy.RequireSymbol || policy.AllowedCharacters is null)
            AddClass(pool, BuildSymbolPool(policy), ref classCount);

        if (policy.AllowWhitespace || policy.RequireWhitespace)
            AddClass(pool, Whitespace, ref classCount);

        if (policy.UnicodeMode == Policies.UnicodeMode.AllowUnicode)
            AddUnicodeSymbols(pool);

        ApplyDisallowedAndUnicodeFilters(pool, policy);
        return new string(pool.OrderBy(c => c).ToArray());
    }

    private static string BuildLowercasePool(Policies.PasswordPolicy policy)
    {
        var pool = new HashSet<char>(LowercaseAscii);
        if (policy.UnicodeMode != Policies.UnicodeMode.AsciiOnly)
            AddUnicodeLetters(pool, upper: false, lower: true);

        return policy.AvoidAmbiguousCharacters
            ? RemoveAmbiguous(new string(pool.OrderBy(c => c).ToArray()), policy.AmbiguousCharacters)
            : new string(pool.OrderBy(c => c).ToArray());
    }

    private static string BuildUppercasePool(Policies.PasswordPolicy policy)
    {
        var pool = new HashSet<char>(UppercaseAscii);
        if (policy.UnicodeMode != Policies.UnicodeMode.AsciiOnly)
            AddUnicodeLetters(pool, upper: true, lower: false);

        return policy.AvoidAmbiguousCharacters
            ? RemoveAmbiguous(new string(pool.OrderBy(c => c).ToArray()), policy.AmbiguousCharacters)
            : new string(pool.OrderBy(c => c).ToArray());
    }

    private static string BuildDigitPool(Policies.PasswordPolicy policy) =>
        policy.AvoidAmbiguousCharacters
            ? RemoveAmbiguous(Digits, policy.AmbiguousCharacters)
            : Digits;

    private static string BuildSymbolPool(Policies.PasswordPolicy policy)
    {
        var pool = policy.AllowedSymbols ?? CommonSymbols;
        return policy.AvoidAmbiguousCharacters
            ? RemoveAmbiguous(pool, policy.AmbiguousCharacters)
            : pool;
    }

    private static void AddUnicodeSymbols(HashSet<char> pool)
    {
        const string unicodeSymbols = "£€¥§©®°±×÷";
        foreach (var c in unicodeSymbols)
            pool.Add(c);
    }

    private static void ApplyDisallowedAndUnicodeFilters(HashSet<char> pool, Policies.PasswordPolicy policy)
    {
        if (policy.DisallowedCharacters is not null)
        {
            foreach (var c in policy.DisallowedCharacters)
                pool.Remove(c);
        }

        if (policy.UnicodeMode == Policies.UnicodeMode.AsciiOnly)
        {
            pool.RemoveWhere(c => c > 127);
        }
        else if (policy.UnicodeMode == Policies.UnicodeMode.AllowUnicodeLettersOnly)
        {
            pool.RemoveWhere(c => c > 127 && !char.IsLetter(c));
        }
    }

    private static int CountDistinctClasses(HashSet<char> pool, Policies.PasswordPolicy policy)
    {
        var count = 0;
        if (pool.Any(char.IsLower)) count++;
        if (pool.Any(char.IsUpper)) count++;
        if (pool.Any(char.IsDigit)) count++;
        if (pool.Any(c => IsSymbolChar(c, policy))) count++;
        if (pool.Any(char.IsWhiteSpace)) count++;
        return count;
    }

    private static bool IsSymbolChar(char c, Policies.PasswordPolicy policy)
    {
        if (char.IsLetterOrDigit(c) || char.IsWhiteSpace(c))
            return false;

        var symbols = policy.AllowedSymbols ?? CommonSymbols;
        return symbols.Contains(c);
    }

    private static void AddClass(HashSet<char> pool, string chars, ref int classCount)
    {
        if (chars.Length == 0)
            return;

        var added = false;
        foreach (var c in chars)
        {
            if (pool.Add(c))
                added = true;
        }

        if (added)
            classCount++;
    }
}
