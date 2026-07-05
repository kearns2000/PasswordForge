namespace PasswordForge.Validation;

/// <summary>
/// Analyses character class composition of a password.
/// </summary>
internal static class PasswordCharacterAnalyser
{
    public static Reports.PasswordCharacterBreakdown Analyse(string password)
    {
        var upper = 0;
        var lower = 0;
        var digit = 0;
        var symbol = 0;
        var whitespace = 0;
        var other = 0;

        foreach (var c in password)
        {
            if (char.IsUpper(c)) upper++;
            else if (char.IsLower(c)) lower++;
            else if (char.IsDigit(c)) digit++;
            else if (char.IsWhiteSpace(c)) whitespace++;
            else if (Internal.CharacterSets.CommonSymbols.Contains(c) ||
                     Internal.CharacterSets.ExtendedSymbols.Contains(c))
                symbol++;
            else
                other++;
        }

        return new Reports.PasswordCharacterBreakdown(
            upper, lower, digit, symbol, whitespace, other, password.Length);
    }

    public static int NormalisedLength(string password) =>
        password.Normalize().Length;
}
