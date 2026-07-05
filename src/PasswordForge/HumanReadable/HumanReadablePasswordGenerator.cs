namespace PasswordForge.HumanReadable;

/// <summary>
/// Generates human-readable passwords that satisfy password policies.
/// </summary>
internal sealed class HumanReadablePasswordGenerator
{
    private readonly Internal.IRandomSource _random;
    private readonly Abstractions.ICommonPasswordProvider _commonPasswordProvider;

    public HumanReadablePasswordGenerator(Internal.IRandomSource random, Abstractions.ICommonPasswordProvider commonPasswordProvider)
    {
        _random = random;
        _commonPasswordProvider = commonPasswordProvider;
    }

    public Reports.PasswordGenerationResult Generate(
        Policies.PasswordPolicy policy,
        HumanReadablePasswordOptions? options = null)
    {
        options ??= HumanReadablePasswordOptions.Default;
        var wordList = options.CustomWordList ?? Internal.DefaultWordList.Words;

        if (wordList.Count == 0)
        {
            return new Reports.PasswordGenerationResult(
                false, null, 0, policy, null, null, [],
                ["Cannot generate a human-readable password because the word list is empty."]);
        }

        var diagnostics = Diagnostics.PolicyDiagnostics.Analyse(policy);
        if (diagnostics.Count > 0)
        {
            return new Reports.PasswordGenerationResult(
                false, null, 0, policy, null, null, [], diagnostics);
        }

        for (var attempt = 1; attempt <= options.MaxAttempts; attempt++)
        {
            var password = BuildPassword(policy, options, wordList);
            var validation = Validation.PasswordValidator.ValidateInternal(password, policy, _commonPasswordProvider);

            if (validation.IsValid)
            {
                var extraBits = (options.AppendNumber ? Math.Log2(100) : 0) +
                                (options.AppendSymbol ? Math.Log2(10) : 0);
                var entropy = Validation.PasswordEntropyEstimator.EstimatePassphrase(
                    wordList.Count, options.WordCount, extraBits);

                var report = new Reports.PasswordGenerationReport(
                    attempt,
                    password.Length,
                    wordList.Count,
                    ["human-readable"],
                    "human-readable");

                return new Reports.PasswordGenerationResult(
                    true,
                    password,
                    entropy.EntropyBits,
                    policy,
                    validation,
                    report,
                    [],
                    []);
            }
        }

        return new Reports.PasswordGenerationResult(
            false, null, 0, policy, null, null, [],
            [$"Human-readable password generation failed after {options.MaxAttempts} attempts."]);
    }

    private string BuildPassword(
        Policies.PasswordPolicy policy,
        HumanReadablePasswordOptions options,
        IReadOnlyList<string> wordList)
    {
        var words = new List<string>();
        for (var i = 0; i < options.WordCount; i++)
        {
            var word = wordList[_random.NextInt32(wordList.Count)];
            words.Add(Capitalise(word, options.CapitalisationMode));
        }

        var parts = new List<string>(words);

        if (options.AppendNumber)
            parts.Add(_random.NextInt32(100).ToString("00"));

        if (options.AppendSymbol)
        {
            var symbols = policy.AllowedSymbols ?? Internal.CharacterSets.CommonSymbols;
            if (symbols.Length > 0)
                parts.Add(symbols[_random.NextInt32(symbols.Length)].ToString());
        }

        var password = string.Join(options.Separator, parts);

        while (password.Length < policy.MinLength)
        {
            var extra = wordList[_random.NextInt32(wordList.Count)];
            password += options.Separator + Capitalise(extra, options.CapitalisationMode);
        }

        if (password.Length > policy.MaxLength)
            password = password[..policy.MaxLength];

        return password;
    }

    private string Capitalise(string word, CapitalisationMode mode) =>
        mode switch
        {
            CapitalisationMode.TitleCase => char.ToUpperInvariant(word[0]) + word[1..],
            CapitalisationMode.LowerCase => word,
            CapitalisationMode.UpperCase => word.ToUpperInvariant(),
            CapitalisationMode.Random => _random.NextInt32(2) == 0
                ? word
                : char.ToUpperInvariant(word[0]) + word[1..],
            _ => word
        };
}
