namespace PasswordForge.TestSets;

/// <summary>
/// Fluent builder for generating password test sets.
/// </summary>
public sealed class PasswordTestSetBuilder
{
    private readonly Policies.PasswordPolicy _policy;
    private readonly Internal.IRandomSource _random;
    private readonly Abstractions.ICommonPasswordProvider _commonPasswordProvider;
    private int _validCount;
    private int _invalidTooShort;
    private int _invalidTooLong;
    private int _invalidMissingUppercase;
    private int _invalidMissingLowercase;
    private int _invalidMissingDigit;
    private int _invalidMissingSymbol;
    private int _invalidRepeated;
    private int _invalidSequential;
    private bool _invalidCommonPasswords;
    private bool _edgeCases;

    internal PasswordTestSetBuilder(
        Policies.PasswordPolicy policy,
        Internal.IRandomSource random,
        Abstractions.ICommonPasswordProvider commonPasswordProvider)
    {
        _policy = policy;
        _random = random;
        _commonPasswordProvider = commonPasswordProvider;
    }

    /// <summary>Generates valid password samples.</summary>
    public PasswordTestSetBuilder Valid(int count)
    {
        _validCount = count;
        return this;
    }

    /// <summary>Generates passwords that are too short.</summary>
    public PasswordTestSetBuilder InvalidTooShort(int count)
    {
        _invalidTooShort = count;
        return this;
    }

    /// <summary>Generates passwords that are too long.</summary>
    public PasswordTestSetBuilder InvalidTooLong(int count)
    {
        _invalidTooLong = count;
        return this;
    }

    /// <summary>Generates passwords missing uppercase letters.</summary>
    public PasswordTestSetBuilder InvalidMissingUppercase(int count)
    {
        _invalidMissingUppercase = count;
        return this;
    }

    /// <summary>Generates passwords missing lowercase letters.</summary>
    public PasswordTestSetBuilder InvalidMissingLowercase(int count)
    {
        _invalidMissingLowercase = count;
        return this;
    }

    /// <summary>Generates passwords missing digits.</summary>
    public PasswordTestSetBuilder InvalidMissingDigit(int count)
    {
        _invalidMissingDigit = count;
        return this;
    }

    /// <summary>Generates passwords missing symbols.</summary>
    public PasswordTestSetBuilder InvalidMissingSymbol(int count)
    {
        _invalidMissingSymbol = count;
        return this;
    }

    /// <summary>Generates passwords with excessive repeated characters.</summary>
    public PasswordTestSetBuilder InvalidRepeatedCharacters(int count)
    {
        _invalidRepeated = count;
        return this;
    }

    /// <summary>Generates passwords with sequential characters.</summary>
    public PasswordTestSetBuilder InvalidSequentialCharacters(int count)
    {
        _invalidSequential = count;
        return this;
    }

    /// <summary>Includes common password invalid cases.</summary>
    public PasswordTestSetBuilder InvalidCommonPasswords()
    {
        _invalidCommonPasswords = true;
        return this;
    }

    /// <summary>Includes edge case samples.</summary>
    public PasswordTestSetBuilder EdgeCases()
    {
        _edgeCases = true;
        return this;
    }

    /// <summary>Generates the test set.</summary>
    public PasswordTestSetResult Generate()
    {
        var items = new List<PasswordTestSetItem>();
        var diagnostics = new List<string>();
        var generator = new Generation.PasswordGenerator(_random, _commonPasswordProvider);

        for (var i = 0; i < _validCount; i++)
        {
            var result = generator.Generate(_policy);
            if (result.Success && result.Value is not null)
            {
                items.Add(new PasswordTestSetItem(
                    result.Value, true, PasswordTestScenario.Valid, [],
                    "Valid password generated from policy."));
            }
            else
            {
                items.Add(new PasswordTestSetItem(
                    string.Empty, true, PasswordTestScenario.Valid, [],
                    "Valid password generation skipped.",
                    Skipped: true,
                    SkipReason: "Could not generate a valid password for this policy."));
            }
        }

        GenerateInvalidTooShort(items, diagnostics);
        GenerateInvalidTooLong(items, diagnostics);
        GenerateInvalidMissingClass(items, _invalidMissingUppercase, PasswordTestScenario.InvalidMissingUppercase,
            "require-uppercase", "Password missing uppercase letter.", c => !char.IsUpper(c));
        GenerateInvalidMissingClass(items, _invalidMissingLowercase, PasswordTestScenario.InvalidMissingLowercase,
            "require-lowercase", "Password missing lowercase letter.", c => !char.IsLower(c));
        GenerateInvalidMissingClass(items, _invalidMissingDigit, PasswordTestScenario.InvalidMissingDigit,
            "require-digit", "Password missing digit.", c => !char.IsDigit(c));
        GenerateInvalidMissingSymbol(items, diagnostics);
        GenerateInvalidRepeated(items, diagnostics);
        GenerateInvalidSequential(items, diagnostics);

        if (_invalidCommonPasswords)
        {
            if (_policy.DisallowCommonPasswords)
            {
                items.Add(new PasswordTestSetItem(
                    "password123", false, PasswordTestScenario.InvalidCommonPassword,
                    ["disallow-common"], "Common password that should be rejected."));
            }
            else
            {
                items.Add(new PasswordTestSetItem(
                    string.Empty, false, PasswordTestScenario.InvalidCommonPassword,
                    ["disallow-common"], "Common password scenario skipped.",
                    Skipped: true,
                    SkipReason: "Policy does not disallow common passwords."));
            }
        }

        if (_edgeCases)
        {
            var minPassword = new string('a', Math.Max(0, _policy.MinLength - 1)) + "A1!";
            if (_policy.RequireUppercase) minPassword = AdjustToMinLength(minPassword);
            items.Add(new PasswordTestSetItem(
                minPassword[..Math.Min(minPassword.Length, _policy.MaxLength)],
                minPassword.Length >= _policy.MinLength,
                PasswordTestScenario.EdgeCase,
                minPassword.Length >= _policy.MinLength ? [] : ["min-length"],
                "Edge case at minimum length boundary."));
        }

        return new PasswordTestSetResult(items, diagnostics);
    }

    private void GenerateInvalidTooShort(List<PasswordTestSetItem> items, List<string> diagnostics)
    {
        if (_invalidTooShort == 0) return;

        if (_policy.MinLength <= 1)
        {
            diagnostics.Add("InvalidTooShort scenario skipped: minimum length is already 1 or less.");
            for (var i = 0; i < _invalidTooShort; i++)
            {
                items.Add(new PasswordTestSetItem(
                    string.Empty, false, PasswordTestScenario.InvalidTooShort,
                    ["min-length"], "Too short scenario skipped.",
                    Skipped: true, SkipReason: "Policy minimum length is too low."));
            }
            return;
        }

        for (var i = 0; i < _invalidTooShort; i++)
        {
            var password = new string('a', _policy.MinLength - 1);
            items.Add(new PasswordTestSetItem(
                password, false, PasswordTestScenario.InvalidTooShort,
                ["min-length"], $"Password with length {_policy.MinLength - 1}, below minimum."));
        }
    }

    private void GenerateInvalidTooLong(List<PasswordTestSetItem> items, List<string> diagnostics)
    {
        if (_invalidTooLong == 0) return;

        for (var i = 0; i < _invalidTooLong; i++)
        {
            var password = new string('a', _policy.MaxLength + 1) + "A1!";
            items.Add(new PasswordTestSetItem(
                password, false, PasswordTestScenario.InvalidTooLong,
                ["max-length"], $"Password exceeding maximum length of {_policy.MaxLength}."));
        }
    }

    private void GenerateInvalidMissingClass(
        List<PasswordTestSetItem> items,
        int count,
        PasswordTestScenario scenario,
        string ruleId,
        string description,
        Func<char, bool> charPredicate)
    {
        if (count == 0) return;

        for (var i = 0; i < count; i++)
        {
            var password = BuildBasePassword();
            password = new string(password.Where(c => charPredicate(c) || !char.IsLetter(c)).ToArray());
            password = EnsureLength(password);

            items.Add(new PasswordTestSetItem(
                password, false, scenario, [ruleId], description));
        }
    }

    private void GenerateInvalidMissingSymbol(List<PasswordTestSetItem> items, List<string> diagnostics)
    {
        if (_invalidMissingSymbol == 0) return;

        if (!_policy.RequireSymbol)
        {
            diagnostics.Add("InvalidMissingSymbol scenario skipped: policy does not require symbols.");
            return;
        }

        for (var i = 0; i < _invalidMissingSymbol; i++)
        {
            var password = BuildBasePassword().Where(c => !IsSymbol(c)).Aggregate("", (a, c) => a + c);
            password = EnsureLength(password);
            items.Add(new PasswordTestSetItem(
                password, false, PasswordTestScenario.InvalidMissingSymbol,
                ["require-symbol"], "Password missing required symbol."));
        }
    }

    private void GenerateInvalidRepeated(List<PasswordTestSetItem> items, List<string> diagnostics)
    {
        if (_invalidRepeated == 0) return;

        if (_policy.MaxRepeatedCharacterRun is null)
        {
            diagnostics.Add("InvalidRepeatedCharacters scenario skipped: policy does not limit repeats.");
            return;
        }

        var run = _policy.MaxRepeatedCharacterRun.Value + 1;
        for (var i = 0; i < _invalidRepeated; i++)
        {
            var password = new string('a', run) + "A1!";
            password = EnsureLength(password);
            items.Add(new PasswordTestSetItem(
                password, false, PasswordTestScenario.InvalidRepeatedCharacters,
                ["disallow-repeated"], $"Password with {run} repeated characters."));
        }
    }

    private void GenerateInvalidSequential(List<PasswordTestSetItem> items, List<string> diagnostics)
    {
        if (_invalidSequential == 0) return;

        if (!_policy.DisallowSequentialCharacters)
        {
            diagnostics.Add("InvalidSequentialCharacters scenario skipped: policy does not disallow sequential characters.");
            return;
        }

        for (var i = 0; i < _invalidSequential; i++)
        {
            var password = "abc123" + BuildBasePassword();
            password = EnsureLength(password);
            items.Add(new PasswordTestSetItem(
                password, false, PasswordTestScenario.InvalidSequentialCharacters,
                ["disallow-sequential"], "Password containing sequential characters."));
        }
    }

    private string BuildBasePassword()
    {
        var chars = new List<char>();
        if (_policy.RequireLowercase || !_policy.RequireUppercase) chars.Add('a');
        if (_policy.RequireUppercase) chars.Add('A');
        if (_policy.RequireDigit) chars.Add('1');
        if (_policy.RequireSymbol)
        {
            var symbols = _policy.AllowedSymbols ?? Internal.CharacterSets.CommonSymbols;
            if (symbols.Length > 0) chars.Add(symbols[0]);
        }

        return new string(chars.ToArray());
    }

    private string EnsureLength(string password)
    {
        while (password.Length < _policy.MinLength)
            password += "x";
        return password.Length > _policy.MaxLength ? password[.._policy.MaxLength] : password;
    }

    private string AdjustToMinLength(string password)
    {
        while (password.Length < _policy.MinLength)
            password += "x";
        return password;
    }

    private bool IsSymbol(char c)
    {
        var symbols = _policy.AllowedSymbols ?? Internal.CharacterSets.CommonSymbols;
        return symbols.Contains(c);
    }
}
