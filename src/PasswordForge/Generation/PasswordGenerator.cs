namespace PasswordForge.Generation;

/// <summary>
/// Generates passwords that satisfy password policies.
/// </summary>
internal sealed class PasswordGenerator
{
    private readonly Internal.IRandomSource _random;
    private readonly Abstractions.ICommonPasswordProvider _commonPasswordProvider;

    public PasswordGenerator(Internal.IRandomSource random, Abstractions.ICommonPasswordProvider commonPasswordProvider)
    {
        _random = random;
        _commonPasswordProvider = commonPasswordProvider;
    }

    public Reports.PasswordGenerationResult Generate(
        Policies.PasswordPolicy policy,
        PasswordGenerationOptions? options = null)
    {
        options ??= PasswordGenerationOptions.Default;

        var diagnostics = Diagnostics.PolicyDiagnostics.Analyse(policy);
        if (diagnostics.Count > 0)
        {
            return Failed(policy, diagnostics, options.MaxAttempts, 0);
        }

        var targetLength = DetermineTargetLength(policy, options);
        var pool = Internal.CharacterSets.BuildAllowedPool(policy, out _);

        if (pool.Length == 0)
        {
            return Failed(policy, ["Cannot generate a password because the allowed character set is empty."],
                options.MaxAttempts, targetLength);
        }

        var warnings = new List<string>();
        var appliedRules = BuildAppliedRulesList(policy);

        for (var attempt = 1; attempt <= options.MaxAttempts; attempt++)
        {
            var password = BuildPassword(policy, pool, targetLength);

            if (options.AvoidStartingWithSymbol && password.Length > 0 &&
                IsSymbol(password[0], policy))
            {
                continue;
            }

            if (options.AvoidEndingWithSymbol && password.Length > 0 &&
                IsSymbol(password[^1], policy))
            {
                continue;
            }

            var validation = Validation.PasswordValidator.ValidateInternal(password, policy, _commonPasswordProvider);
            if (validation.IsValid)
            {
                var entropy = Validation.PasswordEntropyEstimator.EstimateRandom(password, pool.Length);
                var report = new Reports.PasswordGenerationReport(
                    attempt,
                    targetLength,
                    pool.Length,
                    appliedRules,
                    "random");

                return new Reports.PasswordGenerationResult(
                    true,
                    password,
                    entropy.EntropyBits,
                    policy,
                    validation,
                    report,
                    warnings,
                    []);
            }
        }

        if (options.HumanReadableFallback)
        {
            warnings.Add("Random generation failed. Falling back to human-readable generation.");
            var humanGenerator = new HumanReadable.HumanReadablePasswordGenerator(_random, _commonPasswordProvider);
            var humanResult = humanGenerator.Generate(policy);
            return humanResult with { Warnings = warnings.Concat(humanResult.Warnings).ToList() };
        }

        return Failed(
            policy,
            [$"Password generation failed after {options.MaxAttempts} attempts. The policy constraints may be too restrictive."],
            options.MaxAttempts,
            targetLength);
    }

    private string BuildPassword(Policies.PasswordPolicy policy, string pool, int targetLength)
    {
        var chars = new List<char>();

        if (policy.RequireLowercase)
            chars.Add(PickFrom(GetLowercasePool(policy)));

        if (policy.RequireUppercase)
            chars.Add(PickFrom(GetUppercasePool(policy)));

        if (policy.RequireDigit)
            chars.Add(PickFrom(GetDigitPool(policy)));

        if (policy.RequireSymbol)
            chars.Add(PickFrom(GetSymbolPool(policy)));

        if (policy.RequireWhitespace)
            chars.Add(PickFrom(Internal.CharacterSets.Whitespace));

        foreach (var requirement in policy.RequireAtLeastOneFrom)
        {
            if (Internal.NamedCharacterSetResolver.TryGetPool(requirement.SetName, policy, out var setPool))
                chars.Add(PickFrom(setPool));
        }

        foreach (var requirement in policy.RequireCountFrom)
        {
            if (!Internal.NamedCharacterSetResolver.TryGetPool(requirement.SetName, policy, out var setPool))
                continue;

            for (var i = 0; i < requirement.MinimumCount; i++)
                chars.Add(PickFrom(setPool));
        }

        while (chars.Count < targetLength)
            chars.Add(PickFrom(pool));

        if (chars.Count > targetLength)
            chars = chars.Take(targetLength).ToList();

        var buffer = chars.ToArray().AsSpan();
        _random.Shuffle(buffer);
        return new string(buffer);
    }

    private char PickFrom(string pool)
    {
        if (pool.Length == 0)
            throw new InvalidOperationException("Character pool is empty.");
        return pool[_random.NextInt32(pool.Length)];
    }

    private static string GetLowercasePool(Policies.PasswordPolicy policy) =>
        Internal.NamedCharacterSetResolver.ResolvePool("lowercase", policy);

    private static string GetUppercasePool(Policies.PasswordPolicy policy) =>
        Internal.NamedCharacterSetResolver.ResolvePool("uppercase", policy);

    private static string GetDigitPool(Policies.PasswordPolicy policy) =>
        Internal.NamedCharacterSetResolver.ResolvePool("digit", policy);

    private static string GetSymbolPool(Policies.PasswordPolicy policy) =>
        Internal.NamedCharacterSetResolver.ResolvePool("symbol", policy);

    private static int DetermineTargetLength(Policies.PasswordPolicy policy, PasswordGenerationOptions options)
    {
        if (options.PreferredLength is not null)
            return Math.Clamp(options.PreferredLength.Value, policy.MinLength, policy.MaxLength);

        if (options.EntropyTargetBits is not null)
        {
            var poolSize = Validation.PasswordEntropyEstimator.ComputeEffectivePoolSize(policy);
            var length = (int)Math.Ceiling(options.EntropyTargetBits.Value / Math.Log2(poolSize));
            return Math.Clamp(length, policy.MinLength, policy.MaxLength);
        }

        return Math.Max(policy.MinLength, Math.Min(policy.MaxLength, Math.Max(16, policy.MinLength)));
    }

    private static bool IsSymbol(char c, Policies.PasswordPolicy policy)
    {
        var symbols = policy.AllowedSymbols ?? Internal.CharacterSets.CommonSymbols;
        return symbols.Contains(c);
    }

    private static List<string> BuildAppliedRulesList(Policies.PasswordPolicy policy)
    {
        var rules = new List<string>();
        if (policy.RequireUppercase) rules.Add("require-uppercase");
        if (policy.RequireLowercase) rules.Add("require-lowercase");
        if (policy.RequireDigit) rules.Add("require-digit");
        if (policy.RequireSymbol) rules.Add("require-symbol");
        if (policy.RequireWhitespace) rules.Add("require-whitespace");
        if (policy.DisallowWhitespace) rules.Add("disallow-whitespace");
        if (policy.AvoidAmbiguousCharacters) rules.Add("avoid-ambiguous");
        if (policy.MaxRepeatedCharacterRun is not null) rules.Add("disallow-repeated");
        if (policy.DisallowSequentialCharacters) rules.Add("disallow-sequential");
        if (policy.DisallowKeyboardSequences) rules.Add("disallow-keyboard");
        if (policy.DisallowCommonPasswords) rules.Add("disallow-common");
        foreach (var req in policy.RequireAtLeastOneFrom)
            rules.Add($"require-at-least-one-from:{req.SetName}");
        foreach (var req in policy.RequireCountFrom)
            rules.Add($"require-count-from:{req.SetName}:{req.MinimumCount}");
        return rules;
    }

    private static Reports.PasswordGenerationResult Failed(
        Policies.PasswordPolicy policy,
        IReadOnlyList<string> diagnostics,
        int maxAttempts,
        int targetLength)
    {
        return new Reports.PasswordGenerationResult(
            false,
            null,
            0,
            policy,
            null,
            new Reports.PasswordGenerationReport(maxAttempts, targetLength, 0, [], "random"),
            [],
            diagnostics);
    }
}
