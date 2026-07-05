namespace PasswordForge.Validation;

/// <summary>
/// Estimates password entropy based on character pool and length.
/// </summary>
public static class PasswordEntropyEstimator
{
    /// <summary>
    /// Estimates entropy for a random password based on pool size and length.
    /// </summary>
    public static Reports.PasswordEntropyEstimate EstimateRandom(string password, int effectivePoolSize)
    {
        var length = password.Length;
        var bits = length * Math.Log2(Math.Max(2, effectivePoolSize));
        return new Reports.PasswordEntropyEstimate(
            bits,
            "character-pool",
            "This is an estimate based on assumed random selection from the effective character pool.");
    }

    /// <summary>
    /// Estimates entropy for a passphrase based on word list size and word count.
    /// </summary>
    public static Reports.PasswordEntropyEstimate EstimatePassphrase(int wordListSize, int wordCount, double extraEntropyBits = 0)
    {
        var bits = wordCount * Math.Log2(Math.Max(2, wordListSize)) + extraEntropyBits;
        return new Reports.PasswordEntropyEstimate(
            bits,
            "word-list",
            "This is an estimate based on word selection from the supplied list. Actual entropy may be lower if words are predictable.");
    }

    /// <summary>
    /// Computes effective pool size from a policy.
    /// </summary>
    public static int ComputeEffectivePoolSize(Policies.PasswordPolicy policy)
    {
        var pool = Internal.CharacterSets.BuildAllowedPool(policy, out _);
        return Math.Max(2, pool.Length);
    }
}
