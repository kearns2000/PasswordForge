namespace PasswordForge.Generation;

/// <summary>
/// Options controlling password generation behaviour.
/// </summary>
public sealed class PasswordGenerationOptions
{
    /// <summary>Default generation options.</summary>
    public static PasswordGenerationOptions Default { get; } = new();

    /// <summary>Preferred password length when within policy bounds.</summary>
    public int? PreferredLength { get; init; }

    /// <summary>Maximum generation attempts before failing.</summary>
    public int MaxAttempts { get; init; } = 100;

    /// <summary>Target entropy in bits. Generation may extend length to approach this value.</summary>
    public double? EntropyTargetBits { get; init; }

    /// <summary>When true, falls back to human-readable generation if random generation fails.</summary>
    public bool HumanReadableFallback { get; init; }

    /// <summary>When true, avoids passwords starting with a symbol (compatibility option).</summary>
    public bool AvoidStartingWithSymbol { get; init; }

    /// <summary>When true, avoids passwords ending with a symbol (compatibility option).</summary>
    public bool AvoidEndingWithSymbol { get; init; }
}
