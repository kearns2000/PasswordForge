namespace PasswordForge.TemporaryCredentials;

/// <summary>
/// Hint for how a temporary credential should be delivered.
/// </summary>
public enum DeliveryHint
{
    /// <summary>No delivery hint specified.</summary>
    None,

    /// <summary>Deliver via email.</summary>
    Email,

    /// <summary>Deliver via SMS.</summary>
    Sms,

    /// <summary>Deliver via voice call.</summary>
    Voice,

    /// <summary>Deliver manually (for example, in person).</summary>
    Manual,

    /// <summary>Deliver via a secure channel.</summary>
    SecureChannel
}

/// <summary>
/// Abstraction for time operations in temporary credential generation.
/// </summary>
public interface IClock
{
    /// <summary>Gets the current UTC date and time.</summary>
    DateTimeOffset UtcNow { get; }
}

/// <summary>
/// Default system clock implementation.
/// </summary>
public sealed class SystemClock : IClock
{
    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

/// <summary>
/// Options for temporary credential generation.
/// </summary>
public sealed class TemporaryCredentialOptions
{
    /// <summary>Duration after which the credential expires.</summary>
    public TimeSpan ExpiresAfter { get; init; } = TimeSpan.FromHours(24);

    /// <summary>When true, the user must reset the password on first use.</summary>
    public bool RequireResetOnFirstUse { get; init; } = true;

    /// <summary>Hint for how the credential should be delivered.</summary>
    public DeliveryHint DeliveryHint { get; init; } = DeliveryHint.Manual;

    /// <summary>Clock abstraction for testing.</summary>
    public IClock Clock { get; init; } = new SystemClock();
}

/// <summary>
/// Result of temporary credential generation.
/// </summary>
public sealed record TemporaryCredentialResult(
    string Password,
    DateTimeOffset ExpiresAt,
    bool RequireResetOnFirstUse,
    DateTimeOffset CreatedAt,
    DeliveryHint DeliveryHint,
    string SafeDisplayText,
    Reports.PasswordGenerationResult GenerationResult);
