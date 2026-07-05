using PasswordForge.Policies;
using PasswordForge.Reviews;
using PasswordForge.TemporaryCredentials;
using Xunit;

namespace PasswordForge.Tests;

public class HumanReadableAndTemporaryCredentialTests
{
    private static PasswordPolicy CreatePolicy() =>
        PasswordPolicy.Create()
            .MinLength(12)
            .MaxLength(48)
            .RequireUppercase()
            .RequireLowercase()
            .RequireDigit()
            .RequireSymbol()
            .AllowedSymbols("@#$%!").Build();

    [Fact]
    public void Human_readable_generation_passes_policy()
    {
        var result = global::PasswordForge.PasswordForge.GenerateHumanReadable(CreatePolicy());
        Assert.True(result.Success);
        Assert.True(result.ValidationReport!.IsValid);
    }

    [Fact]
    public void Temporary_credential_has_expiry()
    {
        var clock = new FixedClock(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        var options = new TemporaryCredentialOptions
        {
            ExpiresAfter = TimeSpan.FromHours(24),
            Clock = clock
        };

        var credential = global::PasswordForge.PasswordForge.GenerateTemporaryCredential(CreatePolicy(), options);
        Assert.Equal(clock.UtcNow.AddHours(24), credential.ExpiresAt);
    }

    [Fact]
    public void Temporary_credential_sets_reset_flag()
    {
        var options = new TemporaryCredentialOptions { RequireResetOnFirstUse = true };
        var credential = global::PasswordForge.PasswordForge.GenerateTemporaryCredential(CreatePolicy(), options);
        Assert.True(credential.RequireResetOnFirstUse);
    }

    [Fact]
    public void Policy_review_returns_score_and_findings()
    {
        var policy = PasswordPolicy.Create().MinLength(8).MaxLength(16).RequireDigit().Build();
        var review = PasswordPolicyReviewer.Review(policy);
        Assert.InRange(review.Score, 0, 100);
        Assert.NotEmpty(review.Findings);
    }

    private sealed class FixedClock : IClock
    {
        public FixedClock(DateTimeOffset utcNow) => UtcNow = utcNow;
        public DateTimeOffset UtcNow { get; }
    }
}
