using PasswordForge.Generation;
using PasswordForge.Policies;
using PasswordForge.Validation;
using Xunit;

namespace PasswordForge.Tests;

public class ExtendedFeatureTests
{
    [Fact]
    public void RequireAtLeastOneFrom_is_validated_and_generated()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(12)
            .MaxLength(24)
            .RequireAtLeastOneFrom("symbol")
            .RequireAtLeastOneFrom("digit")
            .AllowedSymbols("@#")
            .Build();

        var result = global::PasswordForge.PasswordForge.Generate(policy);
        Assert.True(result.Success);
        Assert.Contains(result.Value!, c => char.IsDigit(c));
        Assert.Contains(result.Value!, c => "@#".Contains(c));
    }

    [Fact]
    public void RequireCountFrom_is_validated()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(5)
            .MaxLength(32)
            .RequireCountFrom("digit", 3)
            .Build();

        Assert.False(PasswordValidator.Validate("ab12", policy).IsValid);
        Assert.True(PasswordValidator.Validate("ab123", policy).IsValid);
    }

    [Fact]
    public void Unknown_named_set_returns_diagnostic()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(8)
            .MaxLength(16)
            .RequireAtLeastOneFrom("unknown-set")
            .Build();

        var result = global::PasswordForge.PasswordForge.TryGenerate(policy);
        Assert.False(result.Success);
        Assert.Contains(result.Diagnostics, d => d.Contains("unknown-set", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void HumanReadableFallback_generates_when_random_generation_is_skipped()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(12)
            .MaxLength(48)
            .RequireUppercase()
            .RequireLowercase()
            .RequireDigit()
            .RequireSymbol()
            .AllowedSymbols("@#$%!")
            .Build();

        var options = new PasswordGenerationOptions
        {
            MaxAttempts = 0,
            HumanReadableFallback = true
        };

        var result = global::PasswordForge.PasswordForge.Generate(policy, options);
        Assert.True(result.Success);
        Assert.Equal("human-readable", result.GenerationReport!.GenerationMethod);
        Assert.Contains(result.Warnings, w => w.Contains("human-readable", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void AllowUnicode_accepts_unicode_letters_in_validation()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(4)
            .MaxLength(32)
            .UnicodeMode(UnicodeMode.AllowUnicode)
            .Build();

        Assert.True(PasswordValidator.Validate("café", policy).IsValid);
    }

    [Fact]
    public void DisallowUsername_without_value_returns_policy_diagnostic()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(8)
            .MaxLength(16)
            .DisallowUsername()
            .Build();

        var result = global::PasswordForge.PasswordForge.TryGenerate(policy);
        Assert.False(result.Success);
        Assert.Contains(result.Diagnostics, d => d.Contains("DisallowUsername", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DisallowUsername_without_value_adds_validation_warning()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(8)
            .MaxLength(16)
            .DisallowUsername()
            .Build();

        var report = PasswordValidator.Validate("ValidPass1", policy);
        Assert.Contains(report.Warnings, w => w.Contains("DisallowUsername", StringComparison.OrdinalIgnoreCase));
    }
}
