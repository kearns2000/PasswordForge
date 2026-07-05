using PasswordForge.Policies;
using PasswordForge.Validation;
using Xunit;

namespace PasswordForge.Tests;

public class PasswordGenerationTests
{
    private static PasswordPolicy CreateStandardPolicy() =>
        PasswordPolicy.Create()
            .MinLength(16)
            .MaxLength(64)
            .RequireUppercase()
            .RequireLowercase()
            .RequireDigit()
            .RequireSymbol()
            .AllowedSymbols("@#$%!")
            .AvoidAmbiguousCharacters().Build();

    [Fact]
    public void Generate_succeeds_for_simple_policy()
    {
        var result = global::PasswordForge.PasswordForge.Generate(CreateStandardPolicy());
        Assert.True(result.Success);
        Assert.False(string.IsNullOrEmpty(result.Value));
    }

    [Fact]
    public void Generated_password_validates_against_policy()
    {
        var policy = CreateStandardPolicy();
        var result = global::PasswordForge.PasswordForge.Generate(policy);
        var report = PasswordValidator.Validate(result.Value!, policy);
        Assert.True(report.IsValid);
    }

    [Fact]
    public void Generate_respects_min_and_max_length()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(20)
            .MaxLength(24)
            .RequireLowercase()
            .RequireUppercase()
            .RequireDigit().Build();

        for (var i = 0; i < 50; i++)
        {
            var result = global::PasswordForge.PasswordForge.Generate(policy);
            Assert.True(result.Success);
            Assert.InRange(result.Value!.Length, 20, 24);
        }
    }

    [Fact]
    public void Generate_includes_required_uppercase()
    {
        var policy = PasswordPolicy.Create().MinLength(8).MaxLength(16).RequireUppercase().Build();
        var result = global::PasswordForge.PasswordForge.Generate(policy);
        Assert.Contains(result.Value!, c => char.IsUpper(c));
    }

    [Fact]
    public void Generate_includes_required_lowercase()
    {
        var policy = PasswordPolicy.Create().MinLength(8).MaxLength(16).RequireLowercase().Build();
        var result = global::PasswordForge.PasswordForge.Generate(policy);
        Assert.Contains(result.Value!, c => char.IsLower(c));
    }

    [Fact]
    public void Generate_includes_required_digit()
    {
        var policy = PasswordPolicy.Create().MinLength(8).MaxLength(16).RequireDigit().Build();
        var result = global::PasswordForge.PasswordForge.Generate(policy);
        Assert.Contains(result.Value!, c => char.IsDigit(c));
    }

    [Fact]
    public void Generate_includes_required_symbol()
    {
        var policy = PasswordPolicy.Create().MinLength(8).MaxLength(16).RequireSymbol().AllowedSymbols("@#").Build();
        var result = global::PasswordForge.PasswordForge.Generate(policy);
        Assert.Contains(result.Value!, c => "@#".Contains(c));
    }

    [Fact]
    public void Generate_uses_only_allowed_symbols()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(12).MaxLength(20)
            .RequireSymbol()
            .AllowedSymbols("@#$").Build();

        for (var i = 0; i < 20; i++)
        {
            var result = global::PasswordForge.PasswordForge.Generate(policy);
            var symbols = result.Value!.Where(c => !char.IsLetterOrDigit(c));
            Assert.All(symbols, c => Assert.True("@#$".Contains(c)));
        }
    }

    [Fact]
    public void Generate_can_include_whitespace_when_allowed()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(12).MaxLength(24)
            .AllowWhitespace()
            .RequireWhitespace()
            .RequireLowercase()
            .RequireUppercase().Build();

        var result = global::PasswordForge.PasswordForge.Generate(policy);
        Assert.True(result.Success);
        Assert.Contains(result.Value!, c => char.IsWhiteSpace(c));
    }

    [Fact]
    public void Validation_rejects_whitespace_when_disallowed()
    {
        var policy = PasswordPolicy.Create().MinLength(8).MaxLength(16).DisallowWhitespace().Build();
        var report = PasswordValidator.Validate("hello world", policy);
        Assert.False(report.IsValid);
        Assert.Contains(report.FailedRules, r => r.RuleId == "disallow-whitespace");
    }

    [Fact]
    public void Generate_avoids_ambiguous_characters()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(16).MaxLength(32)
            .RequireLowercase().RequireUppercase().RequireDigit()
            .AvoidAmbiguousCharacters().Build();

        for (var i = 0; i < 20; i++)
        {
            var result = global::PasswordForge.PasswordForge.Generate(policy);
            Assert.DoesNotContain(result.Value!, c => "0Oo1lI5S8B".Contains(c));
        }
    }

    [Fact]
    public void Validation_rejects_repeated_characters()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(8).MaxLength(32)
            .DisallowRepeatedCharacters(3).Build();

        var report = PasswordValidator.Validate("aaaabbbccc", policy);
        Assert.False(report.IsValid);
    }

    [Fact]
    public void Validation_rejects_sequential_characters()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(8).MaxLength(32)
            .DisallowSequentialCharacters().Build();

        var report = PasswordValidator.Validate("abcdefgh", policy);
        Assert.False(report.IsValid);
    }

    [Fact]
    public void Validation_rejects_common_passwords()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(8).MaxLength(32)
            .DisallowCommonPasswords().Build();

        var report = PasswordValidator.Validate("password123", policy);
        Assert.False(report.IsValid);
    }

    [Fact]
    public void Validation_rejects_username_in_password()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(8).MaxLength(32)
            .DisallowUsername("johndoe").Build();

        var report = PasswordValidator.Validate("johndoe123", policy);
        Assert.False(report.IsValid);
    }

    [Fact]
    public void Validation_rejects_email_parts_in_password()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(8).MaxLength(32)
            .DisallowEmailParts("john@example.com").Build();

        var report = PasswordValidator.Validate("example123", policy);
        Assert.False(report.IsValid);
    }

    [Fact]
    public void TryGenerate_returns_diagnostics_for_impossible_policy()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(20)
            .MaxLength(10).Build();

        var result = global::PasswordForge.PasswordForge.TryGenerate(policy);
        Assert.False(result.Success);
        Assert.NotEmpty(result.Diagnostics);
        Assert.Contains(result.Diagnostics, d => d.Contains("minimum length", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Generate_includes_entropy_estimate()
    {
        var result = global::PasswordForge.PasswordForge.Generate(CreateStandardPolicy());
        Assert.True(result.EntropyBits > 0);
    }

    [Fact]
    public void GenerateOrThrow_throws_without_password_in_message()
    {
        var policy = PasswordPolicy.Create().MinLength(20).MaxLength(10).Build();
        var result = global::PasswordForge.PasswordForge.Generate(policy);
        var ex = Assert.Throws<InvalidOperationException>(() => result.GenerateOrThrow());
        Assert.Contains("minimum length", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Generate_1000_passwords_all_validate()
    {
        var policy = CreateStandardPolicy();
        for (var i = 0; i < 1000; i++)
        {
            var result = global::PasswordForge.PasswordForge.Generate(policy);
            Assert.True(result.Success);
            Assert.True(PasswordValidator.Validate(result.Value!, policy).IsValid);
        }
    }

    [Fact]
    public void Generate_1000_passwords_respect_max_length()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(16)
            .MaxLength(20)
            .RequireUppercase()
            .RequireLowercase()
            .RequireDigit()
            .RequireSymbol().Build();

        for (var i = 0; i < 1000; i++)
        {
            var result = global::PasswordForge.PasswordForge.Generate(policy);
            Assert.True(result.Value!.Length <= 20);
        }
    }
}
