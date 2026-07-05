using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PasswordForge.AspNetCore;
using PasswordForge.Configuration;
using PasswordForge.Identity;
using PasswordForge.Policies;
using PasswordForge.Testing;
using PasswordForge.Validation;
using Xunit;

namespace PasswordForge.Tests;

public class IntegrationTests
{
    [Fact]
    public void Test_set_generates_valid_and_invalid_cases()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(12)
            .MaxLength(32)
            .RequireUppercase()
            .RequireLowercase()
            .RequireDigit()
            .RequireSymbol().Build();

        var result = global::PasswordForge.PasswordForge.TestSet(policy)
            .Valid(5)
            .InvalidTooShort(3)
            .InvalidMissingDigit(3)
            .EdgeCases()
            .Generate();

        Assert.NotEmpty(result.Items);
        Assert.All(
            result.Items.Where(i => i.Scenario == TestSets.PasswordTestScenario.Valid && !i.Skipped),
            i => Assert.True(i.ExpectedValid));
        Assert.All(
            result.Items.Where(i => i.Scenario == TestSets.PasswordTestScenario.InvalidTooShort),
            i => Assert.False(i.ExpectedValid));
    }

    [Fact]
    public void AspNet_Identity_adapter_maps_options()
    {
        var identityOptions = new PasswordOptions
        {
            RequiredLength = 12,
            RequireDigit = true,
            RequireLowercase = true,
            RequireUppercase = true,
            RequireNonAlphanumeric = true,
            RequiredUniqueChars = 4
        };

        var policy = PasswordPolicy.FromAspNetIdentity(identityOptions);
        Assert.Equal(12, policy.MinLength);
        Assert.True(policy.RequireDigit);
        Assert.True(policy.RequireSymbol);
        Assert.Equal(4, policy.MaxRepeatedCharacterRun);
    }

    [Fact]
    public void AspNet_Identity_extension_method_works()
    {
        var options = new PasswordOptions { RequiredLength = 10, RequireDigit = true };
        var policy = options.ToPasswordForgePolicy();
        Assert.Equal(10, policy.MinLength);
    }

    [Fact]
    public async Task Json_options_binding_loads_named_policies()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PasswordForge:Policies:CustomerPassword:MinLength"] = "16",
                ["PasswordForge:Policies:CustomerPassword:MaxLength"] = "64",
                ["PasswordForge:Policies:CustomerPassword:RequireUppercase"] = "true",
                ["PasswordForge:Policies:CustomerPassword:RequireDigit"] = "true"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddPasswordForge(config.GetSection("PasswordForge"));
        var provider = services.BuildServiceProvider();

        var forge = provider.GetRequiredService<Abstractions.IPasswordForge>();
        var result = await forge.GenerateAsync("CustomerPassword");
        Assert.True(result.Success);
    }

    [Fact]
    public void Json_options_binding_loads_named_sets_and_context_values()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PasswordForge:Policies:ContextPolicy:MinLength"] = "8",
                ["PasswordForge:Policies:ContextPolicy:MaxLength"] = "32",
                ["PasswordForge:Policies:ContextPolicy:RequireAtLeastOneFrom:0"] = "digit",
                ["PasswordForge:Policies:ContextPolicy:RequireCountFrom:digit"] = "2",
                ["PasswordForge:Policies:ContextPolicy:DisallowUsername"] = "true",
                ["PasswordForge:Policies:ContextPolicy:Username"] = "johndoe",
                ["PasswordForge:Policies:ContextPolicy:DisallowEmailParts"] = "true",
                ["PasswordForge:Policies:ContextPolicy:Email"] = "john@example.com",
                ["PasswordForge:Policies:ContextPolicy:DisallowedContextValues:0"] = "companyname",
                ["PasswordForge:Policies:ContextPolicy:UnicodeMode"] = "AllowUnicode"
            })
            .Build();

        var options = new PasswordForgeOptions();
        config.GetSection("PasswordForge").Bind(options);
        var policy = options.Policies["ContextPolicy"].ToPolicy();

        Assert.Contains(policy.RequireAtLeastOneFrom, r => r.SetName == "digit");
        Assert.Contains(policy.RequireCountFrom, r => r.SetName == "digit" && r.MinimumCount == 2);
        Assert.Equal("johndoe", policy.Username);
        Assert.Equal("john@example.com", policy.Email);
        Assert.Contains("companyname", policy.DisallowedContextValues);
        Assert.Equal(Policies.UnicodeMode.AllowUnicode, policy.UnicodeMode);

        Assert.False(PasswordValidator.Validate("johndoe12", policy).IsValid);
        Assert.False(PasswordValidator.Validate("example12", policy).IsValid);
        Assert.False(PasswordValidator.Validate("companyname12", policy).IsValid);
        Assert.True(PasswordValidator.Validate("café1234", policy).IsValid);
    }

    [Fact]
    public async Task DI_named_policy_generation_works()
    {
        var services = new ServiceCollection();
        services.AddPasswordForge(options =>
        {
            options.AddPolicy("TemporaryPassword",
                PasswordPolicy.Create()
                    .MinLength(20)
                    .MaxLength(32)
                    .RequireUppercase()
                    .RequireLowercase()
                    .RequireDigit()
                    .RequireSymbol()
                    .Build());
        });

        var provider = services.BuildServiceProvider();
        var forge = provider.GetRequiredService<Abstractions.IPasswordForge>();
        var result = await forge.GenerateAsync("TemporaryPassword");
        Assert.True(result.Success);
    }

    [Fact]
    public void DI_missing_policy_name_returns_clear_error()
    {
        var services = new ServiceCollection();
        services.AddPasswordForge(_ => { });
        var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetRequiredService<Abstractions.IPasswordPolicyProvider>();

        var ex = Assert.Throws<InvalidOperationException>(() => policyProvider.GetPolicy("MissingPolicy"));
        Assert.Contains("MissingPolicy", ex.Message);
    }

    [Fact]
    public void Regex_import_succeeds_for_simple_pattern()
    {
        var result = PasswordPolicy.FromRegex(@"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%]).{12,32}$");
        Assert.True(result.Success);
        Assert.Equal(12, result.Policy!.MinLength);
        Assert.Equal(32, result.Policy.MaxLength);
        Assert.True(result.Policy.RequireUppercase);
        Assert.True(result.Policy.RequireDigit);
        Assert.True(result.Policy.RequireSymbol);
    }

    [Fact]
    public void Regex_import_reports_unsupported_complexity()
    {
        var result = PasswordPolicy.FromRegex(@"(?=.*[A-Z]|(?=.*[a-z])).{8,16}$");
        Assert.NotEmpty(result.UnsupportedFeatures);
    }

    [Fact]
    public void Deterministic_generator_repeats_output_for_same_seed()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(16).MaxLength(16)
            .RequireLowercase().RequireUppercase().RequireDigit().Build();

        var forge1 = PasswordForgeTesting.CreateDeterministic(123);
        var forge2 = PasswordForgeTesting.CreateDeterministic(123);

        var result1 = forge1.Generate(policy);
        var result2 = forge2.Generate(policy);

        Assert.Equal(result1.Value, result2.Value);
    }

    [Fact]
    public void Production_generator_does_not_repeat_deterministically()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(16).MaxLength(16)
            .RequireLowercase().RequireUppercase().RequireDigit().Build();

        var results = Enumerable.Range(0, 10)
            .Select(_ => global::PasswordForge.PasswordForge.Generate(policy).Value)
            .Distinct()
            .ToList();

        Assert.True(results.Count > 1);
    }
}
