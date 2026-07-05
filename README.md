![PasswordForge](https://raw.githubusercontent.com/kearns2000/PasswordForge/main/assets/icon.png)

# PasswordForge

[![NuGet](https://img.shields.io/nuget/v/PasswordForge?style=flat&logo=nuget)](https://www.nuget.org/packages/PasswordForge)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0-512BD4?style=flat&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/download)
[![Build](https://github.com/kearns2000/PasswordForge/actions/workflows/ci.yml/badge.svg)](https://github.com/kearns2000/PasswordForge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-xUnit-5C2D91?style=flat&logo=xunit)](tests/PasswordForge.Tests)

**Target frameworks:** `net8.0` · `net9.0` · **Language:** C# · **Test runner:** xUnit

**PasswordForge generates passwords that satisfy your policy, not just random strings.**

PasswordForge is a policy-aware password generator and password-policy test kit for .NET. Most generators produce a random string and hope it fits. PasswordForge starts with the policy your application must satisfy, then generates, validates, explains, and tests against that policy.

PasswordForge does **not** store, hash, deliver, or reset passwords. It is not an identity system.

## Why it exists

Production password rules are easy to get wrong:

- Generation and validation drift apart over time
- Policies are hard to test without deliberate invalid samples
- Human-readable and temporary credentials need the same rules as random passwords
- ASP.NET Identity and `appsettings.json` policies are tedious to keep in sync

PasswordForge gives you:

- One shared rule engine for generation and validation
- Detailed generation and validation reports with entropy estimates
- Human-readable generation with optional fallback when random generation fails
- Named character set requirements and Unicode modes
- Structured valid and invalid test sets for policy regression tests
- ASP.NET Core DI, JSON configuration binding, and Identity adapters
- Deterministic test mode isolated under `PasswordForge.Testing`

## Installation

```bash
dotnet add package PasswordForge
```

See [PUBLISHING.md](PUBLISHING.md) for how releases are published via NuGet trusted publishing.

## Quick start

```csharp
using PasswordForge;
using PasswordForge.Policies;

var policy = PasswordPolicy.Create()
    .MinLength(16)
    .MaxLength(64)
    .RequireUppercase()
    .RequireLowercase()
    .RequireDigit()
    .RequireSymbol()
    .AllowedSymbols("@#$%!")
    .AvoidAmbiguousCharacters()
    .Build();

var result = PasswordForge.PasswordForge.Generate(policy);

if (result.Success)
{
    Console.WriteLine(result.Value);
    Console.WriteLine($"Estimated entropy: {result.EntropyBits:F1} bits");
}
```

## Validation

Validate passwords with the same rule engine used during generation:

```csharp
using PasswordForge.Validation;

var report = PasswordValidator.Validate(password, policy);

if (!report.IsValid)
{
    foreach (var failure in report.FailedRules)
    {
        Console.WriteLine(failure.Message);
    }
}
```

## Policy review

```csharp
using PasswordForge.Reviews;

var review = PasswordPolicyReviewer.Review(policy);
Console.WriteLine($"Score: {review.Score}/100 ({review.EstimatedStrength})");

foreach (var finding in review.Findings)
{
    Console.WriteLine($"[{finding.Severity}] {finding.Message}");
}
```

Review findings use alignment hints against common modern guidance. PasswordForge does not claim formal NIST or OWASP certification.

## Human-readable passwords

```csharp
var result = PasswordForge.PasswordForge.GenerateHumanReadable(policy);

// Examples: River#Maple#74!, Cobalt#Duck#192
```

Human-readable generation uses a neutral built-in word list. Supply your own via `HumanReadablePasswordOptions`.

When random generation fails or is skipped, enable fallback:

```csharp
var result = PasswordForge.PasswordForge.Generate(policy, new PasswordGenerationOptions
{
    HumanReadableFallback = true
});
```

## Named character sets

Built-in named sets: `lowercase`, `uppercase`, `digit`, `symbol`, and `whitespace`.

```csharp
var policy = PasswordPolicy.Create()
    .MinLength(12)
    .RequireAtLeastOneFrom("symbol")
    .RequireCountFrom("digit", 3)
    .Build();
```

Unknown or empty set names produce policy configuration warnings at validation and generation time.

## Unicode modes

```csharp
var policy = PasswordPolicy.Create()
    .MinLength(8)
    .UnicodeMode(UnicodeMode.AllowUnicode) // or AllowUnicodeLettersOnly
    .Build();
```

| Mode | Behaviour |
|------|-----------|
| `AsciiOnly` | ASCII characters only (default) |
| `AllowUnicode` | Unicode letters and symbols permitted |
| `AllowUnicodeLettersOnly` | Unicode letters permitted; symbols stay ASCII |

## Temporary credentials

```csharp
using PasswordForge.TemporaryCredentials;

var credential = PasswordForge.PasswordForge.GenerateTemporaryCredential(
    policy,
    new TemporaryCredentialOptions
    {
        ExpiresAfter = TimeSpan.FromHours(24),
        RequireResetOnFirstUse = true,
        DeliveryHint = DeliveryHint.Manual
    });

Console.WriteLine(credential.SafeDisplayText);
// SafeDisplayText is for one-time presentation. Do not log it.
```

## Test set generation

Generate deliberate valid and invalid samples for policy tests:

```csharp
var samples = PasswordForge.PasswordForge.TestSet(policy)
    .Valid(10)
    .InvalidTooShort(3)
    .InvalidMissingDigit(3)
    .EdgeCases()
    .Generate();

foreach (var item in samples.Items)
{
    Console.WriteLine($"{item.Scenario}: valid={item.ExpectedValid}, value={item.Value}");
}
```

Invalid samples are generated to fail for the intended rule where practical.

## ASP.NET Core dependency injection

```csharp
using PasswordForge.AspNetCore;

builder.Services.AddPasswordForge(options =>
{
    options.AddPolicy("TemporaryPassword", policy =>
        policy.MinLength(20)
            .MaxLength(32)
            .RequireUppercase()
            .RequireLowercase()
            .RequireDigit()
            .RequireSymbol());
});

// Or bind from configuration:
builder.Services.AddPasswordForge(builder.Configuration.GetSection("PasswordForge"));
```

```csharp
app.MapGet("/password/sample", async (IPasswordForge forge) =>
{
    var result = await forge.GenerateAsync("TemporaryPassword");
    return Results.Ok(new { result.EntropyBits, result.Warnings });
});
```

Production systems should be careful about exposing generated credentials from HTTP endpoints.

## appsettings.json binding

```json
{
  "PasswordForge": {
    "Policies": {
      "CustomerPassword": {
        "MinLength": 16,
        "MaxLength": 64,
        "RequireUppercase": true,
        "RequireLowercase": true,
        "RequireDigit": true,
        "RequireSymbol": true,
        "AllowedSymbols": "@#$%!",
        "AvoidAmbiguousCharacters": true,
        "UnicodeMode": "AsciiOnly",
        "RequireAtLeastOneFrom": [ "symbol" ],
        "RequireCountFrom": {
          "digit": 2
        },
        "DisallowUsername": true,
        "Username": "johndoe",
        "DisallowEmailParts": true,
        "Email": "john@example.com",
        "DisallowedContextValues": [ "companyname", "product" ]
      }
    }
  }
}
```

## ASP.NET Identity adapter

```csharp
using PasswordForge.Identity;
using PasswordForge.Policies;

var policy = PasswordPolicy.FromAspNetIdentity(identityOptions.Password);

// Or:
var policy = identityOptions.Password.ToPasswordForgePolicy();
```

## Regex policy import

```csharp
var import = PasswordPolicy.FromRegex(@"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%]).{12,32}$");

if (import.Success)
{
    var policy = import.Policy!;
}
else
{
    foreach (var feature in import.UnsupportedFeatures)
    {
        Console.WriteLine(feature);
    }
}
```

Regex import supports common patterns only. Complex expressions return honest unsupported feature warnings.

## Deterministic test mode

```csharp
using PasswordForge.Testing;

// WARNING: Test-only. Never use in production.
var forge = PasswordForgeTesting.CreateDeterministic(seed: 123);
var result = forge.Generate(policy);
```

Deterministic generation is isolated under `PasswordForge.Testing` and uses predictable randomness unsuitable for real credentials.

## Security notes

- Production randomness uses `RandomNumberGenerator` from `System.Security.Cryptography`.
- Generated passwords are never included in exception messages or policy diagnostics.
- The built-in common password list is small by design. Production validation should use a larger compromised-password check outside this package.
- Entropy values are estimates, not guarantees of strength.

## Example xUnit usage

```csharp
using PasswordForge.Policies;
using PasswordForge.Validation;
using Xunit;

public class PasswordPolicyTests
{
    [Fact]
    public void Generated_password_satisfies_policy()
    {
        var policy = PasswordPolicy.Create()
            .MinLength(12)
            .RequireUppercase()
            .RequireLowercase()
            .RequireDigit()
            .RequireSymbol()
            .AllowedSymbols("@#$%!")
            .Build();

        var result = global::PasswordForge.PasswordForge.Generate(policy);

        Assert.True(result.Success);
        Assert.True(PasswordValidator.Validate(result.Value!, policy).IsValid);
    }
}
```

## Building from source

```bash
dotnet build -c Release
dotnet test -c Release
dotnet pack -c Release src/PasswordForge/PasswordForge.csproj
dotnet run --project samples/PasswordForge.SampleConsole
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, project layout, and pull request expectations.

Quick start for contributors:

```bash
git clone https://github.com/kearns2000/PasswordForge.git
cd PasswordForge
dotnet build -c Release
dotnet test -c Release -f net8.0
dotnet test -c Release -f net9.0
```

Open a pull request with tests for any behaviour change. CI runs build and test on `net8.0` and `net9.0` on every PR.

## License

MIT
