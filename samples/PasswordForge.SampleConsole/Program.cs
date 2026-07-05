using PasswordForge;
using PasswordForge.Policies;
using PasswordForge.Reviews;
using PasswordForge.Validation;

// Sample-only display: do not log generated passwords in production applications.
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

Console.WriteLine("PasswordForge sample console");
Console.WriteLine("============================");
Console.WriteLine();

var result = global::PasswordForge.PasswordForge.Generate(policy);

if (result.Success)
{
    // Display for demonstration only. Never log passwords in production.
    Console.WriteLine($"Generated password: {result.Value}");
    Console.WriteLine($"Estimated entropy: {result.EntropyBits:F1} bits");
}
else
{
    Console.WriteLine("Generation failed:");
    foreach (var diagnostic in result.Diagnostics)
        Console.WriteLine($"  - {diagnostic}");
}

Console.WriteLine();

var validation = PasswordValidator.Validate(result.Value!, policy);
Console.WriteLine($"Validation passed: {validation.IsValid}");
Console.WriteLine($"Character breakdown: upper={validation.CharacterClassBreakdown.UppercaseCount}, " +
                  $"lower={validation.CharacterClassBreakdown.LowercaseCount}, " +
                  $"digit={validation.CharacterClassBreakdown.DigitCount}, " +
                  $"symbol={validation.CharacterClassBreakdown.SymbolCount}");

Console.WriteLine();

var review = PasswordPolicyReviewer.Review(policy);
Console.WriteLine($"Policy review score: {review.Score}/100 ({review.EstimatedStrength})");
foreach (var finding in review.Findings.Take(3))
    Console.WriteLine($"  [{finding.Severity}] {finding.Message}");
