namespace PasswordForge.Identity;

/// <summary>
/// Converts ASP.NET Identity password options to PasswordForge policies.
/// </summary>
public static class AspNetIdentityPasswordPolicyAdapter
{
    /// <summary>
    /// Creates a PasswordForge policy from ASP.NET Identity PasswordOptions.
    /// </summary>
    public static Policies.PasswordPolicy FromAspNetIdentity(Microsoft.AspNetCore.Identity.PasswordOptions options)
    {
        var builder = Policies.PasswordPolicy.Create()
            .MinLength(options.RequiredLength)
            .MaxLength(Math.Max(options.RequiredLength, 64));

        if (options.RequireLowercase) builder.RequireLowercase();
        if (options.RequireUppercase) builder.RequireUppercase();
        if (options.RequireDigit) builder.RequireDigit();
        if (options.RequireNonAlphanumeric) builder.RequireSymbol();

        if (options.RequiredUniqueChars > 1)
            builder.DisallowRepeatedCharacters(options.RequiredUniqueChars);

        return builder.Build();
    }

    /// <summary>
    /// Extension method to convert PasswordOptions to a PasswordForge policy.
    /// </summary>
    public static Policies.PasswordPolicy ToPasswordForgePolicy(
        this Microsoft.AspNetCore.Identity.PasswordOptions options) =>
        FromAspNetIdentity(options);
}
