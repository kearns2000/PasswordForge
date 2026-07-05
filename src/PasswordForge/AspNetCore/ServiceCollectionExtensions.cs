using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace PasswordForge.AspNetCore;

/// <summary>
/// ASP.NET Core dependency injection extensions for PasswordForge.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds PasswordForge services with configuration binding.
    /// </summary>
    public static IServiceCollection AddPasswordForge(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<Configuration.PasswordForgeOptions>(configuration);
        return services.AddPasswordForgeCore();
    }

    /// <summary>
    /// Adds PasswordForge services with manual configuration.
    /// </summary>
    public static IServiceCollection AddPasswordForge(
        this IServiceCollection services,
        Action<Configuration.PasswordForgeOptionsConfigurator> configure)
    {
        services.AddOptions<Configuration.PasswordForgeOptions>()
            .Configure(options =>
            {
                var configurator = new Configuration.PasswordForgeOptionsConfigurator(options);
                configure(configurator);
            });

        return services.AddPasswordForgeCore();
    }

    private static IServiceCollection AddPasswordForgeCore(this IServiceCollection services)
    {
        services.AddSingleton<Abstractions.ICommonPasswordProvider, Internal.BuiltInCommonPasswordProvider>();
        services.AddSingleton<Abstractions.IPasswordPolicyProvider>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<Configuration.PasswordForgeOptions>>().Value;
            return new Configuration.PasswordPolicyProvider(options.BuildPolicyDictionary());
        });
        services.AddSingleton<Abstractions.IPasswordValidator>(sp =>
            new Validation.DefaultPasswordValidator(
                sp.GetRequiredService<Abstractions.ICommonPasswordProvider>(),
                sp.GetRequiredService<Abstractions.IPasswordPolicyProvider>()));
        services.AddSingleton<Abstractions.IPasswordPolicyReviewer, Reviews.DefaultPasswordPolicyReviewer>();
        services.AddSingleton<Abstractions.IPasswordTestSetGenerator, TestSets.PasswordTestSetGeneratorService>();
        services.AddSingleton<Abstractions.IPasswordForge, PasswordForgeService>();
        return services;
    }
}
