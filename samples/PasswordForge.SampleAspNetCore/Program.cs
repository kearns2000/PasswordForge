using PasswordForge.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPasswordForge(builder.Configuration.GetSection("PasswordForge"));

var app = builder.Build();

// WARNING: Production systems should be careful about exposing generated credentials.
// This endpoint is for development demonstration only.
app.MapGet("/password/sample", async (PasswordForge.Abstractions.IPasswordForge forge) =>
{
    var result = await forge.GenerateAsync("TemporaryPassword");
    return Results.Ok(new
    {
        result.EntropyBits,
        result.Warnings,
        result.GenerationReport?.GenerationMethod
    });
});

app.MapGet("/", () => "PasswordForge sample API. Try GET /password/sample");

app.Run();
