using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;
using PasswordForge.McpServer.Tools;

var serverVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";

var builder = Host.CreateApplicationBuilder(args);

// STDIO MCP servers must not write logs to stdout.
builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);

builder.Services
    .AddMcpServer(options =>
    {
        options.ServerInfo = new()
        {
            Name = "PasswordForge",
            Version = serverVersion,
            Title = "PasswordForge MCP Server",
            Description = "Policy-aware password validation and review. Generated passwords are never returned."
        };
    })
    .WithStdioServerTransport()
    .WithTools<PasswordForgeMcpTools>();

await builder.Build().RunAsync();
