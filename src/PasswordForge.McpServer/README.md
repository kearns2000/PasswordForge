# PasswordForge MCP Server

Stdio MCP server for [PasswordForge](https://www.nuget.org/packages/PasswordForge). Exposes policy validation, review, generation metadata, and test-set summaries.

**Security:** generated and test-sample password values are **never** returned in tool responses.

`validate_password` accepts a password in the tool request so the server can check it against a policy. That value is not echoed in the response, but it may appear in MCP client logs or host diagnostics depending on your setup. Prefer `review_policy`, `analyse_policy_configuration`, and metadata-only generation tools when you do not need to validate a specific secret.

## Tools

| Tool | Purpose |
|------|---------|
| `validate_password` | Validate a password against a policy (password sent in request only) |
| `review_policy` | Score a policy against common modern guidance |
| `analyse_policy_configuration` | Check whether a policy can generate passwords |
| `generate_password_metadata` | Generate a password and return metadata only |
| `generate_human_readable_metadata` | Human-readable generation metadata only |
| `generate_test_set_summary` | Valid/invalid test scenarios without sample values |
| `import_policy_from_regex` | Map a regex pattern to a policy |

Policy arguments use the `PasswordPolicyOptions` JSON shape (same as `appsettings.json`).

## Run locally

```bash
dotnet run --project src/PasswordForge.McpServer
```

## Cursor / Claude Desktop

Add to your MCP config:

```json
{
  "mcpServers": {
    "passwordforge": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "/absolute/path/to/PasswordForge/src/PasswordForge.McpServer"
      ]
    }
  }
}
```

Or install as a .NET tool after publishing:

```bash
dotnet tool install --global PasswordForge.McpServer
```

```json
{
  "mcpServers": {
    "passwordforge": {
      "command": "passwordforge-mcp"
    }
  }
}
```
