# Publishing to NuGet

PasswordForge uses [NuGet trusted publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing) from GitHub Actions. No long-lived API keys are stored in the repo.

## One-time setup (maintainers)

### 1. Create a trusted publishing policy on nuget.org

1. Sign in at [nuget.org](https://www.nuget.org)
2. Click your username → **Trusted Publishing**
3. **Add new policy** with:

| Field | Value |
|-------|-------|
| Policy name | `passwordforge` (or any label) |
| Package owner | Your nuget.org account |
| Repository owner | `kearns2000` |
| Repository | `PasswordForge` |
| Workflow file | `ci.yml` |
| Environment | `release` |

Docs: [Trusted Publishing on Microsoft Learn](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing)

### 2. Add a GitHub repository secret

**Settings → Secrets and variables → Actions → New repository secret**

| Name | Value |
|------|-------|
| `NUGET_USER` | Your **nuget.org username** (profile name, not your email) |

Trusted publishing still needs your NuGet username for the login step; the temporary API key comes from OIDC.

### 3. Create the GitHub environment

Create a GitHub environment named **`release`** if you use environment protection rules. The `publish` job in `.github/workflows/ci.yml` targets this environment.

### 4. Publish a release

1. Ensure `Version` in both project files matches the tag:
   - `src/PasswordForge/PasswordForge.csproj`
   - `src/PasswordForge.McpServer/PasswordForge.McpServer.csproj`
2. Commit and push to `main`
3. Create and push a version tag:

```bash
git tag v1.0.3
git push origin v1.0.3
```

The `publish` job packs both packages with the tag version (without the `v` prefix) and pushes `.nupkg` and `.snupkg` to NuGet.org:

- `PasswordForge` (library)
- `PasswordForge.McpServer` (.NET global tool, command `passwordforge-mcp`)

Add a trusted publishing policy for each package ID on nuget.org if required.
