# Contributing to PasswordForge

Thanks for your interest in contributing. PasswordForge is a focused library for policy-aware password generation and validation. Improvements that keep generation and validation aligned are welcome.

## Before you start

- Search [existing issues](https://github.com/kearns2000/PasswordForge/issues) to avoid duplicate work.
- For large changes (new policy rules, API changes, architecture), open an issue first to discuss approach.
- Keep pull requests focused. One feature or fix per PR is easier to review.

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- Any editor (VS, VS Code, Rider)

## Getting started

```bash
git clone https://github.com/kearns2000/PasswordForge.git
cd PasswordForge
dotnet build -c Release
dotnet test -c Release -f net8.0
dotnet test -c Release -f net9.0
```

Run the sample console:

```bash
dotnet run --project samples/PasswordForge.SampleConsole
```

## Project layout

```text
src/PasswordForge/              # Library
  Policies/                     # Fluent policy builder and immutable policy model
  Generation/                   # Password and human-readable generators
  Validation/                   # Shared rule engine and entropy estimates
  Configuration/                # appsettings.json binding and DI providers
  AspNetCore/                   # Service collection extensions
  Identity/                     # ASP.NET Identity adapter
  Testing/                      # Deterministic test-only API
tests/PasswordForge.Tests/      # xUnit tests (net8.0 and net9.0)
samples/                        # Console and ASP.NET Core samples
```

## Making changes

### Bug fixes

1. Add a failing test in `tests/PasswordForge.Tests/` that reproduces the bug.
2. Fix the issue in `src/PasswordForge/`.
3. Ensure tests pass on both target frameworks:

```bash
dotnet test -c Release -f net8.0
dotnet test -c Release -f net9.0
```

### New policy rules

1. Add builder methods to `PasswordPolicyBuilder` and properties on `PasswordPolicy`.
2. Implement the rule in both `PasswordGenerator` and `PasswordValidator`.
3. Add diagnostics in `PolicyDiagnostics` when misconfiguration should block generation.
4. Bind the rule in `PasswordPolicyOptions` if it should work from `appsettings.json`.
5. Add tests for generation, validation, and configuration binding where relevant.

### Public API changes

- Keep the public surface focused.
- Update `README.md` for any user-visible API change.
- Avoid breaking changes in patch/minor releases without discussion.

## Code guidelines

- Use nullable reference types; avoid suppressing null warnings without reason.
- Production randomness must use `RandomNumberGenerator`. Predictable randomness belongs only in `PasswordForge.Testing`.
- Generated passwords must never appear in exception messages or policy diagnostics.
- Match existing naming, UK English in user-facing text, and file structure.
- Do not use em dashes in repository text.

## Testing expectations

All PRs should pass:

```bash
dotnet build -c Release
dotnet test -c Release -f net8.0
dotnet test -c Release -f net9.0
```

Add tests when you:

- Fix a bug
- Add or change a policy rule
- Change generation or validation behaviour
- Touch JSON configuration binding or DI registration

## Pull request checklist

- [ ] `dotnet build -c Release` succeeds
- [ ] `dotnet test -c Release -f net8.0` passes
- [ ] `dotnet test -c Release -f net9.0` passes
- [ ] Tests added or updated for the change
- [ ] README updated if public API or behaviour changed
- [ ] No unrelated formatting or drive-by refactors

## Questions

Open a [GitHub issue](https://github.com/kearns2000/PasswordForge/issues) for questions or ideas.
