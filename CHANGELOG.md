# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-07-05

### Added

- `PasswordForge.McpServer` stdio MCP server with policy validation, review, and redacted generation metadata.
- CI publishes `PasswordForge` and `PasswordForge.McpServer` to NuGet on release tags.

### Changed

- NuGet search tags include `password generator`.

## [1.0.2] - 2026-07-05

### Changed

- Expanded NuGet package description and search tags for OWASP and NIST-aligned visibility.

## [1.0.1] - 2026-07-05

### Changed

- Additional NuGet search tags for password and security-related discovery.

## [1.0.0] - 2026-07-05

### Added

- Initial release of PasswordForge.
- Policy-aware password generation with fluent `PasswordPolicy` builder.
- Validation using the same rule engine as generation.
- Detailed generation and validation reports with entropy estimates.
- Human-readable password generation with configurable word lists.
- Temporary credential generation with expiry metadata.
- Password policy review against common modern guidance.
- Structured valid and invalid test set generation.
- ASP.NET Core dependency injection with named policies.
- JSON configuration binding via `PasswordForgeOptions`.
- ASP.NET Identity `PasswordOptions` adapter.
- Limited regex-based policy import.
- Deterministic test mode under `PasswordForge.Testing` namespace.
- Console and ASP.NET Core sample projects.
- Named character set requirements (`RequireAtLeastOneFrom`, `RequireCountFrom`).
- Unicode modes (`AllowUnicode`, `AllowUnicodeLettersOnly`).
- Human-readable fallback when random generation fails.
- Policy configuration diagnostics for missing context values and unknown sets.
- Multi-targeting for `net8.0` and `net9.0` with stable dependencies.

### Changed

- JSON configuration binding supports `RequireAtLeastOneFrom`, `RequireCountFrom`, `Username`, `Email`, and `DisallowedContextValues`.
- Tests multi-target `net8.0` and `net9.0`; assertions use xUnit (FluentAssertions removed).
