# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `as-https` checks present authorization-server metadata endpoints for HTTPS, failing public HTTP and warning for loopback HTTP used in local development.

## [0.1.1] - 2026-10-06

### Changed

- Removed the umbrella branding; this project stands alone and links its sibling repositories directly.

## [0.1.0] - 2026-10-04

### Added

- Container image `ghcr.io/basitalisandhu/mcp-auth-doctor` for linux/amd64 and linux/arm64, published on each version tag with an SPDX SBOM, a build provenance attestation and a keyless cosign signature. The image runs as uid 1000 with `/work` as the working directory.
- `mcp-auth-doctor <mcp-url>` with fifteen checks: the unauthenticated 401, the `WWW-Authenticate` challenge, protected resource metadata discovery (header URL, path-aware and root well-known locations), `resource` match with explicit trailing-slash detection, `authorization_servers`, authorization server metadata discovery (RFC 8414 then OpenID Connect Discovery, path insertion for issuers with a path), `issuer` validation, endpoints, PKCE S256, registration options (DCR and Client ID Metadata Documents), RFC 9207 `iss` advertisement, the token endpoint error format, and the opt-in `--dcr-probe` and `--login` flows.
- `--spec 2026-07-28|2025-11-25` to switch the rules that differ between the two MCP authorization specification versions.
- Text table and `--json` output (`{url, checks:[{id,status,reason,evidence}], summary}`), exit codes 0, 1, 2 and 3.
- `scripts/demo_server.py`, a standard-library MCP and authorization server for local trials, with a `--broken` mode.
- 66 pytest tests with respx-mocked servers, CI on Python 3.11 and 3.12, PyPI trusted-publishing release workflow (off until the repository variable `PYPI_PUBLISH` is set).

### Changed

- Renamed the umbrella project from Hisar to Masoon; links, names and identifiers updated.

[Unreleased]: https://github.com/basitalisandhu/mcp-auth-doctor/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/basitalisandhu/mcp-auth-doctor/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/basitalisandhu/mcp-auth-doctor/releases/tag/v0.1.0
