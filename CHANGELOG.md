# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-10-16

### Added

- `as-https` also checks the issuer identifier: a public `http://` issuer fails even when its endpoints say `https`, because metadata fetched over plain HTTP can be altered in transit (RFC 8414 section 2). Loopback issuers warn, as loopback endpoints already did. The evidence carries `insecure_issuer`.
- README: who it is for, a quick start and a sample on the first screen; example outputs regenerated from the demo server.
- Add `--format text|json|markdown` to select the report output format (text is the default); `--json` remains an alias for `--format json`. Markdown output renders the report as a Markdown table suitable for pasting into an issue.

### Fixed

- `as-https` no longer fails when an optional endpoint such as `registration_endpoint` or `jwks_uri` is present as `null`; it is treated as absent.
- `--login` with a `--callback-port` that is already in use crashed with a traceback; it now fails `login-token` with the port and the fix.
- `--login` crashed when a `tools/list` reply had a `result` that was not an object; `login-tools-list` now fails with a clear reason.
- The usage error for a plain `http://` URL now names `::1`, which was already accepted.

## [0.2.0] - 2026-10-09

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

[Unreleased]: https://github.com/basitalisandhu/mcp-auth-doctor/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/basitalisandhu/mcp-auth-doctor/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/basitalisandhu/mcp-auth-doctor/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/basitalisandhu/mcp-auth-doctor/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/basitalisandhu/mcp-auth-doctor/releases/tag/v0.1.0
