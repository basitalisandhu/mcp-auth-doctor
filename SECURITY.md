# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability") rather than a public issue. Include the version, the command you ran (with the server URL redacted if needed) and the `--json` output if you have it.

You will get an acknowledgement within 7 days and a fix or a mitigation plan within 30 days for confirmed issues. Credit is given in the release notes unless you prefer otherwise.

## What the tool does on the network

By default `mcp-auth-doctor` only reads:

- one unauthenticated `POST` of a JSON-RPC `initialize` message to the MCP URL you give it (to provoke the 401 challenge), unless you explicitly supply an Authorization header with `-H/--header`,
- `GET` requests for the protected resource metadata and authorization server metadata documents at their well-known locations,
- one `POST` to the token endpoint with a deliberately invalid authorization code, to see whether the error comes back as `application/json`. This creates no state on the server and uses no credentials.

`-H/--header` sends user-supplied headers only to the MCP URL (also on authenticated MCP calls). They are never forwarded to metadata discovery, registration or token endpoints, and values are not added to diagnostic reports. Supplying Authorization means the initial request no longer tests unauthenticated protection; the tool warns rather than claiming that it does. Avoid placing sensitive header values in shell history or shared process arguments.

Two flags are opt-in and documented in the README because they go beyond reading:

- `--dcr-probe` sends one dynamic client registration request (`application_type: "native"`, redirect URI `http://127.0.0.1:1/callback`, no client secret). Authorization servers that accept it will create a throwaway client record; the tool never uses it.
- `--login` runs the full OAuth 2.1 authorization code flow with PKCE: it registers a client (unless you pass `--client-id`), opens your browser, receives the code on a loopback listener bound to 127.0.0.1, redeems it, and calls `tools/list` once with the access token. The access token is held in memory for that one call and is never written to disk or printed; the report shows only its type, lifetime and scope.

The tool refuses plain `http://` URLs for anything other than localhost and 127.0.0.1, follows redirects only for metadata `GET` requests, and never sends the `Authorization` header to a host other than the MCP URL you gave it.

## Scope

Issues of interest: anything that makes the tool send credentials or tokens where it should not, follow a redirect it should not, print a secret, or misreport a check in a way that would lead someone to deploy an insecure configuration (for example reporting PKCE as supported when it is not). Findings the tool produces about a server are not vulnerabilities in the tool; for those, open a normal issue.
