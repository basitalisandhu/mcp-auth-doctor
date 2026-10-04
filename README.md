# mcp-auth-doctor: diagnose OAuth discovery problems on remote MCP servers

One read-only command that explains why a remote MCP server's OAuth login fails. It does what a conforming MCP client does when it meets a server, step by step, and reports each step as pass, fail, warn or skip with a one-line reason and the evidence: the unauthenticated 401, the `WWW-Authenticate` challenge, Protected Resource Metadata (RFC 9728), authorization server metadata (RFC 8414 or OpenID Connect Discovery), PKCE S256, client registration options, the RFC 9207 `iss` parameter and the token endpoint's error format. Optionally it runs the whole PKCE login and calls `tools/list` with the token.

Checked against the MCP authorization specification, both the 2026-07-28 release and 2025-11-25. Python 3.11+, one dependency (httpx), runs with `pipx` or `uvx`.

Part of [Masoon](https://github.com/basitalisandhu/masoon) ([docs](https://basitalisandhu.github.io/masoon/)), open-source trust infrastructure for AI agents: who they are, what they may touch, and proof of what they did.

[![CI](https://github.com/basitalisandhu/mcp-auth-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/basitalisandhu/mcp-auth-doctor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

## Why

Remote MCP servers fail to authenticate for a short list of reasons, and the clients report all of them the same way: "OAuth failed", "cannot discover OAuth configuration", or nothing at all. The same faults keep being filed against different clients:

- the GitHub remote MCP server's documented URL carried a trailing slash that its protected resource metadata did not, and its token endpoint answered form-encoded while the SDK expected JSON ([github/github-mcp-server#804](https://github.com/github/github-mcp-server/issues/804));
- dynamic client registration answered HTTP 422 and the client stopped there ([anomalyco/opencode#6067](https://github.com/anomalyco/opencode/issues/6067));
- `/mcp auth` could not discover the OAuth configuration at all ([google-gemini/gemini-cli#5011](https://github.com/google-gemini/gemini-cli/issues/5011));
- remote servers that never return 401 do not trigger OAuth in the client ([netclaw-dev/netclaw#2141](https://github.com/netclaw-dev/netclaw/issues/2141), [milind-soni/OpenMausBot#1496](https://github.com/milind-soni/OpenMausBot/issues/1496));
- servers that use header authentication get listed as OAuth-capable and the error suggests a command that cannot help ([Kilo-Org/kilocode#12763](https://github.com/Kilo-Org/kilocode/issues/12763)).

The 2026-07-28 specification added rules on top ([changelog](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/changelog.mdx)): clients must validate `iss` (RFC 9207), must send `application_type` when registering, must key credentials by issuer, and dynamic client registration is deprecated in favour of Client ID Metadata Documents. A server that was fine last year can now be refused for a missing metadata field.

This tool runs the discovery once, in the order the spec prescribes, and names the step that breaks. It is not a conformance suite and it cannot prove a server validates token audience without logging in; it tells you what a client will see.

## When to use this

- **My MCP client says it cannot discover OAuth configuration for the server. Which step fails?** Run it against the URL; the first `FAIL` line is the step.
- **The server returns 401 but the client never opens a browser.** The `www-authenticate` and `prm-fetch` checks show whether the challenge points at metadata that is actually served.
- **Login works, then every call fails with 401 again.** `prm-resource` flags the trailing-slash mismatch between the URL and the metadata `resource`; `--login` then shows whether the server accepts its own authorization server's token.
- **Does this authorization server work with MCP clients at all?** `as-pkce`, `as-registration` and `token-error-json` are the three things SDK clients refuse to proceed without.
- **We are moving to the 2026-07-28 rules. What will clients start complaining about?** Compare `--spec 2025-11-25` with the default.

## Install

Requires Python 3.11 or newer. PyPI publication is pending, so install from the repository:

```bash
pipx install git+https://github.com/basitalisandhu/mcp-auth-doctor                                 # isolated CLI install
uvx --from git+https://github.com/basitalisandhu/mcp-auth-doctor mcp-auth-doctor https://host/mcp  # run without installing
pip install git+https://github.com/basitalisandhu/mcp-auth-doctor                                  # into the current environment
```

Once the package is on PyPI the short forms work too: `pipx install mcp-auth-doctor`, `uvx mcp-auth-doctor https://host/mcp`, `pip install mcp-auth-doctor`.

### Container image

Each release tag publishes `ghcr.io/basitalisandhu/mcp-auth-doctor` for linux/amd64 and linux/arm64, tagged with the version and `latest`. The image runs as uid 1000 with `/work` as the working directory:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/basitalisandhu/mcp-auth-doctor:0.1.0 https://host/mcp --json
```

Inside a container, `127.0.0.1` is the container itself. To check a server on your machine, use the server's network address, or on Linux add `--network host`. The `--login` flow needs a browser and a loopback callback, so run it from a local install instead.

The image is signed with a keyless cosign signature and has a build provenance attestation and an SPDX SBOM (attached to the GitHub Release). To verify:

```bash
cosign verify ghcr.io/basitalisandhu/mcp-auth-doctor:0.1.0 \
  --certificate-identity-regexp '^https://github.com/basitalisandhu/mcp-auth-doctor/\.github/workflows/publish-github-packages\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/basitalisandhu/mcp-auth-doctor:0.1.0 --repo basitalisandhu/mcp-auth-doctor
```

### pip

Once published to PyPI:

```bash
pip install mcp-auth-doctor
```

## Usage

```text
mcp-auth-doctor <mcp-url> [--json] [--spec 2026-07-28|2025-11-25] [--dcr-probe] [--login]
                [--client-id ID] [--callback-port N] [--login-timeout S] [--no-browser]
                [--timeout S] [-v]
```

| Option | Effect |
|---|---|
| `--json` | Print `{url, checks:[{id,status,reason,evidence}], summary}` instead of the table. |
| `--spec` | Which specification's rules to apply where they differ (default `2026-07-28`, see below). |
| `--dcr-probe` | Opt in: send one dynamic client registration (`application_type: "native"`, loopback redirect URI, no secret) and report the status code and whether the answer is JSON. |
| `--login` | Opt in: run the authorization code flow with PKCE and a loopback callback, redeem the code with the `resource` parameter (RFC 8707), validate `iss`, then call `tools/list` with the token. Registers a client unless `--client-id` is given. |
| `--client-id` | Pre-registered client id for `--login` (its registered redirect URI must be `http://127.0.0.1:<port>/callback`; pin the port with `--callback-port`). |
| `--no-browser` | With `--login`, print the authorization URL instead of opening a browser. |
| `--timeout` | HTTP timeout per request in seconds (default 10). |
| `-v` | Show evidence for every check, not only failures and warnings. |

Plain `http://` is refused unless the host is `localhost`, `127.0.0.1` or `::1`.

Exit codes: `0` every check passed (warnings and skips allowed), `1` at least one check failed, `2` inconclusive (the server neither returned 401 nor served any metadata, or could not be reached), `3` usage error.

## Checks

In execution order. The `as-*`, `dcr-probe` and `token-error-json` checks repeat for every issuer in `authorization_servers`; `evidence.issuer` says which.

| Id | What is verified | A fail means | Fix on the server side |
|---|---|---|---|
| `unauth-401` | `POST` of a JSON-RPC `initialize` without `Authorization` returns 401. | 200: the endpoint is not protected, clients never start OAuth. 3xx: clients do not follow redirects on the MCP endpoint. 403, 404, 405: wrong status or path. | Return 401 for every request without a valid bearer token, including `POST`. Publish the final URL (no redirect from `/mcp` to `/mcp/`). |
| `www-authenticate` | The 401 carries `WWW-Authenticate: Bearer resource_metadata="<url>"`. | (warn) No header or no `resource_metadata`; clients fall back to the well-known locations. | Add `WWW-Authenticate: Bearer resource_metadata="https://host/.well-known/oauth-protected-resource/path", scope="..."` to the 401 (RFC 9728 section 5.1). |
| `prm-fetch` | The metadata is fetched from the header URL, else `/.well-known/oauth-protected-resource<path>`, then `/.well-known/oauth-protected-resource`. | None of the locations returned 200 JSON, or the header named a URL that does not work. | Serve the JSON document with 200 and `application/json` at the path-aware location (insert the well-known string between host and path) or at the root, and make the header URL point exactly there. |
| `prm-resource` | `resource` equals the MCP URL (case-insensitive scheme and host, default port ignored). A difference that is only a trailing slash is named as such. | Clients will request a token for one audience and present it to another; the server then returns 401 after login. | Set `resource` to the exact URL clients use. The spec recommends the form without a trailing slash; whichever you choose, use it everywhere. |
| `prm-authorization-servers` | `authorization_servers` is a non-empty list of issuer URLs. | Clients have nowhere to go. | List at least one issuer URL (the value whose metadata `issuer` is identical). |
| `as-metadata` | Metadata is found at `/.well-known/oauth-authorization-server[/path]`, then `/.well-known/openid-configuration[/path]`, then `/path/.well-known/openid-configuration`. | No document at any location clients try. | Serve RFC 8414 metadata at the root well-known path (path inserted after `.well-known/...` for issuers with a path), or OpenID Connect Discovery. |
| `as-issuer` | The document's `issuer` is identical to the URL used for discovery. | Clients MUST NOT use the metadata (RFC 8414 section 3.3). | Make `issuer` exactly the value listed in `authorization_servers`. |
| `as-endpoints` | `authorization_endpoint` and `token_endpoint` are absolute URLs. | Nothing to redirect to or redeem at. | Add both as absolute `https://` URLs. |
| `as-pkce` | `code_challenge_methods_supported` contains `S256`. | MCP clients MUST refuse to proceed when the member is absent, including with OpenID Connect Discovery. | Add `"code_challenge_methods_supported": ["S256"]` and enforce PKCE at the token endpoint. |
| `as-registration` | `client_id_metadata_document_supported` is true or `registration_endpoint` is present. | (warn) Clients without a pre-registered client id cannot register. Under 2026-07-28, DCR alone passes with a note that it is deprecated. | Support Client ID Metadata Documents (`client_id_metadata_document_supported: true`), or offer RFC 7591 registration, or document how users obtain a client id. |
| `as-iss` | `authorization_response_iss_parameter_supported` is true. | (warn under 2026-07-28, skip under 2025-11-25) Clients cannot detect mix-up attacks; the spec says the server SHOULD send `iss`. | Include `iss` in every authorization response and advertise it (RFC 9207). |
| `dcr-probe` | With `--dcr-probe`: a native registration with `redirect_uris: ["http://127.0.0.1:1/callback"]` and `token_endpoint_auth_method: "none"` is answered with JSON and a `client_id`. | Non-JSON answer (clients cannot read it) or a JSON error such as `invalid_redirect_uri` (loopback clients rejected). | Accept `application_type: "native"` with loopback redirect URIs and public clients; return 201 JSON or an RFC 7591 JSON error. |
| `token-error-json` | A deliberately invalid token request is refused with a 4xx `application/json` body carrying `error`. | The error (and most likely the success body) is form-encoded, HTML or a 5xx; SDK clients fail to parse it. | Return 400 with `{"error": "invalid_grant"}` as `application/json` (RFC 6749 section 5.2) and the token response as JSON (section 5.1). |
| `login-token` | With `--login`: registration (or `--client-id`), browser authorization, `state` check, `iss` validation per the spec table, code redeemed with `code_verifier` and `resource`. | The reason names the step: registration refused, `state` or `iss` mismatch, `iss` missing while advertised, token endpoint error. | Fix the named step; for `iss`, either send it or stop advertising `authorization_response_iss_parameter_supported`. |
| `login-tools-list` | With `--login`: `initialize` and `tools/list` succeed with the bearer token. | 401 after a successful login means the server rejects its own authorization server's token: audience (`resource`) or issuer validation is misconfigured. | Validate the token's audience against the same `resource` value the metadata publishes and accept the issuer listed in `authorization_servers`. |

## Example output

Against [`scripts/demo_server.py`](scripts/demo_server.py), a standard-library MCP server plus authorization server on 127.0.0.1 (correct mode):

```text
$ mcp-auth-doctor http://127.0.0.1:8765/mcp
mcp-auth-doctor 0.1.0  spec 2026-07-28  http://127.0.0.1:8765/mcp

  unauth-401                 PASS  POST initialize without Authorization returned 401
  www-authenticate           PASS  Bearer challenge carries resource_metadata
  prm-fetch                  PASS  Protected Resource Metadata fetched from the resource_metadata URL
  prm-resource               PASS  resource matches the MCP URL
  prm-authorization-servers  PASS  1 authorization server(s) listed
  as-metadata                PASS  authorization server metadata found (oauth-authorization-server)
  as-issuer                  PASS  metadata `issuer` matches the issuer used for discovery
  as-endpoints               PASS  authorization_endpoint and token_endpoint present
  as-pkce                    PASS  PKCE S256 advertised
  as-registration            PASS  Client ID Metadata Documents and Dynamic Client Registration both available
  as-iss                     PASS  `iss` in authorization responses advertised (RFC 9207)
  dcr-probe                  skip  pass --dcr-probe to send a registration request
  token-error-json           PASS  invalid token request refused with 400 application/json (invalid_grant)
  login-token                skip  pass --login to run the PKCE code flow
  login-tools-list           skip  pass --login to run the PKCE code flow

12 pass, 0 fail, 0 warn, 3 skip. Verdict: PASS (exit 0)
```

The same script started with `--broken` reproduces three faults seen in the field, a trailing-slash mismatch, no PKCE advertised and a form-encoded token error:

```text
$ mcp-auth-doctor http://127.0.0.1:8766/mcp
mcp-auth-doctor 0.1.0  spec 2026-07-28  http://127.0.0.1:8766/mcp

  unauth-401                 PASS  POST initialize without Authorization returned 401
  www-authenticate           PASS  Bearer challenge carries resource_metadata
  prm-fetch                  PASS  Protected Resource Metadata fetched from the resource_metadata URL
  prm-resource               FAIL  resource differs from the MCP URL only by a trailing slash (resource has the slash): resource='http://127.0.0.1:8766/mcp/' url='http://127.0.0.1:8766/mcp'
                                   resource: http://127.0.0.1:8766/mcp/
                                   url: http://127.0.0.1:8766/mcp
                                   trailing_slash_only: True
  prm-authorization-servers  PASS  1 authorization server(s) listed
  as-metadata                PASS  authorization server metadata found (oauth-authorization-server)
  as-issuer                  PASS  metadata `issuer` matches the issuer used for discovery
  as-endpoints               PASS  authorization_endpoint and token_endpoint present
  as-pkce                    FAIL  `code_challenge_methods_supported` is absent; MCP clients MUST refuse to proceed (advertise ["S256"])
                                   issuer: http://127.0.0.1:8766
  as-registration            PASS  Client ID Metadata Documents and Dynamic Client Registration both available
  as-iss                     PASS  `iss` in authorization responses advertised (RFC 9207)
  dcr-probe                  skip  pass --dcr-probe to send a registration request
  token-error-json           FAIL  token endpoint error response is 'application/x-www-form-urlencoded', not application/json (RFC 6749 section 5.2); SDK clients fail to parse the error and the success body is probably form-encoded too
                                   body_preview: error=invalid_grant&error_description=bad+code
                                   issuer: http://127.0.0.1:8766
                                   token_endpoint: http://127.0.0.1:8766/token
                                   status: 400
                                   content_type: application/x-www-form-urlencoded
  login-token                skip  pass --login to run the PKCE code flow
  login-tools-list           skip  pass --login to run the PKCE code flow

9 pass, 3 fail, 0 warn, 3 skip. Verdict: FAIL (exit 1)
```

`--json` prints the whole document; three checks from the broken run with `--dcr-probe`:

```json
{
  "url": "http://127.0.0.1:8766/mcp",
  "checks": [
    {
      "id": "prm-resource",
      "status": "fail",
      "reason": "resource differs from the MCP URL only by a trailing slash (resource has the slash): resource='http://127.0.0.1:8766/mcp/' url='http://127.0.0.1:8766/mcp'",
      "evidence": {
        "resource": "http://127.0.0.1:8766/mcp/",
        "url": "http://127.0.0.1:8766/mcp",
        "trailing_slash_only": true
      }
    },
    {
      "id": "dcr-probe",
      "status": "pass",
      "reason": "registration accepted (201, JSON with client_id)",
      "evidence": {
        "client_id_issued": true,
        "token_endpoint_auth_method": "none",
        "issuer": "http://127.0.0.1:8766",
        "registration_endpoint": "http://127.0.0.1:8766/register",
        "status": 201,
        "content_type": "application/json",
        "json": true
      }
    },
    {
      "id": "token-error-json",
      "status": "fail",
      "reason": "token endpoint error response is 'application/x-www-form-urlencoded', not application/json (RFC 6749 section 5.2); SDK clients fail to parse the error and the success body is probably form-encoded too",
      "evidence": {
        "body_preview": "error=invalid_grant&error_description=bad+code",
        "issuer": "http://127.0.0.1:8766",
        "token_endpoint": "http://127.0.0.1:8766/token",
        "status": 400,
        "content_type": "application/x-www-form-urlencoded"
      }
    }
  ],
  "summary": {
    "verdict": "fail",
    "exit_code": 1,
    "pass": 10,
    "fail": 3,
    "warn": 0,
    "skip": 2,
    "spec": "2026-07-28",
    "tool": "mcp-auth-doctor 0.1.0"
  }
}
```

`--login` on the correct demo server (the demo authorization server approves without a user; `--no-browser` prints the URL to open):

```text
$ mcp-auth-doctor http://127.0.0.1:8765/mcp --login --no-browser
Open this URL to authorize:
  http://127.0.0.1:8765/authorize?response_type=code&client_id=demo-client&redirect_uri=http%3A%2F%2F127.0.0.1%3A42523%2Fcallback&code_challenge=...&code_challenge_method=S256&state=...&resource=http%3A%2F%2F127.0.0.1%3A8765%2Fmcp&scope=mcp%3Aread
mcp-auth-doctor 0.1.0  spec 2026-07-28  http://127.0.0.1:8765/mcp

  unauth-401                 PASS  POST initialize without Authorization returned 401
  www-authenticate           PASS  Bearer challenge carries resource_metadata
  prm-fetch                  PASS  Protected Resource Metadata fetched from the resource_metadata URL
  prm-resource               PASS  resource matches the MCP URL
  prm-authorization-servers  PASS  1 authorization server(s) listed
  as-metadata                PASS  authorization server metadata found (oauth-authorization-server)
  as-issuer                  PASS  metadata `issuer` matches the issuer used for discovery
  as-endpoints               PASS  authorization_endpoint and token_endpoint present
  as-pkce                    PASS  PKCE S256 advertised
  as-registration            PASS  Client ID Metadata Documents and Dynamic Client Registration both available
  as-iss                     PASS  `iss` in authorization responses advertised (RFC 9207)
  dcr-probe                  skip  pass --dcr-probe to send a registration request
  token-error-json           PASS  invalid token request refused with 400 application/json (invalid_grant)
  login-token                PASS  authorization code redeemed with PKCE and the `resource` parameter
  login-tools-list           PASS  tools/list returned 2 tool(s) with the bearer token

14 pass, 0 fail, 0 warn, 1 skip. Verdict: PASS (exit 0)
```

To reproduce: `python scripts/demo_server.py --port 8765` in one terminal (add `--broken` for the second variant) and the commands above in another.

## What `--spec` changes

Both versions share the discovery order, PKCE and `resource` rules. The switch matters in three places:

| | `2026-07-28` (default) | `2025-11-25` |
|---|---|---|
| `as-iss` | warn when `authorization_response_iss_parameter_supported` is not true | skip (RFC 9207 is not part of these rules) |
| `as-registration` with DCR only | pass, with a note that DCR is deprecated | pass |
| `--login` with `iss` advertised but absent | fail (clients MUST reject the response) | pass (only a present `iss` is compared) |

The `MCP-Protocol-Version` header and `protocolVersion` in the `initialize` request follow the chosen version.

## Frequently asked questions

**Why does my MCP client say it cannot discover the OAuth configuration?**
Discovery is a chain: a 401 with a `WWW-Authenticate` challenge, a Protected Resource Metadata document at the URL the challenge names (or at the well-known location derived from the MCP URL), an `authorization_servers` entry, and authorization server metadata at that issuer's well-known location. Clients stop at the first link that does not answer with 200 and JSON, and most of them report only that the chain failed. The tool walks the same chain with the same fallbacks and prints every URL it tried with the status it got, so the broken link is on the screen. The usual culprits are a 401 without the header on a server whose metadata is not at the path-aware location, and a `resource_metadata` URL that returns 404 because the metadata is served one path segment away.

**Login succeeds, then the server answers 401 again. Why?**
Almost always an audience mismatch. The client sends `resource=<the URL it was configured with>` when it asks for the token, and the server validates the token's audience against the `resource` value it publishes in its metadata. If one has a trailing slash and the other does not, the token is for a different resource. `prm-resource` compares the two and says explicitly when the only difference is the slash. The fix is on the server: publish the same `resource` that users are told to configure, preferably without the trailing slash as the spec recommends, and do not redirect between the two forms.

**Dynamic client registration returns 422 (or HTML). Is the server broken?**
Possibly only strict. MCP clients are native applications with a loopback redirect URI and no client secret; an authorization server that assumes web clients rejects that registration, and under OpenID Connect the default `application_type` is `web`, which is why the 2026-07-28 spec requires clients to send `application_type: "native"`. `--dcr-probe` sends exactly that request and shows whether the answer is JSON (an RFC 7591 error you can act on) or something the client cannot parse. Since DCR is deprecated in 2026-07-28, the longer-term fix for a server is `client_id_metadata_document_supported: true`, which lets clients identify themselves with an HTTPS URL and needs no registration endpoint at all.

**Is it safe to run against a production server?**
By default the tool only reads: one unauthenticated `initialize`, metadata `GET`s, and one token request with an invalid code that creates nothing and exercises the error path every client hits anyway. `--dcr-probe` creates a throwaway client registration on servers that accept it, and `--login` obtains a real access token for your user, keeps it in memory for one `tools/list` call and never prints or stores it; both are opt-in and described in [SECURITY.md](SECURITY.md). The tool never sends `Authorization` to any host other than the MCP URL you gave it.

## Roadmap

- Checks for `bearer_methods_supported`, HTTPS on every endpoint and challenge scope versus `scopes_supported` (see [docs/good-first-issues.md](docs/good-first-issues.md)).
- Markdown output for pasting into issues, and extra request headers for servers behind access proxies.
- Recording real server exchanges as fixtures so a reported failure can be replayed in the test suite.
- A `--client-metadata-url` mode for `--login` on servers that support Client ID Metadata Documents, once a hosted document is available.

## Contributing

Issues and pull requests are welcome. Adding a check is a few lines in `checks.py`, a table row and a test; see [CONTRIBUTING.md](CONTRIBUTING.md). Run `make check` (ruff and pytest) before opening a pull request. Security problems: see [SECURITY.md](SECURITY.md).

## Sibling projects

- [masoon](https://github.com/basitalisandhu/masoon): the platform front door, with the [docs site](https://basitalisandhu.github.io/masoon/).
- [Masoon Broker](https://basitalisandhu.github.io/masoon/masoon-broker.html): scoped, short-lived credentials for AI agents with approvals, kill switch and tamper-evident audit.
- [agent-threat-model](https://github.com/basitalisandhu/agent-threat-model): deterministic STRIDE and OWASP Agentic threat modelling for agent systems described in YAML.
- [agentic-semgrep-rules](https://github.com/basitalisandhu/agentic-semgrep-rules): Semgrep rule pack for insecure agent code, including MCP servers without auth.
- [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills): Claude Code plugin and skill pack for agent security reviews.

## Licence

MIT, see [LICENSE](LICENSE). Copyright 2026 Muhammad Basit Ali.
