"""The diagnosis: one HTTP conversation with the MCP server and its authorization
servers, producing a list of checks with a status and a one-line reason each.

Check ids (in order of execution):

  unauth-401                POST initialize without Authorization returns 401
  www-authenticate          the 401 carries Bearer ... resource_metadata="<url>"
  prm-fetch                 Protected Resource Metadata is reachable (RFC 9728)
  prm-resource              PRM `resource` equals the MCP URL (trailing slash flagged)
  prm-authorization-servers PRM lists at least one authorization server
  as-metadata               AS metadata found (RFC 8414, then OpenID Connect Discovery)
  as-issuer                 metadata `issuer` equals the issuer used for discovery
  as-endpoints              authorization_endpoint and token_endpoint present
  as-https                  authorization server endpoints use HTTPS
  as-pkce                   code_challenge_methods_supported contains S256
  as-registration           registration_endpoint or client_id_metadata_document_supported
  as-iss                    authorization_response_iss_parameter_supported is true (RFC 9207)
  dcr-probe                 (--dcr-probe) a native registration request is answered with JSON
  token-error-json          an invalid token request is refused with application/json
  login-token               (--login) PKCE code flow completed, token redeemed with `resource`
  login-tools-list          (--login) tools/list with the bearer token succeeds

The as-* and token checks are repeated for every authorization server the PRM lists;
`evidence.issuer` says which one a check belongs to.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import __version__
from .discovery import (
    as_metadata_urls,
    bearer_scope,
    compare_resource,
    is_json_content_type,
    issuer_matches,
    prm_well_known_urls,
    resource_metadata_url,
)
from .mcpclient import initialize_request, mcp_headers

SPECS = ("2026-07-28", "2025-11-25")
DEFAULT_SPEC = "2026-07-28"

PASS, FAIL, WARN, SKIP = "pass", "fail", "warn", "skip"

PROBE_REDIRECT_URI = "http://127.0.0.1:1/callback"


@dataclass
class Check:
    id: str
    status: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Options:
    spec: str = DEFAULT_SPEC
    dcr_probe: bool = False
    login: bool = False
    client_id: str | None = None
    timeout: float = 10.0
    callback_port: int = 0
    login_timeout: float = 180.0
    open_browser: Callable[[str], None] | None = None


@dataclass
class Report:
    url: str
    spec: str
    checks: list[Check]
    inconclusive: bool = False

    def counts(self) -> dict[str, int]:
        counts = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0}
        for check in self.checks:
            counts[check.status] = counts.get(check.status, 0) + 1
        return counts

    @property
    def exit_code(self) -> int:
        if self.inconclusive:
            return 2
        return 1 if any(c.status == FAIL for c in self.checks) else 0

    @property
    def verdict(self) -> str:
        return {0: "pass", 1: "fail", 2: "inconclusive"}[self.exit_code]

    def to_dict(self) -> dict[str, Any]:
        counts = self.counts()
        return {
            "url": self.url,
            "checks": [asdict(c) for c in self.checks],
            "summary": {
                "verdict": self.verdict,
                "exit_code": self.exit_code,
                "pass": counts[PASS],
                "fail": counts[FAIL],
                "warn": counts[WARN],
                "skip": counts[SKIP],
                "spec": self.spec,
                "tool": f"mcp-auth-doctor {__version__}",
            },
        }


def make_client(timeout: float) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": f"mcp-auth-doctor/{__version__}"},
    )


def diagnose(
    url: str, options: Options | None = None, client: httpx.Client | None = None
) -> Report:
    """Run every check against `url` and return the report. Never raises for HTTP
    or network trouble; those become failed or skipped checks."""
    options = options or Options()
    own_client = client is None
    client = client or make_client(options.timeout)
    try:
        return _Diagnosis(url, options, client).run()
    finally:
        if own_client:
            client.close()


class _Diagnosis:
    def __init__(self, url: str, options: Options, client: httpx.Client) -> None:
        self.url = url
        self.options = options
        self.client = client
        self.checks: list[Check] = []
        self.got_401 = False
        self.challenge_scope: str | None = None

    def add(self, check_id: str, outcome: str, reason: str, **evidence: Any) -> Check:
        check = Check(
            check_id, outcome, reason, {k: v for k, v in evidence.items() if v is not None}
        )
        self.checks.append(check)
        return check

    # ---- top level -------------------------------------------------------------

    def run(self) -> Report:
        header_url = self.step_unauthenticated()
        if header_url is _UNREACHABLE:
            self.skip_rest("the MCP URL could not be reached")
            return Report(self.url, self.options.spec, self.checks, inconclusive=True)

        prm = self.step_prm(header_url)
        if prm is None:
            self.skip_rest("no Protected Resource Metadata")
            return Report(self.url, self.options.spec, self.checks, inconclusive=not self.got_401)

        issuers = self.step_prm_contents(prm)
        login_done = False
        for issuer in issuers:
            as_md = self.step_as_metadata(issuer)
            if as_md is None:
                continue
            self.step_as_contents(issuer, as_md)
            self.step_dcr_probe(issuer, as_md)
            self.step_token_error(issuer, as_md)
            if self.options.login and not login_done:
                login_done = True
                self.step_login(prm, as_md)
        if not issuers:
            self.skip_as_checks("no authorization server to check")
        if not login_done:
            reason = (
                "pass --login to run the PKCE code flow"
                if not self.options.login
                else "no authorization server metadata to log in with"
            )
            self.add("login-token", SKIP, reason)
            self.add("login-tools-list", SKIP, reason)
        return Report(self.url, self.options.spec, self.checks)

    def skip_as_checks(self, reason: str) -> None:
        for check_id in (
            "as-metadata",
            "as-issuer",
            "as-endpoints",
            "as-https",
            "as-pkce",
            "as-registration",
            "as-iss",
            "dcr-probe",
            "token-error-json",
        ):
            self.add(check_id, SKIP, reason)

    def skip_rest(self, reason: str) -> None:
        done = {c.id for c in self.checks}
        for check_id in (
            "www-authenticate",
            "prm-fetch",
            "prm-resource",
            "prm-authorization-servers",
        ):
            if check_id not in done:
                self.add(check_id, SKIP, reason)
        self.skip_as_checks(reason)
        self.add("login-token", SKIP, reason)
        self.add("login-tools-list", SKIP, reason)

    # ---- step 1 and 2: the unauthenticated request --------------------------------

    def step_unauthenticated(self) -> str | object | None:
        """POST initialize without a token. Returns the resource_metadata URL from the
        WWW-Authenticate header, None when there is none, or _UNREACHABLE."""
        try:
            response = self.client.post(
                self.url,
                json=initialize_request(self.options.spec),
                headers=mcp_headers(self.options.spec),
            )
        except (httpx.HTTPError, ValueError) as exc:
            self.add("unauth-401", FAIL, f"could not reach the MCP URL: {describe(exc)}")
            return _UNREACHABLE

        status = response.status_code
        header = response.headers.get("www-authenticate")
        evidence: dict[str, Any] = {"status": status, "www_authenticate": header}
        if status == 401:
            self.got_401 = True
            self.add(
                "unauth-401", PASS, "POST initialize without Authorization returned 401", **evidence
            )
        elif status == 200:
            self.add(
                "unauth-401",
                FAIL,
                "POST initialize without Authorization returned 200: the endpoint is not "
                "protected, so clients never start the OAuth flow",
                **evidence,
            )
        elif 300 <= status < 400:
            self.add(
                "unauth-401",
                FAIL,
                f"POST initialize was redirected ({status} to {response.headers.get('location')}); "
                "clients do not follow redirects on the MCP endpoint, configure the final URL",
                location=response.headers.get("location"),
                **evidence,
            )
        else:
            hint = {
                404: " (wrong path?)",
                405: " (POST not allowed: not a Streamable HTTP endpoint?)",
                403: " (403 is for insufficient scope; a missing token must get 401)",
            }.get(status, "")
            self.add(
                "unauth-401",
                FAIL,
                f"POST initialize without Authorization returned {status}, expected 401{hint}",
                **evidence,
            )

        if header:
            self.challenge_scope = bearer_scope(header)
            url = resource_metadata_url(header)
            if url and url.lower().startswith(("https://", "http://")):
                status_word = PASS if status == 401 else WARN
                reason = "Bearer challenge carries resource_metadata"
                if status != 401:
                    reason += f" (but on a {status} response, not a 401)"
                self.add(
                    "www-authenticate",
                    status_word,
                    reason,
                    header=header,
                    resource_metadata=url,
                    scope=self.challenge_scope,
                )
                return url
            if url:
                self.add(
                    "www-authenticate",
                    WARN,
                    f"resource_metadata is not an absolute URL ({url!r}); falling back to the "
                    "well-known locations",
                    header=header,
                )
                return None
            self.add(
                "www-authenticate",
                WARN,
                "WWW-Authenticate has no Bearer resource_metadata parameter; clients fall back "
                "to the well-known locations (RFC 9728 section 5.1 recommends the parameter)",
                header=header,
            )
            return None
        if status == 401:
            self.add(
                "www-authenticate",
                WARN,
                "401 without a WWW-Authenticate header; clients fall back to the well-known "
                "locations (the MCP spec allows this, the header is recommended)",
            )
        else:
            self.add("www-authenticate", SKIP, f"no 401 challenge to parse (status {status})")
        return None

    # ---- step 3: protected resource metadata ---------------------------------------

    def step_prm(self, header_url: str | None) -> dict[str, Any] | None:
        candidates = [header_url] if header_url else []
        for candidate in prm_well_known_urls(self.url):
            if candidate not in candidates:
                candidates.append(candidate)
        attempts: list[dict[str, Any]] = []
        found: dict[str, Any] | None = None
        found_url: str | None = None
        found_ct_ok = True
        for candidate in candidates:
            document, attempt = self.fetch_json(candidate)
            attempts.append(attempt)
            if document is not None:
                found, found_url, found_ct_ok = (
                    document,
                    candidate,
                    attempt.get("json_content_type", True),
                )
                break
        evidence = {"attempts": attempts, "url": found_url}
        if found is None:
            where = "the resource_metadata URL or " if header_url else ""
            self.add(
                "prm-fetch",
                FAIL,
                f"no Protected Resource Metadata at {where}the well-known locations "
                f"(tried {len(attempts)}); the server must serve RFC 9728 metadata",
                **evidence,
            )
            return None
        if header_url and found_url != header_url:
            self.add(
                "prm-fetch",
                FAIL,
                f"resource_metadata URL {header_url} did not return metadata "
                f"(found it at {found_url} instead); clients that follow the header fail",
                **evidence,
            )
        elif not found_ct_ok:
            self.add(
                "prm-fetch",
                WARN,
                f"metadata at {found_url} is served as {attempts[-1].get('content_type')!r}, "
                "not application/json (RFC 9728 section 3.2)",
                **evidence,
            )
        else:
            via = "the resource_metadata URL" if header_url else "a well-known location"
            self.add(
                "prm-fetch", PASS, f"Protected Resource Metadata fetched from {via}", **evidence
            )
        return found

    def step_prm_contents(self, prm: dict[str, Any]) -> list[str]:
        resource = prm.get("resource")
        if not isinstance(resource, str) or not resource:
            self.add(
                "prm-resource",
                FAIL,
                "PRM has no `resource` member (REQUIRED by RFC 9728); clients cannot bind the "
                "token audience",
                resource=resource,
            )
        else:
            match = compare_resource(self.url, resource)
            self.add(
                "prm-resource",
                PASS if match.ok else FAIL,
                match.reason,
                resource=resource,
                url=self.url,
                trailing_slash_only=match.trailing_slash_only or None,
            )

        servers = prm.get("authorization_servers")
        issuers = (
            [s for s in servers if isinstance(s, str) and s] if isinstance(servers, list) else []
        )
        if not issuers:
            self.add(
                "prm-authorization-servers",
                FAIL,
                "PRM has no non-empty `authorization_servers` list; the MCP spec requires at "
                "least one issuer URL",
                authorization_servers=servers,
            )
        else:
            self.add(
                "prm-authorization-servers",
                PASS,
                f"{len(issuers)} authorization server(s) listed",
                authorization_servers=issuers,
                scopes_supported=prm.get("scopes_supported"),
            )
        return issuers

    # ---- step 4: authorization server metadata --------------------------------------

    def step_as_metadata(self, issuer: str) -> dict[str, Any] | None:
        attempts: list[dict[str, Any]] = []
        for candidate in as_metadata_urls(issuer):
            document, attempt = self.fetch_json(candidate)
            attempts.append(attempt)
            if document is not None:
                kind = (
                    "openid-configuration"
                    if "openid-configuration" in candidate
                    else "oauth-authorization-server"
                )
                self.add(
                    "as-metadata",
                    PASS,
                    f"authorization server metadata found ({kind})",
                    issuer=issuer,
                    url=candidate,
                    attempts=attempts,
                )
                return document
        self.add(
            "as-metadata",
            FAIL,
            f"no metadata at any of the {len(attempts)} well-known locations for {issuer}; "
            "serve RFC 8414 or OpenID Connect Discovery metadata",
            issuer=issuer,
            attempts=attempts,
        )
        for check_id in (
            "as-issuer",
            "as-endpoints",
            "as-https",
            "as-pkce",
            "as-registration",
            "as-iss",
            "dcr-probe",
            "token-error-json",
        ):
            self.add(check_id, SKIP, "no authorization server metadata", issuer=issuer)
        return None

    def step_as_contents(self, issuer: str, md: dict[str, Any]) -> None:
        actual_issuer = md.get("issuer")
        if not actual_issuer:
            self.add(
                "as-issuer",
                WARN,
                "metadata has no `issuer` member (REQUIRED by RFC 8414)",
                issuer=issuer,
            )
        elif issuer_matches(issuer, actual_issuer):
            self.add(
                "as-issuer",
                PASS,
                "metadata `issuer` matches the issuer used for discovery",
                issuer=issuer,
            )
        else:
            self.add(
                "as-issuer",
                FAIL,
                f"metadata `issuer` is {actual_issuer!r} but discovery used {issuer!r}; clients "
                "MUST NOT use the metadata (RFC 8414 section 3.3)",
                issuer=issuer,
                metadata_issuer=actual_issuer,
            )

        missing = [
            k for k in ("authorization_endpoint", "token_endpoint") if not is_http_url(md.get(k))
        ]
        if missing:
            self.add(
                "as-endpoints",
                FAIL,
                "metadata lacks an absolute " + " and ".join(f"`{m}`" for m in missing),
                issuer=issuer,
                **{m: md.get(m) for m in missing},
            )
        else:
            self.add(
                "as-endpoints",
                PASS,
                "authorization_endpoint and token_endpoint present",
                issuer=issuer,
                authorization_endpoint=md["authorization_endpoint"],
                token_endpoint=md["token_endpoint"],
            )

        insecure = {
            key: md[key]
            for key in (
                "authorization_endpoint",
                "token_endpoint",
                "registration_endpoint",
                "jwks_uri",
            )
            if key in md
            and (not isinstance(md[key], str) or not md[key].lower().startswith("https://"))
        }
        local_only = bool(insecure)
        for value in insecure.values():
            try:
                parts = urlsplit(value) if isinstance(value, str) else None
                local = (
                    parts is not None
                    and parts.scheme.lower() == "http"
                    and parts.hostname in ("localhost", "127.0.0.1", "::1")
                )
            except ValueError:
                local = False
            local_only = local_only and local
        if insecure:
            self.add(
                "as-https",
                WARN if local_only else FAIL,
                "authorization server endpoints MUST use HTTPS (MCP authorization, Security "
                "Considerations); HTTP loopback is warned for local development"
                if local_only
                else "authorization server endpoints MUST use HTTPS (MCP authorization, Security "
                "Considerations): " + ", ".join(insecure),
                issuer=issuer,
                endpoints=insecure,
            )
        else:
            self.add("as-https", PASS, "authorization server endpoints use HTTPS", issuer=issuer)

        methods = md.get("code_challenge_methods_supported")
        if methods is None:
            self.add(
                "as-pkce",
                FAIL,
                "`code_challenge_methods_supported` is absent; MCP clients MUST refuse to proceed "
                '(advertise ["S256"])',
                issuer=issuer,
            )
        elif not isinstance(methods, list) or "S256" not in methods:
            self.add(
                "as-pkce",
                FAIL,
                f"`code_challenge_methods_supported` does not include S256 (got {methods!r})",
                issuer=issuer,
                code_challenge_methods_supported=methods,
            )
        else:
            self.add(
                "as-pkce",
                PASS,
                "PKCE S256 advertised",
                issuer=issuer,
                code_challenge_methods_supported=methods,
            )

        registration = md.get("registration_endpoint")
        cimd = md.get("client_id_metadata_document_supported") is True
        evidence = {
            "issuer": issuer,
            "registration_endpoint": registration,
            "client_id_metadata_document_supported": md.get(
                "client_id_metadata_document_supported"
            ),
        }
        if cimd and registration:
            self.add(
                "as-registration",
                PASS,
                "Client ID Metadata Documents and Dynamic Client Registration both available",
                **evidence,
            )
        elif cimd:
            self.add("as-registration", PASS, "Client ID Metadata Documents supported", **evidence)
        elif registration:
            note = (
                "Dynamic Client Registration only; DCR is deprecated in 2026-07-28, consider "
                "advertising client_id_metadata_document_supported"
                if self.options.spec == "2026-07-28"
                else "Dynamic Client Registration available (CIMD not advertised)"
            )
            self.add("as-registration", PASS, note, **evidence)
        else:
            self.add(
                "as-registration",
                WARN,
                "no `registration_endpoint` and `client_id_metadata_document_supported` is not "
                "true; clients without a pre-registered client_id cannot register",
                **evidence,
            )

        iss_supported = md.get("authorization_response_iss_parameter_supported")
        evidence = {
            "issuer": issuer,
            "authorization_response_iss_parameter_supported": iss_supported,
        }
        if iss_supported is True:
            self.add(
                "as-iss", PASS, "`iss` in authorization responses advertised (RFC 9207)", **evidence
            )
        elif self.options.spec == "2026-07-28":
            self.add(
                "as-iss",
                WARN,
                "`authorization_response_iss_parameter_supported` is not true; 2026-07-28 says "
                "the server SHOULD send `iss` (RFC 9207) so clients can detect mix-up attacks",
                **evidence,
            )
        else:
            self.add(
                "as-iss", SKIP, "RFC 9207 `iss` is not part of the 2025-11-25 rules", **evidence
            )

    # ---- step 5: optional registration probe -----------------------------------------

    def step_dcr_probe(self, issuer: str, md: dict[str, Any]) -> None:
        registration = md.get("registration_endpoint")
        if not self.options.dcr_probe:
            self.add(
                "dcr-probe", SKIP, "pass --dcr-probe to send a registration request", issuer=issuer
            )
            return
        if not is_http_url(registration):
            self.add("dcr-probe", SKIP, "no usable registration_endpoint to probe", issuer=issuer)
            return
        body = {
            "client_name": "mcp-auth-doctor probe",
            "application_type": "native",
            "redirect_uris": [PROBE_REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }
        try:
            response = self.client.post(
                registration, json=body, headers={"Accept": "application/json"}
            )
        except (httpx.HTTPError, ValueError) as exc:
            self.add(
                "dcr-probe",
                FAIL,
                f"registration request failed: {describe(exc)}",
                issuer=issuer,
                registration_endpoint=registration,
            )
            return
        content_type = response.headers.get("content-type")
        is_json = is_json_content_type(content_type)
        document: Any = None
        if is_json:
            try:
                document = response.json()
            except ValueError:
                is_json = False
        evidence = {
            "issuer": issuer,
            "registration_endpoint": registration,
            "status": response.status_code,
            "content_type": content_type,
            "json": is_json,
            "body_preview": None if is_json else response.text[:200],
        }
        if not is_json:
            self.add(
                "dcr-probe",
                FAIL,
                f"registration returned {response.status_code} with a non-JSON body "
                f"({content_type!r}); clients cannot read the result",
                **evidence,
            )
        elif (
            response.status_code in (200, 201)
            and isinstance(document, dict)
            and document.get("client_id")
        ):
            self.add(
                "dcr-probe",
                PASS,
                f"registration accepted ({response.status_code}, JSON with client_id)",
                client_id_issued=True,
                token_endpoint_auth_method=document.get("token_endpoint_auth_method"),
                **evidence,
            )
        elif response.status_code in (200, 201):
            self.add(
                "dcr-probe",
                FAIL,
                f"registration returned {response.status_code} but no client_id in the JSON",
                **evidence,
            )
        else:
            error = document.get("error") if isinstance(document, dict) else None
            description = document.get("error_description") if isinstance(document, dict) else None
            self.add(
                "dcr-probe",
                FAIL,
                f"registration rejected with {response.status_code}: {error or 'no error code'}"
                + (f" ({description})" if description else ""),
                error=error,
                error_description=description,
                **evidence,
            )

    # ---- step 6: token endpoint error format -------------------------------------------

    def step_token_error(self, issuer: str, md: dict[str, Any]) -> None:
        token_endpoint = md.get("token_endpoint")
        if not is_http_url(token_endpoint):
            self.add("token-error-json", SKIP, "no usable token_endpoint", issuer=issuer)
            return
        form = {
            "grant_type": "authorization_code",
            "code": "mcp-auth-doctor-invalid-code",
            "redirect_uri": PROBE_REDIRECT_URI,
            "client_id": self.options.client_id or "mcp-auth-doctor",
            "code_verifier": secrets.token_urlsafe(32),
            "resource": self.url,
        }
        try:
            response = self.client.post(
                token_endpoint, data=form, headers={"Accept": "application/json"}
            )
        except (httpx.HTTPError, ValueError) as exc:
            self.add(
                "token-error-json",
                FAIL,
                f"token request failed: {describe(exc)}",
                issuer=issuer,
                token_endpoint=token_endpoint,
            )
            return
        content_type = response.headers.get("content-type")
        evidence: dict[str, Any] = {
            "issuer": issuer,
            "token_endpoint": token_endpoint,
            "status": response.status_code,
            "content_type": content_type,
        }
        if response.status_code == 200:
            self.add(
                "token-error-json",
                FAIL,
                "token endpoint returned 200 for an invalid authorization code",
                **evidence,
            )
            return
        if response.status_code >= 500:
            self.add(
                "token-error-json",
                FAIL,
                f"token endpoint returned {response.status_code} for an invalid code "
                "(expected 400 with a JSON error)",
                body_preview=response.text[:200],
                **evidence,
            )
            return
        if not is_json_content_type(content_type):
            self.add(
                "token-error-json",
                FAIL,
                f"token endpoint error response is {content_type!r}, not application/json "
                "(RFC 6749 section 5.2); SDK clients fail to parse the error and the success body "
                "is probably form-encoded too",
                body_preview=response.text[:200],
                **evidence,
            )
            return
        try:
            document = response.json()
        except ValueError:
            self.add(
                "token-error-json",
                FAIL,
                "token endpoint says application/json but the body is not valid JSON",
                body_preview=response.text[:200],
                **evidence,
            )
            return
        error = document.get("error") if isinstance(document, dict) else None
        if not error:
            self.add(
                "token-error-json",
                WARN,
                f"token endpoint returned {response.status_code} JSON without an `error` member",
                **evidence,
            )
            return
        self.add(
            "token-error-json",
            PASS,
            f"invalid token request refused with {response.status_code} application/json ({error})",
            error=error,
            **evidence,
        )

    # ---- step 7: optional login --------------------------------------------------------

    def step_login(self, prm: dict[str, Any], md: dict[str, Any]) -> None:
        from .login import run_login

        self.checks.extend(
            run_login(self.client, self.url, prm, md, self.options, self.challenge_scope)
        )

    # ---- helpers ------------------------------------------------------------------------

    def fetch_json(self, url: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        """GET a metadata document. Returns (document or None, attempt record)."""
        attempt: dict[str, Any] = {"url": url}
        try:
            response = self.client.get(
                url, headers={"Accept": "application/json"}, follow_redirects=True
            )
        except (httpx.HTTPError, ValueError) as exc:
            attempt["error"] = describe(exc)
            return None, attempt
        attempt["status"] = response.status_code
        content_type = response.headers.get("content-type")
        attempt["content_type"] = content_type
        if str(response.url) != url:
            attempt["final_url"] = str(response.url)
        if response.status_code != 200:
            return None, attempt
        try:
            document = response.json()
        except ValueError:
            attempt["error"] = "body is not JSON"
            return None, attempt
        if not isinstance(document, dict):
            attempt["error"] = "body is not a JSON object"
            return None, attempt
        attempt["json_content_type"] = is_json_content_type(content_type)
        return document, attempt


_UNREACHABLE = object()


def is_http_url(value: Any) -> bool:
    return isinstance(value, str) and value.lower().startswith(("https://", "http://"))


def describe(exc: Exception) -> str:
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__
