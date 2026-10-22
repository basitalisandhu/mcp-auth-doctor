"""Opt-in `--login`: a full OAuth 2.1 authorization code flow with PKCE and a loopback
callback, then one authenticated `tools/list` call.

This is the only part of the tool that creates state on the server side (a client
registration when no --client-id is given, and an access token). It runs only when the
user passes --login.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from . import __version__
from .checks import FAIL, PASS, SKIP, Check, Options, describe
from .discovery import is_json_content_type
from .mcpclient import initialize_request, mcp_headers, parse_jsonrpc_response, tools_list_request

CALLBACK_PATH = "/callback"


class _Callback:
    def __init__(self) -> None:
        self.params: dict[str, str] | None = None
        self.event = threading.Event()


class _Handler(BaseHTTPRequestHandler):
    callback: _Callback

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        if parts.path != CALLBACK_PATH:
            self.send_response(404)
            self.end_headers()
            return
        self.callback.params = {k: v[0] for k, v in parse_qs(parts.query).items()}
        self.callback.event.set()
        body = b"mcp-auth-doctor: authorization response received, you can close this tab."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def run_login(
    client: httpx.Client,
    url: str,
    prm: dict[str, Any],
    md: dict[str, Any],
    options: Options,
    challenge_scope: str | None = None,
) -> list[Check]:
    checks: list[Check] = []
    issuer = md.get("issuer") or ""
    authorization_endpoint = md.get("authorization_endpoint")
    token_endpoint = md.get("token_endpoint")
    if not authorization_endpoint or not token_endpoint:
        checks.append(
            Check(
                "login-token",
                SKIP,
                "no authorization_endpoint or token_endpoint",
                {"issuer": issuer},
            )
        )
        checks.append(Check("login-tools-list", SKIP, "no token", {}))
        return checks

    callback = _Callback()
    handler = type("Handler", (_Handler,), {"callback": callback})
    try:
        server = HTTPServer(("127.0.0.1", options.callback_port), handler)
    except OSError as exc:
        checks.append(
            Check(
                "login-token",
                FAIL,
                f"cannot listen for the authorization callback on 127.0.0.1 port "
                f"{options.callback_port}: {describe(exc)}; free the port or choose another "
                "with --callback-port",
                {"issuer": issuer, "callback_port": options.callback_port},
            )
        )
        checks.append(Check("login-tools-list", SKIP, "no token", {}))
        return checks
    port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}{CALLBACK_PATH}"

    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    )
    thread.start()
    try:
        client_id = options.client_id
        registered: dict[str, Any] = {}
        if not client_id:
            registration = md.get("registration_endpoint")
            if not registration:
                checks.append(
                    Check(
                        "login-token",
                        FAIL,
                        "no --client-id given and the authorization server has no "
                        "registration_endpoint; pass a pre-registered client id",
                        {"issuer": issuer},
                    )
                )
                checks.append(Check("login-tools-list", SKIP, "no token", {}))
                return checks
            registered = _register(client, registration, redirect_uri)
            if "error" in registered:
                checks.append(
                    Check(
                        "login-token",
                        FAIL,
                        f"dynamic client registration failed: {registered['error']}",
                        {"issuer": issuer, "registration_endpoint": registration},
                    )
                )
                checks.append(Check("login-tools-list", SKIP, "no token", {}))
                return checks
            client_id = registered["client_id"]

        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(16)
        scope = challenge_scope
        if not scope and isinstance(prm.get("scopes_supported"), list):
            scope = " ".join(str(s) for s in prm["scopes_supported"]) or None
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "resource": url,
        }
        if scope:
            params["scope"] = scope
        separator = "&" if "?" in authorization_endpoint else "?"
        auth_url = f"{authorization_endpoint}{separator}{urlencode(params)}"
        (options.open_browser or _open_browser)(auth_url)

        if not callback.event.wait(options.login_timeout):
            checks.append(
                Check(
                    "login-token",
                    FAIL,
                    f"no authorization response within {options.login_timeout:.0f}s",
                    {"issuer": issuer, "redirect_uri": redirect_uri},
                )
            )
            checks.append(Check("login-tools-list", SKIP, "no token", {}))
            return checks
        response_params = callback.params or {}
        evidence: dict[str, Any] = {
            "issuer": issuer,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        }

        if response_params.get("state") != state:
            checks.append(
                Check(
                    "login-token", FAIL, "authorization response `state` does not match", evidence
                )
            )
            checks.append(Check("login-tools-list", SKIP, "no token", {}))
            return checks

        iss_problem = _check_iss(md, response_params, options.spec)
        if iss_problem:
            checks.append(
                Check(
                    "login-token",
                    FAIL,
                    iss_problem,
                    {**evidence, "iss": response_params.get("iss")},
                )
            )
            checks.append(Check("login-tools-list", SKIP, "no token", {}))
            return checks

        if "error" in response_params:
            checks.append(
                Check(
                    "login-token",
                    FAIL,
                    f"authorization server returned error {response_params['error']!r}"
                    + (
                        f": {response_params['error_description']}"
                        if response_params.get("error_description")
                        else ""
                    ),
                    evidence,
                )
            )
            checks.append(Check("login-tools-list", SKIP, "no token", {}))
            return checks
        code = response_params.get("code")
        if not code:
            checks.append(
                Check("login-token", FAIL, "authorization response has no `code`", evidence)
            )
            checks.append(Check("login-tools-list", SKIP, "no token", {}))
            return checks

        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": url,
        }
        if registered.get("client_secret"):
            form["client_secret"] = registered["client_secret"]
        try:
            token_response = client.post(
                token_endpoint, data=form, headers={"Accept": "application/json"}
            )
        except (httpx.HTTPError, ValueError) as exc:
            checks.append(
                Check("login-token", FAIL, f"token request failed: {describe(exc)}", evidence)
            )
            checks.append(Check("login-tools-list", SKIP, "no token", {}))
            return checks
        content_type = token_response.headers.get("content-type")
        evidence["token_status"] = token_response.status_code
        evidence["token_content_type"] = content_type
        token: dict[str, Any] | None = None
        if is_json_content_type(content_type):
            try:
                token = token_response.json()
            except ValueError:
                token = None
        if (
            token_response.status_code != 200
            or not isinstance(token, dict)
            or not token.get("access_token")
        ):
            problem = (
                f"token endpoint returned {token_response.status_code} with {content_type!r}"
                if not is_json_content_type(content_type)
                else f"token endpoint returned {token_response.status_code}: "
                + (str((token or {}).get("error", "no access_token")))
            )
            checks.append(
                Check(
                    "login-token",
                    FAIL,
                    problem,
                    {**evidence, "body_preview": token_response.text[:200]},
                )
            )
            checks.append(Check("login-tools-list", SKIP, "no token", {}))
            return checks
        evidence.update(
            {
                "token_type": token.get("token_type"),
                "expires_in": token.get("expires_in"),
                "scope": token.get("scope"),
                "refresh_token": bool(token.get("refresh_token")),
                "iss_validated": "iss" in response_params,
            }
        )
        checks.append(
            Check(
                "login-token",
                PASS,
                "authorization code redeemed with PKCE and the `resource` parameter",
                evidence,
            )
        )
        checks.append(
            _tools_list(client, url, str(token["access_token"]), options.spec, options.headers)
        )
        return checks
    finally:
        server.shutdown()
        server.server_close()


def _register(
    client: httpx.Client, registration_endpoint: str, redirect_uri: str
) -> dict[str, Any]:
    body = {
        "client_name": "mcp-auth-doctor",
        "client_uri": "https://github.com/basitalisandhu/mcp-auth-doctor",
        "software_id": "mcp-auth-doctor",
        "software_version": __version__,
        "application_type": "native",
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }
    try:
        response = client.post(
            registration_endpoint, json=body, headers={"Accept": "application/json"}
        )
    except (httpx.HTTPError, ValueError) as exc:
        return {"error": describe(exc)}
    try:
        document = response.json()
    except ValueError:
        return {"error": f"{response.status_code} with a non-JSON body"}
    if (
        response.status_code not in (200, 201)
        or not isinstance(document, dict)
        or not document.get("client_id")
    ):
        error = document.get("error") if isinstance(document, dict) else None
        return {"error": f"{response.status_code} {error or 'without client_id'}"}
    return document


def _check_iss(md: dict[str, Any], params: dict[str, str], spec: str) -> str | None:
    """RFC 9207 validation as the MCP spec tables it. Returns a problem or None."""
    supported = md.get("authorization_response_iss_parameter_supported") is True
    iss = params.get("iss")
    expected = md.get("issuer")
    if iss is not None:
        if iss != expected:
            return (
                f"`iss` {iss!r} does not match the recorded issuer {expected!r} (RFC 9207); "
                "possible mix-up"
            )
        return None
    if supported and spec == "2026-07-28":
        return (
            "metadata advertises authorization_response_iss_parameter_supported but the "
            "authorization response has no `iss`; clients MUST reject it"
        )
    return None


def _tools_list(
    client: httpx.Client,
    url: str,
    token: str,
    spec: str,
    extra_headers: dict[str, str] | None = None,
) -> Check:
    evidence: dict[str, Any] = {}
    try:
        init = client.post(
            url,
            json=initialize_request(spec, 1),
            headers=mcp_headers(spec, token, extra_headers=extra_headers),
        )
    except (httpx.HTTPError, ValueError) as exc:
        return Check(
            "login-tools-list", FAIL, f"initialize with the token failed: {describe(exc)}", evidence
        )
    evidence["initialize_status"] = init.status_code
    if init.status_code == 401:
        return Check(
            "login-tools-list",
            FAIL,
            "initialize with the token returned 401: the server does not accept its own "
            "authorization server's token (audience or issuer mismatch?)",
            {**evidence, "www_authenticate": init.headers.get("www-authenticate")},
        )
    if init.status_code >= 400:
        return Check(
            "login-tools-list",
            FAIL,
            f"initialize with the token returned {init.status_code}",
            {**evidence, "body_preview": init.text[:200]},
        )
    session = init.headers.get("mcp-session-id")
    headers = mcp_headers(spec, token, session, extra_headers=extra_headers)
    try:
        client.post(
            url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers
        )
        listed = client.post(url, json=tools_list_request(2), headers=headers)
    except (httpx.HTTPError, ValueError) as exc:
        return Check("login-tools-list", FAIL, f"tools/list failed: {describe(exc)}", evidence)
    evidence["tools_list_status"] = listed.status_code
    if listed.status_code >= 400:
        return Check(
            "login-tools-list",
            FAIL,
            f"tools/list returned {listed.status_code}",
            {**evidence, "body_preview": listed.text[:200]},
        )
    message = parse_jsonrpc_response(listed, 2)
    if not message:
        return Check(
            "login-tools-list",
            FAIL,
            "tools/list reply could not be parsed as JSON-RPC",
            {**evidence, "body_preview": listed.text[:200]},
        )
    if "error" in message:
        return Check(
            "login-tools-list",
            FAIL,
            f"tools/list returned JSON-RPC error: {message['error']}",
            evidence,
        )
    result = message.get("result")
    tools = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(tools, list):
        return Check(
            "login-tools-list",
            FAIL,
            "tools/list reply has no `result.tools` list",
            {**evidence, "body_preview": listed.text[:200]},
        )
    names = [t.get("name") for t in tools if isinstance(t, dict)][:10]
    return Check(
        "login-tools-list",
        PASS,
        f"tools/list returned {len(tools)} tool(s) with the bearer token",
        {**evidence, "tool_count": len(tools), "tools": names},
    )


def _open_browser(url: str) -> None:
    import sys

    print(f"Open this URL to authorize:\n  {url}", file=sys.stderr)
    with contextlib.suppress(Exception):
        webbrowser.open(url)
