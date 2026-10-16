"""--login end to end: the browser is replaced by a hook that captures the authorization
URL, and the test itself plays the authorization server's redirect by calling the loopback
callback with urllib (which respx does not intercept)."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.request
from urllib.parse import parse_qs, urlsplit

import httpx

from mcp_auth_doctor.checks import FAIL, PASS, SKIP, Options, diagnose
from tests.conftest import AS, MCP, as_metadata, by_id, form, mount


def mcp_handler_factory(token: str, sse: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != f"Bearer {token}":
            return httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer resource_metadata="https://mcp.example.com/.well-known/'
                        'oauth-protected-resource/mcp", scope="mcp:read"'
                    )
                },
            )
        body = json.loads(request.content)
        method = body.get("method")
        if method == "initialize":
            return httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2026-07-28"}},
                headers={"Mcp-Session-Id": "sess-1"},
            )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            assert request.headers.get("mcp-session-id") == "sess-1"
            result = {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"tools": [{"name": "alpha"}, {"name": "beta"}]},
            }
            if sse:
                return httpx.Response(
                    200,
                    content=f"event: message\ndata: {json.dumps(result)}\n\n",
                    headers={"Content-Type": "text/event-stream"},
                )
            return httpx.Response(200, json=result)
        return httpx.Response(400)

    return handler


def token_handler_factory(expected_code: str, challenge_holder: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        data = form(request)
        if data.get("code") != expected_code:
            return httpx.Response(400, json={"error": "invalid_grant"})
        digest = hashlib.sha256(data["code_verifier"].encode()).digest()
        assert (
            base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            == challenge_holder["code_challenge"]
        )
        assert data["resource"] == MCP
        assert data["redirect_uri"] == challenge_holder["redirect_uri"]
        assert data["client_id"] == challenge_holder["client_id"]
        return httpx.Response(
            200,
            json={
                "access_token": "tok-1",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "r",
            },
        )

    return handler


def drive_login(
    router,
    *,
    iss: str | None = AS,
    state_override: str | None = None,
    sse: bool = False,
    options: Options | None = None,
    error: str | None = None,
):
    captured: dict = {}

    def opener(url: str) -> None:
        captured["url"] = url

    options = options or Options()
    options.login = True
    options.open_browser = opener
    options.login_timeout = 10
    holder: dict = {}
    mount(router, mcp_handler=mcp_handler_factory("tok-1", sse=sse))
    router.post(f"{AS}/token").mock(side_effect=token_handler_factory("good-code", holder))

    result: dict = {}

    def run() -> None:
        result["report"] = diagnose(MCP, options)

    thread = threading.Thread(target=run)
    thread.start()
    deadline = time.time() + 10
    while "url" not in captured and time.time() < deadline:
        time.sleep(0.02)
    assert "url" in captured, "login never opened the authorization URL"
    params = {k: v[0] for k, v in parse_qs(urlsplit(captured["url"]).query).items()}
    holder.update(
        {
            "code_challenge": params["code_challenge"],
            "redirect_uri": params["redirect_uri"],
            "client_id": params["client_id"],
        }
    )
    assert params["code_challenge_method"] == "S256"
    assert params["resource"] == MCP
    assert params["scope"] == "mcp:read"
    query = {"state": state_override or params["state"]}
    if error:
        query["error"] = error
    else:
        query["code"] = "good-code"
    if iss is not None:
        query["iss"] = iss
    from urllib.parse import urlencode

    with urllib.request.urlopen(params["redirect_uri"] + "?" + urlencode(query), timeout=5) as resp:
        assert resp.status == 200
    thread.join(timeout=10)
    assert not thread.is_alive()
    return result["report"], params


def test_login_happy_path_registers_and_lists_tools(router):
    report, params = drive_login(router)
    token = by_id(report, "login-token")
    assert token.status == PASS, token.reason
    assert token.evidence["client_id"] == "abc"
    assert token.evidence["iss_validated"] is True
    assert token.evidence["refresh_token"] is True
    assert "access_token" not in json.dumps(token.evidence)
    tools = by_id(report, "login-tools-list")
    assert tools.status == PASS and tools.evidence["tool_count"] == 2
    assert report.exit_code == 0
    registration = json.loads(router.post(f"{AS}/register").calls.last.request.content)
    assert registration["application_type"] == "native"
    assert registration["redirect_uris"] == [params["redirect_uri"]]


def test_login_with_sse_tools_list_and_preregistered_client(router):
    report, params = drive_login(router, sse=True, options=Options(client_id="my-client"))
    assert params["client_id"] == "my-client"
    assert not router.post(f"{AS}/register").called
    assert by_id(report, "login-tools-list").status == PASS


def test_login_iss_mismatch_fails_before_token_exchange(router):
    report, _ = drive_login(router, iss="https://evil.example")
    check = by_id(report, "login-token")
    assert check.status == FAIL and "mix-up" in check.reason
    assert not router.post(f"{AS}/token").calls.last.request.content.startswith(
        b"grant_type=authorization_code&code=good-code"
    )
    assert by_id(report, "login-tools-list").status == SKIP


def test_login_missing_iss_rejected_under_2026_rules_only(router):
    report, _ = drive_login(router, iss=None)
    assert by_id(report, "login-token").status == FAIL
    assert "no `iss`" in by_id(report, "login-token").reason
    router.reset()
    report, _ = drive_login(router, iss=None, options=Options(spec="2025-11-25"))
    assert by_id(report, "login-token").status == PASS


def test_login_state_mismatch_and_error_response(router):
    report, _ = drive_login(router, state_override="wrong")
    assert "state" in by_id(report, "login-token").reason
    router.reset()
    report, _ = drive_login(router, error="access_denied")
    assert "access_denied" in by_id(report, "login-token").reason


def test_login_without_client_id_or_registration_fails(router):
    mount(router, metadata={AS: as_metadata(registration_endpoint=None)})
    report = diagnose(MCP, Options(login=True, open_browser=lambda url: None, login_timeout=1))
    check = by_id(report, "login-token")
    assert check.status == FAIL and "--client-id" in check.reason
    assert by_id(report, "login-tools-list").status == SKIP


def test_login_skipped_by_default(router):
    mount(router)
    report = diagnose(MCP)
    assert by_id(report, "login-token").status == SKIP
    assert "--login" in by_id(report, "login-token").reason


def _login_options(**overrides) -> Options:
    options = Options(login=True, open_browser=lambda url: None, login_timeout=0.3)
    for key, value in overrides.items():
        setattr(options, key, value)
    return options


def test_login_reports_a_busy_callback_port_instead_of_crashing(router):
    import socket

    mount(router)
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        report = diagnose(MCP, _login_options(callback_port=port))
    check = by_id(report, "login-token")
    assert check.status == FAIL
    assert f"port {port}" in check.reason and "--callback-port" in check.reason
    assert by_id(report, "login-tools-list").status == SKIP


def test_login_times_out_without_a_callback(router):
    mount(router)
    report = diagnose(MCP, _login_options())
    check = by_id(report, "login-token")
    assert check.status == FAIL and "no authorization response" in check.reason


def test_login_registration_failures_are_named(router):
    mount(router, dcr=(422, "text/html", "<html>nope</html>"))
    reason = by_id(diagnose(MCP, _login_options()), "login-token").reason
    assert "dynamic client registration failed: 422 with a non-JSON body" in reason
    router.reset()
    mount(router, dcr=(400, "application/json", '{"error":"invalid_redirect_uri"}'))
    reason = by_id(diagnose(MCP, _login_options()), "login-token").reason
    assert reason.endswith("400 invalid_redirect_uri")
    router.reset()
    mount(router, dcr=(201, "application/json", '{"client_name":"x"}'))
    reason = by_id(diagnose(MCP, _login_options()), "login-token").reason
    assert reason.endswith("201 without client_id")


def _token_failure(router, response: httpx.Response):
    mount(router, mcp_handler=mcp_handler_factory("tok-1"))
    router.post(f"{AS}/token").mock(return_value=response)
    return _drive_callback(router, {"code": "good-code", "iss": AS})


def _drive_callback(router, query: dict, options: Options | None = None):
    """Run diagnose with --login, answer the callback with `query` plus the right state."""
    from urllib.parse import urlencode

    captured: dict = {}
    options = options or Options()
    options.login = True
    options.open_browser = lambda url: captured.__setitem__("url", url)
    options.login_timeout = 10
    result: dict = {}
    thread = threading.Thread(target=lambda: result.__setitem__("report", diagnose(MCP, options)))
    thread.start()
    deadline = time.time() + 10
    while "url" not in captured and time.time() < deadline:
        time.sleep(0.02)
    params = {k: v[0] for k, v in parse_qs(urlsplit(captured["url"]).query).items()}
    full = {"state": params["state"], **query}
    with urllib.request.urlopen(params["redirect_uri"] + "?" + urlencode(full), timeout=5):
        pass
    thread.join(timeout=10)
    return result["report"]


def test_login_token_endpoint_failures(router):
    report = _token_failure(
        router,
        httpx.Response(200, content="access_token=x", headers={"Content-Type": "text/plain"}),
    )
    check = by_id(report, "login-token")
    assert check.status == FAIL and "returned 200 with 'text/plain'" in check.reason
    assert check.evidence["body_preview"] == "access_token=x"
    router.reset()
    report = _token_failure(router, httpx.Response(400, json={"error": "invalid_grant"}))
    assert by_id(report, "login-token").reason == "token endpoint returned 400: invalid_grant"
    router.reset()
    report = _token_failure(router, httpx.Response(200, json={"token_type": "Bearer"}))
    assert by_id(report, "login-token").reason == "token endpoint returned 200: no access_token"


def test_login_without_code_fails(router):
    mount(router)
    report = _drive_callback(router, {"iss": AS})
    assert by_id(report, "login-token").reason == "authorization response has no `code`"


def _tools_list_failure(router, handler):
    mount(router, mcp_handler=handler)
    router.post(f"{AS}/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok-1", "token_type": "Bearer"})
    )
    report = _drive_callback(router, {"code": "c", "iss": AS})
    assert by_id(report, "login-token").status == PASS
    return by_id(report, "login-tools-list")


def _authed(respond):
    good = mcp_handler_factory("tok-1")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != "Bearer tok-1":
            return good(request)
        return respond(json.loads(request.content).get("method"), good, request)

    return handler


def test_login_tools_list_failures_are_named(router):
    check = _tools_list_failure(
        router,
        _authed(
            lambda method, good, req: httpx.Response(
                401, headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
            )
        ),
    )
    assert check.status == FAIL and "does not accept its own" in check.reason
    assert check.evidence["www_authenticate"] == 'Bearer error="invalid_token"'

    router.reset()
    check = _tools_list_failure(
        router, _authed(lambda method, good, req: httpx.Response(500, text="boom"))
    )
    assert check.reason == "initialize with the token returned 500"

    def tools_status(status, **kwargs):
        def respond(method, good, req):
            return httpx.Response(status, **kwargs) if method == "tools/list" else good(req)

        return respond

    router.reset()
    check = _tools_list_failure(router, _authed(tools_status(403, text="denied")))
    assert check.reason == "tools/list returned 403"
    router.reset()
    check = _tools_list_failure(router, _authed(tools_status(200, text="not json")))
    assert check.reason == "tools/list reply could not be parsed as JSON-RPC"
    router.reset()
    error = {"jsonrpc": "2.0", "id": 2, "error": {"code": -32601, "message": "nope"}}
    check = _tools_list_failure(router, _authed(tools_status(200, json=error)))
    assert check.reason.startswith("tools/list returned JSON-RPC error")
    router.reset()
    odd = {"jsonrpc": "2.0", "id": 2, "result": ["alpha"]}
    check = _tools_list_failure(router, _authed(tools_status(200, json=odd)))
    assert check.reason == "tools/list reply has no `result.tools` list"
