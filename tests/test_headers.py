"""Extra headers stay on MCP requests, including the authenticated session."""

import json

import httpx
import pytest

from mcp_auth_doctor.checks import WARN, Options, diagnose
from mcp_auth_doctor.cli import main
from mcp_auth_doctor.mcpclient import mcp_headers
from tests.conftest import AS, MCP, by_id, mount
from tests.test_login import drive_login


def test_cli_repeatable_headers_are_confined_to_mcp(router, capsys):
    mount(router)
    assert (
        main(
            [
                MCP,
                "-H",
                "X-Tenant: old",
                "--header",
                "x-tenant: demo",
                "-H",
                "X-Trace: a:b",
                "--dcr-probe",
                "--json",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert json.loads(output)["summary"]["exit_code"] == 0
    assert "X-Tenant" not in output and "demo" not in output
    for call in router.calls:
        headers = call.request.headers
        if str(call.request.url) == MCP:
            assert headers["x-tenant"] == "demo"
            assert headers["x-trace"] == "a:b"
        else:
            assert "x-tenant" not in headers and "x-trace" not in headers
    assert any(str(c.request.url) == f"{AS}/register" for c in router.calls)


def test_headers_are_sent_on_authenticated_mcp_requests_only(router):
    report, _ = drive_login(router, options=Options(headers={"X-Tenant": "demo"}))
    assert by_id(report, "login-tools-list").status == "pass"
    authenticated = []
    for call in router.calls:
        request = call.request
        if str(request.url) == MCP:
            assert request.headers["x-tenant"] == "demo"
            if request.headers.get("authorization"):
                authenticated.append(json.loads(request.content)["method"])
        else:
            assert "x-tenant" not in request.headers
    assert authenticated == ["initialize", "notifications/initialized", "tools/list"]


@pytest.mark.parametrize("status", [200, 401])
def test_authorization_override_does_not_claim_an_unauthenticated_probe(router, status):
    mount(router, unauth_status=status)
    report = diagnose(MCP, Options(headers={"aUtHoRiZaTiOn": "Bearer synthetic"}))
    check = by_id(report, "unauth-401")
    assert check.status == WARN
    assert "Authorization" in check.reason
    assert "synthetic" not in json.dumps(report.to_dict())


def test_cli_warns_about_authorization_without_echoing_it(router, capsys):
    mount(router)
    assert main([MCP, "-H", "Authorization: Bearer synthetic", "--json"]) == 0
    captured = capsys.readouterr()
    assert "Authorization" in captured.err
    assert "synthetic" not in captured.out + captured.err


@pytest.mark.parametrize(
    "header",
    [
        "no-colon",
        ": value",
        "Bad Name: value",
        "X-Test: first\r\nInjected: bad",
        "X-Test: \x00",
        "X-Test: café",
    ],
)
def test_invalid_header_is_a_usage_error_without_network_or_value_echo(router, capsys, header):
    with pytest.raises(SystemExit) as exc:
        main([MCP, "-H", header])
    assert exc.value.code == 3
    assert len(router.calls) == 0
    assert header not in capsys.readouterr().err


def test_mcp_protocol_and_session_headers_take_precedence():
    headers = httpx.Headers(
        mcp_headers(
            "2026-07-28",
            "real-token",
            "real-session",
            extra_headers={
                "accept": "wrong",
                "content-type": "wrong",
                "mcp-protocol-version": "wrong",
                "mcp-session-id": "wrong",
                "authorization": "Bearer override",
                "X-Tenant": "demo",
            },
        )
    )
    assert headers["accept"] == "application/json, text/event-stream"
    assert headers["content-type"] == "application/json"
    assert headers["mcp-protocol-version"] == "2026-07-28"
    assert headers["mcp-session-id"] == "real-session"
    assert headers["authorization"] == "Bearer real-token"
    assert headers["x-tenant"] == "demo"
