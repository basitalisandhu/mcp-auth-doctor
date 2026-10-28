"""Seeded fuzz and scaling tests for everything that reads server input.

A misconfigured server can answer with anything: wrong JSON types, deep nesting,
non-UTF-8 bodies, URLs httpx cannot build a request for, odd WWW-Authenticate headers.
The tool must turn all of that into failed or skipped checks, never a traceback, and
never hang. Each case runs in a worker thread with a time limit so a hang fails the test
instead of stalling CI.
"""

from __future__ import annotations

import json
import random
import threading
import time
from typing import Any

import httpx
import pytest

from mcp_auth_doctor.checks import Options, diagnose
from mcp_auth_doctor.cli import main, printable
from mcp_auth_doctor.discovery import (
    canonical,
    issuer_matches,
    parse_www_authenticate,
)
from mcp_auth_doctor.report import render_json, render_markdown, render_table

MCP = "https://mcp.example.com/mcp"
AS = "https://auth.example.com"
PRM = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

KEYS = [
    "resource",
    "authorization_servers",
    "scopes_supported",
    "bearer_methods_supported",
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "response_types_supported",
    "code_challenge_methods_supported",
    "client_id_metadata_document_supported",
    "authorization_response_iss_parameter_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    "error",
    "error_description",
    "client_id",
]
STRINGS = [
    MCP,
    AS,
    AS + "/token",
    "http://evil.example",
    "https://[::1",
    "https://a.example:99999/x",
    "S256",
    "code",
    "\x00\udcff",
    "x" * 5000,
]
HEADERS = [
    f'Bearer resource_metadata="{PRM}"',
    "Bearer",
    "",
    "Bearer resource_metadata=",
    'Bearer scope="a b", error="invalid_token", resource_metadata="x"',
    ",,,,",
    "Bearer " + "a=b," * 2000,
    'Bearer resource_metadata="javascript:alert(1)"',
    'Basic realm="x", Bearer resource_metadata="https://[::1"',
]
RAW_BODIES = [
    b"",
    b"\xff\xfe\x00",
    b"[1,2]",
    b"null",
    b"[" * 5000,
    b'{"a":' * 3000 + b"1" + b"}" * 3000,
]
TIME_LIMIT = 60.0


def _value(rng: random.Random, depth: int = 0) -> Any:
    makers = [
        lambda: None,
        lambda: True,
        lambda: 0,
        lambda: -1.5,
        lambda: "",
        lambda: rng.choice(STRINGS),
        lambda: [],
        lambda: {},
        lambda: [AS, MCP],
        lambda: 2**70,
        lambda: [_value(rng, depth + 1) for _ in range(rng.randrange(4))],
        lambda: {rng.choice(KEYS): _value(rng, depth + 1) for _ in range(rng.randrange(4))},
    ]
    limit = len(makers) if depth < 3 else len(makers) - 2
    return makers[rng.randrange(limit)]()


def _body(rng: random.Random) -> bytes:
    if rng.random() < 0.1:
        return rng.choice(RAW_BODIES)
    document: dict[str, Any] = {
        "resource": MCP,
        "authorization_servers": [AS],
        "issuer": AS,
        "authorization_endpoint": AS + "/authorize",
        "token_endpoint": AS + "/token",
        "code_challenge_methods_supported": ["S256"],
    }
    for _ in range(rng.randrange(6)):
        document[rng.choice(KEYS)] = _value(rng)
    return json.dumps(document).encode()


def _transport(seed: int) -> httpx.MockTransport:
    rng = random.Random(seed)

    def handler(request: httpx.Request) -> httpx.Response:
        status = rng.choice([200, 200, 200, 401, 400, 404, 500, 302])
        headers = {
            "content-type": rng.choice(
                ["application/json", "text/html", "", "application/json; charset=utf-8"]
            )
        }
        if request.method == "POST" and str(request.url) == MCP:
            status = rng.choice([401, 401, 200, 403])
            headers["www-authenticate"] = rng.choice(HEADERS)
        if status == 302:
            headers["location"] = rng.choice(["/x", "http://[bad", "https://other.example/"])
        return httpx.Response(status, headers=headers, content=_body(rng))

    return httpx.MockTransport(handler)


def _within_limit(func, *args) -> Any:
    """Run func in a thread; fail if it raises or takes longer than TIME_LIMIT."""
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["value"] = func(*args)
        except BaseException as exc:  # pragma: no cover - reported below
            outcome["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(TIME_LIMIT)
    assert not worker.is_alive(), f"{func.__name__}{args} did not finish in {TIME_LIMIT}s"
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def _diagnose_and_render(seed: int) -> None:
    rng = random.Random(seed ^ 0x5EED)
    with httpx.Client(transport=_transport(seed)) as client:
        report = diagnose(MCP, Options(dcr_probe=rng.random() < 0.5), client=client)
    assert report.exit_code in (0, 1, 2)
    for text in (
        render_json(report),
        render_markdown(report, verbose=True),
        render_table(report, verbose=True),
    ):
        printable(text).encode("utf-8")


@pytest.mark.parametrize("block", range(4))
def test_diagnose_never_raises_on_hostile_servers(block: int) -> None:
    for seed in range(block * 100, block * 100 + 100):
        _within_limit(_diagnose_and_render, seed)


def test_www_authenticate_parser_never_raises() -> None:
    rng = random.Random(9110)
    alphabet = 'Bbearer =",\\ \t;resource_metadata:/x\x00é'
    for _ in range(2000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(80)))
        for challenge in parse_www_authenticate(text):
            assert challenge.scheme
            assert all(isinstance(v, str) for v in challenge.params.values())


def test_www_authenticate_parser_is_linear() -> None:
    # 150,000 challenges is about 1.7 MB. The old parser sliced the header for every
    # parameter, which made this take several seconds; matching at an offset is linear.
    header = ", ".join(f"S{i} a=b" for i in range(150_000))
    start = time.perf_counter()
    challenges = parse_www_authenticate(header)
    elapsed = time.perf_counter() - start
    assert len(challenges) == 150_000
    assert elapsed < 2.0, f"parsing took {elapsed:.2f}s"


def test_unbuildable_url_in_metadata_is_a_failed_check() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                401, headers={"www-authenticate": f'Bearer resource_metadata="{PRM}"'}
            )
        return httpx.Response(
            200, json={"resource": MCP, "authorization_servers": ["https://[::1"]}
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        report = diagnose(MCP, Options(), client=client)
    statuses = {c.id: c.status for c in report.checks}
    assert statuses["as-metadata"] == "fail"


def test_issuer_of_the_wrong_type_does_not_match() -> None:
    assert issuer_matches(AS, {"x": 1}) is False
    assert issuer_matches(AS, ["x"]) is False
    assert issuer_matches(AS, AS + "/") is True


def test_canonical_keeps_unparseable_urls_as_text() -> None:
    assert canonical("https://[::1") == "https://[::1"
    assert canonical("https://a.example:99999/x") == "https://a.example:99999/x"


def test_lone_surrogate_in_a_report_still_prints() -> None:
    assert printable("a\udcffb") == "a\\udcffb"


@pytest.mark.parametrize(
    "url",
    [
        "https://[::1/mcp",
        "https://h.example:99999/mcp",
        "https://h.example:abc/mcp",
        "https://h/a b",
    ],
)
def test_unparseable_url_is_a_usage_error(url: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([url]) == 3
    assert "error:" in capsys.readouterr().err
