"""--record and --replay: save a run's exchanges and reproduce the report offline."""

from __future__ import annotations

import io
import json
import random
import sys

import httpx
import pytest

from mcp_auth_doctor.checks import Options, diagnose
from mcp_auth_doctor.cli import main
from mcp_auth_doctor.exchanges import (
    FORMAT,
    REDACTED,
    ExchangeFileError,
    RecordingTransport,
    ReplayTransport,
    load,
)

MCP = "https://mcp.example.com/mcp"
AS = "https://auth.example.com"
PRM = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"


def _server(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if request.method == "POST" and url == MCP:
        return httpx.Response(
            401, headers={"www-authenticate": f'Bearer resource_metadata="{PRM}"'}
        )
    if url == PRM:
        return httpx.Response(200, json={"resource": MCP + "/", "authorization_servers": [AS]})
    if url == AS + "/.well-known/oauth-authorization-server":
        return httpx.Response(
            200,
            json={
                "issuer": AS,
                "authorization_endpoint": AS + "/authorize",
                "token_endpoint": AS + "/token",
                "registration_endpoint": AS + "/register",
            },
        )
    if url == AS + "/register":
        return httpx.Response(201, json={"client_id": "abc", "client_secret": "s3cr3t"})
    if url == AS + "/token":
        return httpx.Response(400, json={"error": "invalid_grant"})
    return httpx.Response(404)


def _record() -> tuple[RecordingTransport, object]:
    recorder = RecordingTransport(httpx.MockTransport(_server))
    with httpx.Client(transport=recorder) as client:
        report = diagnose(MCP, Options(dcr_probe=True), client=client)
    return recorder, report


def _statuses(report) -> list[tuple[str, str]]:
    return [(c.id, c.status) for c in report.checks]


def test_replay_reproduces_the_recorded_report(tmp_path) -> None:
    recorder, live = _record()
    path = tmp_path / "run.json"
    recorder.write(str(path), MCP)
    url, exchanges = load(str(path))
    assert url == MCP
    with httpx.Client(transport=ReplayTransport(exchanges)) as client:
        replayed = diagnose(url, Options(dcr_probe=True), client=client)
    assert _statuses(replayed) == _statuses(live)
    assert ("prm-resource", "fail") in _statuses(replayed)


def test_secrets_in_bodies_are_redacted(tmp_path) -> None:
    recorder, _ = _record()
    path = tmp_path / "run.json"
    recorder.write(str(path), MCP)
    text = path.read_text()
    assert "s3cr3t" not in text
    registration = next(e for e in json.loads(text)["exchanges"] if e["url"].endswith("/register"))
    assert json.loads(registration["body"])["client_secret"] == REDACTED


def test_request_headers_are_never_written(tmp_path) -> None:
    recorder = RecordingTransport(httpx.MockTransport(_server))
    with httpx.Client(transport=recorder) as client:
        diagnose(MCP, Options(headers={"x-api-key": "do-not-save"}), client=client)
    path = tmp_path / "run.json"
    recorder.write(str(path), MCP)
    assert "do-not-save" not in path.read_text()


def test_unrecorded_request_is_a_connection_error() -> None:
    with httpx.Client(transport=ReplayTransport([])) as client:
        report = diagnose(MCP, Options(), client=client)
    assert report.exit_code == 2
    assert report.checks[0].status == "fail"
    assert "not in the replay file" in report.checks[0].reason


def test_cli_replay_without_a_url(tmp_path, capsys) -> None:
    recorder, _ = _record()
    path = tmp_path / "run.json"
    recorder.write(str(path), MCP)
    assert main(["--replay", str(path), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["url"] == MCP


@pytest.mark.parametrize(
    "args, message",
    [
        (["--replay", "a.json", "--record", "b.json"], "cannot be combined"),
        (["--replay", "a.json", "--login"], "--login cannot be combined"),
        (["--record", "b.json", "--login", MCP], "--login cannot be combined"),
        ([], "required: url"),
    ],
)
def test_cli_option_conflicts(args, message, capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    assert exit_info.value.code == 3
    assert message in capsys.readouterr().err


def test_cli_replay_url_must_match(tmp_path, capsys) -> None:
    recorder, _ = _record()
    path = tmp_path / "run.json"
    recorder.write(str(path), MCP)
    with pytest.raises(SystemExit):
        main(["--replay", str(path), "https://other.example/mcp"])
    assert "was recorded for" in capsys.readouterr().err


@pytest.mark.parametrize(
    "content, message",
    [
        (b"\xff\xfe\x00", "not UTF-8"),
        (b"", "not JSON"),
        (b"[" * 100_000, "nested too deeply"),
        (b"[]", "not an exchanges file"),
        (json.dumps({"format": FORMAT, "url": 1, "exchanges": []}).encode(), "string `url`"),
        (
            json.dumps({"format": FORMAT, "url": MCP, "exchanges": [{"method": "GET"}]}).encode(),
            "exchanges[0]",
        ),
    ],
)
def test_bad_replay_files_name_the_file(tmp_path, content, message, capsys) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(content)
    assert main(["--replay", str(path)]) == 3
    err = capsys.readouterr().err
    assert str(path) in err
    assert message in err


def test_missing_replay_file(tmp_path, capsys) -> None:
    assert main(["--replay", str(tmp_path / "nope.json")]) == 3
    assert "nope.json" in capsys.readouterr().err


def test_replay_from_stdin_matches_the_file(tmp_path, monkeypatch, capsys) -> None:
    recorder, _ = _record()
    path = tmp_path / "run.json"
    recorder.write(str(path), MCP)
    assert main(["--replay", str(path), "--json"]) == 1
    from_file = json.loads(capsys.readouterr().out)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(path.read_bytes())))
    assert main(["--replay", "-", "--json"]) == 1
    from_stdin = json.loads(capsys.readouterr().out)
    assert from_stdin["url"] == from_file["url"]
    assert [(c["id"], c["status"]) for c in from_stdin["checks"]] == [
        (c["id"], c["status"]) for c in from_file["checks"]
    ]


def test_stdin_replay_errors_name_stdin(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"not json")))
    assert main(["--replay", "-"]) == 3
    err = capsys.readouterr().err
    assert "<stdin>" in err
    assert "not JSON" in err


def test_fuzzed_replay_files_never_raise_anything_else(tmp_path) -> None:
    rng = random.Random(8414)
    values = [None, True, 0, 200, 999, "", "GET", MCP, [], {}, {"a": "b"}, {"a": 1}, "\udcff"]
    path = tmp_path / "fuzz.json"
    for _ in range(500):
        exchange = {
            k: rng.choice(values)
            for k in ("method", "url", "status", "headers", "body")
            if rng.random() < 0.9
        }
        document = {"format": FORMAT, "url": rng.choice([MCP, 1, None]), "exchanges": [exchange]}
        path.write_text(json.dumps(document))
        try:
            url, exchanges = load(str(path))
        except ExchangeFileError:
            continue
        with httpx.Client(transport=ReplayTransport(exchanges)) as client:
            diagnose(url, Options(), client=client)
