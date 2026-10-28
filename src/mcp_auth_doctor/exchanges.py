"""Record a run's HTTP exchanges to a file and replay them later without a network.

`--record FILE` saves every request the tool made and the answer it got. `--replay FILE`
runs the same checks against that file instead of the server, so a failure someone
reports can be reproduced, attached to an issue or turned into a test fixture.

What is written: method, URL, status, the response content type, location and
WWW-Authenticate headers, and the response body as text. Request headers are not
written (extra `-H` headers may be credentials). JSON members that carry secrets
(client secrets, tokens) are replaced with "[redacted]". `--login` cannot be combined
with either option, so no real access token ever reaches the file.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import httpx

from . import __version__

FORMAT = "mcp-auth-doctor-exchanges/1"
KEPT_HEADERS = ("content-type", "location", "www-authenticate")
SECRET_KEYS = {
    "access_token",
    "client_secret",
    "id_token",
    "refresh_token",
    "registration_access_token",
}
REDACTED = "[redacted]"
MAX_FILE_BYTES = 50 * 1024 * 1024


class ExchangeFileError(ValueError):
    """The replay file cannot be used."""


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (REDACTED if isinstance(k, str) and k.lower() in SECRET_KEYS else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _body_text(response: httpx.Response) -> str:
    text = response.content.decode("utf-8", "backslashreplace")
    try:
        document = json.loads(text)
    except RecursionError:
        # Too deep to walk for secrets, so it is not written; the checks treat it as
        # "not JSON" either way.
        return "[body omitted: JSON nested too deeply to redact]"
    except ValueError:
        return text
    if isinstance(document, (dict, list)):
        try:
            redacted = _redact(document)
        except RecursionError:
            return "[body omitted: JSON nested too deeply to redact]"
        if redacted != document:
            return json.dumps(redacted)
    return text


class RecordingTransport(httpx.BaseTransport):
    """Forward requests to a real transport and keep a copy of every exchange."""

    def __init__(self, inner: httpx.BaseTransport | None = None) -> None:
        self.inner = inner or httpx.HTTPTransport()
        self.exchanges: list[dict[str, Any]] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self.inner.handle_request(request)
        response.read()
        self.exchanges.append(
            {
                "method": request.method,
                "url": str(request.url),
                "status": response.status_code,
                "headers": {k: response.headers[k] for k in KEPT_HEADERS if k in response.headers},
                "body": _body_text(response),
            }
        )
        return response

    def close(self) -> None:
        self.inner.close()

    def write(self, path: str, mcp_url: str) -> None:
        document = {
            "format": FORMAT,
            "tool": f"mcp-auth-doctor {__version__}",
            "url": mcp_url,
            "exchanges": self.exchanges,
        }
        Path(path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


class ReplayTransport(httpx.BaseTransport):
    """Answer each request with the next recorded exchange for the same method and URL.

    A request that was not recorded fails as a connection error, which the checks report
    the same way as an unreachable server.
    """

    def __init__(self, exchanges: list[dict[str, Any]]) -> None:
        self.queues: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)
        for exchange in exchanges:
            self.queues[(exchange["method"], exchange["url"])].append(exchange)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        queue = self.queues.get((request.method, str(request.url)))
        if not queue:
            raise httpx.ConnectError(
                f"not in the replay file: {request.method} {request.url}", request=request
            )
        exchange = queue.popleft() if len(queue) > 1 else queue[0]
        headers = [
            (k.encode("ascii"), v.encode("utf-8", "surrogatepass"))
            for k, v in exchange["headers"].items()
        ]
        return httpx.Response(
            exchange["status"],
            headers=headers,
            content=exchange["body"].encode("utf-8", "surrogatepass"),
            request=request,
        )


def load(path: str) -> tuple[str, list[dict[str, Any]]]:
    """Read a replay file. Returns (MCP URL, exchanges). Raises ExchangeFileError."""
    file = Path(path)
    try:
        if file.stat().st_size > MAX_FILE_BYTES:
            raise ExchangeFileError(f"{path}: larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
        text = file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ExchangeFileError(f"{path}: {exc.strerror or exc}") from None
    except UnicodeDecodeError:
        raise ExchangeFileError(f"{path}: not UTF-8 text") from None
    try:
        document = json.loads(text)
    except RecursionError:
        raise ExchangeFileError(f"{path}: JSON nested too deeply") from None
    except ValueError as exc:
        raise ExchangeFileError(f"{path}: not JSON ({exc})") from None
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        raise ExchangeFileError(f"{path}: not an exchanges file (expected format {FORMAT!r})")
    url = document.get("url")
    exchanges = document.get("exchanges")
    if not isinstance(url, str) or not isinstance(exchanges, list):
        raise ExchangeFileError(f"{path}: needs a string `url` and an `exchanges` list")
    for index, exchange in enumerate(exchanges):
        if not (
            isinstance(exchange, dict)
            and isinstance(exchange.get("method"), str)
            and isinstance(exchange.get("url"), str)
            and isinstance(exchange.get("status"), int)
            and not isinstance(exchange.get("status"), bool)
            and 100 <= exchange["status"] <= 599
            and isinstance(exchange.get("headers"), dict)
            and all(
                isinstance(k, str) and k.isascii() and k.isprintable() and isinstance(v, str)
                for k, v in exchange["headers"].items()
            )
            and isinstance(exchange.get("body"), str)
        ):
            raise ExchangeFileError(
                f"{path}: exchanges[{index}] needs method, url, status (100-599), "
                "headers (strings) and body (string)"
            )
    return url, exchanges
