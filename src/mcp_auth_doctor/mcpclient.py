"""Minimal MCP Streamable HTTP helpers: build JSON-RPC requests and read replies.

Only what the diagnosis needs: an `initialize` request (sent without a token to
provoke the 401, and with one after `--login`) and a `tools/list` request. Replies may
be plain JSON or a text/event-stream body; both are handled.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import httpx

from . import __version__

MCP_PROTOCOL_VERSIONS = {"2026-07-28": "2026-07-28", "2025-11-25": "2025-11-25"}

ACCEPT = "application/json, text/event-stream"


def mcp_headers(
    spec: str,
    token: str | None = None,
    session: str | None = None,
    extra_headers: Mapping[str, str] | None = None,
) -> dict[str, str]:
    reserved = {"accept", "content-type", "mcp-protocol-version", "user-agent", "mcp-session-id"}
    if token:
        reserved.add("authorization")
    headers = {
        name: value for name, value in (extra_headers or {}).items() if name.lower() not in reserved
    }
    headers.update(
        {
            "Accept": ACCEPT,
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSIONS.get(spec, spec),
            "User-Agent": f"mcp-auth-doctor/{__version__}",
        }
    )
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session:
        headers["Mcp-Session-Id"] = session
    return headers


def initialize_request(spec: str, request_id: int = 1) -> dict[str, Any]:
    """A minimal JSON-RPC initialize request (no optional capabilities)."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSIONS.get(spec, spec),
            "capabilities": {},
            "clientInfo": {"name": "mcp-auth-doctor", "version": __version__},
        },
    }


def tools_list_request(request_id: int = 2) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}}


def parse_jsonrpc_response(response: httpx.Response, request_id: int) -> dict[str, Any] | None:
    """Return the JSON-RPC message with `request_id` from a JSON or SSE body."""
    content_type = (response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if content_type == "text/event-stream":
        for data in _sse_data_blocks(response.text):
            try:
                message = json.loads(data)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("id") == request_id:
                return message
        return None
    try:
        message = response.json()
    except ValueError:
        return None
    if isinstance(message, dict):
        return message
    if isinstance(message, list):
        for item in message:
            if isinstance(item, dict) and item.get("id") == request_id:
                return item
    return None


def _sse_data_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.startswith("data:"):
            current.append(line[5:].lstrip())
        elif line.strip() == "" and current:
            blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))
    return blocks
