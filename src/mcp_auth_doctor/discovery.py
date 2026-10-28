"""URL construction, header parsing and comparison helpers.

Everything here is pure: no network calls. The rules come from RFC 9728 (protected
resource metadata), RFC 8414 (authorization server metadata), OpenID Connect Discovery
1.0 and the MCP authorization specification (2025-11-25 and 2026-07-28).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

PRM_SUFFIX = "/.well-known/oauth-protected-resource"
AS_SUFFIX = "/.well-known/oauth-authorization-server"
OIDC_SUFFIX = "/.well-known/openid-configuration"

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_PORTS = {"http": 80, "https": 443}


class UrlError(ValueError):
    """The MCP URL cannot be used."""


def validate_mcp_url(url: str) -> str:
    """Return the URL unchanged when it is usable, else raise UrlError.

    Only https is accepted, except for http on localhost, 127.0.0.1 or ::1, which is
    what the OAuth 2.1 and MCP specifications allow for loopback development servers.
    """
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for a port that is not 0-65535
    except ValueError as exc:
        raise UrlError(f"URL cannot be parsed: {exc} (got {url!r})") from None
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise UrlError(f"URL contains a space or control character (got {url!r})")
    if parts.scheme not in ("http", "https"):
        raise UrlError(f"URL must start with https:// (got {url!r})")
    if not parts.hostname:
        raise UrlError(f"URL has no host (got {url!r})")
    if parts.scheme == "http" and parts.hostname.lower() not in LOCAL_HOSTS:
        raise UrlError(
            "refusing plain http:// for a non-local host; OAuth requires https "
            "(http is only accepted for localhost, 127.0.0.1 and ::1)"
        )
    if parts.fragment:
        raise UrlError("URL must not contain a fragment (RFC 8707 canonical URI)")
    return url


def origin(url: str) -> str:
    """scheme://host[:port] of a URL, lower-cased scheme and host."""
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def prm_well_known_urls(mcp_url: str) -> list[str]:
    """Protected resource metadata URLs to try, in the order the MCP spec gives.

    RFC 9728 section 3 inserts the well-known string between the host and the path
    (after removing a slash that directly follows the host), so
    https://example.com/public/mcp becomes
    https://example.com/.well-known/oauth-protected-resource/public/mcp. The MCP spec
    says clients try that path-aware form first and the root form second. When the MCP
    path ends with a slash the strict insertion keeps it, so the form without the slash
    is tried as well, between the two. When the MCP URL has no path only the root form
    is returned.
    """
    parts = urlsplit(mcp_url)
    base = origin(mcp_url)
    path = parts.path
    urls: list[str] = []
    if path and path != "/":
        urls.append(base + PRM_SUFFIX + path)
        if path.endswith("/"):
            urls.append(base + PRM_SUFFIX + path.rstrip("/"))
    urls.append(base + PRM_SUFFIX)
    return urls


def as_metadata_urls(issuer: str) -> list[str]:
    """Authorization server metadata URLs to try, in MCP priority order.

    With a path component (https://auth.example.com/tenant1):
      1. https://auth.example.com/.well-known/oauth-authorization-server/tenant1
      2. https://auth.example.com/.well-known/openid-configuration/tenant1
      3. https://auth.example.com/tenant1/.well-known/openid-configuration
    Without a path component:
      1. https://auth.example.com/.well-known/oauth-authorization-server
      2. https://auth.example.com/.well-known/openid-configuration
    """
    parts = urlsplit(issuer)
    base = origin(issuer)
    path = parts.path.rstrip("/")
    if path and path != "/":
        return [base + AS_SUFFIX + path, base + OIDC_SUFFIX + path, base + path + OIDC_SUFFIX]
    return [base + AS_SUFFIX, base + OIDC_SUFFIX]


@dataclass
class Challenge:
    """One challenge from a WWW-Authenticate header."""

    scheme: str
    params: dict[str, str] = field(default_factory=dict)


_TOKEN68 = r"[A-Za-z0-9._~+/-]+=*"
_PARAM = re.compile(r'\s*([A-Za-z0-9_.-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))\s*')
_SCHEME = re.compile(r"\s*,?\s*([A-Za-z][A-Za-z0-9._~+/-]*)")
_NEXT = re.compile(r"\s*([A-Za-z][A-Za-z0-9._~+/-]*)\s*(=?)")
_ESCAPE = re.compile(r"\\(.)")


def parse_www_authenticate(value: str) -> list[Challenge]:
    """Parse a WWW-Authenticate header into challenges (RFC 9110 section 11.6.1).

    Handles several comma-separated challenges, quoted and unquoted parameter values,
    and case-insensitive scheme and parameter names. Parameter names are lower-cased.
    Malformed input yields as many challenges as could be read; it never raises.
    """
    challenges: list[Challenge] = []
    pos = 0
    text = value.strip()
    while pos < len(text):
        # Patterns are matched at an offset rather than on a slice, so a long header is
        # read in linear time (slicing made it quadratic).
        m = _SCHEME.match(text, pos)
        if not m:
            break
        scheme = m.group(1)
        pos = m.end()
        ch = Challenge(scheme=scheme)
        challenges.append(ch)
        # Parameters follow until the next token that is a scheme (a bare word followed
        # by a space and not by '=').
        while pos < len(text):
            pm = _PARAM.match(text, pos)
            if pm:
                name = pm.group(1).lower()
                raw = pm.group(2) if pm.group(2) is not None else pm.group(3)
                ch.params[name] = _ESCAPE.sub(r"\1", raw)
                pos = pm.end()
                if pos < len(text) and text[pos] == ",":
                    pos += 1
                    # Look ahead: a new scheme starts if the next word is not followed by '='.
                    nxt = _NEXT.match(text, pos)
                    if nxt and nxt.group(2) != "=":
                        break
                continue
            break
    return challenges


def resource_metadata_url(header_value: str) -> str | None:
    """The resource_metadata URL from a Bearer challenge, or None."""
    for ch in parse_www_authenticate(header_value):
        if ch.scheme.lower() == "bearer" and ch.params.get("resource_metadata"):
            return ch.params["resource_metadata"]
    return None


def bearer_scope(header_value: str) -> str | None:
    for ch in parse_www_authenticate(header_value):
        if ch.scheme.lower() == "bearer" and ch.params.get("scope"):
            return ch.params["scope"]
    return None


def canonical(url: str) -> str:
    """Normalise a URL for comparison: lower-case scheme and host, drop default port.

    The path is kept as is, including any trailing slash, because the MCP spec treats
    https://x/ and https://x as different resource identifiers that implementations
    should not mix.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        # An unclosed IPv6 bracket or a port out of range: compare the text as given.
        return url
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None or DEFAULT_PORTS.get(scheme) == port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


@dataclass
class ResourceMatch:
    ok: bool
    reason: str
    trailing_slash_only: bool = False


def compare_resource(mcp_url: str, resource: str) -> ResourceMatch:
    """Compare the PRM `resource` value with the MCP URL.

    RFC 9728 section 3.3: the `resource` value must be identical to the protected
    resource's identifier, otherwise the metadata must not be used. A difference that is
    only a trailing slash is reported explicitly because it is the most common cause of
    audience mismatches (the client sends resource=https://x/mcp, the server expects
    https://x/mcp/).
    """
    a = canonical(mcp_url)
    b = canonical(resource)
    if a == b:
        return ResourceMatch(True, "resource matches the MCP URL")
    if a.rstrip("/") == b.rstrip("/"):
        which = "resource has" if b.endswith("/") else "MCP URL has"
        return ResourceMatch(
            False,
            f"resource differs from the MCP URL only by a trailing slash ({which} the slash): "
            f"resource={resource!r} url={mcp_url!r}",
            trailing_slash_only=True,
        )
    return ResourceMatch(False, f"resource {resource!r} does not match the MCP URL {mcp_url!r}")


def is_json_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


def issuer_matches(expected: str, actual: object) -> bool:
    """RFC 8414 section 3.3: issuer must be identical to the one used to build the URL.

    A trailing slash on either side is tolerated, since many servers list the issuer
    with one and the metadata without; anything else is a mismatch.
    """
    if not isinstance(actual, str) or not actual:
        return False
    return expected.rstrip("/") == actual.rstrip("/")
