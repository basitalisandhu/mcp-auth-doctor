"""Command line entry point.

Exit codes: 0 every check passed (warnings and skips allowed), 1 at least one check
failed, 2 inconclusive (the server neither returned 401 nor served metadata, or could
not be reached), 3 usage error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .checks import DEFAULT_SPEC, SPECS, Options, diagnose
from .discovery import UrlError, validate_mcp_url
from .report import render_json, render_markdown, render_table

EXIT_USAGE = 3


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="mcp-auth-doctor",
        description=(
            "Diagnose OAuth discovery problems on a remote MCP server: the 401 challenge, "
            "Protected Resource Metadata (RFC 9728), authorization server metadata "
            "(RFC 8414, OpenID Connect Discovery), PKCE, client registration and the "
            "token endpoint, checked against the MCP authorization specification."
        ),
        epilog="Exit codes: 0 all pass, 1 any fail, 2 inconclusive, 3 usage error.",
    )
    parser.add_argument("url", help="MCP server URL (https; http only for localhost)")
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--json",
        dest="format",
        action="store_const",
        const="json",
        default=argparse.SUPPRESS,
        help="alias for --format json",
    )
    parser.add_argument(
        "--spec",
        choices=SPECS,
        default=DEFAULT_SPEC,
        help=f"MCP authorization rules to apply (default {DEFAULT_SPEC})",
    )
    parser.add_argument(
        "--dcr-probe",
        action="store_true",
        help="opt in: POST a throwaway native-client registration and report the answer",
    )
    parser.add_argument(
        "--login",
        action="store_true",
        help="opt in: run the PKCE code flow with a loopback callback, then call tools/list",
    )
    parser.add_argument(
        "--client-id",
        help="pre-registered client id to use with --login (skips dynamic registration)",
    )
    parser.add_argument(
        "--callback-port",
        type=int,
        default=0,
        help="loopback port for the --login callback (default: random)",
    )
    parser.add_argument(
        "--login-timeout",
        type=float,
        default=180.0,
        help="seconds to wait for the browser callback (default 180)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="with --login, print the authorization URL instead of opening a browser",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default 10)"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show evidence for every check, not only failures and warnings",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_mcp_url(args.url)
    except UrlError as exc:
        parser.print_usage(sys.stderr)
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.callback_port < 0 or args.callback_port > 65535:
        parser.error("--callback-port must be between 0 and 65535")

    options = Options(
        spec=args.spec,
        dcr_probe=args.dcr_probe,
        login=args.login,
        client_id=args.client_id,
        timeout=args.timeout,
        callback_port=args.callback_port,
        login_timeout=args.login_timeout,
        open_browser=_print_url if args.no_browser else None,
    )
    report = diagnose(args.url, options)
    if args.format == "json":
        output = render_json(report)
    elif args.format == "markdown":
        output = render_markdown(report, verbose=args.verbose)
    else:
        output = render_table(report, verbose=args.verbose)

    print(output)
    return report.exit_code


def _print_url(url: str) -> None:
    print(f"Open this URL to authorize:\n  {url}", file=sys.stderr)


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
