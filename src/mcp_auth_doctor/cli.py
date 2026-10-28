"""Command line entry point.

Exit codes: 0 every check passed (warnings and skips allowed), 1 at least one check
failed, 2 inconclusive (the server neither returned 401 nor served metadata, or could
not be reached), 3 usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence

import httpx

from . import __version__
from .checks import DEFAULT_SPEC, SPECS, Options, diagnose
from .discovery import UrlError, validate_mcp_url
from .exchanges import ExchangeFileError, RecordingTransport, ReplayTransport, load
from .report import render_json, render_markdown, render_table

EXIT_USAGE = 3


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def _header(value: str) -> tuple[str, str]:
    name, separator, content = value.partition(":")
    name, content = name.strip(), content.strip()
    if (
        not separator
        or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
        or any(ord(c) < 32 or ord(c) > 126 for c in content)
        or "\r" in value
        or "\n" in value
    ):
        raise argparse.ArgumentTypeError(
            "expected an ASCII HTTP header with a nonempty name and colon"
        )
    if name.lower() == "authorization":
        raise argparse.ArgumentTypeError(
            "Authorization is not allowed in --header; use --login for bearer authentication"
        )
    return name.lower(), content


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
    parser.add_argument(
        "url",
        nargs="?",
        help="MCP server URL (https; http only for localhost); optional with --replay",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        type=_header,
        default=[],
        help="extra MCP request header 'Name: value' (repeatable; never sent to OAuth endpoints)",
    )
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
        "--record",
        metavar="FILE",
        help="save every HTTP exchange of this run to FILE (secrets redacted; not with --login)",
    )
    parser.add_argument(
        "--replay",
        metavar="FILE",
        help=(
            "run the checks against exchanges saved with --record instead of the "
            "network; '-' reads standard input"
        ),
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
    replay = None
    if args.record and args.replay:
        parser.error("--record and --replay cannot be combined")
    if (args.record or args.replay) and args.login:
        parser.error("--login cannot be combined with --record or --replay")
    if args.replay:
        try:
            recorded_url, exchanges = load(args.replay)
        except ExchangeFileError as exc:
            print(f"{parser.prog}: error: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if args.url and args.url != recorded_url:
            parser.error(f"the replay file was recorded for {recorded_url}, not {args.url}")
        args.url = recorded_url
        replay = ReplayTransport(exchanges)
    if not args.url:
        parser.error("the following arguments are required: url")
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
        headers=dict(args.header),
    )
    transport: httpx.BaseTransport | None = replay
    if args.record:
        transport = RecordingTransport()
    client = None
    if transport is not None:
        # The same settings as checks.make_client, on the recording or replay transport.
        client = httpx.Client(
            transport=transport,
            timeout=args.timeout,
            follow_redirects=False,
            headers={"User-Agent": f"mcp-auth-doctor/{__version__}"},
        )
    try:
        report = diagnose(args.url, options, client=client)
    finally:
        if client is not None:
            client.close()
    if isinstance(transport, RecordingTransport):
        try:
            transport.write(args.record, args.url)
        except OSError as exc:
            print(
                f"{parser.prog}: error: cannot write {args.record}: {exc.strerror}", file=sys.stderr
            )
            return EXIT_USAGE
    # Name standard input the way error messages do, not as a bare "-".
    replayed_from = "<stdin>" if args.replay == "-" else args.replay
    if args.format == "json":
        output = render_json(report, replayed_from=replayed_from)
    elif args.format == "markdown":
        output = render_markdown(report, verbose=args.verbose, replayed_from=replayed_from)
    else:
        output = render_table(report, verbose=args.verbose, replayed_from=replayed_from)

    print(printable(output))
    return report.exit_code


def printable(text: str) -> str:
    """Escape lone surrogates so the report always prints.

    A JSON body can carry an escaped lone surrogate ("\\udcff"), which json decodes into a
    str that UTF-8 cannot encode; printing it raised UnicodeEncodeError after every check
    had run. Such characters are shown as backslash escapes instead.
    """
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _print_url(url: str) -> None:
    print(f"Open this URL to authorize:\n  {url}", file=sys.stderr)


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
