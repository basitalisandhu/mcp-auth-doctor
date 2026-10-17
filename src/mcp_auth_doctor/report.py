"""Render a Report as a text table or as the JSON document."""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .checks import FAIL, WARN, Report

STATUS_LABEL = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "skip": "skip"}


def render_table(report: Report, verbose: bool = False) -> str:
    lines = [f"mcp-auth-doctor {__version__}  spec {report.spec}  {report.url}", ""]
    width = max(len(c.id) for c in report.checks) if report.checks else 10
    for check in report.checks:
        label = STATUS_LABEL.get(check.status, check.status)
        lines.append(f"  {check.id.ljust(width)}  {label:<4}  {check.reason}")
        if verbose or check.status in (FAIL, WARN):
            for line in _evidence_lines(check.evidence):
                lines.append(f"  {' ' * width}        {line}")
    lines.append("")
    lines.append(_summary(report))
    return "\n".join(lines)


def render_markdown(report: Report, verbose: bool = False) -> str:
    output = []

    # Header
    output.append(f"## mcp-auth-doctor {__version__}")
    output.append("")
    output.append(f"- Spec: {report.spec}")
    output.append(f"- URL: `{report.url}`")
    output.append("")

    # Diagnostics
    output.append("| Check | Status | Reason |")
    output.append("|---|---|---|")
    for check in report.checks:
        label = STATUS_LABEL.get(check.status, check.status)
        reason = _cell(check.reason)
        if verbose or check.status in (FAIL, WARN):
            evidence = _evidence_lines(check.evidence)
            if evidence:
                reason += "<br>" + "<br>".join(_cell(line) for line in evidence)
        output.append(f"| {check.id} | {label} | {reason} |")
    output.append("")

    # Summary
    output.append(_summary(report))
    return "\n".join(output)


def _evidence_lines(evidence: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for key, value in evidence.items():
        if key == "attempts" and isinstance(value, list):
            for attempt in value:
                status = attempt.get("status", attempt.get("error", "?"))
                extra = (
                    f" {attempt['content_type']}"
                    if attempt.get("content_type") and attempt.get("status") == 200
                    else ""
                )
                lines.append(f"tried {attempt.get('url')} -> {status}{extra}")
            continue
        if value is None or value is False:
            continue
        if isinstance(value, (dict, list)):
            value = json.dumps(value, separators=(",", ":"))
        lines.append(f"{key}: {value}")
    return lines


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def _cell(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def _summary(report: Report) -> str:
    counts = report.counts()
    return (
        f"{counts['pass']} pass, {counts['fail']} fail, "
        f"{counts['warn']} warn, {counts['skip']} skip. "
        f"Verdict: {report.verdict.upper()} (exit {report.exit_code})"
    )


__all__ = ["WARN", "render_json", "render_markdown", "render_table"]
