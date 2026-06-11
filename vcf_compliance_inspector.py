#!/usr/bin/env python3
"""VCF Compliance Inspector — forensic review of VMware VCF 9+ .data registration files.

Safely inspect JWT-encoded VCF mandatory compliance artifacts (Registration-*.data)
before uploading in disconnected / air-gapped environments. Provides dual-view analysis
(raw hex + decoded JWT), xr2 fingerprint inspection, and sensitive-data scanning.

Usage examples::

    python vcf_compliance_inspector.py Registration-*.data
    python vcf_compliance_inspector.py /path/to/compliance/ --dir --json audit-report.json
    python vcf_compliance_inspector.py file.data --head 1024 --verbose

References:
    - https://blogs.vmware.com/cloud-foundation/2025/06/24/licensing-in-vmware-cloud-foundation-9-0/
    - https://www.linkedin.com/pulse/whats-inside-vcf-9-license-file-understanding-connected-kusek-95gfc

Future extension hooks:
    - License Usage File parsing (180-day compliance artifact) — see ``analyze_license_usage_file()``.
    - Additional VMware compliance report formats — register in ``COMPLIANCE_ANALYZERS``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.1.0"

RISK_ASSESSMENT_PATH = Path(__file__).resolve().parent / "RISK_ASSESSMENT.md"

SECURITY_LIMITATIONS = (
    "This tool performs local, read-only inspection. It does not verify JWT signatures, "
    "prove that opaque fields (xr2, UUIDs) cannot be correlated by Broadcom, or certify "
    "legal adequacy of upload. A clean verdict means no obvious sensitive patterns were "
    "found in decoded content—not zero residual risk. See RISK_ASSESSMENT.md."
)

EXPECTED_VCF_CLAIMS = frozenset(
    {
        "model_version",
        "asset_name",
        "created_on",
        "asset_type",
        "asset_id",
        "request_id",
        "xr2",
    }
)

XR2_EXPLANATION = (
    "Opaque fingerprint used to link usage data; no identifiable environment "
    "details can be derived (per Broadcom / VMware VCF 9 documentation)."
)

SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "secret",
    "credential",
    "credentials",
    "private",
    "apikey",
    "api_key",
    "access_key",
    "auth_token",
    "bearer",
    "ssh-rsa",
    "ssh-ed25519",
    "-----begin",
    "-----end",
    "aws_secret",
    "client_secret",
)

SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    (
        "ipv4",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    (
        "ipv6",
        re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
            r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
            r"|\b(?:[0-9a-fA-F]{1,4}:){1,6}:\b"
        ),
    ),
    (
        "internal_hostname",
        re.compile(
            r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
            r"(?:local|internal|corp|lan|intranet|private)\b",
            re.IGNORECASE,
        ),
    ),
    ("pem_header", re.compile(r"-----BEGIN\s+[A-Z ]+-----")),
    (
        "high_entropy_base64",
        re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/=])"),
    ),
]

BYTES_PER_HEX_LINE = 16

# Registry for future compliance artifact analyzers (License Usage File, etc.).
COMPLIANCE_ANALYZERS: dict[str, str] = {
    "registration_data": "analyze_vcf_data_file",
    # "license_usage": "analyze_license_usage_file",  # future hook
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SensitiveFinding:
    """A single sensitive-data scan hit."""

    category: str
    match: str
    context: str


@dataclass
class Xr2Analysis:
    """Decoded xr2 fingerprint analysis."""

    present: bool
    raw_value: str | None = None
    decoded_bytes: bytes | None = None
    decoded_json: Any | None = None
    decode_method: str | None = None
    error: str | None = None


@dataclass
class FileAnalysis:
    """Complete analysis result for one .data file."""

    path: str
    sha256: str
    size_bytes: int
    is_jwt: bool
    jwt_header: dict[str, Any] | None = None
    jwt_payload: dict[str, Any] | None = None
    jwt_signature_b64: str | None = None
    jwt_errors: list[str] = field(default_factory=list)
    raw_text_preview: str = ""
    hexdump: str = ""
    hexdump_truncated: bool = False
    hexdump_head: int | None = None
    xr2: Xr2Analysis = field(default_factory=lambda: Xr2Analysis(present=False))
    sensitive_findings: list[SensitiveFinding] = field(default_factory=list)
    verdict: str = "review_recommended"
    verdict_reason: str = ""
    expected_claims_present: list[str] = field(default_factory=list)
    expected_claims_missing: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def compute_sha256(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment with correct padding.

    Args:
        segment: Base64url-encoded string (JWT segment without padding).

    Returns:
        Decoded bytes.

    Raises:
        ValueError: If decoding fails.
    """
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"base64url decode failed: {exc}") from exc


def decode_jwt_part(segment: str) -> dict[str, Any]:
    """Decode a single JWT header or payload segment to a JSON object.

    Uses manual base64url decode and ``json.loads`` — no signature verification.

    Args:
        segment: Dot-separated JWT part (header or payload).

    Returns:
        Parsed JSON object.

    Raises:
        ValueError: On decode or JSON parse failure.
    """
    raw = b64url_decode(segment)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"JWT part is not valid UTF-8: {exc}") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JWT part is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("JWT part JSON root must be an object")
    return parsed


def pretty_hexdump(
    data: bytes,
    *,
    head: int | None = None,
    colorize: bool = True,
) -> tuple[str, bool]:
    """Format *data* as a classic offset / hex / ASCII hexdump.

    Args:
        data: Raw file bytes.
        head: If set, limit output to the first *head* bytes.
        colorize: When True, embed Rich markup for non-printable highlighting.

    Returns:
        Tuple of (formatted hexdump string, truncated_flag).
    """
    truncated = head is not None and len(data) > head
    view = data[:head] if head is not None else data
    lines: list[str] = []

    if colorize:
        lines.append(
            "[bold white]Offset[/bold white]    "
            "[bold white]Hex[/bold white]                                              "
            "[bold white]ASCII[/bold white]"
        )
        lines.append("[dim]" + "─" * 76 + "[/dim]")

    for offset in range(0, len(view), BYTES_PER_HEX_LINE):
        chunk = view[offset : offset + BYTES_PER_HEX_LINE]
        hex_parts: list[str] = []
        ascii_parts: list[str] = []

        for index, byte in enumerate(chunk):
            if colorize:
                tone = "bright_blue" if index % 2 == 0 else "blue"
                hex_parts.append(f"[{tone}]{byte:02x}[/{tone}]")
            else:
                hex_parts.append(f"{byte:02x}")

            if 32 <= byte <= 126:
                ch = chr(byte)
                if colorize:
                    ascii_parts.append(f"[bold green]{ch}[/bold green]")
                else:
                    ascii_parts.append(ch)
            elif colorize:
                ascii_parts.append("[dim red]·[/dim red]")
            else:
                ascii_parts.append(".")

        hex_col = " ".join(hex_parts)
        if len(chunk) < BYTES_PER_HEX_LINE:
            pad = "   " * (BYTES_PER_HEX_LINE - len(chunk))
            hex_col = f"{hex_col}{pad}"

        ascii_col = "".join(ascii_parts)
        if colorize:
            line = (
                f"[bold cyan]{offset:08x}[/bold cyan]  "
                f"{hex_col}  "
                f"[dim]│[/dim]{ascii_col}[dim]│[/dim]"
            )
        else:
            hex_plain = " ".join(f"{byte:02x}" for byte in chunk).ljust(BYTES_PER_HEX_LINE * 3 - 1)
            line = f"{offset:08x}  {hex_plain}  |{ascii_col}|"
        lines.append(line)

    if truncated and colorize:
        lines.append("")
        lines.append(
            f"[yellow]… truncated — {len(data) - len(view):,} additional bytes not shown "
            f"(use --head to adjust)[/yellow]"
        )
    elif truncated:
        lines.append(f"... truncated — {len(data) - len(view):,} additional bytes not shown")

    return "\n".join(lines), truncated


def render_raw_hexdump_panel(
    analysis: FileAnalysis,
    console: Console,
) -> None:
    """Render the raw byte-level hex/ASCII view (always shown last in the report)."""
    raw_bytes = Path(analysis.path).read_bytes()
    hexdump_display, trunc = pretty_hexdump(
        raw_bytes,
        head=analysis.hexdump_head,
        colorize=not console.no_color,
    )
    title = "[bold white]Raw Hex & ASCII Dump[/bold white]"
    subtitle_parts = [
        f"[dim]{analysis.size_bytes:,} total bytes[/dim]",
        f"[dim]SHA-256:[/dim] [cyan]{analysis.sha256[:16]}…[/cyan]",
    ]
    if trunc and analysis.hexdump_head is not None:
        subtitle_parts.append(
            f"[yellow]showing first {analysis.hexdump_head:,} bytes[/yellow]"
        )
    console.print(
        Panel(
            hexdump_display,
            title=title,
            subtitle="  ·  ".join(subtitle_parts),
            border_style="bright_blue",
            padding=(1, 2),
        )
    )


def decode_xr2(value: str) -> Xr2Analysis:
    """Attempt to decode the ``xr2`` claim value.

    Tries base64url first, then standard base64. Parses JSON when possible;
    otherwise returns raw bytes for hexdump display.

    Args:
        value: The xr2 string from the JWT payload.

    Returns:
        Populated :class:`Xr2Analysis`.
    """
    analysis = Xr2Analysis(present=True, raw_value=value)
    decoded: bytes | None = None
    method: str | None = None

    for label, decoder in (
        ("base64url", lambda v: b64url_decode(v)),
        ("base64", lambda v: base64.b64decode(v + "=" * (-len(v) % 4))),
    ):
        try:
            decoded = decoder(value)
            method = label
            break
        except (ValueError, binascii.Error):
            continue

    if decoded is None:
        analysis.error = "Could not decode xr2 as base64url or standard base64"
        return analysis

    analysis.decoded_bytes = decoded
    analysis.decode_method = method

    try:
        text = decoded.decode("utf-8")
        analysis.decoded_json = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    return analysis


def _context_snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    """Return a short context window around a match span."""
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    snippet = text[left:right]
    if left > 0:
        snippet = "..." + snippet
    if right < len(text):
        snippet = snippet + "..."
    return snippet.replace("\n", "\\n")


def scan_for_sensitive_data(
    texts: Iterable[str],
    *,
    jwt_segments: Sequence[str] | None = None,
    exclude_values: Sequence[str] | None = None,
) -> list[SensitiveFinding]:
    """Scan decoded text for keywords and regex patterns indicating sensitive data.

    Args:
        texts: Iterable of strings to scan (decoded JWT parts, raw text, etc.).
        jwt_segments: Known JWT dot-separated segments to exclude from high-entropy
            base64 matching (avoids false positives on the token itself).
        exclude_values: Additional literal strings to exclude from high-entropy
            matching (e.g. documented opaque claims like ``xr2``).

    Returns:
        Deduplicated list of findings.
    """
    findings: list[SensitiveFinding] = []
    seen: set[tuple[str, str]] = set()
    jwt_blob = ".".join(jwt_segments) if jwt_segments else ""
    opaque_literals = [v for v in (exclude_values or []) if v]

    for source in texts:
        if not source:
            continue
        for keyword in SENSITIVE_KEYWORDS:
            pattern = re.compile(rf"\b{re.escape(keyword)}\b", re.IGNORECASE)
            for match in pattern.finditer(source):
                matched = match.group(0)
                key = ("keyword", matched.lower())
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    SensitiveFinding(
                        category=f"keyword:{keyword}",
                        match=matched,
                        context=_context_snippet(source, match.start(), match.end()),
                    )
                )

        for label, pattern in SENSITIVE_PATTERNS:
            for match in pattern.finditer(source):
                matched = match.group(0)
                if label == "high_entropy_base64" and (
                    matched in jwt_blob or matched in opaque_literals
                ):
                    continue
                if label == "ipv4" and matched in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                    continue
                key = (label, matched)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    SensitiveFinding(
                        category=label,
                        match=matched,
                        context=_context_snippet(source, match.start(), match.end()),
                    )
                )

    return findings


def _assess_verdict(
    analysis: FileAnalysis,
    *,
    sensitive_findings: list[SensitiveFinding],
) -> tuple[str, str]:
    """Determine verdict string and human-readable reason."""
    if not analysis.is_jwt:
        return (
            "review_recommended",
            "File does not match expected JWT structure (three dot-separated segments).",
        )

    if analysis.jwt_errors:
        return (
            "review_recommended",
            f"JWT decode issues: {'; '.join(analysis.jwt_errors)}",
        )

    if sensitive_findings:
        cats = sorted({f.category for f in sensitive_findings})
        return (
            "review_recommended",
            f"Sensitive-data scanner flagged potential items: {', '.join(cats)}.",
        )

    # Expected VCF registration claims
    payload = analysis.jwt_payload or {}
    missing = sorted(EXPECTED_VCF_CLAIMS - set(payload.keys()))
    analysis.expected_claims_missing = missing
    analysis.expected_claims_present = sorted(EXPECTED_VCF_CLAIMS & set(payload.keys()))

    if missing:
        return (
            "review_recommended",
            f"Missing expected VCF 9 claims: {', '.join(missing)}.",
        )

    asset_type = str(payload.get("asset_type", ""))
    if asset_type and asset_type != "AC":
        return (
            "review_recommended",
            f"Unexpected asset_type '{asset_type}' (expected 'AC' for registration).",
        )

    return (
        "clean",
        "Structure matches expected VCF 9 registration JWT; no obvious sensitive data detected.",
    )


def analyze_vcf_data_file(
    path: Path,
    *,
    head: int | None = None,
) -> FileAnalysis:
    """Perform full dual-view analysis on a single ``.data`` file.

    Args:
        path: Path to the registration .data file.
        head: Optional byte limit for hexdump output.

    Returns:
        Populated :class:`FileAnalysis`. Never modifies the input file.
    """
    data = path.read_bytes()
    sha = compute_sha256(data)
    hexdump_str, truncated = pretty_hexdump(data, head=head, colorize=False)

    analysis = FileAnalysis(
        path=str(path.resolve()),
        sha256=sha,
        size_bytes=len(data),
        is_jwt=False,
        hexdump=hexdump_str,
        hexdump_truncated=truncated,
        hexdump_head=head,
    )

    try:
        analysis.raw_text_preview = data.decode("utf-8")
    except UnicodeDecodeError:
        analysis.raw_text_preview = data[:512].decode("utf-8", errors="replace")

    parts = analysis.raw_text_preview.strip().split(".")
    jwt_segments: list[str] | None = None

    if len(parts) == 3 and all(parts):
        analysis.is_jwt = True
        jwt_segments = parts
        analysis.jwt_signature_b64 = parts[2]

        try:
            analysis.jwt_header = decode_jwt_part(parts[0])
        except ValueError as exc:
            analysis.jwt_errors.append(f"header: {exc}")

        try:
            analysis.jwt_payload = decode_jwt_part(parts[1])
        except ValueError as exc:
            analysis.jwt_errors.append(f"payload: {exc}")

        if analysis.jwt_payload and "xr2" in analysis.jwt_payload:
            xr2_val = analysis.jwt_payload["xr2"]
            if isinstance(xr2_val, str):
                analysis.xr2 = decode_xr2(xr2_val)
            else:
                analysis.xr2 = Xr2Analysis(
                    present=True,
                    error=f"xr2 claim is not a string (type={type(xr2_val).__name__})",
                )

    scan_texts: list[str] = [analysis.raw_text_preview]
    if analysis.jwt_header:
        scan_texts.append(json.dumps(analysis.jwt_header))
    if analysis.jwt_payload:
        scan_texts.append(json.dumps(analysis.jwt_payload))

    exclude_values: list[str] = []
    if analysis.jwt_payload:
        xr2_val = analysis.jwt_payload.get("xr2")
        if isinstance(xr2_val, str):
            exclude_values.append(xr2_val)

    analysis.sensitive_findings = scan_for_sensitive_data(
        scan_texts,
        jwt_segments=jwt_segments,
        exclude_values=exclude_values,
    )

    verdict, reason = _assess_verdict(analysis, sensitive_findings=analysis.sensitive_findings)
    analysis.verdict = verdict
    analysis.verdict_reason = reason

    return analysis


# ---------------------------------------------------------------------------
# Future extension hook (License Usage File — 180-day artifact)
# ---------------------------------------------------------------------------


def analyze_license_usage_file(path: Path, *, head: int | None = None) -> FileAnalysis:
    """Placeholder for License Usage File analysis (future iteration).

    The License Usage File is the second mandatory VCF 9+ compliance artifact,
    generated every 180 days. Register an implementation here when format
    documentation is available.
    """
    raise NotImplementedError(
        "License Usage File parsing is not yet implemented. "
        "Use analyze_vcf_data_file() for Registration *.data JWT files."
    )


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------


def _verdict_style(verdict: str) -> tuple[str, str, str]:
    """Return (title, border color, icon) for verdict panel."""
    if verdict == "clean":
        return ("SAFE TO UPLOAD", "green", "✓")
    return ("REVIEW RECOMMENDED", "yellow", "⚠")


def _section(console: Console, number: int, title: str, style: str = "bold white") -> None:
    """Print a numbered section heading."""
    console.print()
    console.rule(f"[{style}]{number}. {title}[/{style}]", style="dim")


def render_analysis(
    analysis: FileAnalysis,
    console: Console,
    *,
    verbose: bool = False,
) -> None:
    """Print rich terminal report for one file analysis."""
    filename = Path(analysis.path).name
    console.print()
    console.print(
        Panel(
            f"[bold bright_white]VCF Compliance Inspector[/bold bright_white]  "
            f"[dim]v{VERSION}[/dim]\n"
            f"[cyan]{filename}[/cyan]",
            border_style="bright_cyan",
            padding=(0, 2),
        )
    )

    # 1. File information
    _section(console, 1, "File Information", "bold cyan")
    info = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    info.add_column("Field", style="bold cyan", min_width=12)
    info.add_column("Value", style="white")
    info.add_row("Path", analysis.path)
    info.add_row("Size", f"[white]{analysis.size_bytes:,}[/white] bytes")
    info.add_row("SHA-256", f"[bright_black]{analysis.sha256}[/bright_black]")
    info.add_row("JWT", "[green]Yes[/green]" if analysis.is_jwt else "[yellow]No[/yellow]")
    console.print(info)

    # 2. JWT structure
    _section(console, 2, "JWT Structure", "bold blue")
    if analysis.is_jwt:
        console.print(
            Panel(
                "[bold green]✓ Valid JWT layout detected[/bold green]\n"
                "[dim]Three dot-separated segments: [/dim]"
                "[cyan]header[/cyan][dim].[/dim][cyan]payload[/cyan][dim].[/dim][cyan]signature[/cyan]",
                border_style="green",
                padding=(0, 2),
            )
        )
    else:
        console.print(
            Panel(
                "[bold yellow]⚠ No JWT structure[/bold yellow]\n"
                "[dim]Expected format: [/dim][cyan]header[/cyan][dim].[/dim]"
                "[cyan]payload[/cyan][dim].[/dim][cyan]signature[/cyan]\n"
                "[dim]Decoded claims unavailable — review raw hex dump at end of report.[/dim]",
                border_style="yellow",
                padding=(0, 2),
            )
        )

    # 3. Decoded header
    if analysis.jwt_header is not None:
        _section(console, 3, "Decoded Header", "bold blue")
        header_json = json.dumps(analysis.jwt_header, indent=2)
        console.print(
            Panel(
                Syntax(header_json, "json", theme="monokai", line_numbers=False),
                border_style="blue",
                padding=(0, 1),
            )
        )

    # 4. Decoded payload
    if analysis.jwt_payload is not None:
        _section(console, 4, "Decoded Payload", "bold blue")
        payload_for_display = dict(analysis.jwt_payload)
        table = Table(box=box.ROUNDED, show_lines=True, padding=(0, 1))
        table.add_column("Claim", style="bold cyan", min_width=14)
        table.add_column("Value", style="white")

        for key, value in payload_for_display.items():
            if key == "xr2":
                display_val = (
                    f"[bold magenta]{value}[/bold magenta]\n"
                    f"[dim]→ see xr2 fingerprint analysis (section 5)[/dim]"
                )
            elif key in EXPECTED_VCF_CLAIMS:
                display_val = json.dumps(value) if not isinstance(value, str) else value
                display_val = f"[white]{display_val}[/white]"
            else:
                display_val = (
                    f"[yellow]{json.dumps(value) if not isinstance(value, str) else value}[/yellow]\n"
                    f"[dim]unexpected claim — review manually[/dim]"
                )
            table.add_row(key, display_val)

        console.print(table)
        if verbose:
            console.print(
                Panel(
                    Syntax(json.dumps(payload_for_display, indent=2), "json", theme="monokai"),
                    title="[dim]Full payload JSON[/dim]",
                    border_style="dim",
                )
            )

    if analysis.jwt_errors:
        console.print()
        console.print(
            Panel(
                "\n".join(f"[yellow]•[/yellow] {err}" for err in analysis.jwt_errors),
                title="[bold yellow]JWT Decode Warnings[/bold yellow]",
                border_style="yellow",
                padding=(0, 2),
            )
        )

    # 5. xr2 analysis
    _section(console, 5, "xr2 Fingerprint Analysis", "bold magenta")
    xr2_panel_lines: list[str] = [
        f"[italic dim]{XR2_EXPLANATION}[/italic dim]",
        "",
    ]
    if analysis.xr2.present:
        if analysis.xr2.error:
            xr2_panel_lines.append(f"[yellow]Decode error:[/yellow] {analysis.xr2.error}")
        else:
            xr2_panel_lines.append(
                f"[dim]Decode method:[/dim] [cyan]{analysis.xr2.decode_method}[/cyan]"
            )
            if analysis.xr2.decoded_json is not None:
                xr2_panel_lines.append("[dim]Decoded as JSON:[/dim]")
                xr2_panel_lines.append(
                    json.dumps(analysis.xr2.decoded_json, indent=2)
                )
            elif analysis.xr2.decoded_bytes is not None:
                length = len(analysis.xr2.decoded_bytes)
                xr2_panel_lines.append(
                    f"[dim]Decoded length:[/dim] [white]{length}[/white] bytes "
                    f"[dim](opaque binary — correlation ID, not environment inventory)[/dim]"
                )
                sub_hex, _ = pretty_hexdump(
                    analysis.xr2.decoded_bytes[:256],
                    head=256,
                    colorize=not console.no_color,
                )
                xr2_panel_lines.append("")
                xr2_panel_lines.append(sub_hex)
                if length > 256:
                    xr2_panel_lines.append(
                        f"[dim]… {length - 256} more bytes not shown[/dim]"
                    )
    else:
        xr2_panel_lines.append("[dim]xr2 claim not present in payload.[/dim]")

    console.print(
        Panel(
            "\n".join(xr2_panel_lines),
            border_style="magenta",
            padding=(0, 2),
        )
    )

    # 6. Sensitive data scan
    _section(console, 6, "Sensitive Data Scan", "bold yellow")
    if analysis.sensitive_findings:
        scan_table = Table(
            title=f"[yellow]{len(analysis.sensitive_findings)} finding(s)[/yellow]",
            box=box.HEAVY_HEAD,
            show_lines=True,
            padding=(0, 1),
        )
        scan_table.add_column("Category", style="bold yellow", min_width=18)
        scan_table.add_column("Match", style="red")
        scan_table.add_column("Context", style="dim", overflow="fold")
        for finding in analysis.sensitive_findings:
            scan_table.add_row(finding.category, finding.match, finding.context)
        console.print(scan_table)
    else:
        console.print(
            Panel(
                "[bold green]✓ No obvious proprietary or sensitive data detected[/bold green]\n"
                "[dim]Keyword and pattern scan over decoded JWT content and raw text.[/dim]",
                border_style="green",
                padding=(0, 2),
            )
        )

    # 7. Assurance boundary
    _section(console, 7, "Assurance Boundary", "bold bright_black")
    risk_note = SECURITY_LIMITATIONS
    if RISK_ASSESSMENT_PATH.is_file():
        risk_note += f"\n\n[link=file://{RISK_ASSESSMENT_PATH}]Full risk assessment: RISK_ASSESSMENT.md[/link]"
    console.print(
        Panel(
            risk_note,
            title="[dim]What this tool cannot guarantee[/dim]",
            border_style="bright_black",
            padding=(0, 2),
        )
    )

    # 8. Summary verdict
    _section(console, 8, "Summary & Verdict", "bold white")
    title, color, icon = _verdict_style(analysis.verdict)
    summary_lines = [
        f"[bold {color}]{icon}  {title}[/bold {color}]",
        "",
        analysis.verdict_reason,
    ]
    if analysis.expected_claims_present:
        summary_lines.append("")
        summary_lines.append(
            "[dim]Expected claims present:[/dim] "
            f"[green]{', '.join(analysis.expected_claims_present)}[/green]"
        )
    if analysis.expected_claims_missing:
        summary_lines.append(
            "[dim]Expected claims missing:[/dim] "
            f"[yellow]{', '.join(analysis.expected_claims_missing)}[/yellow]"
        )

    console.print(
        Panel(
            "\n".join(summary_lines),
            border_style=color,
            padding=(1, 2),
        )
    )

    # 9. Raw hex dump — always last
    _section(console, 9, "Raw Hex & ASCII (byte-level review)", "bold bright_blue")
    render_raw_hexdump_panel(analysis, console)
    console.print()


def analysis_to_dict(analysis: FileAnalysis) -> dict[str, Any]:
    """Serialize analysis for JSON audit output."""
    payload = asdict(analysis)
    if analysis.xr2.decoded_bytes is not None:
        payload["xr2"]["decoded_bytes_hex"] = analysis.xr2.decoded_bytes.hex()
        del payload["xr2"]["decoded_bytes"]
    return payload


# ---------------------------------------------------------------------------
# Input resolution
# ---------------------------------------------------------------------------


def collect_files(
    paths: Sequence[str],
    *,
    file_flag: bool,
    dir_flag: bool,
) -> list[Path]:
    """Resolve CLI arguments to a deduplicated list of .data file paths.

    Args:
        paths: Positional paths and/or --file values.
        file_flag: True when --file was used (explicit file mode).
        dir_flag: True when --dir was used (expand directory globs).

    Returns:
        Sorted unique list of existing file paths.

    Raises:
        SystemExit: When no files are found.
    """
    found: list[Path] = []

    for raw in paths:
        p = Path(raw).expanduser()
        if dir_flag or (p.is_dir() and not file_flag):
            found.extend(sorted(p.glob("*.data")))
        elif p.is_file():
            found.append(p)
        elif "*" in raw or "?" in raw:
            found.extend(sorted(Path().glob(raw)))
        else:
            print(f"Error: path not found: {raw}", file=sys.stderr)
            raise SystemExit(2)

    unique = sorted({f.resolve() for f in found})
    if not unique:
        print("Error: no .data files found.", file=sys.stderr)
        raise SystemExit(2)
    return unique


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    epilog = """
Examples:
  python vcf_compliance_inspector.py Registration-*.data
  python vcf_compliance_inspector.py /path/to/compliance/ --dir --json audit-report.json
  python vcf_compliance_inspector.py file.data --head 1024 --verbose

References:
  VMware Cloud Foundation 9.0 licensing (disconnected mode):
    https://blogs.vmware.com/cloud-foundation/2025/06/24/licensing-in-vmware-cloud-foundation-9-0/
  What's inside the VCF 9 license file:
    https://www.linkedin.com/pulse/whats-inside-vcf-9-license-file-understanding-connected-kusek-95gfc

Risk assessment (residual upload risks & tool limitations):
  RISK_ASSESSMENT.md in this repository
"""
    parser = argparse.ArgumentParser(
        prog="vcf_compliance_inspector",
        description=(
            "Forensic inspector for VMware VCF 9+ Registration .data files (JWT-encoded "
            "compliance artifacts). Verifies structure, decodes claims, analyzes the xr2 "
            "fingerprint, and scans for sensitive data before air-gapped upload to Broadcom."
        ),
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="One or more .data file paths, globs, or directories (with --dir).",
    )
    parser.add_argument(
        "--file",
        action="append",
        dest="files",
        metavar="PATH",
        default=[],
        help="Explicit file path (repeatable).",
    )
    parser.add_argument(
        "--dir",
        action="store_true",
        help="Treat positional paths as directories; glob all *.data files within.",
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        nargs="?",
        const="-",
        help="Write machine-readable JSON audit report to PATH (or stdout if omitted).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show additional detail (full payload JSON, etc.).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output.",
    )
    parser.add_argument(
        "--head",
        type=int,
        metavar="BYTES",
        help="Limit hexdump to the first N bytes of each file.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point.

    Returns:
        0 on success, non-zero on errors.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    all_paths = list(args.paths) + list(args.files)
    if not all_paths:
        parser.print_help()
        return 2

    try:
        files = collect_files(all_paths, file_flag=bool(args.files), dir_flag=args.dir)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    console = Console(no_color=args.no_color, force_terminal=not args.no_color)
    results: list[FileAnalysis] = []
    exit_code = 0

    for file_path in files:
        try:
            analysis = analyze_vcf_data_file(file_path, head=args.head)
            results.append(analysis)
            if not args.json:
                render_analysis(analysis, console, verbose=args.verbose)
            if analysis.verdict != "clean":
                exit_code = 1
        except OSError as exc:
            console.print(f"[red]Error reading {file_path}: {exc}[/red]")
            exit_code = 2

    if args.json:
        report = {
            "tool": "vcf_compliance_inspector",
            "version": VERSION,
            "files": [analysis_to_dict(a) for a in results],
        }
        json_text = json.dumps(report, indent=2)
        if args.json == "-":
            print(json_text)
        else:
            Path(args.json).write_text(json_text, encoding="utf-8")
            if not args.no_color:
                console.print(f"[green]JSON audit report written to {args.json}[/green]")
            else:
                print(f"JSON audit report written to {args.json}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
