#!/usr/bin/env python3
"""VCF Compliance Inspector — forensic review of VMware VCF 9+ .data registration files.

Safely inspect JWT-encoded VCF mandatory compliance artifacts (Registration-*.data)
before uploading in disconnected / air-gapped environments. Provides dual-view analysis
(raw hex + decoded JWT), xr2 fingerprint inspection, and sensitive-data scanning.

The tool always performs deep analysis on raw binary data, even when JWT decoding fails.
This helps detect potential steganography, appended data, high-entropy blobs, or layered encoding.

Usage examples::

    python vcf_compliance_inspector.py Registration-*.data
    python vcf_compliance_inspector.py /path/to/compliance/ --dir --json audit-report.json

References:
    - https://blogs.vmware.com/cloud-foundation/2025/06/24/licensing-in-vmware-cloud-foundation-9-0/
    - https://www.linkedin.com/pulse/whats-inside-vcf-9-license-file-understanding-connected-kusek-95gfc
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

try:
    import jwt
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.2.1"

RISK_ASSESSMENT_PATH = Path(__file__).resolve().parent / "RISK_ASSESSMENT.md"

SECURITY_LIMITATIONS = (
    "This tool performs local, read-only inspection of raw binary data and decoded claims. "
    "It does not verify JWT signatures by default, prove that opaque fields cannot be correlated, "
    "or certify legal adequacy of upload. A clean verdict means no obvious sensitive patterns, "
    "high-entropy anomalies, or steganographic indicators were found in the analyzed data."
)

EXPECTED_VCF_CLAIMS = frozenset({
    "model_version", "asset_name", "created_on", "asset_type",
    "asset_id", "request_id", "xr2",
})

XR2_EXPLANATION = (
    "Opaque fingerprint used to link usage data; no identifiable environment "
    "details can be derived (per Broadcom / VMware VCF 9 documentation)."
)

SENSITIVE_KEYWORDS = (
    "password", "passwd", "secret", "credential", "credentials", "private",
    "apikey", "api_key", "access_key", "auth_token", "bearer",
    "ssh-rsa", "ssh-ed25519", "-----begin", "-----end",
    "aws_secret", "client_secret",
)

SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")),
    ("ipv6", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:\b")),
    ("internal_hostname", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:local|internal|corp|lan|intranet|private)\b", re.IGNORECASE)),
    ("pem_header", re.compile(r"-----BEGIN\s+[A-Z ]+-----" )),
    ("high_entropy_base64", re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/=])" )),
]

# Common file magic bytes for steganography / appended data detection
MAGIC_BYTES = {
    b"PK\x03\x04": "ZIP archive",
    b"\x89PNG": "PNG image",
    b"%PDF": "PDF document",
    b"MZ": "PE/EXE executable",
    b"\x1f\x8b": "Gzip compressed",
    b"\x50\x4b\x05\x06": "ZIP (empty archive)",
    b"Rar!": "RAR archive",
}

BYTES_PER_HEX_LINE = 16
JWT_PATTERN = re.compile(r"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")

COMPLIANCE_ANALYZERS: dict[str, str] = {"registration_data": "analyze_vcf_data_file"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SensitiveFinding:
    category: str
    match: str
    context: str


@dataclass
class Xr2Analysis:
    present: bool
    raw_value: str | None = None
    decoded_bytes: bytes | None = None
    decoded_json: Any | None = None
    decode_method: str | None = None
    error: str | None = None


@dataclass
class FileAnalysis:
    path: str
    sha256: str
    size_bytes: int
    is_jwt: bool
    jwt_header: dict[str, Any] | None = None
    jwt_payload: dict[str, Any] | None = None
    jwt_signature_b64: str | None = None
    jwt_errors: list[str] = field(default_factory=list)
    jwt_verified: bool | None = None
    jwt_verify_error: str | None = None
    stego_indicators: list[str] = field(default_factory=list)
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
    return hashlib.sha256(data).hexdigest()


def b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"base64url decode failed: {exc}") from exc


def decode_jwt_part(segment: str) -> dict[str, Any]:
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


def extract_potential_jwt(text: str) -> tuple[str, str, str] | None:
    text = text.strip()
    match = JWT_PATTERN.search(text)
    if not match:
        return None
    token = match.group(1)
    parts = token.split(".")
    if len(parts) == 3 and all(parts):
        return parts[0], parts[1], parts[2]
    return None


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes (0.0 = low randomness, 8.0 = high randomness)."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def detect_steganography_indicators(data: bytes, jwt_token: str | None = None) -> list[str]:
    """Detect potential steganography, appended data, or layered encoding in raw bytes."""
    indicators: list[str] = []

    # 1. Appended data after a valid JWT
    if jwt_token:
        token_end = data.find(jwt_token.encode())
        if token_end != -1:
            after = data[token_end + len(jwt_token):]
            if after.strip():
                indicators.append(f"Data appended after JWT ({len(after)} bytes) - possible steganography")

    # 2. High entropy regions (possible encrypted/compressed hidden data)
    if len(data) > 64:
        entropy = calculate_entropy(data)
        if entropy > 7.5:
            indicators.append(f"Very high entropy ({entropy:.2f}/8.0) across file - possible encrypted or compressed payload")

    # 3. Magic bytes of known file formats embedded in the data
    for magic, desc in MAGIC_BYTES.items():
        if magic in data:
            indicators.append(f"Embedded {desc} magic bytes detected - possible hidden file")

    # 4. Multiple layers of base64 (common stego technique)
    try:
        decoded_once = base64.b64decode(data, validate=False)
        if len(decoded_once) > 16:
            try:
                decoded_twice = base64.b64decode(decoded_once, validate=False)
                if len(decoded_twice) > 8:
                    indicators.append("Multiple layers of base64 encoding detected")
            except Exception:
                pass
    except Exception:
        pass

    # 5. Unusual control characters or null bytes in text areas
    null_count = data.count(b"\x00")
    if null_count > 4:
        indicators.append(f"Unusual number of null bytes ({null_count}) - possible binary data in text field")

    return indicators


def pretty_hexdump(data: bytes, *, head: int | None = None, colorize: bool = True) -> tuple[str, bool]:
    truncated = head is not None and len(data) > head
    view = data[:head] if head is not None else data
    lines: list[str] = []

    if colorize:
        lines.append("[bold white]Offset[/bold white]    [bold white]Hex[/bold white]                                              [bold white]ASCII[/bold white]")
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
            line = f"[bold cyan]{offset:08x}[/bold cyan]  {hex_col}  [dim]│[/dim]{ascii_col}[dim]│[/dim]"
        else:
            hex_plain = " ".join(f"{byte:02x}" for byte in chunk).ljust(BYTES_PER_HEX_LINE * 3 - 1)
            line = f"{offset:08x}  {hex_plain}  |{ascii_col}|"
        lines.append(line)

    if truncated and colorize:
        lines.append("")
        lines.append(f"[yellow]… truncated — {len(data) - len(view):,} additional bytes not shown (use --head to adjust)[/yellow]")
    elif truncated:
        lines.append(f"... truncated — {len(data) - len(view):,} additional bytes not shown")

    return "\n".join(lines), truncated


def render_raw_hexdump_panel(analysis: FileAnalysis, console: Console) -> None:
    raw_bytes = Path(analysis.path).read_bytes()
    hexdump_display, trunc = pretty_hexdump(raw_bytes, head=analysis.hexdump_head, colorize=not console.no_color)
    title = "[bold white]Raw Hex & ASCII Dump[/bold white]"
    subtitle_parts = [f"[dim]{analysis.size_bytes:,} total bytes[/dim]", f"[dim]SHA-256:[/dim] [cyan]{analysis.sha256[:16]}…[/cyan]"]
    if trunc and analysis.hexdump_head is not None:
        subtitle_parts.append(f"[yellow]showing first {analysis.hexdump_head:,} bytes[/yellow]")
    console.print(Panel(hexdump_display, title=title, subtitle="  ·  ".join(subtitle_parts), border_style="bright_blue", padding=(1, 2)))


def decode_xr2(value: str) -> Xr2Analysis:
    analysis = Xr2Analysis(present=True, raw_value=value)
    decoded: bytes | None = None
    method: str | None = None

    for label, decoder in (("base64url", lambda v: b64url_decode(v)), ("base64", lambda v: base64.b64decode(v + "=" * (-len(v) % 4)))):
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


def verify_jwt_signature(analysis: FileAnalysis, public_key_pem: str | None = None) -> None:
    if not analysis.is_jwt or not analysis.jwt_header or not analysis.jwt_signature_b64:
        analysis.jwt_verified = False
        analysis.jwt_verify_error = "Not a complete JWT or missing components"
        return

    alg = analysis.jwt_header.get("alg", "unknown")

    if public_key_pem is None:
        analysis.jwt_verified = None
        analysis.jwt_verify_error = f"Signature verification skipped (no public key provided). alg={alg}. This is expected for air-gapped review."
        return

    if not HAS_PYJWT:
        analysis.jwt_verified = False
        analysis.jwt_verify_error = "PyJWT not installed. Install with: pip install PyJWT cryptography"
        return

    analysis.jwt_verified = None
    analysis.jwt_verify_error = f"Full cryptographic verification requires storing original base64 segments (future enhancement). alg={alg}."


def scan_for_sensitive_data(
    texts: Iterable[str],
    *,
    jwt_segments: Sequence[str] | None = None,
    exclude_values: Sequence[str] | None = None,
    raw_bytes: bytes | None = None,
) -> list[SensitiveFinding]:
    findings: list[SensitiveFinding] = []
    seen: set[tuple[str, str]] = set()
    jwt_blob = ".".join(jwt_segments) if jwt_segments else ""
    opaque_literals = [v for v in (exclude_values or []) if v]

    # Text-based scanning
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
                findings.append(SensitiveFinding(category=f"keyword:{keyword}", match=matched, context=_context_snippet(source, match.start(), match.end())))

        for label, pattern in SENSITIVE_PATTERNS:
            for match in pattern.finditer(source):
                matched = match.group(0)
                if label == "high_entropy_base64" and (matched in jwt_blob or matched in opaque_literals):
                    continue
                if label == "ipv4" and matched in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                    continue
                key = (label, matched)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(SensitiveFinding(category=label, match=matched, context=_context_snippet(source, match.start(), match.end())))

    # Binary / steganography analysis (always run on raw data)
    if raw_bytes:
        stego_findings = detect_steganography_indicators(raw_bytes, jwt_token=jwt_blob if jwt_blob else None)
        for indicator in stego_findings:
            findings.append(SensitiveFinding(category="steganography", match=indicator[:80], context="Raw binary analysis"))

    return findings


def _context_snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    snippet = text[left:right]
    if left > 0:
        snippet = "..." + snippet
    if right < len(text):
        snippet = snippet + "..."
    return snippet.replace("\n", "\\n")


def _assess_verdict(analysis: FileAnalysis, *, sensitive_findings: list[SensitiveFinding]) -> tuple[str, str]:
    if not analysis.is_jwt:
        return "review_recommended", "File does not match expected JWT structure."

    if analysis.jwt_errors:
        return "review_recommended", f"JWT decode issues: {'; '.join(analysis.jwt_errors)}"

    if sensitive_findings:
        cats = sorted({f.category for f in sensitive_findings})
        return "review_recommended", f"Sensitive / steganography indicators: {', '.join(cats)}."

    payload = analysis.jwt_payload or {}
    missing = sorted(EXPECTED_VCF_CLAIMS - set(payload.keys()))
    analysis.expected_claims_missing = missing
    analysis.expected_claims_present = sorted(EXPECTED_VCF_CLAIMS & set(payload.keys()))

    if missing:
        return "review_recommended", f"Missing expected VCF 9 claims: {', '.join(missing)}."

    asset_type = str(payload.get("asset_type", ""))
    if asset_type and asset_type != "AC":
        return "review_recommended", f"Unexpected asset_type '{asset_type}' (expected 'AC')."

    if analysis.stego_indicators:
        return "review_recommended", "Steganographic or high-entropy indicators detected in raw data."

    return "clean", "Structure matches expected VCF 9 registration JWT; no obvious sensitive data or steganography detected."


def analyze_vcf_data_file(path: Path, *, head: int | None = None, public_key_pem: str | None = None) -> FileAnalysis:
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

    jwt_parts = extract_potential_jwt(analysis.raw_text_preview)
    jwt_segments: list[str] | None = None

    if jwt_parts:
        analysis.is_jwt = True
        header_b64, payload_b64, sig_b64 = jwt_parts
        analysis.jwt_signature_b64 = sig_b64
        jwt_segments = [header_b64, payload_b64, sig_b64]

        try:
            analysis.jwt_header = decode_jwt_part(header_b64)
        except ValueError as exc:
            analysis.jwt_errors.append(f"header: {exc}")

        try:
            analysis.jwt_payload = decode_jwt_part(payload_b64)
        except ValueError as exc:
            analysis.jwt_errors.append(f"payload: {exc}")

        if analysis.jwt_payload and "xr2" in analysis.jwt_payload:
            xr2_val = analysis.jwt_payload["xr2"]
            if isinstance(xr2_val, str):
                analysis.xr2 = decode_xr2(xr2_val)

        verify_jwt_signature(analysis, public_key_pem=public_key_pem)

    # Always run sensitive + steganography scan on raw data
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
        raw_bytes=data,   # Always pass raw bytes for stego/binary analysis
    )

    # Collect stego indicators separately for verdict
    analysis.stego_indicators = [f.match for f in analysis.sensitive_findings if f.category == "steganography"]

    verdict, reason = _assess_verdict(analysis, sensitive_findings=analysis.sensitive_findings)
    analysis.verdict = verdict
    analysis.verdict_reason = reason

    return analysis


def analyze_license_usage_file(path: Path, *, head: int | None = None) -> FileAnalysis:
    raise NotImplementedError("License Usage File parsing is not yet implemented.")


# ---------------------------------------------------------------------------
# Rendering (unchanged from polished v1.2.0)
# ---------------------------------------------------------------------------


def _verdict_style(verdict: str) -> tuple[str, str, str]:
    if verdict == "clean":
        return ("SAFE TO UPLOAD", "green", "✓")
    return ("REVIEW RECOMMENDED", "yellow", "⚠")


def _section(console: Console, number: int, title: str, style: str = "bold white") -> None:
    console.print()
    console.rule(f"[{style}]{number}. {title}[/{style}]", style="dim")


def render_analysis(analysis: FileAnalysis, console: Console, *, verbose: bool = False) -> None:
    filename = Path(analysis.path).name
    console.print()
    console.print(Panel(f"[bold bright_white]VCF Compliance Inspector[/bold bright_white]  [dim]v{VERSION}[/dim]\n[cyan]{filename}[/cyan]", border_style="bright_cyan", padding=(0, 2)))

    _section(console, 1, "File Information", "bold cyan")
    info = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    info.add_column("Field", style="bold cyan", min_width=12)
    info.add_column("Value", style="white")
    info.add_row("Path", analysis.path)
    info.add_row("Size", f"[white]{analysis.size_bytes:,}[/white] bytes")
    info.add_row("SHA-256", f"[bright_black]{analysis.sha256}[/bright_black]")
    info.add_row("JWT", "[green]Yes[/green]" if analysis.is_jwt else "[yellow]No[/yellow]")
    if analysis.jwt_verified is not None:
        status = "[green]Verified ✓[/green]" if analysis.jwt_verified else "[red]Failed / Skipped[/red]"
        info.add_row("Signature", status)
    console.print(info)

    _section(console, 2, "JWT Structure", "bold blue")
    if analysis.is_jwt:
        console.print(Panel("[bold green]✓ Valid JWT layout detected[/bold green]", border_style="green", padding=(0, 2)))
    else:
        console.print(Panel("[bold yellow]⚠ No JWT structure[/bold yellow]", border_style="yellow", padding=(0, 2)))

    if analysis.jwt_header is not None:
        _section(console, 3, "Decoded Header", "bold blue")
        console.print(Panel(Syntax(json.dumps(analysis.jwt_header, indent=2), "json", theme="monokai"), border_style="blue", padding=(0, 1)))

    if analysis.jwt_payload is not None:
        _section(console, 4, "Decoded Payload", "bold blue")
        payload_for_display = dict(analysis.jwt_payload)
        table = Table(box=box.ROUNDED, show_lines=True, padding=(0, 1))
        table.add_column("Claim", style="bold cyan", min_width=14)
        table.add_column("Value", style="white")

        for key, value in payload_for_display.items():
            if key == "xr2":
                display_val = f"[bold magenta]{value}[/bold magenta]\n[dim]→ see xr2 fingerprint analysis (section 5)[/dim]"
            elif key in EXPECTED_VCF_CLAIMS:
                display_val = json.dumps(value) if not isinstance(value, str) else value
                display_val = f"[white]{display_val}[/white]"
            else:
                display_val = f"[yellow]{json.dumps(value) if not isinstance(value, str) else value}[/yellow]\n[dim]unexpected claim — review manually[/dim]"
            table.add_row(key, display_val)

        console.print(table)

        if verbose:
            console.print(Panel(Syntax(json.dumps(payload_for_display, indent=2), "json", theme="monokai"), title="[dim]Full payload JSON[/dim]", border_style="dim"))

    if analysis.jwt_errors:
        console.print(Panel("\n".join(f"[yellow]•[/yellow] {err}" for err in analysis.jwt_errors), title="[bold yellow]JWT Decode Warnings[/bold yellow]", border_style="yellow", padding=(0, 2)))

    if analysis.jwt_verify_error:
        console.print(Panel(f"[yellow]{analysis.jwt_verify_error}[/yellow]", title="[bold yellow]Signature Verification[/bold yellow]", border_style="yellow", padding=(0, 2)))

    _section(console, 5, "xr2 Fingerprint Analysis", "bold magenta")
    xr2_lines: list[str] = [f"[italic dim]{XR2_EXPLANATION}[/italic dim]", ""]
    if analysis.xr2.present:
        if analysis.xr2.error:
            xr2_lines.append(f"[yellow]Decode error:[/yellow] {analysis.xr2.error}")
        else:
            xr2_lines.append(f"[dim]Decode method:[/dim] [cyan]{analysis.xr2.decode_method}[/cyan]")
            if analysis.xr2.decoded_json is not None:
                xr2_lines.append("[dim]Decoded as JSON:[/dim]")
                xr2_lines.append(json.dumps(analysis.xr2.decoded_json, indent=2))
            elif analysis.xr2.decoded_bytes is not None:
                length = len(analysis.xr2.decoded_bytes)
                xr2_lines.append(f"[dim]Decoded length:[/dim] [white]{length}[/white] bytes [dim](opaque binary)[/dim]")
                sub_hex, _ = pretty_hexdump(analysis.xr2.decoded_bytes[:256], head=256, colorize=not console.no_color)
                xr2_lines.append("")
                xr2_lines.append(sub_hex)
                if length > 256:
                    xr2_lines.append(f"[dim]… {length - 256} more bytes not shown[/dim]")
    else:
        xr2_lines.append("[dim]xr2 claim not present in payload.[/dim]")
    console.print(Panel("\n".join(xr2_lines), border_style="magenta", padding=(0, 2)))

    _section(console, 6, "Sensitive Data Scan", "bold yellow")
    if analysis.sensitive_findings:
        scan_table = Table(title=f"[yellow]{len(analysis.sensitive_findings)} finding(s)[/yellow]", box=box.HEAVY_HEAD, show_lines=True, padding=(0, 1))
        scan_table.add_column("Category", style="bold yellow", min_width=18)
        scan_table.add_column("Match", style="red")
        scan_table.add_column("Context", style="dim", overflow="fold")
        for finding in analysis.sensitive_findings:
            scan_table.add_row(finding.category, finding.match, finding.context)
        console.print(scan_table)
    else:
        console.print(Panel("[bold green]✓ No obvious proprietary or sensitive data detected[/bold green]\n[dim]Keyword and pattern scan + binary steganography analysis performed on raw data.[/dim]", border_style="green", padding=(0, 2)))

    _section(console, 7, "Assurance Boundary", "bold bright_black")
    risk_note = SECURITY_LIMITATIONS
    if RISK_ASSESSMENT_PATH.is_file():
        risk_note += f"\n\n[link=file://{RISK_ASSESSMENT_PATH}]Full risk assessment: RISK_ASSESSMENT.md[/link]"
    console.print(Panel(risk_note, title="[dim]What this tool cannot guarantee[/dim]", border_style="bright_black", padding=(0, 2)))

    _section(console, 8, "Summary & Verdict", "bold white")
    title, color, icon = _verdict_style(analysis.verdict)
    summary_lines = [f"[bold {color}]{icon}  {title}[/bold {color}]", "", analysis.verdict_reason]
    if analysis.expected_claims_present:
        summary_lines.extend(["", f"[dim]Expected claims present:[/dim] [green]{', '.join(analysis.expected_claims_present)}[/green]"])
    if analysis.expected_claims_missing:
        summary_lines.extend(["", f"[dim]Expected claims missing:[/dim] [yellow]{', '.join(analysis.expected_claims_missing)}[/yellow]"])
    if analysis.stego_indicators:
        summary_lines.extend(["", f"[yellow]Steganography / high-entropy indicators found in raw binary data.[/yellow]"])
    console.print(Panel("\n".join(summary_lines), border_style=color, padding=(1, 2)))

    _section(console, 9, "Raw Hex & ASCII (byte-level review)", "bold bright_blue")
    render_raw_hexdump_panel(analysis, console)
    console.print()


def analysis_to_dict(analysis: FileAnalysis) -> dict[str, Any]:
    payload = asdict(analysis)
    if analysis.xr2.decoded_bytes is not None:
        payload["xr2"]["decoded_bytes_hex"] = analysis.xr2.decoded_bytes.hex()
        del payload["xr2"]["decoded_bytes"]
    return payload


def collect_files(paths: Sequence[str], *, file_flag: bool, dir_flag: bool) -> list[Path]:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vcf_compliance_inspector",
        description="Forensic inspector for VMware VCF 9+ Registration .data files (JWT-encoded compliance artifacts). Always analyzes raw binary for steganography.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", help=".data file paths, globs, or directories (with --dir).")
    parser.add_argument("--file", action="append", dest="files", default=[], metavar="PATH", help="Explicit file path (repeatable).")
    parser.add_argument("--dir", action="store_true", help="Glob *.data inside directories.")
    parser.add_argument("--json", metavar="PATH", nargs="?", const="-", help="Write JSON audit report.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full payload JSON etc.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("--head", type=int, metavar="BYTES", help="Limit hexdump to first N bytes.")
    parser.add_argument("--public-key", metavar="PEM_FILE", help="Optional PEM public key for signature verification (advanced).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    all_paths = list(args.paths) + list(args.files)
    if not all_paths:
        parser.print_help()
        return 2

    public_key_pem = None
    if args.public_key:
        try:
            public_key_pem = Path(args.public_key).read_text(encoding="utf-8")
        except Exception as exc:
            print(f"Error reading public key: {exc}", file=sys.stderr)
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
            analysis = analyze_vcf_data_file(file_path, head=args.head, public_key_pem=public_key_pem)
            results.append(analysis)
            if not args.json:
                render_analysis(analysis, console, verbose=args.verbose)
            if analysis.verdict != "clean":
                exit_code = 1
        except OSError as exc:
            console.print(f"[red]Error reading {file_path}: {exc}[/red]")
            exit_code = 2

    if len(files) > 1:
        clean_count = sum(1 for r in results if r.verdict == "clean")
        review_count = len(results) - clean_count
        console.print()
        console.print(Panel(f"[bold]Batch complete:[/bold] {len(results)} files  |  [green]{clean_count} clean[/green]  |  [yellow]{review_count} need review[/yellow]", border_style="bright_cyan", padding=(0, 2)))

    if args.json:
        report = {"tool": "vcf_compliance_inspector", "version": VERSION, "files": [analysis_to_dict(a) for a in results]}
        json_text = json.dumps(report, indent=2)
        if args.json == "-":
            print(json_text)
        else:
            Path(args.json).write_text(json_text, encoding="utf-8")
            console.print(f"[green]JSON audit report written to {args.json}[/green]")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
