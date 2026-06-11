#!/usr/bin/env python3
"""Regenerate colored CLI captures and HTML exports for README documentation."""

from __future__ import annotations

import json
import re
import sys
from io import StringIO
from pathlib import Path

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

from rich.console import Console

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vcf_compliance_inspector import (  # noqa: E402
    VERSION,
    analyze_vcf_data_file,
    analysis_to_dict,
    render_analysis,
)

OUT = ROOT / "docs" / "outputs"

SAMPLES: list[tuple[str, str]] = [
    ("registration-clean", "samples/Registration-clean-2025-06-24T12_00_00Z.data"),
    ("registration-review", "samples/Registration-review-2025-06-24T12_00_00Z.data"),
    ("registration-malformed", "samples/Registration-malformed-2025-06-24T12_00_00Z.data"),
    ("not-a-jwt-placeholder", "samples/not-a-jwt-placeholder.data"),
]


def _plain(line: str) -> str:
    return ANSI_ESCAPE.sub("", line)


def _line_index(lines: list[str], needle: str, *, start: int = 0) -> int | None:
    for i in range(start, len(lines)):
        if needle in _plain(lines[i]):
            return i
    return None


def build_excerpt(full: str, slug: str) -> str:
    """Build a short, README-friendly excerpt with header, key section, verdict, hex."""
    lines = full.splitlines()
    chunks: list[str] = []

    header_start = _line_index(lines, "VCF Compliance Inspector")
    jwt_start = _line_index(lines, "2. JWT Structure")
    verdict_start = _line_index(lines, "8. Summary & Verdict")
    hex_start = _line_index(lines, "9. Raw Hex & ASCII")

    if header_start is not None and jwt_start is not None:
        chunks.append("\n".join(lines[header_start : jwt_start + 4]))

    if slug == "registration-review":
        scan_start = _line_index(lines, "6. Sensitive Data Scan")
        if scan_start is not None:
            scan_end = _line_index(lines, "7. Assurance Boundary", start=scan_start)
            if scan_end is not None:
                chunks.append("\n".join(lines[scan_start:scan_end]))

    if slug == "registration-malformed":
        warn_start = _line_index(lines, "JWT Decode Warnings")
        if warn_start is not None:
            chunks.append("\n".join(lines[warn_start : warn_start + 6]))

    if verdict_start is not None:
        hex_line = hex_start if hex_start is not None else len(lines)
        chunks.append("\n".join(lines[verdict_start : min(verdict_start + 12, hex_line)]))

    if hex_start is not None:
        chunks.append("\n".join(lines[hex_start : hex_start + 14]))

    return "\n\n".join(chunks)


def capture_ansi(slug: str, sample_rel: str) -> tuple[str, str]:
    """Return (full_ansi_text, verdict) for a sample file."""
    path = ROOT / sample_rel
    analysis = analyze_vcf_data_file(path)
    buffer = StringIO()
    console = Console(
        file=buffer,
        record=True,
        width=110,
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
    )
    render_analysis(analysis, console)
    full = buffer.getvalue()
    (OUT / f"{slug}.ansi").write_text(full, encoding="utf-8")
    (OUT / f"{slug}.excerpt.ansi").write_text(build_excerpt(full, slug), encoding="utf-8")
    console.save_svg(str(OUT / f"{slug}.svg"), title=slug)
    console.save_html(str(OUT / f"{slug}.html"), inline_styles=True)
    return full, analysis.verdict


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, str]] = []

    for slug, rel in SAMPLES:
        _, verdict = capture_ansi(slug, rel)
        manifest.append({"slug": slug, "sample": rel, "verdict": verdict})

    audit = {
        "tool": "vcf_compliance_inspector",
        "version": VERSION,
        "files": [analysis_to_dict(analyze_vcf_data_file(ROOT / rel)) for _, rel in SAMPLES],
    }
    (OUT / "samples-audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote captures to {OUT} ({len(SAMPLES)} samples)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
