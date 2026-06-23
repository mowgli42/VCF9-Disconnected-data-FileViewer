"""Tests for hex annotations, no-wrap hexdump, and xr2 explanation."""

import re
from pathlib import Path

from vcf_compliance_inspector import (
    XR2_EXPLANATION,
    XR2_PURPOSE_DETAIL,
    analyze_vcf_data_file,
    compute_jwt_byte_ranges,
    decode_xr2,
    pretty_hexdump,
    _hexdump_panel_width,
)

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def test_compute_jwt_byte_ranges_finds_header_payload_signature():
    token = "eyJhbGciOiJub25lIn0.eyJ0ZXN0IjoxfQ.c2ln"
    data = token.encode("utf-8")
    ranges = compute_jwt_byte_ranges(data, token, {"test": 1})
    labels = {r.label for r in ranges}
    assert {"header", "payload", "signature"}.issubset(labels)


def test_pretty_hexdump_applies_annotation_styles():
    data = b"eyJ0ZXN0"
    from vcf_compliance_inspector import HexAnnotation

    annotations = [HexAnnotation(0, len(data), "header", "bold cyan")]
    rendered, _ = pretty_hexdump(data, colorize=True, annotations=annotations)
    assert "[bold cyan]" in rendered


def test_hexdump_panel_width_strips_markup():
    markup = "[bold cyan]00000000[/bold cyan]  [blue]65[/blue]"
    width = _hexdump_panel_width(markup)
    plain = re.sub(r"\[[^\]]*\]", "", markup)
    assert width >= len(plain)


def test_decode_xr2_includes_purpose():
    result = decode_xr2("dGVzdA==")
    assert result.purpose == XR2_PURPOSE_DETAIL
    assert result.present


def test_analyze_sample_populates_jwt_byte_ranges():
    sample = SAMPLES_DIR / "Registration-clean-2025-06-24T12_00_00Z.data"
    if not sample.exists():
        return
    analysis = analyze_vcf_data_file(sample)
    assert analysis.is_jwt
    assert analysis.jwt_byte_ranges
    labels = {r.label for r in analysis.jwt_byte_ranges}
    assert "header" in labels and "payload" in labels


def test_xr2_explanation_strings_are_documented():
    assert "fingerprint" in XR2_EXPLANATION.lower()
    assert "asset_id" in XR2_PURPOSE_DETAIL or "usage" in XR2_PURPOSE_DETAIL.lower()
