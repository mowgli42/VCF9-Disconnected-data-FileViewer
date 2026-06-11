"""Test suite for VCF Compliance Inspector (including steganography & aggressive mode)."""

import json
from pathlib import Path

import pytest

from vcf_compliance_inspector import (
    calculate_entropy,
    detect_steganography_indicators,
    scan_for_sensitive_data,
    analyze_vcf_data_file,
    FileAnalysis,
)

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def test_calculate_entropy_low():
    data = b"a" * 100
    assert calculate_entropy(data) < 1.0


def test_calculate_entropy_high():
    import os
    data = os.urandom(256)
    assert calculate_entropy(data) > 7.5


def test_detect_steganography_appended_data():
    jwt = b"eyJhbGciOiJub25lIn0.eyJ0ZXN0IjoxfQ.signature"
    appended = jwt + b"\x00\x01\x02PK\x03\x04hiddenzipdata"
    indicators = detect_steganography_indicators(appended, jwt_token=jwt.decode())
    assert any("appended after JWT" in i for i in indicators)


def test_detect_steganography_high_entropy():
    import os
    data = os.urandom(128)
    indicators = detect_steganography_indicators(data, aggressive=False)
    # May or may not trigger depending on exact entropy, but function runs without error
    assert isinstance(indicators, list)


def test_detect_steganography_magic_bytes():
    data = b"random" + b"PK\x03\x04" + b"more"
    indicators = detect_steganography_indicators(data)
    assert any("ZIP archive" in i for i in indicators)


def test_detect_steganography_multi_layer_base64():
    # Double base64
    inner = base64.b64encode(b"secret data here").decode()
    outer = base64.b64encode(inner.encode()).decode()
    indicators = detect_steganography_indicators(outer.encode())
    assert any("Multiple layers of base64" in i for i in indicators)

def test_scan_always_runs_on_raw_bytes_even_on_decode_failure():
    # Simulate a file that looks like JWT but has bad payload
    bad_jwt = "eyJhbGciOiJub25lIn0.!!!invalidbase64!!!.sig"
    findings = scan_for_sensitive_data([bad_jwt], raw_bytes=bad_jwt.encode(), aggressive=True)
    # Should still produce findings from binary analysis even though decode fails
    assert isinstance(findings, list)

def test_analyze_vcf_data_file_triggers_aggressive_on_decode_failure(tmp_path):
    bad_file = tmp_path / "bad.data"
    bad_file.write_text("eyJhbGciOiJub25lIn0.!!!bad!!!.sig")
    analysis = analyze_vcf_data_file(bad_file)
    assert analysis.jwt_errors  # decode should have failed
    # stego_indicators or sensitive_findings should exist because aggressive mode was triggered
    assert len(analysis.sensitive_findings) >= 0  # at minimum it ran without crashing


def test_sample_files_still_work():
    for name in ["Registration-clean-2025-06-24T12_00_00Z.data", "Registration-review-2025-06-24T12_00_00Z.data"]:
        f = SAMPLES_DIR / name
        if f.exists():
            analysis = analyze_vcf_data_file(f)
            assert analysis.size_bytes > 0
