"""Basic pytest suite for VCF Compliance Inspector core functions.

Run with: pytest tests/ -q
"""

import json
from pathlib import Path

import pytest

from vcf_compliance_inspector import (
    b64url_decode,
    decode_jwt_part,
    extract_potential_jwt,
    decode_xr2,
    scan_for_sensitive_data,
    _assess_verdict,
    FileAnalysis,
    Xr2Analysis,
    SensitiveFinding,
)


SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def test_b64url_decode_basic():
    segment = "eyJhbGciOiJub25lIn0"  # {"alg":"none"}
    decoded = b64url_decode(segment)
    assert json.loads(decoded) == {"alg": "none"}


def test_b64url_decode_with_padding_needed():
    segment = "eyJ0eXAiOiJKV1QifQ"  # {"typ":"JWT"}
    decoded = b64url_decode(segment)
    assert b"typ" in decoded


def test_extract_potential_jwt_clean():
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.signature"
    parts = extract_potential_jwt(token)
    assert parts is not None
    assert len(parts) == 3


def test_extract_potential_jwt_with_surrounding_text():
    text = "header\neyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.sig\ntrailing"
    parts = extract_potential_jwt(text)
    assert parts is not None
    assert len(parts) == 3

def test_extract_potential_jwt_none():
    assert extract_potential_jwt("not a jwt") is None
    assert extract_potential_jwt("only.two.parts") is None

def test_scan_for_sensitive_data_excludes_jwt():
    jwt = "eyJhbGciOiJub25lIn0.eyJ4cjIiOiJsb25nYmFzZTY0dmFsdWUifQ.sig"
    findings = scan_for_sensitive_data([jwt], jwt_segments=jwt.split("."))
    high_entropy = [f for f in findings if f.category == "high_entropy_base64"]
    assert len(high_entropy) == 0

def test_assess_verdict_missing_claims():
    analysis = FileAnalysis(
        path="test.data",
        sha256="abc",
        size_bytes=100,
        is_jwt=True,
        jwt_payload={"model_version": "1.0"},
    )
    verdict, reason = _assess_verdict(analysis, sensitive_findings=[])
    assert verdict == "review_recommended"
    assert "Missing expected VCF 9 claims" in reason


def test_decode_xr2_base64url_json():
    # Simulate a typical xr2 that decodes to JSON
    fake_xr2 = "eyJ0ZXN0IjogInZhbHVlIn0"  # base64url of {"test": "value"}
    result = decode_xr2(fake_xr2)
    assert result.present is True
    assert result.decode_method in ("base64url", "base64")
    assert result.decoded_json == {"test": "value"}
    assert result.error is None

def test_decode_xr2_opaque_binary():
    # Non-JSON, non-UTF8 or random bytes -> should still return decoded_bytes
    # Using a value that won't decode cleanly to JSON
    fake_xr2 = "AQIDBAUGBwgJCgsMDQ4PEA"
    result = decode_xr2(fake_xr2)
    assert result.present is True
    assert result.decoded_bytes is not None
    assert result.decoded_json is None  # not valid JSON

def test_decode_xr2_invalid():
    result = decode_xr2("!!!not-valid-base64!!!")
    assert result.present is True
    assert result.error is not None
    assert "Could not decode" in result.error

def test_sample_clean_file_exists():
    clean = SAMPLES_DIR / "Registration-clean-2025-06-24T12_00_00Z.data"
    assert clean.exists()

# Note: Full integration tests with rendering can be added later with capsys or golden files.
