"""Basic pytest suite for VCF Compliance Inspector core functions."""

import json
from pathlib import Path

import pytest

from vcf_compliance_inspector import (
    b64url_decode,
    decode_jwt_part,
    extract_potential_jwt,
    scan_for_sensitive_data,
    _assess_verdict,
    FileAnalysis,
    SensitiveFinding,
)


SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def test_b64url_decode_basic():
    # Standard JWT-like segment (header example)
    segment = "eyJhbGciOiJub25lIn0"  # {"alg":"none"}
    decoded = b64url_decode(segment)
    assert json.loads(decoded) == {"alg": "none"}


def test_b64url_decode_with_padding_needed():
    # Segment that requires padding
    segment = "eyJ0eXAiOiJKV1QifQ"  # {"typ":"JWT"}
    decoded = b64url_decode(segment)
    assert b"typ" in decoded


def test_extract_potential_jwt_clean():
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.signature"
    parts = extract_potential_jwt(token)
    assert parts is not None
    assert len(parts) == 3
    assert parts[0].startswith("eyJhbGci")

def test_extract_potential_jwt_with_surrounding_text():
    text = "Some header text\n" + "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.sig" + "\ntrailing"
    parts = extract_potential_jwt(text)
    assert parts is not None
    assert len(parts) == 3

def test_extract_potential_jwt_none():
    assert extract_potential_jwt("not a jwt at all") is None
    assert extract_potential_jwt("two.parts.only") is None

def test_scan_for_sensitive_data_excludes_jwt():
    jwt = "eyJhbGciOiJub25lIn0.eyJ4cjIiOiJsb25nYmFzZTY0dmFsdWUifQ.sig"
    findings = scan_for_sensitive_data([jwt], jwt_segments=jwt.split("."))
    # Should not flag the long base64 in the token itself
    high_entropy = [f for f in findings if f.category == "high_entropy_base64"]
    assert len(high_entropy) == 0

def test_assess_verdict_missing_claims():
    analysis = FileAnalysis(
        path="test.data",
        sha256="abc",
        size_bytes=100,
        is_jwt=True,
        jwt_payload={"model_version": "1.0"},  # missing several expected
    )
    verdict, reason = _assess_verdict(analysis, sensitive_findings=[])
    assert verdict == "review_recommended"
    assert "Missing expected VCF 9 claims" in reason

def test_sample_clean_file_exists():
    clean = SAMPLES_DIR / "Registration-clean-2025-06-24T12_00_00Z.data"
    assert clean.exists(), "Synthetic clean sample missing"

# Note: Full end-to-end tests with rich rendering are better done manually
# or with golden file comparison in a future iteration.
