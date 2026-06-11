# Risk Assessment: Sharing VCF Compliance Artifacts with Broadcom

**Document type:** Security and privacy risk assessment  
**Audience:** Security officers, compliance teams, and operators in air-gapped / DoD environments  
**Tool scope:** `vcf_compliance_inspector.py` (VCF 9+ Registration `*.data` files)  
**Last updated:** 2026-06-11

---

## Executive Summary (Updated)

The VCF Compliance Inspector now performs **deep binary analysis on raw data** in addition to JWT decoding. When JWT payload or header decoding fails, the tool **automatically enters aggressive mode**, applying more sensitive entropy thresholds, null-byte detection, and steganography heuristics. This significantly improves detection of hidden or encoded data even in malformed files.

A clean verdict now means: no obvious sensitive patterns **and** no high-entropy, appended, or steganographic indicators were found in the raw binary.

---

## New Capability: Steganography & Binary Analysis

The tool now detects:
- Data appended after a valid JWT
- High-entropy regions (possible encrypted/compressed payloads)
- Embedded magic bytes (ZIP, PNG, PDF, PE, Gzip, etc.)
- Multiple layers of base64 encoding
- Unusual null bytes in text areas

These checks run on **every file**, with expanded sensitivity when normal JWT decoding fails.

This directly addresses the risk of data exfiltration via steganography or encoding tricks in compliance artifacts.

---

## Recommendations

- Review any file that triggers steganography or high-entropy warnings, even if the JWT structure looks mostly valid.
- Retain the JSON audit report (which now includes stego indicators) for compliance records.

The rest of the original risk assessment remains valid.
