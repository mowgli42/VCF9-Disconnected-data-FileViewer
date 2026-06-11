# VCF9-Disconnected-data-FileViewer — Agent Operating Guide

## Project Mission
Forensic, read-only CLI tool for inspecting VMware VCF 9+ Registration `*.data` JWT files before upload in disconnected/air-gapped environments. Primary goals: dual-view visibility (decoded claims + raw hex), `xr2` transparency, sensitive-data scanning, **and automatic expanded binary/steganography analysis when JWT decoding fails**.

## Core Architecture Updates (v1.2.1)
- `detect_steganography_indicators()` + `calculate_entropy()` added.
- `scan_for_sensitive_data()` now always receives `raw_bytes` and an `aggressive` flag.
- When `jwt_errors` exist or the file is not a valid JWT, **aggressive mode is automatically enabled** (lower entropy threshold, more sensitive null-byte detection).
- Steganography findings are categorized separately and influence the final verdict.

## Key Design Decisions
- We **always** analyze the raw binary, even on complete decode failure. This is the correct behavior for a forensic tool.
- Aggressive mode is triggered automatically on decode problems rather than requiring a separate flag (keeps CLI simple while maximizing detection power).
- Entropy, magic bytes, appended data, and multi-layer base64 are the primary steganography signals implemented.

## Extension Points
- Improve `detect_steganography_indicators()` with more sophisticated steganalysis (e.g., statistical tests, machine learning).
- Add a `--aggressive` CLI flag to force expanded search even on clean JWTs.
- Store original base64 segments in `FileAnalysis` to enable real cryptographic signature verification when a public key is supplied.

## Testing
- New tests cover entropy calculation, steganography detection (appended data, magic bytes, multi-layer base64), and the automatic aggressive mode trigger on decode failure.

## Security Model
The tool now provides stronger defense-in-depth by treating every file as potentially containing hidden data in its raw binary form, not just in the decoded JWT claims.

## Current Roadmap
- v1.2.1: Automatic aggressive steganography/entropy analysis on decode failure (current)
- Future: Stronger steganalysis, optional real signature verification, TUI mode

Keep this document updated after every significant change.