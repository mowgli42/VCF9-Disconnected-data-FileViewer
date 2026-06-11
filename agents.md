# VCF9-Disconnected-data-FileViewer — Agent Operating Guide

## Project Mission
Forensic, read-only CLI tool for inspecting VMware VCF 9+ Registration `*.data` JWT files before upload in disconnected/air-gapped environments. Primary goals: dual-view visibility (decoded claims + raw hex), `xr2` transparency, sensitive-data scanning, and explicit assurance boundaries. Supports trust-but-verify workflows for compliance teams (especially DoD/aerospace).

## Core Architecture
- **Entry**: `main()` → `collect_files()` → `analyze_vcf_data_file()` per file → `render_analysis()` or JSON export.
- **Data Model**: `FileAnalysis` dataclass + nested `Xr2Analysis` and `SensitiveFinding`.
- **Decoding**: Manual base64url (`b64url_decode` + padding) + `json.loads`. No signature verification (intentional).
- **Scanning**: Keyword list + regex patterns with smart exclusions (JWT blob itself and `xr2` value excluded from high-entropy matching).
- **Rendering**: Rich panels/tables/syntax. Always ends with raw hexdump (section 9). Graceful plain-text fallback.
- **Extensibility**: `COMPLIANCE_ANALYZERS` registry + placeholder `analyze_license_usage_file()`.
- **Safety**: Never writes input files, no network, SHA-256 for auditability.

## Key Design Decisions & Trade-offs
- Manual JWT decode chosen to avoid external crypto deps and key management in air-gapped contexts.
- `rich` is the only optional dependency (graceful fallback exists via `no_color`).
- Verdict logic combines structural checks (expected claims, asset_type=="AC") + sensitive findings. "Clean" is strong but not absolute.
- Hexdump is always last so analysts finish with byte-level truth.
- `xr2` is decoded when possible but always accompanied by the official Broadcom explanation that it is an opaque fingerprint.

## How to Extend
- **New artifact types** (License Usage File, confirmation files): Implement analyzer function and register in `COMPLIANCE_ANALYZERS`. Wire dispatch in `main()`.
- **Stronger validation**: Add optional jsonschema or stricter dataclass validation behind a flag.
- **TUI**: Textual-based interactive mode for exploring batches.
- **Scanner tuning**: Adjust `SENSITIVE_KEYWORDS` / `SENSITIVE_PATTERNS` or add entropy thresholds. Update tests.
- **Synthetic test data**: Expand `samples/` with new scenarios (malformed xr2, unexpected claims, etc.).

## Testing Expectations
- At minimum: pytest covering `b64url_decode`, `decode_jwt_part`, `scan_for_sensitive_data`, `_assess_verdict`, and `decode_xr2`.
- Use the existing synthetic samples in `samples/`.
- For real customer `.data` files: never commit them; test locally only.
- Golden output tests for terminal rendering are valuable but secondary.

## Security Model (Non-Negotiable)
- Read-only forensic inspection only.
- Explicit "Assurance Boundary" panel on every run (links to RISK_ASSESSMENT.md).
- Scanner is a heuristic triage tool, not a formal proof of absence of secrets.
- Never claim the tool verifies Broadcom-side opacity of `xr2` or performs signature validation.

## Documentation Standards
- Keep `README.md` user-focused with examples and output samples.
- Keep `RISK_ASSESSMENT.md` as the authoritative source for residual risks, limitations, and operator recommendations.
- Update `agents.md` whenever architecture or extension points change.
- Code must have clear docstrings; complex functions should have usage examples in the module docstring.

## Common Pitfalls to Avoid
- Overly aggressive JWT detection that assumes clean single-line content.
- Forgetting to exclude JWT segments / `xr2` from high-entropy scanning → noisy false positives.
- Making the tool write files or perform network operations.
- Weakening the "hexdump always last" principle.
- Treating a "clean" verdict as sufficient for high-assurance/classified programs without human review.

## Current Roadmap Snapshot (update after sessions)
- v1.1.0: Core registration file support + excellent docs (current)
- Next: Robust JWT extraction, batch summary, License Usage File hook wiring, tests/, agents.md
- Future: Stronger schema validation, TUI mode, tighter integration with user’s other tooling (Sentinel-style)

## References (keep current)
- VMware VCF 9.0 Licensing blog & Broadcom TechDocs (disconnected registration & usage files)
- RISK_ASSESSMENT.md in this repo
- Original prompt used to generate v1.x

This project prioritizes **pragmatic defense-in-depth** over perfect guarantees. Every change should preserve that character.