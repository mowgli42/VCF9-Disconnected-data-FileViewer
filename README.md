# VCF9 Disconnected Data File Viewer

Forensic CLI for safely reviewing VMware Cloud Foundation (VCF) 9+ **Registration `*.data`** files before upload in disconnected / air-gapped environments.

The `.data` artifact is a JWT containing registration metadata (including the opaque `xr2` fingerprint). This tool decodes and inspects those files locally — **no network access, no file modification** — so operators can trust-but-verify that nothing sensitive is present before sending artifacts to Broadcom.

For residual risks, assurance boundaries, and what a “clean” verdict does **not** guarantee, see **[RISK_ASSESSMENT.md](RISK_ASSESSMENT.md)**.

## Quick start

```bash
pip install -r requirements.txt

# Try the included sample files
python vcf_compliance_inspector.py samples/ --dir

# Inspect your own registration file
python vcf_compliance_inspector.py Registration-*.data
```

## What it does

| Capability | Description |
|------------|-------------|
| **SHA-256 audit hash** | Per-file digest for change tracking and SIEM logs |
| **JWT decode** | Manual base64url + JSON decode of header and payload (no signature verification) |
| **`xr2` analysis** | Decodes the opaque fingerprint; explains Broadcom’s non-identifying design |
| **Sensitive-data scan** | Keywords + regex (email, IP, internal hostnames, PEM headers, etc.) |
| **Assurance boundary** | Explicit panel on what the tool cannot guarantee (links to risk assessment) |
| **Raw hex & ASCII** | **Always shown last** — full byte-level review with colorized offset / hex / ASCII |
| **Verdict** | `SAFE TO UPLOAD` (green) or `REVIEW RECOMMENDED` (yellow) |

## Report layout (terminal)

Each file is analyzed in **nine numbered sections**. High-level decode and scans come first; the **raw hex/ASCII dump is always section 9** so reviewers finish with byte-level visibility.

| # | Section | Description |
|---|---------|-------------|
| 1 | File Information | Path, size, SHA-256, JWT yes/no |
| 2 | JWT Structure | Valid three-segment layout or warning |
| 3 | Decoded Header | Syntax-highlighted JSON (when decodable) |
| 4 | Decoded Payload | Claims table; `xr2` highlighted in magenta |
| 5 | xr2 Fingerprint Analysis | Opaque fingerprint decode + vendor context |
| 6 | Sensitive Data Scan | Findings table or green “no issues” panel |
| 7 | Assurance Boundary | Tool limitations; link to `RISK_ASSESSMENT.md` |
| 8 | Summary & Verdict | `SAFE TO UPLOAD` or `REVIEW RECOMMENDED` |
| 9 | **Raw Hex & ASCII** | Colorized hexdump (full file, or `--head N` truncated) |

## CLI usage

```bash
python vcf_compliance_inspector.py Registration-*.data
python vcf_compliance_inspector.py /path/to/compliance/ --dir --json audit-report.json
python vcf_compliance_inspector.py file.data --head 1024 --verbose
python vcf_compliance_inspector.py --help
```

| Flag | Purpose |
|------|---------|
| `--file PATH` | Explicit file path (repeatable) |
| `--dir` | Treat paths as directories; glob `*.data` inside |
| `--json [PATH]` | Machine-readable audit report (`-` = stdout) |
| `--verbose` / `-v` | Extra detail (full payload JSON) |
| `--no-color` | Plain terminal output |
| `--head BYTES` | Limit hexdump (section 9) to first *N* bytes |

**Exit codes:** `0` = all files clean; `1` = at least one file needs review; `2` = input/read error.

## Risk assessment

**[RISK_ASSESSMENT.md](RISK_ASSESSMENT.md)** documents:

- All compliance artifacts exchanged with Broadcom (registration, usage, license, confirmation files)
- Residual security concerns (correlation IDs, `asset_name` leakage, opaque `xr2`, transfer-path risks)
- Security measures this tool implements
- What the tool **cannot** identify or guarantee (signature verification, vendor-side inference, usage files, legal adequacy)
- Recommendations for air-gapped and high-assurance environments

The CLI **Assurance Boundary** panel (section 7) summarizes these limits on every run.

## Sample files

The `samples/` directory contains **synthetic demo files only** — not real customer data.

| File | Scenario | Expected verdict |
|------|----------|------------------|
| `Registration-clean-2025-06-24T12_00_00Z.data` | Valid VCF 9 registration JWT with all expected claims | **SAFE TO UPLOAD** |
| `Registration-review-2025-06-24T12_00_00Z.data` | Valid JWT but includes email, internal hostname, and IPv4 in a `notes` field | **REVIEW RECOMMENDED** |
| `Registration-malformed-2025-06-24T12_00_00Z.data` | Three JWT segments, but payload is not valid base64/JSON | **REVIEW RECOMMENDED** (decode warnings) |
| `not-a-jwt-placeholder.data` | Plain text, not a JWT | **REVIEW RECOMMENDED** (sections 1–2, 6–9 only; no decoded claims) |

```bash
python vcf_compliance_inspector.py samples/Registration-clean-2025-06-24T12_00_00Z.data
python vcf_compliance_inspector.py samples/Registration-review-2025-06-24T12_00_00Z.data
python vcf_compliance_inspector.py samples/ --dir --json audit-report.json
```

## Sample output formats

### Terminal (clean file — abbreviated)

Analysis flows through decode/scan sections **first**; raw bytes appear **last** (section 9).

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ VCF Compliance Inspector  v1.1.0                                             │
│ Registration-clean-2025-06-24T12_00_00Z.data                                 │
╰──────────────────────────────────────────────────────────────────────────────╯

──────────────────────────── 1. File Information ─────────────────────────────
╭──────────────┬───────────────────────────────────────────────────────────────╮
│ Path         │ .../samples/Registration-clean-2025-06-24T12_00_00Z.data      │
│ Size         │ 392 bytes                                                     │
│ SHA-256      │ 02493780d54906d39f35620587c5be3b402aff91f44d20aaaf11b307...   │
│ JWT          │ Yes                                                           │
╰──────────────┴───────────────────────────────────────────────────────────────╯

───────────────────────────── 2. JWT Structure ──────────────────────────────
╭──────────────────────────────────────────────────────────────────────────────╮
│ ✓ Valid JWT layout detected                                                  │
│ Three dot-separated segments: header.payload.signature                       │
╰──────────────────────────────────────────────────────────────────────────────╯

... sections 3–6: decoded header, payload table, xr2 analysis, sensitive scan ...

──────────────────────────── 7. Assurance Boundary ───────────────────────────
╭──────────────────── What this tool cannot guarantee ─────────────────────────╮
│ This tool performs local, read-only inspection. It does not verify JWT       │
│ signatures, prove that opaque fields (xr2, UUIDs) cannot be correlated...     │
│ Full risk assessment: RISK_ASSESSMENT.md                                       │
╰──────────────────────────────────────────────────────────────────────────────╯

────────────────────────── 8. Summary & Verdict ───────────────────────────────
╭──────────────────────────────────────────────────────────────────────────────╮
│ ✓  SAFE TO UPLOAD                                                            │
│ Structure matches expected VCF 9 registration JWT; no obvious sensitive    │
│ data detected.                                                               │
╰──────────────────────────────────────────────────────────────────────────────╯

────────────── 9. Raw Hex & ASCII (byte-level review) ───────────────────────
╭────────────────────────── Raw Hex & ASCII Dump ──────────────────────────────╮
│ Offset    Hex                                              ASCII             │
│ ──────────────────────────────────────────────────────────────────────────── │
│ 00000000  65 79 4a 68 62 47 63 69 4f 69 4a 75 62 32 35 6c  │eyJhbGciOiJub25l│
│ 00000010  49 69 77 69 64 48 6c 77 49 6a 6f 69 53 6c 64 55  │IiwidHlwIjoiSldU│
│ ...                                                                          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Terminal (needs review — sensitive data, section 6)

```
────────────────────────── 6. Sensitive Data Scan ─────────────────────────────
                     3 finding(s)
╭───────────────────┬──────────────────────────┬───────────────────────────────╮
│ Category          │ Match                    │ Context                       │
├───────────────────┼──────────────────────────┼───────────────────────────────┤
│ email             │ admin@acme.corp.internal │ ..."notes": "Contact admin@...│
│ ipv4              │ 10.42.0.15               │ ...or 10.42.0.15 before..."}  │
│ internal_hostname │ acme.corp.internal       │ ...admin@acme.corp.internal...│
╰───────────────────┴──────────────────────────┴───────────────────────────────╯

────────────────────────── 8. Summary & Verdict ───────────────────────────────
│ ⚠  REVIEW RECOMMENDED                                                        │
│ Sensitive-data scanner flagged potential items: email, internal_hostname, ipv4.│
```

### Terminal (not a JWT — hexdump still at end)

```
───────────────────────────── 2. JWT Structure ──────────────────────────────
│ ⚠ No JWT structure                                                           │
│ Decoded claims unavailable — review raw hex dump at end of report.           │

... sections 6–8 ...

────────────── 9. Raw Hex & ASCII (byte-level review) ───────────────────────
│ 00000000  43 4f 52 52 55 50 54 45 44 20 4f 52 20 4e 4f 4e  │CORRUPTED OR NON│
│ ...                                                                          │
```

### JSON audit report (`--json`)

```json
{
  "tool": "vcf_compliance_inspector",
  "version": "1.1.0",
  "files": [
    {
      "path": "/workspace/samples/Registration-clean-2025-06-24T12_00_00Z.data",
      "sha256": "02493780d54906d39f35620587c5be3b402aff91f44d20aaaf11b307d115ece2",
      "verdict": "clean",
      "sensitive_findings": [],
      "hexdump": "00000000  65 79 4a 68 ...",
      "hexdump_truncated": false
    }
  ]
}
```

## References

- [Licensing in VMware Cloud Foundation 9.0](https://blogs.vmware.com/cloud-foundation/2025/06/24/licensing-in-vmware-cloud-foundation-9-0/) — disconnected mode and `.data` artifacts
- [What's inside the VCF 9 license file](https://www.linkedin.com/pulse/whats-inside-vcf-9-license-file-understanding-connected-kusek-95gfc) — JWT structure and `xr2` fingerprint
- [Register VCF Operations in disconnected mode](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/vcf-9-0-and-later/9-0/licensing/register-vcf-operations/register-vcf-operations-in-disconnected-mode.html) — Broadcom TechDocs

## License

See [LICENSE](LICENSE).
