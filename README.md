# VCF9 Disconnected Data File Viewer

Forensic CLI for safely reviewing VMware Cloud Foundation (VCF) 9+ **Registration `*.data`** files before upload in disconnected / air-gapped environments.

The `.data` artifact is a JWT containing registration metadata (including the opaque `xr2` fingerprint). This tool decodes and inspects those files locally — **no network access, no file modification** — so operators can trust-but-verify that nothing sensitive is present before sending artifacts to Broadcom.

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
| **Raw hexdump** | Offset / hex / ASCII view of the full file (`--head N` to truncate) |
| **JWT decode** | Manual base64url + JSON decode of header and payload (no signature verification) |
| **`xr2` analysis** | Decodes the opaque fingerprint; explains Broadcom’s non-identifying design |
| **Sensitive-data scan** | Keywords + regex (email, IP, internal hostnames, PEM headers, etc.) |
| **Verdict** | `SAFE TO UPLOAD` (green) or `REVIEW RECOMMENDED` (yellow) |

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
| `--head BYTES` | Limit hexdump to first *N* bytes |

**Exit codes:** `0` = all files clean; `1` = at least one file needs review; `2` = input/read error.

## Sample files

The `samples/` directory contains **synthetic demo files only** — not real customer data. Use them to see how the tool behaves:

| File | Scenario | Expected verdict |
|------|----------|------------------|
| `Registration-clean-2025-06-24T12_00_00Z.data` | Valid VCF 9 registration JWT with all expected claims | **SAFE TO UPLOAD** |
| `Registration-review-2025-06-24T12_00_00Z.data` | Valid JWT but includes email, internal hostname, and IPv4 in a `notes` field | **REVIEW RECOMMENDED** |
| `Registration-malformed-2025-06-24T12_00_00Z.data` | Three JWT segments, but payload is not valid base64/JSON | **REVIEW RECOMMENDED** (decode warnings) |
| `not-a-jwt-placeholder.data` | Plain text, not a JWT | **REVIEW RECOMMENDED** (hexdump only; no decoded claims) |

```bash
# Clean — full decode + green verdict
python vcf_compliance_inspector.py samples/Registration-clean-2025-06-24T12_00_00Z.data

# Needs review — sensitive-data findings
python vcf_compliance_inspector.py samples/Registration-review-2025-06-24T12_00_00Z.data

# JWT parse error — header decodes, payload fails
python vcf_compliance_inspector.py samples/Registration-malformed-2025-06-24T12_00_00Z.data

# Not a JWT — hexdump + structure warning only
python vcf_compliance_inspector.py samples/not-a-jwt-placeholder.data

# All samples + JSON audit trail
python vcf_compliance_inspector.py samples/ --dir --json audit-report.json
```

## Sample output formats

### Terminal (clean file)

```
─── VCF Compliance Inspector — Registration-clean-2025-06-24T12_00_00Z.data ────

                               File Information
╭─────────┬──────────────────────────────────────────────────────────────────╮
│ Path    │ .../samples/Registration-clean-2025-06-24T12_00_00Z.data         │
│ Size    │ 392 bytes                                                        │
│ SHA-256 │ 02493780d54906d39f35620587c5be3b402aff91f44d20aaaf11b307d115ece2 │
╰─────────┴──────────────────────────────────────────────────────────────────╯

╭──────────────────────────────── Raw Hex Dump ────────────────────────────────╮
│ 00000000  65 79 4a 68 62 47 63 69 4f 69 4a 75 62 32 35 6c  |eyJhbGciOiJub25l|
│ ...                                                                          │
╰──────────────────────────────────────────────────────────────────────────────╯

╭─────────────────────────────── JWT Structure ────────────────────────────────╮
│ JWT structure detected (3 dot-separated segments)                            │
╰──────────────────────────────────────────────────────────────────────────────╯

                                Decoded Payload
╭───────────────┬──────────────────────────────────────────────────────────────╮
│ model_version │ 9.0                                                          │
│ asset_name    │ VCF Operations                                               │
│ asset_type    │ AC                                                           │
│ xr2           │ b3BhcXVlLWRlbW8tZnA  (see xr2 analysis below)              │
╰───────────────┴──────────────────────────────────────────────────────────────╯

╭───────────────────────────── Summary & Verdict ──────────────────────────────╮
│ Verdict: SAFE TO UPLOAD                                                      │
│ Structure matches expected VCF 9 registration JWT; no obvious sensitive data │
│ detected.                                                                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Terminal (needs review — sensitive data)

```
                         Sensitive Data Scan — Findings
╭───────────────────┬──────────────────────────┬───────────────────────────────╮
│ Category          │ Match                    │ Context                       │
├───────────────────┼──────────────────────────┼───────────────────────────────┤
│ email             │ admin@acme.corp.internal │ ..."notes": "Contact admin@...│
│ ipv4              │ 10.42.0.15               │ ...or 10.42.0.15 before..."}  │
│ internal_hostname │ acme.corp.internal       │ ...admin@acme.corp.internal...│
╰───────────────────┴──────────────────────────┴───────────────────────────────╯

╭───────────────────────────── Summary & Verdict ──────────────────────────────╮
│ Verdict: REVIEW RECOMMENDED                                                  │
│ Sensitive-data scanner flagged potential items: email, internal_hostname,  │
│ ipv4.                                                                        │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Terminal (not a JWT — hexdump only)

```
╭─────────────────────────────── JWT Structure ────────────────────────────────╮
│ No valid JWT structure detected (expected header.payload.signature)          │
╰──────────────────────────────────────────────────────────────────────────────╯

╭───────────────────────────── Summary & Verdict ──────────────────────────────╮
│ Verdict: REVIEW RECOMMENDED                                                  │
│ File does not match expected JWT structure (three dot-separated segments).   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### JSON audit report (`--json`)

```json
{
  "tool": "vcf_compliance_inspector",
  "version": "1.0.0",
  "files": [
    {
      "path": "/workspace/samples/Registration-clean-2025-06-24T12_00_00Z.data",
      "sha256": "02493780d54906d39f35620587c5be3b402aff91f44d20aaaf11b307d115ece2",
      "size_bytes": 392,
      "is_jwt": true,
      "jwt_header": { "alg": "none", "typ": "JWT" },
      "jwt_payload": {
        "model_version": "9.0",
        "asset_name": "VCF Operations",
        "asset_type": "AC",
        "xr2": "b3BhcXVlLWRlbW8tZnA"
      },
      "sensitive_findings": [],
      "verdict": "clean",
      "verdict_reason": "Structure matches expected VCF 9 registration JWT; no obvious sensitive data detected."
    }
  ]
}
```

## References

- [Licensing in VMware Cloud Foundation 9.0](https://blogs.vmware.com/cloud-foundation/2025/06/24/licensing-in-vmware-cloud-foundation-9-0/) — disconnected mode and `.data` artifacts
- [What's inside the VCF 9 license file](https://www.linkedin.com/pulse/whats-inside-vcf-9-license-file-understanding-connected-kusek-95gfc) — JWT structure and `xr2` fingerprint

## License

See [LICENSE](LICENSE).
