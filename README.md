# VCF9 Disconnected Data File Viewer

Forensic CLI for safely reviewing VMware Cloud Foundation (VCF) 9+ **Registration `*.data`** files before upload in disconnected / air-gapped environments.

The `.data` artifact is a JWT containing registration metadata (including the opaque `xr2` fingerprint). This tool decodes and inspects those files locally — **no network access, no file modification** — so operators can trust-but-verify that nothing sensitive is present before sending artifacts to Broadcom.

**v1.2.0 highlights**: Robust JWT extraction (regex), batch summary panel, optional signature verification stub (`--public-key`), expanded xr2 test coverage, and `agents.md` for AI-assisted development.

For residual risks, assurance boundaries, and what a “clean” verdict does **not** guarantee, see **[RISK_ASSESSMENT.md](RISK_ASSESSMENT.md)**.

## Quick start

```bash
pip install -r requirements.txt

# Try the included sample files
python vcf_compliance_inspector.py samples/ --dir

# Inspect your own registration file
python vcf_compliance_inspector.py Registration-*.data

# Optional: supply a public key for signature verification (advanced)
python vcf_compliance_inspector.py file.data --public-key broadcom_public.pem
```

## What it does

| Capability | Description |
|------------|-------------|
| **SHA-256 audit hash** | Per-file digest for change tracking and SIEM logs |
| **JWT decode** | Manual base64url + JSON decode of header and payload |
| **Robust extraction** | Regex-based detection that tolerates whitespace/newlines |
| **`xr2` analysis** | Decodes the opaque fingerprint; explains Broadcom’s non-identifying design |
| **Sensitive-data scan** | Keywords + regex (email, IP, internal hostnames, PEM headers, high-entropy base64) |
| **Optional signature verification** | `--public-key` flag + documented `verify_jwt_signature()` extension point (PyJWT if available) |
| **Assurance boundary** | Explicit panel on what the tool cannot guarantee (links to risk assessment) |
| **Raw hex & ASCII** | **Always shown last** — full byte-level review |
| **Verdict** | `SAFE TO UPLOAD` (green) or `REVIEW RECOMMENDED` (yellow) |
| **Batch summary** | When processing multiple files, shows clean vs review counts |

## JWT Signature Verification (New in v1.2.0)

By default the tool performs **content inspection only** (decode + structure + sensitive scan). This is the correct default for air-gapped forensic review before upload.

You can optionally supply a PEM public key:

```bash
python vcf_compliance_inspector.py file.data --public-key /path/to/public_key.pem
```

The `verify_jwt_signature()` function documents recommended techniques:
- Reject `alg: none` and weak algorithms
- Verify signature with the supplied key (RS256, ES256, etc.)
- Validate standard claims (`exp`, `nbf`, `iss`, `aud`) when present
- Future: JWKS support for online scenarios

See the function docstring and `agents.md` for extension guidance.

## Report layout (terminal)

Each file is analyzed in **nine numbered sections**. High-level decode and scans come first; the **raw hex/ASCII dump is always section 9**.

## CLI usage

```bash
python vcf_compliance_inspector.py Registration-*.data
python vcf_compliance_inspector.py /path/to/compliance/ --dir --json audit-report.json
python vcf_compliance_inspector.py file.data --head 1024 --verbose --public-key key.pem
python vcf_compliance_inspector.py --help
```

## Risk assessment

See **[RISK_ASSESSMENT.md](RISK_ASSESSMENT.md)** for detailed coverage of residual risks, what the tool can and cannot guarantee, and recommendations for high-assurance environments.

## Sample files & Testing

The `samples/` directory contains synthetic demo files.

```bash
python vcf_compliance_inspector.py samples/ --dir
pytest tests/ -q
```

`agents.md` provides deep context for future AI coding sessions (architecture, extension points, security model, common pitfalls).

## References

- [Licensing in VMware Cloud Foundation 9.0](https://blogs.vmware.com/cloud-foundation/2025/06/24/licensing-in-vmware-cloud-foundation-9-0/)
- [What's inside the VCF 9 license file](https://www.linkedin.com/pulse/whats-inside-vcf-9-license-file-understanding-connected-kusek-95gfc)
- Broadcom TechDocs for VCF 9 disconnected registration

## License

See [LICENSE](LICENSE).
