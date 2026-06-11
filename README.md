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

## Captured sample outputs

Real **v1.2.0** terminal captures from the synthetic `samples/*.data` files. Regenerate after UI changes:

```bash
python3 scripts/capture_outputs.py
```

| Sample | Verdict | Full color output | Terminal replay |
|--------|---------|-------------------|-----------------|
| `Registration-clean-2025-06-24T12_00_00Z.data` | SAFE TO UPLOAD | [HTML](docs/outputs/registration-clean.html) · [SVG](docs/outputs/registration-clean.svg) | [`less -R docs/outputs/registration-clean.ansi`](docs/outputs/registration-clean.ansi) |
| `Registration-review-2025-06-24T12_00_00Z.data` | REVIEW RECOMMENDED | [HTML](docs/outputs/registration-review.html) · [SVG](docs/outputs/registration-review.svg) | [`less -R docs/outputs/registration-review.ansi`](docs/outputs/registration-review.ansi) |
| `Registration-malformed-2025-06-24T12_00_00Z.data` | REVIEW RECOMMENDED | [HTML](docs/outputs/registration-malformed.html) · [SVG](docs/outputs/registration-malformed.svg) | [`less -R docs/outputs/registration-malformed.ansi`](docs/outputs/registration-malformed.ansi) |
| `not-a-jwt-placeholder.data` | REVIEW RECOMMENDED | [HTML](docs/outputs/not-a-jwt-placeholder.html) · [SVG](docs/outputs/not-a-jwt-placeholder.svg) | [`less -R docs/outputs/not-a-jwt-placeholder.ansi`](docs/outputs/not-a-jwt-placeholder.ansi) |

> **Color on GitHub:** click the preview images below, or open `.html` files in a browser.  
> **Color in terminal:** `less -R docs/outputs/registration-clean.ansi`

Index: [docs/outputs/README.md](docs/outputs/README.md) · JSON audit: [samples-audit.json](docs/outputs/samples-audit.json)

### 1. Clean registration JWT

**Sample file:** `samples/Registration-clean-2025-06-24T12_00_00Z.data`  
**Verdict:** SAFE TO UPLOAD (`clean`, exit 0)  
**Summary:** Valid VCF 9 JWT with all expected claims and no sensitive-data hits. Full nine-section report; green verdict; colorized hexdump at section 9.  

```bash
python vcf_compliance_inspector.py samples/Registration-clean-2025-06-24T12_00_00Z.data
```

**Full output:**
- [docs/outputs/registration-clean.html](docs/outputs/registration-clean.html) (color, all sections)
- [docs/outputs/registration-clean.ansi](docs/outputs/registration-clean.ansi) (ANSI — `less -R`)
- [docs/outputs/registration-clean.excerpt.ansi](docs/outputs/registration-clean.excerpt.ansi) (abbreviated)

<a href="docs/outputs/registration-clean.html"><img src="docs/outputs/registration-clean.svg" alt="Clean registration JWT" width="900"/></a>

<details>
<summary>Terminal excerpt (ANSI — color in supporting terminals)</summary>

```ansi
│  [1mVCF Compliance Inspector[0m  [2mv1.2.0[0m                                            │
│  Registration-clean-2025-06-24T12_00_00Z.data                                │
╰──────────────────────────────────────────────────────────────────────────────╯

[2m───────────────────────────── [0m[1m1[0m[1m. File Information[0m[2m ──────────────────────────────[0m
╭──────────────┬───────────────────────────────────────────────────────────────╮
│[1m [0m[1mPath        [0m[1m [0m│ /workspace/samples/Registration-clean-2025-06-24T12_00_00Z.d… │
│[1m [0m[1mSize        [0m[1m [0m│ 392 bytes                                                     │
│[1m [0m[1mSHA-256     [0m[1m [0m│ 02493780d54906d39f35620587c5be3b402aff91f44d20aaaf11b307d115… │
│[1m [0m[1mJWT         [0m[1m [0m│ Yes                                                           │
╰──────────────┴───────────────────────────────────────────────────────────────╯

[2m─────────────────────────────── [0m[1m2[0m[1m. JWT Structure[0m[2m ───────────────────────────────[0m
╭──────────────────────────────────────────────────────────────────────────────╮
│  [1m✓ Valid JWT layout detected[0m                                                 │
│  [2mThree dot-separated segments: header.payload.signature[0m                      │

[2m───────────────────────────── [0m[1m8[0m[1m. Summary & Verdict[0m[2m ─────────────────────────────[0m
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  [1m✓  SAFE TO UPLOAD[0m                                                           │
│                                                                              │
│  Structure matches expected VCF 9 registration JWT; no obvious sensitive     │
│  data detected.                                                              │
│                                                                              │
│  [2mExpected claims present:[0m asset_id, asset_name, asset_type, created_on,      │
│  model_version, request_id, xr2                                              │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯

[2m──────────────────── [0m[1m9[0m[1m. Raw Hex & ASCII [0m[1m([0m[1mbyte-level review[0m[1m)[0m[2m ────────────────────[0m
╭──────────────────────────── [1mRaw Hex & ASCII Dump[0m ────────────────────────────╮
│                                                                              │
│  00000000  65 79 4a 68 62 47 63 69 4f 69 4a 75 62 32 35 6c                   │
│  |eyJhbGciOiJub25l|                                                          │
│  00000010  49 69 77 69 64 48 6c 77 49 6a 6f 69 53 6c 64 55                   │
│  |IiwidHlwIjoiSldU|                                                          │
│  00000020  49 6e 30 2e 65 79 4a 74 62 32 52 6c 62 46 39 32                   │
│  |In0.eyJtb2RlbF92|                                                          │
│  00000030  5a 58 4a 7a 61 57 39 75 49 6a 6f 69 4f 53 34 77                   │
│  |ZXJzaW9uIjoiOS4w|                                                          │
│  00000040  49 69 77 69 59 58 4e 7a 5a 58 52 66 62 6d 46 74                   │
│  |IiwiYXNzZXRfbmFt|                                                          │
│  00000050  5a 53 49 36 49 6c 5a 44 52 69 42 50 63 47 56 79                   │
```

</details>

### 2. Sensitive data detected

**Sample file:** `samples/Registration-review-2025-06-24T12_00_00Z.data`  
**Verdict:** REVIEW RECOMMENDED (`review_recommended`, exit 1)  
**Summary:** Valid JWT; section 6 flags email, internal hostname, and IPv4 in a synthetic `notes` field.  

```bash
python vcf_compliance_inspector.py samples/Registration-review-2025-06-24T12_00_00Z.data
```

**Full output:**
- [docs/outputs/registration-review.html](docs/outputs/registration-review.html) (color, all sections)
- [docs/outputs/registration-review.ansi](docs/outputs/registration-review.ansi) (ANSI — `less -R`)
- [docs/outputs/registration-review.excerpt.ansi](docs/outputs/registration-review.excerpt.ansi) (abbreviated)

<a href="docs/outputs/registration-review.html"><img src="docs/outputs/registration-review.svg" alt="Sensitive data detected" width="900"/></a>

<details>
<summary>Terminal excerpt (ANSI — color in supporting terminals)</summary>

```ansi
│  [1mVCF Compliance Inspector[0m  [2mv1.2.0[0m                                            │
│  Registration-review-2025-06-24T12_00_00Z.data                               │
╰──────────────────────────────────────────────────────────────────────────────╯

[2m───────────────────────────── [0m[1m1[0m[1m. File Information[0m[2m ──────────────────────────────[0m
╭──────────────┬───────────────────────────────────────────────────────────────╮
│[1m [0m[1mPath        [0m[1m [0m│ /workspace/samples/Registration-review-2025-06-24T12_00_00Z.… │
│[1m [0m[1mSize        [0m[1m [0m│ 488 bytes                                                     │
│[1m [0m[1mSHA-256     [0m[1m [0m│ de78349bb1c07ce4ee8df2ba03d440fa91d21332f4fba45bb2a00928c331… │
│[1m [0m[1mJWT         [0m[1m [0m│ Yes                                                           │
╰──────────────┴───────────────────────────────────────────────────────────────╯

[2m─────────────────────────────── [0m[1m2[0m[1m. JWT Structure[0m[2m ───────────────────────────────[0m
╭──────────────────────────────────────────────────────────────────────────────╮
│  [1m✓ Valid JWT layout detected[0m                                                 │
│  [2mThree dot-separated segments: header.payload.signature[0m                      │

[2m──────────────────────────── [0m[1m6[0m[1m. Sensitive Data Scan[0m[2m ────────────────────────────[0m
[3m                                  [0m[3m3 finding(s)[0m[3m                                  [0m
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃[1m [0m[1mCategory          [0m[1m [0m┃[1m [0m[1mMatch                   [0m[1m [0m┃[1m [0m[1mContext                     [0m[1m [0m┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│[1m [0m[1memail             [0m[1m [0m│ admin@acme.corp.internal │[2m [0m[2m...b3BhcXVlLWRlbW8tZnA",    [0m[2m [0m│
│[1m                    [0m│                          │[2m [0m[2m"notes": "Contact           [0m[2m [0m│
│[1m                    [0m│                          │[2m [0m[2madmin@acme.corp.internal or [0m[2m [0m│
│[1m                    [0m│                          │[2m [0m[2m10.42.0.15 before upload."} [0m[2m [0m│
├────────────────────┼──────────────────────────┼──────────────────────────────┤
│[1m [0m[1mipv4              [0m[1m [0m│ 10.42.0.15               │[2m [0m[2m...": "Contact              [0m[2m [0m│
│[1m                    [0m│                          │[2m [0m[2madmin@acme.corp.internal or [0m[2m [0m│
│[1m                    [0m│                          │[2m [0m[2m10.42.0.15 before upload."} [0m[2m [0m│
├────────────────────┼──────────────────────────┼──────────────────────────────┤
│[1m [0m[1minternal_hostname [0m[1m [0m│ acme.corp.internal       │[2m [0m[2m...VlLWRlbW8tZnA", "notes": [0m[2m [0m│
│[1m                    [0m│                          │[2m [0m[2m"Contact                    [0m[2m [0m│
│[1m                    [0m│                          │[2m [0m[2madmin@acme.corp.internal or [0m[2m [0m│
│[1m                    [0m│                          │[2m [0m[2m10.42.0.15 before upload."} [0m[2m [0m│
└────────────────────┴──────────────────────────┴──────────────────────────────┘


[2m───────────────────────────── [0m[1m8[0m[1m. Summary & Verdict[0m[2m ─────────────────────────────[0m
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  [1m⚠  REVIEW RECOMMENDED[0m                                                       │
│                                                                              │
│  Sensitive-data scanner flagged potential items: email, internal_hostname,   │
│  ipv4.                                                                       │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯


[2m──────────────────── [0m[1m9[0m[1m. Raw Hex & ASCII [0m[1m([0m[1mbyte-level review[0m[1m)[0m[2m ────────────────────[0m
╭──────────────────────────── [1mRaw Hex & ASCII Dump[0m ────────────────────────────╮
│                                                                              │
│  00000000  65 79 4a 68 62 47 63 69 4f 69 4a 75 62 32 35 6c                   │
│  |eyJhbGciOiJub25l|                                                          │
│  00000010  49 69 77 69 64 48 6c 77 49 6a 6f 69 53 6c 64 55                   │
│  |IiwidHlwIjoiSldU|                                                          │
│  00000020  49 6e 30 2e 65 79 4a 74 62 32 52 6c 62 46 39 32                   │
│  |In0.eyJtb2RlbF92|                                                          │
│  00000030  5a 58 4a 7a 61 57 39 75 49 6a 6f 69 4f 53 34 77                   │
│  |ZXJzaW9uIjoiOS4w|                                                          │
│  00000040  49 69 77 69 59 58 4e 7a 5a 58 52 66 62 6d 46 74                   │
│  |IiwiYXNzZXRfbmFt|                                                          │
│  00000050  5a 53 49 36 49 6c 5a 44 52 69 42 50 63 47 56 79                   │
```

</details>

### 3. JWT payload decode failure

**Sample file:** `samples/Registration-malformed-2025-06-24T12_00_00Z.data`  
**Verdict:** REVIEW RECOMMENDED (`review_recommended`, exit 1)  
**Summary:** Three JWT segments; header decodes; payload is invalid base64/UTF-8. JWT Decode Warnings shown; hexdump reveals `!!!not-valid-base64url-payload!!!`.  

```bash
python vcf_compliance_inspector.py samples/Registration-malformed-2025-06-24T12_00_00Z.data
```

**Full output:**
- [docs/outputs/registration-malformed.html](docs/outputs/registration-malformed.html) (color, all sections)
- [docs/outputs/registration-malformed.ansi](docs/outputs/registration-malformed.ansi) (ANSI — `less -R`)
- [docs/outputs/registration-malformed.excerpt.ansi](docs/outputs/registration-malformed.excerpt.ansi) (abbreviated)

<a href="docs/outputs/registration-malformed.html"><img src="docs/outputs/registration-malformed.svg" alt="JWT payload decode failure" width="900"/></a>

<details>
<summary>Terminal excerpt (ANSI — color in supporting terminals)</summary>

```ansi
│  [1mVCF Compliance Inspector[0m  [2mv1.2.0[0m                                            │
│  Registration-malformed-2025-06-24T12_00_00Z.data                            │
╰──────────────────────────────────────────────────────────────────────────────╯

[2m───────────────────────────── [0m[1m1[0m[1m. File Information[0m[2m ──────────────────────────────[0m
╭──────────────┬───────────────────────────────────────────────────────────────╮
│[1m [0m[1mPath        [0m[1m [0m│ /workspace/samples/Registration-malformed-2025-06-24T12_00_0… │
│[1m [0m[1mSize        [0m[1m [0m│ 78 bytes                                                      │
│[1m [0m[1mSHA-256     [0m[1m [0m│ 271e36a0b5b53946b2f5b89020f605221460c55f37238d59221dc442add1… │
│[1m [0m[1mJWT         [0m[1m [0m│ No                                                            │
╰──────────────┴───────────────────────────────────────────────────────────────╯

[2m─────────────────────────────── [0m[1m2[0m[1m. JWT Structure[0m[2m ───────────────────────────────[0m
╭──────────────────────────────────────────────────────────────────────────────╮
│  [1m⚠ No JWT structure detected[0m                                                 │
│  [2mDecoded claims unavailable — review raw hex dump at end of report.[0m          │

[2m───────────────────────────── [0m[1m8[0m[1m. Summary & Verdict[0m[2m ─────────────────────────────[0m
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  [1m⚠  REVIEW RECOMMENDED[0m                                                       │
│                                                                              │
│  File does not match expected JWT structure.                                 │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯


[2m──────────────────── [0m[1m9[0m[1m. Raw Hex & ASCII [0m[1m([0m[1mbyte-level review[0m[1m)[0m[2m ────────────────────[0m
╭──────────────────────────── [1mRaw Hex & ASCII Dump[0m ────────────────────────────╮
│                                                                              │
│  00000000  65 79 4a 68 62 47 63 69 4f 69 41 69 62 6d 39 75                   │
│  |eyJhbGciOiAibm9u|                                                          │
│  00000010  5a 53 49 73 49 43 4a 30 65 58 41 69 4f 69 41 69                   │
│  |ZSIsICJ0eXAiOiAi|                                                          │
│  00000020  53 6c 64 55 49 6e 30 2e 21 21 21 6e 6f 74 2d 76                   │
│  |SldUIn0.!!!not-v|                                                          │
│  00000030  61 6c 69 64 2d 62 61 73 65 36 34 75 72 6c 2d 70                   │
│  |alid-base64url-p|                                                          │
│  00000040  61 79 6c 6f 61 64 21 21 21 2e 63 32 6c 6e                         │
│  |ayload!!!.c2ln|                                                            │
│                                                                              │
```

</details>

### 4. Not a JWT (hexdump-only decode path)

**Sample file:** `samples/not-a-jwt-placeholder.data`  
**Verdict:** REVIEW RECOMMENDED (`review_recommended`, exit 1)  
**Summary:** Plain-text file; decoded claims skipped; section 2 warns no JWT structure; section 9 shows readable ASCII.  

```bash
python vcf_compliance_inspector.py samples/not-a-jwt-placeholder.data
```

**Full output:**
- [docs/outputs/not-a-jwt-placeholder.html](docs/outputs/not-a-jwt-placeholder.html) (color, all sections)
- [docs/outputs/not-a-jwt-placeholder.ansi](docs/outputs/not-a-jwt-placeholder.ansi) (ANSI — `less -R`)
- [docs/outputs/not-a-jwt-placeholder.excerpt.ansi](docs/outputs/not-a-jwt-placeholder.excerpt.ansi) (abbreviated)

<a href="docs/outputs/not-a-jwt-placeholder.html"><img src="docs/outputs/not-a-jwt-placeholder.svg" alt="Not a JWT (hexdump-only decode path)" width="900"/></a>

<details>
<summary>Terminal excerpt (ANSI — color in supporting terminals)</summary>

```ansi
│  [1mVCF Compliance Inspector[0m  [2mv1.2.0[0m                                            │
│  not-a-jwt-placeholder.data                                                  │
╰──────────────────────────────────────────────────────────────────────────────╯

[2m───────────────────────────── [0m[1m1[0m[1m. File Information[0m[2m ──────────────────────────────[0m
╭──────────────┬───────────────────────────────────────────────────────────────╮
│[1m [0m[1mPath        [0m[1m [0m│ /workspace/samples/not-a-jwt-placeholder.data                 │
│[1m [0m[1mSize        [0m[1m [0m│ 138 bytes                                                     │
│[1m [0m[1mSHA-256     [0m[1m [0m│ 281dd9b81e6579c3fc152b243b43862422fbd1606b82227738ffe35be71c… │
│[1m [0m[1mJWT         [0m[1m [0m│ No                                                            │
╰──────────────┴───────────────────────────────────────────────────────────────╯

[2m─────────────────────────────── [0m[1m2[0m[1m. JWT Structure[0m[2m ───────────────────────────────[0m
╭──────────────────────────────────────────────────────────────────────────────╮
│  [1m⚠ No JWT structure detected[0m                                                 │
│  [2mDecoded claims unavailable — review raw hex dump at end of report.[0m          │

[2m───────────────────────────── [0m[1m8[0m[1m. Summary & Verdict[0m[2m ─────────────────────────────[0m
╭──────────────────────────────────────────────────────────────────────────────╮
│                                                                              │
│  [1m⚠  REVIEW RECOMMENDED[0m                                                       │
│                                                                              │
│  File does not match expected JWT structure.                                 │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯


[2m──────────────────── [0m[1m9[0m[1m. Raw Hex & ASCII [0m[1m([0m[1mbyte-level review[0m[1m)[0m[2m ────────────────────[0m
╭──────────────────────────── [1mRaw Hex & ASCII Dump[0m ────────────────────────────╮
│                                                                              │
│  00000000  43 4f 52 52 55 50 54 45 44 20 4f 52 20 4e 4f 4e  |CORRUPTED OR    │
│  NON|                                                                        │
│  00000010  2d 4a 57 54 20 55 50 4c 4f 41 44 20 50 4c 41 43  |-JWT UPLOAD     │
│  PLAC|                                                                       │
│  00000020  45 48 4f 4c 44 45 52 0a 54 68 69 73 20 66 69 6c  |EHOLDER.This    │
│  fil|                                                                        │
│  00000030  65 20 69 73 20 69 6e 74 65 6e 74 69 6f 6e 61 6c  |e is            │
│  intentional|                                                                │
│  00000040  6c 79 20 6e 6f 74 20 61 20 4a 57 54 20 66 6f 72  |ly not a JWT    │
│  for|                                                                        │
│  00000050  20 64 65 6d 6f 20 70 75 72 70 6f 73 65 73 2e 0a  | demo           │
```

</details>

### JSON audit (`--json`)

```bash
python vcf_compliance_inspector.py samples/ --dir --json docs/outputs/samples-audit.json
```

```json
{
  "tool": "vcf_compliance_inspector",
  "version": "1.2.0",
  "files": [
    {
      "path": "/workspace/samples/Registration-clean-2025-06-24T12_00_00Z.data",
      "sha256": "02493780d54906d39f35620587c5be3b402aff91f44d20aaaf11b307d115ece2",
      "verdict": "clean",
      "verdict_reason": "Structure matches expected VCF 9 registration JWT; no obvious sensitive data detected.",
      "sensitive_findings": []
    }
  ]
}
```
## References

- [Licensing in VMware Cloud Foundation 9.0](https://blogs.vmware.com/cloud-foundation/2025/06/24/licensing-in-vmware-cloud-foundation-9-0/)
- [What's inside the VCF 9 license file](https://www.linkedin.com/pulse/whats-inside-vcf-9-license-file-understanding-connected-kusek-95gfc)
- Broadcom TechDocs for VCF 9 disconnected registration

## License

See [LICENSE](LICENSE).
