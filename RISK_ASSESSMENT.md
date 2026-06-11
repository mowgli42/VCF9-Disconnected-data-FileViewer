# Risk Assessment: Sharing VCF Compliance Artifacts with Broadcom

**Document type:** Security and privacy risk assessment  
**Audience:** Security officers, compliance teams, and operators in air-gapped / DoD environments  
**Tool scope:** `vcf_compliance_inspector.py` (VCF 9+ Registration `*.data` files)  
**Last updated:** 2025-06-24  

---

## 1. Executive summary

VMware Cloud Foundation (VCF) 9+ disconnected licensing requires periodic exchange of compliance artifacts between the customer environment and Broadcom’s VCF Business Services console (`vcf.broadcom.com`). Broadcom documents that registration and license-usage payloads are designed to carry **license-compliance metadata only**, not passwords, secrets, or general customer content.

This assessment identifies **residual risks** that remain even when vendor documentation is accurate, and explains how the VCF Compliance Inspector implements **defense-in-depth pre-upload review** while **cannot** provide cryptographic proof of absence of sensitive data or guarantee what Broadcom can infer after receipt.

**Bottom line:** The inspector is a valuable local trust-but-verify control. A **clean** verdict means the file matches the expected registration JWT shape and no *obvious* sensitive patterns were found—not that sharing is risk-free or that all future inference is impossible.

---

## 2. Artifacts exchanged with Broadcom (disconnected mode)

| Artifact | Direction | Typical format | Frequency | Primary purpose |
|----------|-----------|----------------|-----------|-----------------|
| **Registration file** (`.data`) | Customer → Broadcom | JWT (JWS) | Once per VCF Operations registration | Link a VCF Operations instance to a Broadcom entitlement |
| **License usage file** | Customer → Broadcom | JWS, often gzip-compressed | At least every **180 days** | Report license consumption and compliance |
| **License file** | Broadcom → Customer | Vendor-defined | After registration / usage upload | Import updated entitlements into VCF Operations |
| **Confirmation file** (VCF 9.1+) | Customer → Broadcom | Vendor-defined | During registration | Lists license servers in the environment |

This tool **currently inspects Registration `*.data` files only**. The License Usage File and confirmation file introduce **additional** data categories (utilization counts, license SKU usage, server inventory) that require separate review when support is added.

**References:**

- [Register VCF Operations in disconnected mode](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/vcf-9-0-and-later/9-0/licensing/register-vcf-operations/register-vcf-operations-in-disconnected-mode.html)
- [Report license usage in disconnected mode](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/vcf-9-0-and-later/9-0/licensing/update-licenses/update-licenses-in-disconnected-mode.html)
- [Licensing in VCF 9.0 (VMware blog)](https://blogs.vmware.com/cloud-foundation/2025/06/24/licensing-in-vmware-cloud-foundation-9-0/)

---

## 3. What Broadcom documents as in-scope data

### 3.1 Registration file (JWT payload)

Per Broadcom / VMware public documentation, disconnected registration files contain claims such as:

| Claim | Risk relevance |
|-------|----------------|
| `model_version` | Low — product version string |
| `asset_name` | **Medium** — display name; may reflect hostname/FQDN if operators customize it |
| `created_on` | Low — timestamp |
| `asset_type` | Low — expected value `AC` for registration |
| `asset_id` | **Medium** — persistent UUID; enables correlation across uploads |
| `request_id` | **Medium** — per-request UUID |
| `xr2` | **Medium (opaque)** — base64-encoded fingerprint; vendor states **no identifiable environment details can be derived** |

The `xr2` value is intentionally opaque: it links usage reporting to a registered instance without exposing inventory, according to vendor documentation. **Customers cannot independently prove the opacity property** without vendor cryptographic specifications or source code.

### 3.2 License usage file (not yet parsed by this tool)

Broadcom states the license usage file records compliance-oriented fields only—for example usage generation time, utilization details, VCF Operations instance ID, report identifier, unused license inventory, and usage anomalies—and **does not collect personal data or customer data** (see VCF 9 licensing documentation).

**Residual concern:** “Utilization details” and “usage anomalies” may still reveal **operational scale** (counts, capacity trends) even without traditional PII. Security teams should treat usage files as a **separate review boundary** from registration files.

### 3.3 What is explicitly out of scope per vendor design

Public documentation states these artifacts **should not** contain:

- Passwords, API keys, or credentials  
- vCenter / ESXi configuration exports  
- VM names, user directories, or application data  
- General “customer data” or personal data (for usage files)

**Important:** Documentation describes **intent and typical content**, not a formal security certification. Schema changes, misconfiguration, or product defects could theoretically introduce unexpected fields.

---

## 4. Residual security and privacy concerns

Even when files conform to documentation, the following concerns remain relevant for DoD and air-gapped programs:

### 4.1 Identifiers and correlation

- **`asset_id`**, **`request_id`**, and **`xr2`** create a durable linkage between your environment and Broadcom’s entitlement records.  
- This is **required for licensing** but is still a form of **pseudonymous tracking**.  
- Combined with upload timing, support portal account, and contract metadata, Broadcom can associate files with a specific customer organization.

### 4.2 Naming and metadata leakage

- **`asset_name`** may embed internal hostnames, datacenter codes, or program names if operators do not use generic labels.  
- **Filenames** (e.g. `Registration-<name>-<timestamp>.data`) may leak context on the medium used for transfer (USB path, ticket attachments).  
- The tool scans **decoded content**; it does not redact or analyze surrounding process metadata (ticket text, email bodies).

### 4.3 Inference from opaque fields

- The inspector can decode `xr2` to bytes or JSON when possible, but **cannot determine** what Broadcom derives from it server-side.  
- Opacity is a **vendor assertion**, not an outcome this tool can verify.

### 4.4 Supply chain and integrity

- Registration files are JWT-shaped; this tool **does not verify signatures** (no Broadcom public key in disconnected review).  
- A file could be corrupted, substituted, or crafted locally; hexdump review helps detect accidents, not attest provenance.  
- **License files downloaded from Broadcom** are a separate integrity concern (import only through change-controlled paths).

### 4.5 Transfer path risks (out of tool scope)

- Sneakernet, email, ticketing systems, and intermediary workstations introduce **handling risks** unrelated to file content (copy-paste errors, wrong attachment, malware on transfer host).  
- Upload to `vcf.broadcom.com` requires **support portal credentials**—credential protection is outside this tool.

### 4.6 Scanner limitations (false negatives and false positives)

| Limitation | Impact |
|------------|--------|
| Keyword / regex coverage | Cannot catch all secret formats, encoded secrets, or novel field names |
| Encrypted or compressed payloads | Content inside non-JWT blobs may evade text scans |
| Unknown JSON claims | New or custom claims are displayed if decodable but not validated against a schema |
| High-entropy detection | May flag benign base64; may miss short secrets |
| Human judgment | “Clean” is automated triage, not a formal authority to operate (ATO) decision |

### 4.7 Future artifacts and schema drift

- VCF 9.1+ **confirmation files** add environment inventory (license servers).  
- Product updates may add claims without this tool’s `EXPECTED_VCF_CLAIMS` set being updated yet.  
- **License Usage File** support is planned but not implemented—teams must not assume one clean registration file implies all compliance uploads are safe.

---

## 5. Security measures implemented by this tool

The VCF Compliance Inspector implements the following **local, read-only** controls:

| Control | Description |
|---------|-------------|
| **No network I/O** | Analysis never contacts Broadcom or the Internet |
| **No file modification** | Input files are read-only; safe for forensic copies |
| **SHA-256 audit hash** | Supports integrity logging and SIEM correlation |
| **Dual-view analysis** | Decoded JWT **and** full raw hex/ASCII for independent verification |
| **Structure validation** | Detects JWT layout and expected VCF 9 registration claims |
| **`xr2` transparency** | Decodes and displays fingerprint bytes with official context text |
| **Sensitive-data scanner** | Keywords + patterns (email, IP, hostnames, PEM, high-entropy base64) |
| **Explicit verdict** | `SAFE TO UPLOAD` vs `REVIEW RECOMMENDED` with stated reason |
| **JSON audit export** | Machine-readable report for compliance archives |
| **Hexdump always last** | Operators always end review with byte-level visibility |

These measures support **defense in depth** and **separation of duties** (security review before release from an air gap). They align with trust-but-verify workflows described in public VCF disconnected licensing guidance.

---

## 6. What this tool cannot identify or guarantee

The following are **outside the assurance boundary** of the inspector:

1. **Whether `xr2` or UUIDs are reversible** to environment specifics on Broadcom’s side.  
2. **Whether every byte of the file** has been mapped to a documented claim (unknown binary in signature segment, steganography, or future encodings).  
3. **Whether the file was generated by authentic VCF Operations** versus crafted or tampered data (no signature verification).  
4. **Whether `asset_name` is operationally sensitive** in your classification scheme (generic product name vs internal codename).  
5. **Content of other compliance artifacts** (usage file, confirmation file, license file imports).  
6. **Organizational / legal adequacy** of sharing pseudonymous licensing metadata with the vendor under your jurisdiction (e.g. ITAR, classified programs, third-country transfer).  
7. **Absence of all secrets** — only *obvious* patterns per configured rules; zero false-negative rate is not claimed.  
8. **Broadcom portal security**, retention, subprocessors, or government access policies.  

**Recommended operator statement:**  
> “This file was reviewed with VCF Compliance Inspector vX.Y.Z on \<date\>. Verdict: \<clean|review\>. SHA-256: \<hash\>. Review confirms no obvious sensitive patterns in decoded content; vendor opaque fields (`xr2`, UUIDs) remain correlation identifiers per licensing design. Formal authorization to upload remains with \<role\>.”

---

## 7. Recommendations for air-gapped and high-assurance environments

1. **Review every artifact type separately** — registration, usage, and confirmation files have different payloads.  
2. **Standardize `asset_name`** to a non-revealing label before generating registration files.  
3. **Retain inspector JSON output** with change tickets and SHA-256 hashes.  
4. **Treat `REVIEW RECOMMENDED` as a hard stop** until a human analyst documents acceptance.  
5. **Use dedicated review workstations** with no Internet access; scan transfer media separately.  
6. **Do not rely on a clean verdict alone** for classified or special-category data environments—perform legal and program-office review.  
7. **Monitor Broadcom documentation** for schema changes and extend the tool (see `COMPLIANCE_ANALYZERS` hook in source).  

---

## 8. Conclusion

Sharing VCF compliance artifacts with Broadcom is a **deliberate, recurring exposure of licensing metadata and pseudonymous identifiers**, which Broadcom documents as necessary for entitlement management and **not** as a channel for credentials or customer content.

The VCF Compliance Inspector reduces operational risk by giving operators **transparent, repeatable, local inspection** before release from controlled environments. It implements practical security measures—hashing, structure checks, dual-view display, and pattern scanning—but **does not eliminate** correlation risk from identifiers, vendor-side inference from opaque fields, or the need for human authorization in high-assurance contexts.

For registration `*.data` files, use the tool as one layer in a broader data-release process, not as a substitute for program-specific risk acceptance.

---

## Appendix A — Mapping concerns to tool features

| Concern | Addressed by tool? | Notes |
|---------|-------------------|-------|
| Passwords / API keys in payload | Partial | Keyword and PEM scanning |
| Email / IP / internal hostnames | Partial | Regex scanner |
| Unexpected JWT claims | Partial | Payload displayed; unknown keys visible to analyst |
| Wrong file type | Yes | JWT structure + verdict |
| File tampering | No | No signature verification |
| `xr2` reversibility | No | Display only; vendor assertion repeated |
| Usage file utilization data | No | Not implemented yet |
| Transfer path security | No | Out of scope |
| Filename metadata | No | Out of scope |

---

*This document is informational and does not constitute legal advice or an official authorization to transmit data.*
