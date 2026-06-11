# Captured inspector outputs

Pre-generated **colored** terminal reports from the synthetic `samples/*.data` files.

| Sample | Verdict | Full output (color) | Preview | Terminal replay |
|--------|---------|---------------------|---------|-----------------|
| Clean registration JWT | `clean` | [registration-clean.html](registration-clean.html) | [registration-clean.svg](registration-clean.svg) | `less -R registration-clean.ansi` |
| Sensitive-data findings | `review_recommended` | [registration-review.html](registration-review.html) | [registration-review.svg](registration-review.svg) | `less -R registration-review.ansi` |
| JWT payload decode failure | `review_recommended` | [registration-malformed.html](registration-malformed.html) | [registration-malformed.svg](registration-malformed.svg) | `less -R registration-malformed.ansi` |
| Not a JWT | `review_recommended` | [not-a-jwt-placeholder.html](not-a-jwt-placeholder.html) | [not-a-jwt-placeholder.svg](not-a-jwt-placeholder.svg) | `less -R not-a-jwt-placeholder.ansi` |

**Viewing tips**

- **Browser (recommended for color):** download or open any `.html` file locally.
- **Terminal:** `less -R docs/outputs/registration-clean.ansi` (or `cat` in a true-color terminal).
- **Regenerate:** `python3 scripts/capture_outputs.py`

Machine-readable audit of all samples: [samples-audit.json](samples-audit.json)
