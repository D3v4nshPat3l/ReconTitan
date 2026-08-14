# ReconTitan 0.4.1 - Detailed PDF Reporting Fix

This maintenance release focuses on PDF report quality and export speed.

## Highlights

- Professional cover page with overall risk, scan timeline, profile, duration, and severity cards.
- Detailed methodology, module coverage, color-coded findings index, finding metadata, evidence, remediation, validation guidance, references, and appendices.
- Structured WHOIS evidence with normalized UTC dates and readable list values.
- Safe wrapping for long URLs, headers, hashes, JavaScript paths, and other evidence.
- Smaller browser export payloads and generation-time diagnostics.

## Validation

- Full backend regression suite passes.
- JavaScript syntax validation passes.
- Reference PDF rendered through PDFium and visually inspected.
- A 25-finding reference report generated in under one second in the release environment.
