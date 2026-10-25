# API Trace security checklist (V1 Phase 2)

## Implemented in this version
- [x] No upload API or external network calls; Content Security Policy sets `connect-src 'none'`.
- [x] Relative local asset paths for GitHub Pages project sites.
- [x] HTML escaping for log-derived text rendered into the interface.
- [x] 20 MB file-size limit and `.log` / `.txt` extension allowlist.
- [x] Reject files containing NUL bytes as likely binary input.
- [x] Best-effort scan for authorization tokens, secret/password/API-key assignments, Salesforce session tokens, email addresses, Salesforce IDs, and sensitive query parameters.
- [x] Export redaction is enabled by default; disabling it requires confirmation.
- [x] No log content is written to localStorage, sessionStorage, cookies, or a remote service by this application.

## Manual review still required
- [ ] Inspect the security panel after uploading a sanitized real log.
- [ ] Inspect the JSON export before sharing it. Pattern-based redaction can miss unknown formats.
- [ ] Confirm that no logs, reports, screenshots, or credentials are committed to the public repository.
- [ ] Test against multiple Salesforce log levels, large logs, truncated logs, and unusual callout sequences.

## Important limitations
This checklist describes implemented safeguards, not a security certification. The browser must hold the uploaded text in memory to analyze it; clearing the app is not a guaranteed forensic memory wipe. Do not upload data you are not authorized to process. Redaction is heuristic and must not be treated as a guarantee that an export is safe to publish.
