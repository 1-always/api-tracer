# Changelog

## V0.3.0 — Security checks and Phase 2 diagnostics
- Added a local sensitive-data pattern scanner with source-line references.
- Added default-on redaction for JSON exports and a confirmation step for unredacted exports.
- Added targeted diagnostic guidance for HTTP 400, 401, 403, 404, 429, and 5xx responses.
- Added timeout-text and slow observed callout timestamp-delta findings.
- Added a restrictive Content Security Policy and `no-referrer` policy.
- Changed asset references to relative paths so GitHub Pages project URLs work.
- Kept analysis in the browser; no Salesforce org connection or backend was added.
