# PII Redact

**Find and redact personal data in your browser.** Paste text (or extract text from a PDF), highlight emails, phones, SSNs, cards, and more — then redact and copy safe text.

**Live:** https://shaikbasha1437.github.io/piiredact/

## Privacy promise

Scanning and redaction run **only on your device**. Your text and PDFs are never uploaded to a server. Optional PDF text extraction uses [pdf.js](https://mozilla.github.io/pdf.js/) from a CDN in your browser; the file itself does not leave your machine.

## Features

- Paste / clear / scan with a large textarea
- Toggleable detectors: email, US phone, SSN, credit card (Luhn), IPv4, optional DOB-like dates
- Color-coded highlight preview and counts by type
- Redact all or by type; black bars (█) or `[REDACTED:TYPE]`
- Copy redacted text; undo last redact
- Load demo text with clearly fake PII
- Optional PDF text extraction (visual PDF black-box redaction is out of scope)
- Installable PWA; works offline after first visit for core assets

## Limits

- Pattern-based detectors — expect false positives and false negatives
- SSNs match common formats only; not validated against SSA issuance rules beyond basic area/group checks
- Credit cards require a passing Luhn check (test PANs like `4111…` will match)
- DOB-like dates are best-effort and may flag ordinary dates
- PDF support extracts text only; scanned/image PDFs may yield little or no text
- Not a substitute for a full DLP or legal compliance review

## License

MIT
