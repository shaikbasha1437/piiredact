# PII Redact

**Find and redact personal data in your browser.** Paste text, extract text from a PDF, or run **client-side OCR** on an image — highlight emails, phones, SSNs, cards, and more — then redact text and (for images) download a black-boxed PNG. Nothing is uploaded to a server.

**Live:** https://shaikbasha1437.github.io/piiredact/

## Privacy promise

Scanning and redaction run **only on your device**. Your text, PDFs, and images are never uploaded to an application server.

- Optional PDF text extraction uses [pdf.js](https://mozilla.github.io/pdf.js/) from a CDN in your browser.
- Optional image OCR uses [Tesseract.js](https://github.com/naptha/tesseract.js) from a CDN. **On first use**, your browser downloads the Tesseract worker/WASM and the English (`eng`) traineddata from the CDN (then typically caches them). The image file itself does not leave your machine.

## Features

- Paste / clear / scan with a large textarea
- Toggleable detectors: email, US phone, SSN, credit card (Luhn), IPv4, optional DOB-like dates
- Color-coded highlight preview and counts by type
- Redact all or by type; black bars (█) or `[REDACTED:TYPE]`
- Copy redacted text; undo last redact
- Load demo text with clearly fake PII
- Optional PDF text extraction (visual PDF black-box redaction is out of scope)
- **Load image / drag-drop** (PNG, JPEG, WebP, GIF) → Tesseract.js OCR (English) with progress % → same scan/highlight/redact pipeline → black boxes on a canvas → **Download redacted image**
- Installable PWA; works offline after first visit for core assets (CDN OCR/PDF libs need network on first use)

## Limits

- Pattern-based detectors — expect false positives and false negatives
- SSNs match common formats only; not validated against SSA issuance rules beyond basic area/group checks
- Credit cards require a passing Luhn check (test PANs like `4111…` will match)
- DOB-like dates are best-effort and may flag ordinary dates
- PDF support extracts text only; scanned/image PDFs may yield little or no text (use **Load image** + OCR instead)
- Image OCR is **English (`eng`) only**; handwriting, low-contrast, or stylized fonts often fail
- Visual redaction maps PII substrings to OCR **word** bounding boxes (whitespace-normalized / fuzzy). Misaligned OCR, split tokens, or partial word matches can leave gaps or over-redact
- Not a substitute for a full DLP or legal compliance review

## License

MIT
