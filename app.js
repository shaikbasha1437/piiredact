/* PII Redact — all scanning stays in-browser */
const $ = (id) => document.getElementById(id);

const DETECTORS = [
  {
    id: 'email',
    label: 'Email',
    enabled: true,
    // pragmatic email pattern
    find(text) {
      const re = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      return matchAll(text, re, 'email');
    },
  },
  {
    id: 'phone',
    label: 'US phone',
    enabled: true,
    find(text) {
      const re = /(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b/g;
      return matchAll(text, re, 'phone').filter((m) => {
        const digits = m.value.replace(/\D/g, '');
        return digits.length === 10 || (digits.length === 11 && digits.startsWith('1'));
      });
    },
  },
  {
    id: 'ssn',
    label: 'SSN',
    enabled: true,
    find(text) {
      const re = /\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b/g;
      return matchAll(text, re, 'ssn').filter((m) => {
        const d = m.value.replace(/\D/g, '');
        return d.length === 9;
      });
    },
  },
  {
    id: 'card',
    label: 'Credit card',
    enabled: true,
    find(text) {
      const re = /\b(?:\d[ -]*?){13,19}\b/g;
      return matchAll(text, re, 'card').filter((m) => {
        const digits = m.value.replace(/\D/g, '');
        return digits.length >= 13 && digits.length <= 19 && luhnOk(digits);
      });
    },
  },
  {
    id: 'ipv4',
    label: 'IPv4',
    enabled: true,
    find(text) {
      const re = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
      return matchAll(text, re, 'ipv4');
    },
  },
  {
    id: 'dob',
    label: 'DOB-like date',
    enabled: false,
    find(text) {
      // MM/DD/YYYY, M/D/YY, YYYY-MM-DD
      const re = /\b(?:(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)?\d{2}|(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01]))\b/g;
      return matchAll(text, re, 'dob');
    },
  },
];

const DEMO = `Customer intake (FAKE DEMO DATA — not real people)

Name: Jordan Example
Email: jordan.example@demo-mail.test
Alt: support+tickets@acme-demo.example
Phone: (415) 555-0134
Mobile: +1 212-555-0199
SSN: 078-05-1120
Card: 4111 1111 1111 1111
Backup card: 5500-0000-0000-0004
Home IP (lab): 192.168.1.42
Public IP: 203.0.113.77
DOB: 03/15/1988
Hired: 2020-06-01

Notes: Please call Jordan at 415-555-0134 about invoice #4412.
Do not share SSN 078-05-1120 outside the secure channel.
`;

const IMAGE_ACCEPT = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);

let findings = [];
let undoStack = [];

/** @type {{ words: Array<{text:string,bbox:{x0:number,y0:number,x1:number,y1:number}}>, image: HTMLImageElement|null, objectUrl: string|null, boxes: Array<{x0:number,y0:number,x1:number,y1:number}>, fileName: string } } */
const imageState = {
  words: [],
  image: null,
  objectUrl: null,
  boxes: [],
  fileName: 'redacted.png',
};

let ocrWorker = null;
let ocrBusy = false;

function matchAll(text, re, type) {
  const out = [];
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({ type, start: m.index, end: m.index + m[0].length, value: m[0] });
    if (m[0].length === 0) re.lastIndex++;
  }
  return out;
}

function luhnOk(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._id);
  toast._id = setTimeout(() => { t.hidden = true; }, 1600);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function mergeOverlaps(list) {
  const sorted = [...list].sort((a, b) => a.start - b.start || b.end - a.end);
  const merged = [];
  for (const f of sorted) {
    const last = merged[merged.length - 1];
    if (last && f.start < last.end) {
      // keep earlier/longer; skip overlapping later match
      continue;
    }
    merged.push(f);
  }
  return merged;
}

function activeDetectors() {
  return DETECTORS.filter((d) => {
    const el = document.querySelector(`input[data-det="${d.id}"]`);
    return el ? el.checked : d.enabled;
  });
}

function scan() {
  const text = $('input').value;
  const found = [];
  for (const det of activeDetectors()) {
    found.push(...det.find(text));
  }
  findings = mergeOverlaps(found);
  renderFindings();
  renderPreview(text, findings);
  $('redactAllBtn').disabled = findings.length === 0;
  $('redactByTypeBtn').disabled = findings.length === 0;
  syncImageBoxesFromFindings(findings);
  if (!findings.length) {
    toast(text.trim() ? 'No PII found with current detectors' : 'Paste text first');
  } else {
    toast(`Found ${findings.length} item${findings.length === 1 ? '' : 's'}`);
  }
}

function renderFindings() {
  const section = $('counts');
  const chips = $('chips');
  chips.innerHTML = '';
  if (!findings.length) {
    section.hidden = true;
    $('typePicker').hidden = true;
    return;
  }
  section.hidden = false;
  const counts = {};
  for (const f of findings) counts[f.type] = (counts[f.type] || 0) + 1;
  for (const [type, n] of Object.entries(counts)) {
    const span = document.createElement('span');
    span.className = `chip chip-${type}`;
    span.textContent = `${labelFor(type)} · ${n}`;
    chips.appendChild(span);
  }
  const picker = $('typePicker');
  picker.innerHTML = '';
  for (const type of Object.keys(counts)) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'ghost sm';
    btn.textContent = `Redact ${labelFor(type)}`;
    btn.addEventListener('click', () => redactTypes([type]));
    picker.appendChild(btn);
  }
}

function labelFor(type) {
  return (DETECTORS.find((d) => d.id === type) || { label: type }).label;
}

function renderPreview(text, list) {
  const el = $('preview');
  if (!text) {
    el.innerHTML = '<span class="muted-empty">Scan to see highlighted PII.</span>';
    return;
  }
  if (!list.length) {
    el.textContent = text;
    return;
  }
  let html = '';
  let cursor = 0;
  for (const f of list) {
    if (f.start > cursor) html += escapeHtml(text.slice(cursor, f.start));
    html += `<mark class="hl hl-${f.type}" title="${escapeHtml(labelFor(f.type))}">${escapeHtml(text.slice(f.start, f.end))}</mark>`;
    cursor = f.end;
  }
  if (cursor < text.length) html += escapeHtml(text.slice(cursor));
  el.innerHTML = html;
}

function redactMode() {
  const checked = document.querySelector('input[name="mode"]:checked');
  return checked ? checked.value : 'bars';
}

function replacementFor(f) {
  if (redactMode() === 'tag') return `[REDACTED:${f.type.toUpperCase()}]`;
  const len = Math.max(f.value.length, 4);
  return '█'.repeat(len);
}

function applyRedactions(types) {
  const text = $('input').value;
  const targets = findings.filter((f) => !types || types.includes(f.type));
  if (!targets.length) {
    toast('Nothing to redact');
    return;
  }
  undoStack.push({
    input: text,
    output: $('output').value,
    imageBoxes: imageState.boxes.map((b) => ({ ...b })),
  });
  $('undoBtn').disabled = false;

  // Visual redaction on image (before clearing findings)
  if (imageState.image && imageState.words.length) {
    const boxes = mapFindingsToWordBoxes(targets, imageState.words, text);
    // Keep previously painted boxes + new ones
    imageState.boxes = mergeBoxes([...imageState.boxes, ...boxes]);
    paintCanvas(imageState.boxes);
    $('downloadImageBtn').disabled = imageState.boxes.length === 0;
  }

  // replace from end so offsets stay valid
  const sorted = [...targets].sort((a, b) => b.start - a.start);
  let out = text;
  for (const f of sorted) {
    out = out.slice(0, f.start) + replacementFor(f) + out.slice(f.end);
  }
  $('output').value = out;
  $('copyBtn').disabled = false;

  // update input to redacted so further scans see safe text, keep preview synced
  $('input').value = out;
  findings = [];
  renderFindings();
  renderPreview(out, []);
  $('redactAllBtn').disabled = true;
  $('redactByTypeBtn').disabled = true;
  $('typePicker').hidden = true;
  toast(`Redacted ${targets.length} item${targets.length === 1 ? '' : 's'}`);
}

function redactTypes(types) {
  applyRedactions(types);
}

function buildToggles() {
  const root = $('toggles');
  root.innerHTML = '';
  for (const d of DETECTORS) {
    const lab = document.createElement('label');
    lab.className = 'toggle';
    lab.innerHTML = `<input type="checkbox" data-det="${d.id}" ${d.enabled ? 'checked' : ''} /> ${d.label}`;
    root.appendChild(lab);
  }
}

async function extractPdfText(file) {
  if (typeof pdfjsLib === 'undefined') throw new Error('PDF library failed to load');
  pdfjsLib.GlobalWorkerOptions.workerSrc =
    'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
  const buf = await file.arrayBuffer();
  const doc = await pdfjsLib.getDocument({ data: buf }).promise;
  const parts = [];
  for (let i = 1; i <= doc.numPages; i++) {
    const page = await doc.getPage(i);
    const content = await page.getTextContent();
    parts.push(content.items.map((it) => it.str).join(' '));
  }
  return parts.join('\n\n');
}

// —— Image OCR + visual redaction ——

function isAcceptedImage(file) {
  if (!file) return false;
  if (IMAGE_ACCEPT.has(file.type)) return true;
  // some browsers omit type; fall back to extension
  const name = (file.name || '').toLowerCase();
  return /\.(png|jpe?g|webp|gif)$/.test(name);
}

function setOcrProgress(pct, visible) {
  const wrap = $('ocrProgress');
  const fill = $('ocrBarFill');
  const label = $('ocrPct');
  if (visible) wrap.hidden = false;
  else wrap.hidden = true;
  const n = Math.max(0, Math.min(100, Math.round(pct)));
  fill.style.width = `${n}%`;
  label.textContent = `${n}%`;
}

function clearImageState() {
  if (imageState.objectUrl) {
    URL.revokeObjectURL(imageState.objectUrl);
  }
  imageState.words = [];
  imageState.image = null;
  imageState.objectUrl = null;
  imageState.boxes = [];
  imageState.fileName = 'redacted.png';
  const card = $('imageCard');
  if (card) card.hidden = true;
  const canvas = $('redactCanvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    ctx && ctx.clearRect(0, 0, canvas.width, canvas.height);
    canvas.width = 0;
    canvas.height = 0;
  }
  const dl = $('downloadImageBtn');
  if (dl) dl.disabled = true;
  setOcrProgress(0, false);
}

function normalizeWs(s) {
  return String(s).replace(/\s+/g, ' ').trim().toLowerCase();
}

function compactAlnum(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9@.+_-]/g, '');
}

/**
 * Locate each OCR word inside the full OCR text (sequential search),
 * then fall back to fuzzy span membership for unmatched words.
 */
function indexWordsInText(words, ocrText) {
  const indexed = [];
  let searchFrom = 0;
  for (const w of words) {
    const raw = (w.text || '');
    const trimmed = raw.trim();
    if (!trimmed || !w.bbox) continue;
    let idx = ocrText.indexOf(trimmed, searchFrom);
    if (idx === -1) idx = ocrText.indexOf(trimmed);
    const entry = {
      text: trimmed,
      bbox: {
        x0: w.bbox.x0,
        y0: w.bbox.y0,
        x1: w.bbox.x1,
        y1: w.bbox.y1,
      },
      start: idx,
      end: idx === -1 ? -1 : idx + trimmed.length,
    };
    indexed.push(entry);
    if (idx !== -1) searchFrom = idx + Math.max(trimmed.length, 1);
  }
  return indexed;
}

/**
 * Map PII findings to OCR word bounding boxes.
 * Prefer character-offset overlap; fuzzy: normalize whitespace / compact form
 * and include words that appear inside a PII span.
 */
function mapFindingsToWordBoxes(findingsList, words, ocrText) {
  if (!findingsList.length || !words.length) return [];
  const indexed = indexWordsInText(words, ocrText || '');
  const boxes = [];
  const seen = new Set();

  function pushBox(bbox) {
    const key = `${bbox.x0}|${bbox.y0}|${bbox.x1}|${bbox.y1}`;
    if (seen.has(key)) return;
    seen.add(key);
    boxes.push({ x0: bbox.x0, y0: bbox.y0, x1: bbox.x1, y1: bbox.y1 });
  }

  for (const f of findingsList) {
    const spanNorm = normalizeWs(f.value);
    const spanCompact = compactAlnum(f.value);
    if (!spanNorm && !spanCompact) continue;

    let any = false;
    for (const w of indexed) {
      // Offset overlap when we know where the word sits in OCR text
      if (w.start >= 0 && w.start < f.end && w.end > f.start) {
        pushBox(w.bbox);
        any = true;
        continue;
      }
      const wordNorm = normalizeWs(w.text);
      const wordCompact = compactAlnum(w.text);
      if (!wordNorm && !wordCompact) continue;
      // Skip tiny crumbs unless they are the entire PII span
      if (wordCompact.length <= 1 && spanCompact.length > 1) continue;
      if (
        (wordNorm && spanNorm.includes(wordNorm)) ||
        (wordCompact.length >= 2 && spanCompact.includes(wordCompact))
      ) {
        pushBox(w.bbox);
        any = true;
      }
    }

    // If nothing matched via words, try a looser pass on raw Tesseract words
    if (!any) {
      for (const w of words) {
        const t = (w.text || '').trim();
        if (!t || !w.bbox) continue;
        const wc = compactAlnum(t);
        if (wc.length >= 2 && spanCompact.includes(wc)) {
          pushBox(w.bbox);
        }
      }
    }
  }
  return boxes;
}

function mergeBoxes(list) {
  // Deduplicate identical rects; keep all distinct (overlapping ok for fill)
  const seen = new Set();
  const out = [];
  for (const b of list) {
    const key = `${b.x0}|${b.y0}|${b.x1}|${b.y1}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(b);
  }
  return out;
}

function paintCanvas(boxes) {
  const img = imageState.image;
  const canvas = $('redactCanvas');
  if (!img || !canvas) return;
  canvas.width = img.naturalWidth || img.width;
  canvas.height = img.naturalHeight || img.height;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(img, 0, 0);
  ctx.fillStyle = '#000000';
  const pad = 2;
  for (const b of boxes) {
    const x = Math.max(0, Math.floor(b.x0) - pad);
    const y = Math.max(0, Math.floor(b.y0) - pad);
    const w = Math.ceil(b.x1 - b.x0) + pad * 2;
    const h = Math.ceil(b.y1 - b.y0) + pad * 2;
    ctx.fillRect(x, y, w, h);
  }
  $('imageCard').hidden = false;
  $('downloadImageBtn').disabled = boxes.length === 0;
}

function syncImageBoxesFromFindings(list) {
  if (!imageState.image || !imageState.words.length) return;
  const text = $('input').value;
  // Preview boxes for current findings (plus any already committed redaction boxes)
  const preview = mapFindingsToWordBoxes(list, imageState.words, text);
  const combined = mergeBoxes([...imageState.boxes, ...preview]);
  paintCanvas(combined);
  // Don't commit preview into imageState.boxes until redact
  $('downloadImageBtn').disabled = combined.length === 0;
  if (list.length === 0 && imageState.boxes.length === 0) {
    // still show the image without boxes
    paintCanvas([]);
    $('downloadImageBtn').disabled = true;
  }
}

function loadImageElement(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => resolve({ img, url });
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('Image failed to load'));
    };
    img.src = url;
  });
}

async function getOcrWorker(onProgress) {
  if (typeof Tesseract === 'undefined') throw new Error('Tesseract.js failed to load');
  if (ocrWorker) return ocrWorker;
  ocrWorker = await Tesseract.createWorker('eng', 1, {
    logger: (m) => {
      if (!onProgress) return;
      if (m && typeof m.progress === 'number') {
        // Map load + recognize into 0–100 display
        const status = m.status || '';
        let pct = m.progress * 100;
        if (status.includes('loading') || status.includes('initializing')) {
          pct = m.progress * 30;
        } else if (status.includes('recognizing')) {
          pct = 30 + m.progress * 70;
        }
        onProgress(pct);
      }
    },
  });
  return ocrWorker;
}

async function runOcrOnFile(file) {
  if (ocrBusy) {
    toast('OCR already running');
    return;
  }
  if (!isAcceptedImage(file)) {
    toast('Use PNG, JPEG, WebP, or GIF');
    return;
  }
  ocrBusy = true;
  setOcrProgress(0, true);
  try {
    toast('Running OCR…');
    clearImageState();
    const { img, url } = await loadImageElement(file);
    imageState.image = img;
    imageState.objectUrl = url;
    const base = (file.name || 'image').replace(/\.[^.]+$/, '');
    imageState.fileName = `${base || 'image'}-redacted.png`;

    const worker = await getOcrWorker((pct) => setOcrProgress(pct, true));
    const result = await worker.recognize(file);
    const data = result.data || {};
    const text = (data.text || '').replace(/\r\n/g, '\n');
    const words = (data.words || [])
      .filter((w) => w && w.bbox && (w.text || '').trim())
      .map((w) => ({
        text: w.text,
        bbox: { x0: w.bbox.x0, y0: w.bbox.y0, x1: w.bbox.x1, y1: w.bbox.y1 },
      }));
    imageState.words = words;
    imageState.boxes = [];

    setOcrProgress(100, true);
    $('input').value = text;
    $('imageCard').hidden = false;
    paintCanvas([]);
    if (!text.trim()) {
      toast('OCR found no text');
      setTimeout(() => setOcrProgress(0, false), 800);
      return;
    }
    scan();
    setTimeout(() => setOcrProgress(0, false), 900);
  } catch (err) {
    console.error(err);
    toast('OCR failed');
    setOcrProgress(0, false);
  } finally {
    ocrBusy = false;
  }
}

function downloadRedactedImage() {
  const canvas = $('redactCanvas');
  if (!canvas || !imageState.image) {
    toast('No image to download');
    return;
  }
  // Ensure committed boxes (or current preview) are painted
  const text = $('input').value;
  const preview = mapFindingsToWordBoxes(findings, imageState.words, text);
  const combined = mergeBoxes([...imageState.boxes, ...preview]);
  paintCanvas(combined.length ? combined : imageState.boxes);
  canvas.toBlob((blob) => {
    if (!blob) {
      toast('Download failed');
      return;
    }
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = imageState.fileName || 'redacted.png';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    toast('Downloaded redacted image');
  }, 'image/png');
}

// —— events ——
buildToggles();

$('scanBtn').addEventListener('click', scan);
$('input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) scan();
});

$('pasteBtn').addEventListener('click', async () => {
  try {
    $('input').value = await navigator.clipboard.readText();
    scan();
  } catch {
    toast('Clipboard paste blocked — paste manually');
  }
});

$('demoBtn').addEventListener('click', () => {
  $('input').value = DEMO;
  scan();
});

$('clearBtn').addEventListener('click', () => {
  $('input').value = '';
  $('output').value = '';
  findings = [];
  renderFindings();
  renderPreview('', []);
  $('redactAllBtn').disabled = true;
  $('redactByTypeBtn').disabled = true;
  $('copyBtn').disabled = true;
  $('typePicker').hidden = true;
  clearImageState();
  $('input').focus();
});

$('redactAllBtn').addEventListener('click', () => applyRedactions(null));

$('redactByTypeBtn').addEventListener('click', () => {
  const p = $('typePicker');
  p.hidden = !p.hidden;
});

$('undoBtn').addEventListener('click', () => {
  const prev = undoStack.pop();
  if (!prev) {
    $('undoBtn').disabled = true;
    return;
  }
  $('input').value = prev.input;
  $('output').value = prev.output;
  $('copyBtn').disabled = !prev.output;
  $('undoBtn').disabled = undoStack.length === 0;
  findings = [];
  renderFindings();
  renderPreview(prev.input, []);
  $('redactAllBtn').disabled = true;
  if (imageState.image && prev.imageBoxes) {
    imageState.boxes = prev.imageBoxes.map((b) => ({ ...b }));
    paintCanvas(imageState.boxes);
    $('downloadImageBtn').disabled = imageState.boxes.length === 0;
  }
  toast('Undid last redact');
});

$('copyBtn').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('output').value);
    toast('Copied redacted text');
  } catch {
    $('output').select();
    toast('Select and copy manually');
  }
});

$('pdfInput').addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  e.target.value = '';
  if (!file) return;
  try {
    toast('Extracting PDF text…');
    const text = await extractPdfText(file);
    if (!text.trim()) {
      toast('No extractable text in that PDF');
      return;
    }
    $('input').value = text;
    scan();
  } catch (err) {
    console.error(err);
    toast('PDF extract failed');
  }
});

$('imageInput').addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  e.target.value = '';
  if (!file) return;
  await runOcrOnFile(file);
});

$('downloadImageBtn').addEventListener('click', downloadRedactedImage);

const dropzone = $('dropzone');
dropzone.addEventListener('click', () => $('imageInput').click());
dropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    $('imageInput').click();
  }
});

['dragenter', 'dragover'].forEach((ev) => {
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.add('dragover');
  });
});
['dragleave', 'drop'].forEach((ev) => {
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove('dragover');
  });
});
dropzone.addEventListener('drop', async (e) => {
  const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (!file) return;
  if (file.type === 'application/pdf' || /\.pdf$/i.test(file.name || '')) {
    try {
      toast('Extracting PDF text…');
      const text = await extractPdfText(file);
      if (!text.trim()) {
        toast('No extractable text in that PDF');
        return;
      }
      $('input').value = text;
      scan();
    } catch (err) {
      console.error(err);
      toast('PDF extract failed');
    }
    return;
  }
  await runOcrOnFile(file);
});

// Prevent the browser from opening dropped files outside the dropzone
['dragover', 'drop'].forEach((ev) => {
  document.addEventListener(ev, (e) => {
    if (e.target === dropzone || dropzone.contains(e.target)) return;
    e.preventDefault();
  });
});
