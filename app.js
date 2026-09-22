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

let findings = [];
let undoStack = [];

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
  undoStack.push({ input: text, output: $('output').value });
  $('undoBtn').disabled = false;

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
