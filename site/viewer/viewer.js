// Browser glue for the SIGIL AI-BOM viewer.
//
// Boot the wasm module, wire the drop zone / file picker / sample buttons, and
// pipe AI-BOM JSON through `render_aibom_markdown(json)` → minimal MD→HTML →
// the report panel. No CDN, no analytics, no upload — the only fetches are
// same-origin reads of the wasm bundle and the three sample JSONs in
// ./samples/.

import init, {
  render_aibom_markdown,
  aibom_schema_version,
} from "./pkg/sigil_aibom_wasm.js";

const $ = (id) => document.getElementById(id);
const dropzone = $("dropzone");
const filepicker = $("filepicker");
const errorBanner = $("error");
const outputWrap = $("output-wrap");
const output = $("output");
const outputSource = $("output-source");
const placeholder = $("placeholder");
const schemaCaption = $("schema-caption");
const copyButton = $("copy-md");

let lastMarkdown = "";

const sampleVerdicts = {
  pass: "PASS",
  warn: "WARN",
  fail: "FAIL",
};

(async function boot() {
  try {
    await init();
    schemaCaption.textContent = `Schema ${aibom_schema_version()}`;
    wireUi();
  } catch (err) {
    showError(
      "Failed to initialise the wasm renderer.\n" +
        "Most likely cause: the page was opened from the local filesystem " +
        "(file://) which blocks module loads. Serve the directory with any " +
        "static server (e.g. `python3 -m http.server`) and reload.\n\n" +
        humanizeError(err),
    );
  }
})();

function wireUi() {
  // Drop zone interactions.
  ["dragenter", "dragover"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("is-hover");
    });
  });
  ["dragleave", "dragend"].forEach((evt) => {
    dropzone.addEventListener(evt, () => dropzone.classList.remove("is-hover"));
  });
  dropzone.addEventListener("drop", async (e) => {
    e.preventDefault();
    dropzone.classList.remove("is-hover");
    const file = e.dataTransfer?.files?.[0];
    if (file) await loadFile(file);
  });
  dropzone.addEventListener("click", (e) => {
    // Clicking the inner "choose a file" label already opens the picker —
    // avoid opening it twice when the user clicks the label itself.
    if (e.target.closest(".dropzone-pick")) return;
    filepicker.click();
  });
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      filepicker.click();
    }
  });

  filepicker.addEventListener("change", async () => {
    const file = filepicker.files?.[0];
    if (file) await loadFile(file);
    filepicker.value = ""; // allow re-selecting the same file
  });

  // Sample buttons.
  document.querySelectorAll("[data-sample]").forEach((btn) => {
    btn.addEventListener("click", () => loadSample(btn.dataset.sample));
  });

  copyButton.addEventListener("click", async () => {
    if (!lastMarkdown) return;
    try {
      await navigator.clipboard.writeText(lastMarkdown);
      const original = copyButton.textContent;
      copyButton.textContent = "Copied";
      setTimeout(() => (copyButton.textContent = original), 1200);
    } catch {
      // Older browsers / insecure contexts — fall back to a textarea select.
      const ta = document.createElement("textarea");
      ta.value = lastMarkdown;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
      } catch {
        /* swallow — copying is non-essential */
      }
      ta.remove();
    }
  });
}

async function loadFile(file) {
  if (!file.name.endsWith(".json")) {
    showError(
      `Expected a .json file, got "${file.name}". Drop a SIGIL AI-BOM ` +
        `(e.g. gemma3_4b.aibom.json).`,
    );
    return;
  }
  let text;
  try {
    text = await file.text();
  } catch (err) {
    showError(`Could not read file: ${humanizeError(err)}`);
    return;
  }
  renderJson(text, `file: ${file.name}`);
}

async function loadSample(key) {
  const url = `./samples/${key}.aibom.json`;
  try {
    const res = await fetch(url);
    if (!res.ok) {
      showError(
        `Sample fetch returned HTTP ${res.status}. The sample file ${url} ` +
          `may not be served by the current static host.`,
      );
      return;
    }
    const text = await res.text();
    renderJson(text, `sample: ${sampleVerdicts[key] ?? key}`);
  } catch (err) {
    showError(`Could not load sample (${url}): ${humanizeError(err)}`);
  }
}

function renderJson(jsonText, sourceLabel) {
  clearError();
  let markdown;
  try {
    markdown = render_aibom_markdown(jsonText);
  } catch (err) {
    // serde_json's error message is already human-readable (includes
    // line/column for syntactic errors; reports the missing field for shape
    // mismatches). Surface it directly instead of swallowing.
    showError(humanizeError(err));
    return;
  }
  lastMarkdown = markdown;
  outputSource.textContent = sourceLabel;
  output.innerHTML = markdownToHtml(markdown);
  outputWrap.hidden = false;
  placeholder.hidden = true;
  outputWrap.scrollIntoView({ behavior: "smooth", block: "start" });
}

function showError(message) {
  errorBanner.textContent = message;
  errorBanner.hidden = false;
  outputWrap.hidden = true;
  placeholder.hidden = false;
}

function clearError() {
  errorBanner.textContent = "";
  errorBanner.hidden = true;
}

function humanizeError(err) {
  if (!err) return "Unknown error.";
  if (typeof err === "string") return err;
  return err.message || String(err);
}

// ---------------------------------------------------------------------------
// Minimal Markdown → HTML pass.
//
// The renderer in sigil-core emits a deliberately small subset:
//   # / ## / ### headings, "- " bullet lists, pipe tables with "|---|" rules,
//   inline `code`, **bold**, _italic_. No fenced code, no links, no images.
// We escape HTML special characters first and only re-introduce markup for
// the tokens render_ai_bom actually produces.
// ---------------------------------------------------------------------------
function markdownToHtml(md) {
  const lines = md.split("\n");
  const out = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    if (line === "") {
      i += 1;
      continue;
    }

    // Pipe table: current line starts with "|", next line is a separator
    // ("|---|---|"). Collect until a non-pipe line.
    if (line.startsWith("|") && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      const header = parseTableRow(line);
      const rows = [];
      i += 2;
      while (i < lines.length && lines[i].startsWith("|")) {
        rows.push(parseTableRow(lines[i]));
        i += 1;
      }
      out.push(renderTable(header, rows));
      continue;
    }

    // Bullet list: collect consecutive "- " lines.
    if (line.startsWith("- ")) {
      const items = [];
      while (i < lines.length && lines[i].startsWith("- ")) {
        items.push(inline(lines[i].slice(2)));
        i += 1;
      }
      out.push(`<ul>${items.map((it) => `<li>${it}</li>`).join("")}</ul>`);
      continue;
    }

    // Headings.
    if (line.startsWith("### ")) {
      out.push(`<h3>${inline(line.slice(4))}</h3>`);
      i += 1;
      continue;
    }
    if (line.startsWith("## ")) {
      out.push(`<h2>${inline(line.slice(3))}</h2>`);
      i += 1;
      continue;
    }
    if (line.startsWith("# ")) {
      out.push(`<h1>${inline(line.slice(2))}</h1>`);
      i += 1;
      continue;
    }

    // Paragraph fallback.
    out.push(`<p>${inline(line)}</p>`);
    i += 1;
  }

  return out.join("\n");
}

function isTableSeparator(line) {
  if (!line.startsWith("|")) return false;
  // Each cell must be only dashes/colons/spaces, with at least one dash.
  const cells = line.slice(1, line.endsWith("|") ? -1 : undefined).split("|");
  return cells.every((cell) => /^\s*:?-+:?\s*$/.test(cell));
}

function parseTableRow(line) {
  const trimmed = line.startsWith("|") ? line.slice(1) : line;
  const body = trimmed.endsWith("|") ? trimmed.slice(0, -1) : trimmed;
  return body.split("|").map((cell) => cell.trim());
}

function renderTable(header, rows) {
  const head = `<thead><tr>${header
    .map((h) => `<th>${inline(h)}</th>`)
    .join("")}</tr></thead>`;
  const body = `<tbody>${rows
    .map(
      (row) =>
        `<tr>${row.map((cell) => `<td>${inline(cell)}</td>`).join("")}</tr>`,
    )
    .join("")}</tbody>`;
  return `<table>${head}${body}</table>`;
}

// Inline-level transforms. Order matters: escape HTML first, then convert
// backticked code (which must not interpret bold/italic markers inside), then
// the remaining emphasis markers in the leftover text.
function inline(text) {
  let s = escapeHtml(text);
  s = s.replace(/`([^`]+)`/g, (_m, code) => `<code>${code}</code>`);
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  // Underscore italics — only between word boundaries to avoid eating
  // underscores that show up inside sha256 paths or identifiers.
  s = s.replace(/(^|\s)_([^_\s][^_]*[^_\s]|[^_\s])_(?=\s|$)/g, "$1<em>$2</em>");
  return s;
}

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
