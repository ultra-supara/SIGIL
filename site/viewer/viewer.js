// SIGIL viewer: shows the report of a session or an AI-BOM v2, in the browser.
//
// The wasm module (crates/sigil-wasm) runs the CLI's renderers. The report's HTML comes only from
// its `markdown_html`, whose escaping contract is sigil_model::render::html (U-10). Everything
// else on the page is set with textContent. Nothing is uploaded; the only fetches are the wasm
// bundle and the samples, from this site.

import init, { render_markdown, markdown_html } from "./pkg/sigil_wasm.js";

const $ = (id) => document.getElementById(id);
const report = $("report");
const error = $("error");
const actions = $("actions");
const source = $("source");

let markdown = "";
// Discards a render that finishes after a later one was started.
let latest = 0;

function show(json, label) {
  try {
    markdown = render_markdown(json);
  } catch (err) {
    markdown = "";
    report.replaceChildren();
    actions.hidden = true;
    error.textContent = String(err?.message ?? err);
    error.hidden = false;
    return;
  }
  error.hidden = true;
  report.innerHTML = markdown_html(markdown);
  source.textContent = label;
  actions.hidden = false;
}

async function load(read, label) {
  const mine = ++latest;
  let json;
  try {
    json = await read();
  } catch (err) {
    json = null;
    if (mine === latest) {
      error.textContent = `Could not read ${label}: ${err?.message ?? err}`;
      error.hidden = false;
    }
  }
  if (json !== null && mine === latest) show(json, label);
}

try {
  await init();
} catch (err) {
  error.textContent =
    "The renderer could not start. Serve this directory over HTTP (for example `python3 -m http.server`), " +
    `not from a file:// URL. (${err?.message ?? err})`;
  error.hidden = false;
}

$("file").addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  if (file) load(() => file.text(), file.name);
});

for (const button of document.querySelectorAll("[data-sample]")) {
  button.addEventListener("click", () => {
    const name = button.dataset.sample;
    load(async () => {
      const response = await fetch(`./samples/${name}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.text();
    }, `sample ${name}`);
  });
}

$("copy").addEventListener("click", () => {
  if (markdown) navigator.clipboard?.writeText(markdown);
});
