// SIGIL viewer: shows the report of a session or an AI-BOM v2, in the browser.
//
// The wasm module (crates/sigil-wasm) runs the CLI's renderers. The report's HTML comes only from
// its `markdown_html`, whose escaping contract is sigil_model::render::html (U-10). Everything
// else on the page is set with textContent (viewer-state.js). Nothing is uploaded; the only
// fetches are the wasm bundle and the samples, from this site.

import init, { render_markdown, markdown_html } from "./pkg/sigil_wasm.js";
import { createViewer, domView } from "./viewer-state.js";

const $ = (id) => document.getElementById(id);
const view = domView({
  report: $("report"),
  error: $("error"),
  actions: $("actions"),
  copy: $("copy"),
  source: $("source"),
});
const viewer = createViewer({ render: render_markdown, toHtml: markdown_html, view });

try {
  await init();
} catch (err) {
  view.showError(
    "The renderer could not start. Serve this directory over HTTP (for example `python3 -m http.server`), " +
      `not from a file:// URL. (${err?.message ?? err})`,
  );
}

$("file").addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  if (file) viewer.load(() => file.text(), file.name);
});

for (const button of document.querySelectorAll("[data-sample]")) {
  button.addEventListener("click", () => {
    const name = button.dataset.sample;
    viewer.load(async () => {
      const response = await fetch(`./samples/${name}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.text();
    }, `sample ${name}`);
  });
}

$("copy").addEventListener("click", () => {
  const markdown = viewer.markdown();
  if (markdown) navigator.clipboard?.writeText(markdown);
});
