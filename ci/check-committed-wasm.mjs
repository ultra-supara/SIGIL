// CI behavioural check for the committed viewer bundle (.github/workflows/wasm.yml).
//
// Loads `site/viewer/pkg/sigil_wasm_bg.wasm`, the bundle the browser actually serves, and runs
// every viewer sample through it:
//
// - each sample's Markdown (`render_markdown`) and HTML (`markdown_html`) must be byte-equal to
//   the native render of the current Rust source, given in `<expected-dir>/<stem>.md` and
//   `<expected-dir>/<stem>.html` (from `cargo run -p sigil-wasm --example render_sample`);
// - each invalid sample must be refused with the error substring its `manifest.json` names.
//
// A behavioural change in the renderers that keeps the exported signatures would otherwise let a
// stale committed bundle through: the API-surface diff alone cannot see it.
//
// Usage: node ci/check-committed-wasm.mjs <expected-dir>

import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const expectedDir = process.argv[2];
if (!expectedDir) {
  console.error("usage: check-committed-wasm.mjs <expected-dir>");
  process.exit(2);
}

const pkgDir = path.join(repoRoot, "site/viewer/pkg");
const samplesDir = path.join(repoRoot, "site/viewer/samples");
const wasm = await import(`file://${path.join(pkgDir, "sigil_wasm.js")}`);
await wasm.default({ module_or_path: await fs.readFile(path.join(pkgDir, "sigil_wasm_bg.wasm")) });

for (const name of ["render_markdown", "markdown_html", "detect"]) {
  if (typeof wasm[name] !== "function") {
    console.error(`::error::the committed bundle does not export ${name}`);
    process.exit(1);
  }
}

let failed = 0;
const samples = (await fs.readdir(samplesDir)).filter((n) => n.endsWith(".json")).sort();
if (samples.length === 0) {
  console.error(`::error::no samples in ${samplesDir}`);
  process.exit(1);
}
for (const sample of samples) {
  const stem = sample.replace(/\.json$/, "");
  const json = await fs.readFile(path.join(samplesDir, sample), "utf8");
  let markdown;
  try {
    markdown = wasm.render_markdown(json);
  } catch (err) {
    console.error(`::error::${sample}: the committed bundle refused it: ${err?.message ?? err}`);
    failed += 1;
    continue;
  }
  const html = wasm.markdown_html(markdown);
  for (const [ext, actual] of [["md", markdown], ["html", html]]) {
    const expected = await fs.readFile(path.join(expectedDir, `${stem}.${ext}`), "utf8");
    if (actual === expected) {
      console.log(`ok   ${sample} (${ext}, ${actual.length} bytes)`);
    } else {
      console.error(`::error::${sample}: the committed bundle's ${ext} differs from the native render`);
      failed += 1;
    }
  }
}

const invalidDir = path.join(samplesDir, "invalid");
const manifest = JSON.parse(await fs.readFile(path.join(invalidDir, "manifest.json"), "utf8"));
for (const { file, expect } of manifest) {
  const json = await fs.readFile(path.join(invalidDir, file), "utf8");
  try {
    wasm.render_markdown(json);
    console.error(`::error::invalid sample ${file} was rendered`);
    failed += 1;
  } catch (err) {
    const message = String(err?.message ?? err);
    if (message.includes(expect)) {
      console.log(`ok   invalid/${file}`);
    } else {
      console.error(`::error::invalid/${file}: ${JSON.stringify(message)} lacks ${JSON.stringify(expect)}`);
      failed += 1;
    }
  }
}

if (failed > 0) {
  console.error(`${failed} check(s) failed`);
  process.exit(1);
}
