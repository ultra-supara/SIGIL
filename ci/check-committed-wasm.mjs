// CI behavioural check for the committed wasm bundle.
//
// Loads `site/viewer/pkg/sigil_aibom_wasm_bg.wasm` (the bundle the browser
// actually serves) and renders every sample under `site/viewer/samples/`
// through its `render_aibom_markdown` export. For each sample, compares
// the wasm output to a pre-computed native render produced by the
// `render_sample` example in `crates/sigil-aibom-wasm`.
//
// This closes the gap left by the API-surface diff in the freshness
// workflow: a behavioural change in `sigil-core` that keeps the
// `#[wasm_bindgen]` signatures the same and stays within the size-swing
// budget would otherwise let a stale committed wasm slip through (Codex
// PR #36 P1, discussion r3367938924). If the committed wasm produces
// different bytes than the native render of the same JSON, the script
// exits non-zero and CI fails.
//
// Usage (called from .github/workflows/aibom-wasm.yml):
//
//   node ci/check-committed-wasm.mjs path/to/expected-dir
//
// `expected-dir` contains one `<sample-stem>.md` file per sample, each
// the verbatim native render produced by
//
//   cargo run -q -p sigil-aibom-wasm --example render_sample -- <sample>
//
// We don't run cargo from this script so the check stays single-purpose
// and fast.

import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");

const expectedDir = process.argv[2];
if (!expectedDir) {
  console.error("usage: check-committed-wasm.mjs <expected-render-dir>");
  process.exit(2);
}

const pkgDir = path.join(repoRoot, "site/viewer/pkg");
const samplesDir = path.join(repoRoot, "site/viewer/samples");
const wasmPath = path.join(pkgDir, "sigil_aibom_wasm_bg.wasm");
const jsPath = path.join(pkgDir, "sigil_aibom_wasm.js");

const wasmBytes = await fs.readFile(wasmPath);
const wasmMod = await import(`file://${jsPath}`);
await wasmMod.default({ module_or_path: wasmBytes });

if (typeof wasmMod.render_aibom_markdown !== "function") {
  console.error(
    "::error::Committed wasm bundle does not export render_aibom_markdown.",
  );
  process.exit(1);
}

const samples = (await fs.readdir(samplesDir))
  .filter((name) => name.endsWith(".aibom.json"))
  .sort();

if (samples.length === 0) {
  console.error(`::error::No samples found in ${samplesDir}`);
  process.exit(1);
}

let failed = 0;
for (const sample of samples) {
  const stem = sample.replace(/\.aibom\.json$/, "");
  const jsonPath = path.join(samplesDir, sample);
  const expectedPath = path.join(expectedDir, `${stem}.md`);

  const json = await fs.readFile(jsonPath, "utf8");
  const expected = await fs.readFile(expectedPath, "utf8");

  let actual;
  try {
    actual = wasmMod.render_aibom_markdown(json);
  } catch (err) {
    console.error(
      `::error file=site/viewer/samples/${sample}::Committed wasm threw on a sample the native render accepts: ${err.message}`,
    );
    failed += 1;
    continue;
  }

  if (actual === expected) {
    console.log(`OK ${sample} (${actual.length} bytes)`);
    continue;
  }
  failed += 1;
  console.error(
    `::error file=site/viewer/pkg/sigil_aibom_wasm_bg.wasm::Committed wasm rendered ${sample} differently from the current Rust source.`,
  );

  // Surface the first diverging line so the failure is debuggable from
  // the CI logs alone.
  const actualLines = actual.split("\n");
  const expectedLines = expected.split("\n");
  const limit = Math.max(actualLines.length, expectedLines.length);
  for (let i = 0; i < limit; i++) {
    if (actualLines[i] !== expectedLines[i]) {
      console.error(`  first divergence at line ${i + 1}:`);
      console.error(`    expected (native): ${JSON.stringify(expectedLines[i] ?? "<eof>")}`);
      console.error(`    actual   (wasm):   ${JSON.stringify(actualLines[i] ?? "<eof>")}`);
      break;
    }
  }
}

if (failed > 0) {
  console.error(
    `::error::${failed} sample(s) diverged between committed wasm and native render. Rebuild and commit site/viewer/pkg/.`,
  );
  process.exit(1);
}

console.log(
  `Committed wasm behaviourally matches the native render for all ${samples.length} sample(s).`,
);
