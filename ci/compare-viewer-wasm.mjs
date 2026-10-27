// Differential check for build/optimizer changes. Run from any working directory:
// node ci/compare-viewer-wasm.mjs BEFORE_PKG AFTER_PKG
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';

if (process.argv.length !== 4) {
  console.error('usage: node ci/compare-viewer-wasm.mjs BEFORE_PKG AFTER_PKG');
  process.exit(2);
}
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function load(dir) {
  const pkg = path.resolve(dir);
  const api = await import(pathToFileURL(path.join(pkg, 'sigil_wasm.js')));
  const instance = await api.default({
    module_or_path: await fs.readFile(path.join(pkg, 'sigil_wasm_bg.wasm')),
  });
  return { api, instance };
}

const [before, after] = await Promise.all(process.argv.slice(2).map(load));
assert.deepEqual(Object.keys(after.api).sort(), Object.keys(before.api).sort());
assert.deepEqual(Object.keys(after.instance).sort(), Object.keys(before.instance).sort());
assert.equal(after.api.versions(), before.api.versions());

function result(fn, input) {
  try {
    return { value: fn(input) };
  } catch (e) {
    return { error: e.message };
  }
}

let count = 0;
function compare(input, all = false) {
  const methods = all
    ? ['detect', 'render_markdown', 'render_session_markdown', 'render_aibom_markdown']
    : ['detect', 'render_markdown'];
  for (const name of methods) {
    assert.deepEqual(result(after.api[name], input), result(before.api[name], input),
      `${name}, document ${count}`);
  }
  count++;
}

for (const relative of ['site/viewer/samples', 'schemas/examples/session-v1', 'schemas/examples/aibom-v2']) {
  const dir = path.join(root, relative);
  for (const name of (await fs.readdir(dir)).filter(n => n.endsWith('.json')).sort()) {
    const input = await fs.readFile(path.join(dir, name), 'utf8');
    compare(input, true);
    const value = JSON.parse(input);
    for (const key of Object.keys(value)) {
      for (const replacement of [undefined, null, [], {}, true, 0, 'x']) {
        compare(JSON.stringify({ ...value, [key]: replacement }));
      }
    }
    for (const end of [0, 1, 2, Math.floor(input.length / 2), input.length - 1]) {
      compare(input.slice(0, end));
    }
  }
}
for (const input of ['null', 'true', '0', '"x"', '[]', '{}', '{', '\u0000', '{"schema":"wrong"}']) {
  compare(input, true);
}
for (const md of ['', '# <script>alert(1)</script>', '| a | b |\n|---|---|\n| & | < |', 'é 日本語 😀', '**a**\n\n- b']) {
  assert.equal(after.api.markdown_html(md), before.api.markdown_html(md));
}
console.log(`${count} documents: exports, detection, reports and rejection messages match`);
console.log(`Memory after comparisons: before=${before.instance.memory.buffer.byteLength}; after=${after.instance.memory.buffer.byteLength}`);
