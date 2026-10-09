// The viewer's state (site/viewer/viewer-state.js) without a browser: what the page shows after
// each load, including failures and out-of-order completions. Run: node --test ci/viewer-state.test.mjs

import test from "node:test";
import assert from "node:assert/strict";
import { createViewer, domView } from "../site/viewer/viewer-state.js";

/// Elements with the properties the view uses, as site/viewer/index.html starts them: no report,
/// the error and the actions hidden, "Copy Markdown" disabled.
function elements() {
  const el = (state = {}) => ({ hidden: false, disabled: false, textContent: "", innerHTML: "", ...state });
  const report = el();
  report.replaceChildren = () => {
    report.innerHTML = "";
  };
  return {
    report,
    error: el({ hidden: true }),
    actions: el({ hidden: true }),
    copy: el({ disabled: true }),
    source: el(),
  };
}

const render = (json) => {
  if (json === "bad") throw new Error("This is not valid JSON");
  return `# ${json}`;
};
const toHtml = (md) => `<h1>${md.slice(2)}</h1>`;

function viewer() {
  const el = elements();
  const v = createViewer({ render, toHtml, view: domView(el) });
  return { el, v };
}

const deferred = () => {
  let resolve, reject;
  const promise = new Promise((res, rej) => ((resolve = res), (reject = rej)));
  return { promise, resolve, reject };
};

test("a loaded file is shown and can be copied", async () => {
  const { el, v } = viewer();
  await v.load(async () => "a", "a.json");
  assert.equal(el.report.innerHTML, "<h1>a</h1>");
  assert.equal(v.markdown(), "# a");
  assert.equal(el.actions.hidden, false);
  assert.equal(el.copy.disabled, false);
  assert.equal(el.source.textContent, "a.json");
  assert.equal(el.error.hidden, true);
});

test("a read failure clears the previous report and disables copying", async () => {
  const { el, v } = viewer();
  await v.load(async () => "a", "a.json");
  await v.load(async () => {
    throw new Error("HTTP 404");
  }, "sample x.json");
  assert.equal(el.report.innerHTML, "");
  assert.equal(v.markdown(), "");
  assert.equal(el.copy.disabled, true);
  assert.equal(el.actions.hidden, true);
  assert.equal(el.source.textContent, "");
  assert.equal(el.error.hidden, false);
  assert.match(el.error.textContent, /Could not read sample x\.json: HTTP 404/);
});

test("a render failure clears the previous report and disables copying", async () => {
  const { el, v } = viewer();
  await v.load(async () => "a", "a.json");
  await v.load(async () => "bad", "b.json");
  assert.equal(el.report.innerHTML, "");
  assert.equal(v.markdown(), "");
  assert.equal(el.copy.disabled, true);
  assert.match(el.error.textContent, /not valid JSON/);
});

test("a report loaded after a failure can be copied again", async () => {
  const { el, v } = viewer();
  await v.load(async () => "bad", "b.json");
  await v.load(async () => "c", "c.json");
  assert.equal(el.report.innerHTML, "<h1>c</h1>");
  assert.equal(v.markdown(), "# c");
  assert.equal(el.copy.disabled, false);
  assert.equal(el.actions.hidden, false);
  assert.equal(el.error.hidden, true);
  assert.equal(el.source.textContent, "c.json");
});

test("the latest request wins, whichever finishes first", async () => {
  const { el, v } = viewer();
  const slow = deferred();
  const first = v.load(() => slow.promise, "slow.json");
  await v.load(async () => "fast", "fast.json");
  slow.resolve("slow");
  await first;
  assert.equal(el.report.innerHTML, "<h1>fast</h1>");
  assert.equal(v.markdown(), "# fast");
});

test("a stale failure does not clear a newer report", async () => {
  const { el, v } = viewer();
  const slow = deferred();
  const first = v.load(() => slow.promise, "slow.json");
  await v.load(async () => "fast", "fast.json");
  slow.reject(new Error("network"));
  await first;
  assert.equal(el.report.innerHTML, "<h1>fast</h1>");
  assert.equal(el.copy.disabled, false);
  assert.equal(el.error.hidden, true);
});
