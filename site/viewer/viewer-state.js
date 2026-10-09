// The viewer's state, apart from the DOM and the wasm module, so that node can test it
// (ci/viewer-state.test.mjs).
//
// - The latest load wins: a read or render that finishes after a later load started is dropped,
//   whether it succeeded or failed.
// - Any failure (reading the file, fetching a sample, rendering) clears the report shown before
//   and disables "Copy Markdown", so nothing stale stays on the page.

/// What the page shows, on its elements. The report's HTML is `toHtml` output only; everything
/// else is set as text.
export function domView(el) {
  return {
    showReport(html, label) {
      el.error.hidden = true;
      el.report.innerHTML = html;
      el.source.textContent = label;
      el.copy.disabled = false;
      el.actions.hidden = false;
    },
    showError(message) {
      el.report.replaceChildren();
      el.source.textContent = "";
      el.copy.disabled = true;
      el.actions.hidden = true;
      el.error.textContent = message;
      el.error.hidden = false;
    },
  };
}

/// `render(json)` gives Markdown or throws; `toHtml(markdown)` gives the report's HTML.
export function createViewer({ render, toHtml, view }) {
  let markdown = "";
  let latest = 0;
  const message = (err) => String(err?.message ?? err);
  const fail = (text) => {
    markdown = "";
    view.showError(text);
  };

  async function load(read, label) {
    const mine = ++latest;
    let json;
    try {
      json = await read();
    } catch (err) {
      if (mine === latest) fail(`Could not read ${label}: ${message(err)}`);
      return;
    }
    if (mine !== latest) return;
    try {
      markdown = render(json);
    } catch (err) {
      fail(message(err));
      return;
    }
    view.showReport(toHtml(markdown), label);
  }

  return { load, markdown: () => markdown };
}
