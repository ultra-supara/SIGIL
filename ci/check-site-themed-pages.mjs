import { readFileSync } from "node:fs";

const css = readFileSync("site/styles.css", "utf8");
const h1ReportHtml = readFileSync("site/reports/2026-h1/index.html", "utf8");
const h1Summary = readFileSync("reports/2026-h1/summary.json", "utf8");
const h1Phi3Raw = readFileSync("reports/2026-h1/raw/phi3_mini.aibom.json", "utf8");
const compareIndexHtml = readFileSync("site/compare/index.html", "utf8");
const compareCardHeadings = [
  ...compareIndexHtml.matchAll(
    /<a class="compare-index-card"[\s\S]*?<h3>([\s\S]*?)<\/h3>/g,
  ),
].map((match) => match[1]);
const pages = [
  {
    name: "compare",
    path: "site/compare/index.html",
    topPrefix: "../",
    expectedTerminal: "sigil://compare",
  },
  {
    name: "report",
    path: "site/reports/2026-h1/index.html",
    topPrefix: "../../",
    expectedTerminal: "sigil://report",
  },
  {
    name: "syft comparison",
    path: "site/compare/sigil-vs-syft/index.html",
    topPrefix: "../../",
    expectedTerminal: "sigil://syft",
  },
  {
    name: "builtins comparison",
    path: "site/compare/sigil-vs-builtins/index.html",
    topPrefix: "../../",
    expectedTerminal: "sigil://builtins",
  },
  {
    name: "owasp comparison",
    path: "site/compare/sigil-vs-owasp-aibom-generator/index.html",
    topPrefix: "../../",
    expectedTerminal: "sigil://owasp",
  },
];

const checks = [];

for (const page of pages) {
  const html = readFileSync(page.path, "utf8");

  checks.push(
    {
      name: `${page.name} page opts into sakura theme`,
      pass: /<body\s+class="sakura-page[^"]*">/.test(html),
    },
    {
      name: `${page.name} page has ambient background layers`,
      pass: html.includes('<div class="site-noise"></div>') && html.includes('<div class="site-bg"></div>'),
    },
    {
      name: `${page.name} hero uses top-page sigil visual language`,
      pass:
        html.includes('class="sigil-orb"') &&
        html.includes('class="sigil-ring ring-a"') &&
        html.includes('class="floating-label label-one"') &&
        html.includes('class="terminal-card"') &&
        html.includes(page.expectedTerminal),
    },
    {
      name: `${page.name} nav points to current top-page sections`,
      pass:
        html.includes(`href="${page.topPrefix}#platform"`) &&
        html.includes(`href="${page.topPrefix}#research"`) &&
        html.includes(`href="${page.topPrefix}#tools"`),
    },
  );
}

checks.push(
  {
    name: "shared sakura page CSS exists",
    pass:
      css.includes(".sakura-page {") &&
      css.includes(".sakura-page .site-bg::before") &&
      css.includes(".sakura-page .hero-visual") &&
      css.includes(".sakura-page .terminal-card"),
  },
  {
    name: "sakura page cards are dark themed",
    pass: css.includes(".sakura-page .compare-index-card"),
  },
  {
    name: "report table sections keep the dark sakura background",
    pass:
      /\.sakura-page\s+\.compare-axes\s*{[\s\S]*background:\s*transparent/.test(css) &&
      /\.sakura-page\s+\.compare-axes\s+\.table-wrap\s*{[\s\S]*background:\s*rgba\(255,\s*255,\s*255,\s*0\.025\)/.test(
        css,
      ),
  },
  {
    name: "compare card headings avoid inline code chips",
    pass:
      compareCardHeadings.length === 3 &&
      compareCardHeadings.every((heading) => !heading.includes("<code>")),
  },
  {
    name: "2026 H1 report no longer carries the phi3 Microsoft SPDX false positive",
    pass:
      !h1ReportHtml.includes("Microsoft.") &&
      !h1ReportHtml.includes("false positive") &&
      !h1Summary.includes("Microsoft.") &&
      !h1Phi3Raw.includes('"spdx_id": "Microsoft."') &&
      h1ReportHtml.includes("<td><code>MIT</code></td>") &&
      h1Summary.includes('"spdx_id": "MIT"') &&
      h1Phi3Raw.includes('"spdx_id": "MIT"'),
  },
);

const failures = checks.filter((check) => !check.pass);

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`FAIL ${failure.name}`);
  }
  process.exit(1);
}

for (const check of checks) {
  console.log(`PASS ${check.name}`);
}
