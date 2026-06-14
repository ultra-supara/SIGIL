import { existsSync, readFileSync } from "node:fs";

const html = readFileSync("site/index.html", "utf8");
const css = readFileSync("site/styles.css", "utf8");

const checks = [
  {
    name: "home page title uses local-first AI-BOM positioning",
    pass: html.includes("<title>SIGIL — Local-first AI-BOMs for Local LLMs</title>"),
  },
  {
    name: "home page uses an isolated body scope",
    pass: /<body\s+class="home-page">/.test(html),
  },
  {
    name: "ambient background layers are present",
    pass: html.includes('<div class="site-noise"></div>') && html.includes('<div class="site-bg"></div>'),
  },
  {
    name: "hero headline matches the new positioning",
    pass: html.includes("Local-first AI-BOMs") && html.includes("for auditing local LLMs"),
  },
  {
    name: "existing public routes remain linked",
    pass:
      html.includes('href="./viewer/"') &&
      html.includes('href="./compare/"') &&
      html.includes('href="./reports/2026-h1/"') &&
      html.includes("https://github.com/ultra-supara/SIGIL"),
  },
  {
    name: "home visual includes sigil, terminal, and guardian layers",
    pass:
      html.includes('class="sigil-orb"') &&
      html.includes('class="terminal-card"') &&
      html.includes('class="anime-guardian"'),
  },
  {
    name: "compare and viewer are visible from the hero actions",
    pass:
      /<div class="hero-actions">[\s\S]*href="\.\/compare\/"[\s\S]*Compare Tools[\s\S]*href="\.\/viewer\/"[\s\S]*Open Viewer[\s\S]*<\/div>/.test(
        html,
      ),
  },
  {
    name: "dark homepage CSS is scoped away from subpages",
    pass:
      css.includes(".home-page {") &&
      css.includes(".home-page .site-header") &&
      css.includes(".home-page .hero-visual") &&
      css.includes(".home-page .sigil-orb"),
  },
  {
    name: "sakura and gold reference asset is wired into the homepage",
    pass:
      existsSync("site/assets/sakura-gold-top.jpeg") &&
      existsSync("site/assets/sakura-gold-bottom.jpeg") &&
      css.includes('url("./assets/sakura-gold-top.jpeg")') &&
      css.includes('url("./assets/sakura-gold-bottom.jpeg")'),
  },
  {
    name: "retired homepage image assets are not kept in git",
    pass:
      !existsSync("site/assets/hero-placeholder.svg") &&
      !existsSync("site/assets/sigil-layers.png"),
  },
  {
    name: "home responsive CSS is scoped",
    pass: /@media\s+\(max-width:\s*980px\)\s*{[\s\S]*\.home-page\s+\.hero/.test(css),
  },
  {
    name: "mobile navigation keeps compare and viewer visible",
    pass:
      css.includes(".home-page .nav-section") &&
      css.includes(".home-page .nav-route") &&
      /@media\s+\(max-width:\s*680px\)\s*{[\s\S]*\.home-page\s+\.site-nav\s*{[\s\S]*display:\s*flex/.test(css) &&
      /@media\s+\(max-width:\s*680px\)\s*{[\s\S]*\.home-page\s+\.nav-section\s*{[\s\S]*display:\s*none/.test(css),
  },
];

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
