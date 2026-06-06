# SIGIL hero — image-generation brief

Use this brief verbatim with Midjourney, DALL·E 3, Stable Diffusion, or
similar. Drop the final PNG into `site/assets/sigil-hero.png` and the home
page will pick it up automatically (`site/index.html` swaps the inline
placeholder SVG for the file once present).

## One-paragraph prompt (paste-ready)

> Elegant wide-format hero illustration for a Japanese-style OSS security
> tool's landing page, drawn in clean monochrome anime style on aged washi
> paper. A composed protagonist in subdued traditional Japanese attire
> stands on one side of the frame, with a quiet, focused expression and a
> sharp inward gaze — they see what others cannot. The opposite side of the
> frame is intentionally empty, reserved for logo, headline, and call to
> action. Setting: a still, pre-dawn Japanese space — a torii gate seen
> through a faint circular ward (kekkai) pattern, bamboo silhouettes in
> the middle distance, soft moonlight, a stone path receding into ink
> mist. No computers, no screens, no code, no servers. Security is implied
> only through symbolism: the protagonist's perceptive gaze, the circular
> barrier protecting the gate, ink lines flowing as boundaries, a faint
> shadow already dissolving at the edge of the path. The story reads:
> _quietly notice, see through, protect — and walk on_. Tone is elegant,
> serene, intelligent, trustworthy, slightly mysterious; never aggressive,
> never dark. Composition is cinematic, asymmetric, with generous negative
> space and a strong vertical reading line. Strict monochrome palette —
> warm off-white paper, deep ink black, ash grey midtones, no other hues.
> Line work is delicate, confident, and varied; shading is sparing,
> sumi-e in feel. The final image must work as the first thing a visitor
> sees on an OSS security tool's homepage: text overlay over the empty
> half must remain perfectly legible.

## Negative prompt / things to avoid

> No keyboards, no monitors, no laptops, no smartphones, no code, no
> servers, no cables, no neon, no cyberpunk, no glowing UI, no high-tech
> implants, no weapons drawn in attack, no blood, no signage with English
> text, no logo, no watermark, no extra characters in the empty half.
> Avoid heavy line weights, oversaturated values, and any colour other
> than ink, paper, and ash.

## Composition checklist

- **Aspect ratio**: 4:3 or wider (3:2 / 16:9 also fine). The placeholder
  SVG is authored at 720 × 540 (4:3) — match or render wider.
- **Subject position**: protagonist occupies ~40–45% of the frame (one
  side). Leave the other ~55–60% as breathable space for overlay text.
- **Reading order**: the eye lands on the figure's gaze first, follows the
  gaze across the negative space, settles on the implied CTA region.
- **Vertical alignment**: the figure's head should sit roughly on the
  upper-third horizontal line so headlines in the empty half align
  visually with it.
- **Tonal range**: stay in the lighter half — primary tone is paper
  white, with ink reserved for accents and silhouettes. Do not let the
  image fall darker than a 60% mid-grey on average.

## Style references

- `Mononoke Hime` early concept ink studies — for the warmth of monochrome
  Japanese composition.
- `Aoashi` opening promotional art — for clean modern anime line work
  applied to a quiet scene.
- Sumi-e by Sesshū Tōyō — for the use of negative space and the
  confidence of a single brush stroke implying a much larger world.

## After generation

1. Export at 2× the intended display size (the home page renders the hero
   at ~720 px wide on desktop, so target ≥ 1440 × 1080 PNG).
2. Run through a lossless optimiser (`oxipng -o 4 sigil-hero.png` or
   `pngquant 256 --strip --skip-if-larger sigil-hero.png`) before
   committing.
3. Drop into `site/assets/sigil-hero.png`.
4. Replace the inline placeholder SVG in `site/index.html` with:

   ```html
   <img
     src="./assets/sigil-hero.png"
     alt="A protagonist in traditional Japanese dress stands by a torii gate at dawn, a faint circular ward protecting the path behind them."
     width="720"
     height="540"
     loading="eager"
   />
   ```

5. Commit on a branch and open a PR titled `feat(site): replace hero
   placeholder with commissioned key visual`.
