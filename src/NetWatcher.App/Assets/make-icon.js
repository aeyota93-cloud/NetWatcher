const { chromium } = require('playwright');
// Rounded square with the Windows blue gradient and a white "pulse" line.
// Small sizes get a thicker line so it stays readable at 16 px.
const svg = (size) => {
  const sw = size <= 20 ? 2.0 : size <= 48 ? 1.6 : 1.25;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 16 16">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#0F6CBD"/><stop offset="1" stop-color="#3A96DD"/></linearGradient></defs>
  <rect x="0.5" y="0.5" width="15" height="15" rx="3.6" fill="url(#g)"/>
  <path d="M2.4 8.6h2.5l1.6-3.6 2.6 7 1.7-4.4h2.8" fill="none" stroke="#fff" stroke-width="${sw}"
        stroke-linecap="round" stroke-linejoin="round" transform="translate(0,-0.3)"/>
</svg>`;
};
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage();
  for (const s of [16, 20, 24, 32, 40, 48, 64, 128, 256]) {
    await p.setViewportSize({ width: s, height: s });
    await p.setContent(`<html><body style="margin:0;background:transparent">${svg(s)}</body></html>`);
    await p.screenshot({ path: `${__dirname}/icon-${s}.png`, omitBackground: true, clip: { x: 0, y: 0, width: s, height: s } });
  }
  await b.close();
})();
