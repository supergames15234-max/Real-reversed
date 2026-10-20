// debug: why does extraction fail for _app assets?
const fs = require('fs'); const zlib = require('zlib');
const buf = fs.readFileSync('C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
const txt = buf.toString('latin1');
const pathRe = /\/(?:[\w .\-\/]{2,160}?\.(?:html|js|css|json|svg|png|webp|woff2?|mp4|wasm|ico|txt|map|luau|lua))(?=[^\/\w]|$)/g;
const occ = []; let m;
while ((m = pathRe.exec(txt)) !== null) occ.push({ str: m[0], end: m.index + m[0].length });
console.log('occurrences:', occ.length);
let n = 0;
for (const o of occ) {
  if (n >= 6) break;
  const blob = buf.slice(o.end, Math.min(buf.length, o.end + 4 * 1024 * 1024));
  try { const out = zlib.brotliDecompressSync(blob, { maxOutput: 64 * 1024 * 1024 }); console.log(`OK  ${o.str} -> ${out.length}`); n++; }
  catch (e) { console.log(`ERR ${o.str}: ${e.message.slice(0, 80)}`); }
}
