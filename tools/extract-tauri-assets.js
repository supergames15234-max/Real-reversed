// Tauri v2 embedded-asset extractor (final):
// layout = "<asset path string><brotli stream>" — brotli ignores trailing bytes.
// Plain assets allowed only when they start with recognizable text markers.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const EXE = 'C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe';
const OUT = 'C:/Users/[name]/Documents/Default Project/Real-Reversed/ui-assets';

const buf = fs.readFileSync(EXE);
const txt = buf.toString('latin1');
const pathRe = /\/(?:[\w .\-\/]{2,160}?\.(?:html|js|css|json|svg|png|webp|woff2?|mp4|wasm|ico|txt|map|luau|lua))(?=[^\/\w]|$)/g;
const occ = []; let m;
while ((m = pathRe.exec(txt)) !== null) occ.push({ str: m[0], end: m.index + m[0].length });
console.log(`occurrences: ${occ.length}`);

fs.mkdirSync(OUT, { recursive: true });
const results = [], skipped = [];
const seen = new Set();
function saveNative(str, data, raw = false) {
  if (results.some(r => r.p === str)) return false;
  const safe = str.replace(/^\/+/, '').replace(/[^A-Za-z0-9._\/-]/g, '_');
  if (!safe || safe.length < 4) return false;
  const dest = path.join(OUT, safe);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, data);
  results.push({ p: str, outLen: data.length, raw });
  return true;
}

for (const o of occ) {
  const blob = buf.slice(o.end, Math.min(buf.length, o.end + 4 * 1024 * 1024));
  if (blob.length < 4) continue;
  let out = null;
  try { out = zlib.brotliDecompressSync(blob, { maxOutput: 64 * 1024 * 1024 }); } catch (e) { out = null; }
  if ((out && out.length > 0)) { saveNative(o.str, out); continue; }
  try { out = zlib.gunzipSync(blob); if (out && out.length > 0) { saveNative(o.str, out); continue; } } catch (e) {}
  // plain-text asset fallback
  const s = blob.slice(0, 32).toString('latin1');
  const plain = /^(<!DOCTYPE|<!doctype|<html|<svg|\{|\s*<\?xml|'"|\s*\/\*|\s*\/\/)/.test(s);
  if (plain && blob.length > 8) { saveNative(o.str, blob.slice(0, Math.min(blob.length, 4 * 1024 * 1024)), true); continue; }
  skipped.push(o.str);
}
fs.writeFileSync(path.join(OUT, '_manifest.json'), JSON.stringify({ extracted: results, skipped }, null, 2));
console.log(`extracted ${results.length}, skipped ${skipped.length}`);
for (const r of results.sort((a, b) => b.outLen - a.outLen).slice(0, 80)) console.log(`  ${r.raw ? '[raw] ' : ''}${r.p} (${r.outLen})`);
