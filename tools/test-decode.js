// manual decode test on a known-good chunk asset
const fs = require('fs'); const zlib = require('zlib');
const buf = fs.readFileSync('C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
const p = Buffer.from('/_app/immutable/chunks/DkPI0BL9.js', 'latin1');
const off = buf.indexOf(p);
const blobStart = off + p.length;
const blob = buf.slice(blobStart, blobStart + 4_000_000);
console.log(`path@0x${off.toString(16)} blob@0x${blobStart.toString(16)}`);
try { const out = zlib.brotliDecompressSync(blob, { maxOutput: 64 * 1024 * 1024 }); console.log('OK len', out.length, out.slice(0, 120).toString()); }
catch (e) { console.log('ERR:', e.message, e.code || ''); }
// try truncated progressively to see if it just needs a bound
for (const L of [1024, 4096, 65536, 262144]) {
  try { const out = zlib.brotliDecompressSync(blob.slice(0, L), { maxOutput: 64 * 1024 * 1024 }); console.log(`bound ${L}: OK len`, out.length); break; }
  catch (e) { console.log(`bound ${L}: ERR ${e.message.slice(0, 60)}`); }
}
