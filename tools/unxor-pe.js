// Unwrap a repeating-key-XOR'd PE. usage: node unxor-pe.js [inFile] [outFile]
// Derives the key from the canonical MZ/DOS-header crib (16 bytes), verifies by
// checking that the unwrapped e_lfanew points at a real "PE\0\0" signature.
// For bin/Real.dll (v2.7.9): in = .../bin/Real.dll, out = decrypted PE image.
const fs = require('fs');
const inPath = process.argv[2] || process.env.REAL_DLL_PATH || 'C:/Users/[name]/AppData/Local/Real/real-2.7.9/bin/Real.dll';
const outPath = process.argv[3] || 'Real-decrypted.dll';
const b = fs.readFileSync(inPath);

// standard DOS header prefix; bytes 8..15 are usually zero/stuff-padding here,
// so only the first 8 bytes are trusted for the key, then verified against
// the PE signature via e_lfanew.
const crib = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
const key = Buffer.alloc(crib.length);
for (let i = 0; i < crib.length; i++) key[i] = b[i] ^ crib[i];

const out = Buffer.alloc(b.length);
for (let i = 0; i < b.length; i++) out[i] = b[i] ^ key[i % key.length];

const peOff = out.readUInt32LE(0x3c);
const sig = out.slice(peOff, peOff + 4).toString('ascii');
const ok = sig === 'PE\0\0';
console.log(`derived repeating-key: ${key.toString('hex')}  e_lfanew=0x${peOff.toString(16)}  sig@e_lfanew=${JSON.stringify(sig)}  ${ok ? 'VERIFIED' : 'FAILED (wrong key length or crib)'}`);
if (ok) {
  fs.writeFileSync(outPath, out);
  console.log(`wrote ${outPath} (${out.length} bytes)`);
} else if (process.argv[3]) {
  fs.writeFileSync(outPath, out);
  console.log(`wrote ${outPath} anyway (inspect manually)`);
}
