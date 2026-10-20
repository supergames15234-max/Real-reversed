// PE forensics: DOS/PE header validity, section table, entropy + printable-ASCII
// density per section, entry point resolution. usage: node pe-forensics.js [file...]
const fs = require('fs');
const crypto = require('crypto');

function entropy(buf) {
  if (!buf.length) return 0;
  const h = new Array(256).fill(0);
  for (const x of buf) h[x]++;
  let e = 0;
  for (const c of h) { if (!c) continue; const p = c / buf.length; e -= p * Math.log2(p); }
  return e;
}
function asciiDensity(buf) {
  if (!buf.length) return 0;
  let n = 0;
  for (const x of buf) if ((x >= 32 && x < 0x7f)) n++;
  return (n / buf.length * 100).toFixed(1);
}

function parsePe(path) {
  const b = fs.readFileSync(path);
  console.log('\n### ' + path + ' (' + b.length + ' bytes)');
  const pe = b.readInt32LE(0x3c);
  if (pe <= 0 || pe + 0x190 > b.length || b.slice(pe, pe + 4).toString('ascii') !== 'PE\0\0') {
    console.log(`  !! no valid PE header at e_lfanew=0x${pe.toString(16)} — not a (shifted) PE; try unxor-pe.js if it is an encrypted image`);
    return null;
  }
  const nSections = b.readUInt16LE(pe + 6);
  const optSize = b.readUInt16LE(pe + 20);
  const optOff = pe + 24;
  const magic = b.readUInt16LE(optOff);
  const isPE32plus = magic === 0x20b;
  const entryRva = b.readUInt32LE(optOff + 16);
  const imageBase = isPE32plus ? b.readBigUInt64LE(optOff + 24) : BigInt(b.readUInt32LE(optOff + 28));
  const secTable = optOff + optSize;
  console.log(`  magic=0x${magic.toString(16)} sections=${nSections} imageBase=0x${imageBase.toString(16)} entryRVA=0x${entryRva.toString(16)}`);
  const secs = [];
  for (let i = 0; i < nSections; i++) {
    const s = secTable + i * 40;
    const name = b.slice(s, s + 8).toString('ascii').replace(/[\0 ]+$/, '');
    const vsize = b.readUInt32LE(s + 8), vrva = b.readUInt32LE(s + 12);
    const rsize = b.readUInt32LE(s + 16), roff = b.readUInt32LE(s + 20);
    const chars = b.readUInt32LE(s + 36);
    const raw = b.slice(roff, Math.min(roff + rsize, b.length));
    console.log(`  ${name.padEnd(10)} fileOff=0x${roff.toString(16).padStart(6)} raw=0x${rsize.toString(16).padStart(7)} vRVA=0x${vrva.toString(16).padStart(7)} vSize=0x${vsize.toString(16).padStart(7)} entropy=${entropy(raw).toFixed(3)} ascii=${asciiDensity(raw)}% chars=0x${chars.toString(16)}${(chars & 0x20000000) ? ' EXEC' : ''}${(chars & 0x80000000) ? ' W' : ''}`);
    secs.push({ vrva, vsize, roff, rsize });
  }
  console.log('  sha256[:16]=' + crypto.createHash('sha256').update(b).digest('hex').slice(0, 16));
  for (const s of secs) {
    if (entryRva >= s.vrva && entryRva < s.vrva + s.vsize) {
      const delta = entryRva - s.vrva;
      console.log(`  ENTRY -> file=0x${(s.roff + delta).toString(16)}${delta >= s.rsize ? '  (inside VIRTUAL padding — not present in raw file!)' : ''}`);
      break;
    }
  }
}

for (const f of (process.argv.slice(2).length ? process.argv.slice(2) : [process.env.REAL_EXE_PATH || 'C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe'])) parsePe(f);
