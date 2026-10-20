// 1) wide dump of .rdata pool near vault strings; 2) scan .text for 8-byte refs to those string VAs
const fs = require('fs');
const buf = fs.readFileSync('C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
const txt = buf.toString('latin1');

function show(off, span, label) {
  const a = Math.max(0, off - span), b = Math.min(txt.length, off + span);
  const s = txt.slice(a, b).replace(/[\x00-\x1f]/g, m => '.');
  console.log(`=== ${label} @0x${off.toString(16)} ===`);
  console.log(s);
}
const encOff = txt.indexOf('[::1]enc:v1:');
show(encOff, 3000, 'vault pool context');

// VA mapping for .rdata: va=0x7bd000 rawptr=0x7bc200
function vaOf(fileOff) { return 0x140000000n + 0x7bd000n + BigInt(fileOff - 0x7bc200); }
const targets = {
  'enc:v1:': encOff + 7, // after [::1]
  'keyv1name': txt.indexOf('Real-UI account vault key v1'),
  'nonceerr': txt.indexOf('Encrypted value has an invalid nonce'),
  'devv1': txt.indexOf('dev:v1:'),
};
// also parse the (ptr,len) &str table entries in the pool: find all u64le values in range that map into file
console.log('\n=== &str slice pairs in pool window ===');
const start = Math.max(0, encOff - 3500), end = Math.min(buf.length, encOff + 3500);
for (let o = start; o <= end - 16; o += 8) {
  const ptr = buf.readBigUInt64LE(o), len = buf.readBigInt64LE(o + 8);
  if (ptr > 0x140000000n && ptr < 0x140f00000n && len > 3n && len < 400n) {
    const rva = ptr - 0x140000000n - 0x7bd000n;
    const foff = Number(rva) + 0x7bc200;
    if (foff > 0 && foff < buf.length) {
      const s = buf.slice(foff, foff + Number(len)).toString('utf8');
      if (/^[\x20-\x7e]{3,}$/.test(s)) console.log(`  len=${len} "${s}"`);
    }
  }
}

console.log('\n=== .text xrefs ===');
const textStart = 0x400, textEnd = 0x7BC200;
for (const [name, foff] of Object.entries(targets)) {
  if (foff < 0) continue;
  const va = vaOf(foff);
  const le = Buffer.from(va.toString(16).padStart(16, '0').match(/../g).reverse().join(''), 'hex');
  let refs = [], i = textStart;
  while ((i = buf.indexOf(le, i)) !== -1 && refs.length < 8) { refs.push(i); i += 1; }
  console.log(`${name}: va=0x${va.toString(16)} xrefs: ${refs.map(r => '0x' + r.toString(16)).join(', ') || 'none'}`);
}
