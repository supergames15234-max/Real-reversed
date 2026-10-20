// find enc:v1-related literals, get their VAs, rip-xref them, dump surrounding code + nearby statics
const fs = require('fs');
const csmod = require('capstone-wasm');
const buf = fs.readFileSync('C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
const txt = buf.toString('latin1');
const TEXT_START = 0x400, TEXT_END = 0x7BC200;
function vaFullRdata(fileOff) { return 0x140000000n + 0x7bd000n + BigInt(fileOff - 0x7bc200); }
function vaFullText(fileOff) { return 0x140000000n + 0x1000n + BigInt(fileOff - TEXT_START); }
function ripXrefs(targetVaBig) {
  const hits = [];
  for (let P = TEXT_START; P < TEXT_END - 4; P++) {
    const D = (Number(targetVaBig & 0xffffffffn) - 0x140000000 - 0x1000 - (P + 4 - TEXT_START)) >>> 0;
    if (buf.readUInt32LE(P) === D) hits.push(P + 4);
  }
  return hits;
}
function findStrOffsets(needle, max = 6) {
  const res = []; let i = txt.indexOf(needle);
  while (i !== -1 && res.length < max) { res.push(i); i = txt.indexOf(needle, i + 1); }
  return res;
}

(async () => {
  await csmod.loadCapstone();
  const md = new csmod.Capstone(csmod.Const.CS_ARCH_X86, csmod.Const.CS_MODE_64);
  function disasm(innerStart, len) {
    try {
      const rv = md.disasm(buf.slice(innerStart, innerStart + len), 0);
      let off = innerStart, lines = [];
      for (const i of rv) { lines.push(`0x${vaFullText(off).toString(16)}  ${i.mnemonic} ${i.opStr || ''}`); off += i.size; }
      return lines.join('\n');
    } catch (e) { return '(disasm fail)'; }
  }

  const lits = { 'enc:v1:': 'enc:v1:', devv1: 'dev:v1:', nonceerr: 'Encrypted value has an invalid nonce' };
  for (const [name, lit] of Object.entries(lits)) {
    const offs = findStrOffsets(lit, 4);
    console.log(`\n### literal "${lit}" occurrences: ${offs.map(o => '0x' + o.toString(16)).join(', ')}`);
    for (const o of offs) {
      const va = vaFullRdata(o);
      const refs = ripXrefs(va);
      console.log(`  VA 0x${va.toString(16)} → refs: ${refs.map(r => '0x' + r.toString(16)).join(', ') || 'none'}`);
      for (const r0 of refs.slice(0, 3)) {
        console.log(`  --- code at insn-end 0x${r0.toString(16)} ---`);
        console.log(disasm(r0 - 48 >= TEXT_START ? r0 - 48 : TEXT_START, 320));
      }
    }
  }
})();
