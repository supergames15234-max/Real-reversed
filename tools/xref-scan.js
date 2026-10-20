// RIP-relative xref finder for known string VAs + local disasm around hits using capstone-wasm (async init)
const fs = require('fs');
const csmod = require('capstone-wasm');
const buf = fs.readFileSync('C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
const txt = buf.toString('latin1');

const TEXT_START = 0x400, TEXT_END = 0x7BC200;
function vaFullText(fileOff) { return 0x140000000n + 0x1000n + BigInt(fileOff - TEXT_START); }
function vaFull(fileOff) { return 0x140000000n + 0x7bd000n + BigInt(fileOff - 0x7bc200); }

function ripXrefs(targetVaBig) {
  const hits = [];
  for (let P = TEXT_START; P < TEXT_END - 4; P++) {
    const D = (Number(targetVaBig & 0xffffffffn) - 0x140000000 - 0x1000 - (P + 4 - TEXT_START)) >>> 0;
    if (buf.readUInt32LE(P) === D) hits.push(P + 4);
  }
  return hits;
}

async function main() {
  await csmod.loadCapstone();
  const md = new csmod.Capstone(csmod.Const.CS_ARCH_X86, csmod.Const.CS_MODE_64);
  function disasmAround(insnEndOff, pre = 32, post = 128) {
    for (let s = insnEndOff - pre; s < insnEndOff; s++) {
      try {
        const rv = md.disasm(buf.slice(s, insnEndOff + post), 0);
        if (!rv || rv.length === 0) continue;
        let off = s, lines = [];
        for (const i of rv) {
          lines.push(`0x${vaFullText(off).toString(16)}  ${i.mnemonic} ${i.opStr || ''}`);
          off += i.size;
        }
        console.log(lines.join('\n'));
        return;
      } catch (e) { }
    }
    console.log('disasm failed near insnEnd 0x' + insnEndOff.toString(16));
  }

  const targets = {
    keyName: txt.indexOf('Real-UI account vault key v1'),
  };
  for (const [n, f] of Object.entries(targets)) console.log(`${n}: fileoff 0x${f.toString(16)}, VA 0x${vaFull(f).toString(16)}`);
  console.log('\nscanning rip-rel refs (7MB pass)...');
  const refs = ripXrefs(vaFull(targets.keyName));
  console.log(`refs at (insn-end abouts): ${refs.map(r => '0x' + r.toString(16)).join(', ')}`);
  refs.slice(0, 4).forEach(r => { console.log(`\n--- around insnEnd 0x${r.toString(16)} ---`); disasmAround(r); });
}
main().catch(e => { console.error(e); process.exit(1); });
