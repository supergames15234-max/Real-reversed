// Locate vault/KDF strings in binary, compute VAs, rip-xref them, disasm around hits.
const fs = require('fs');
const csmod = require('capstone-wasm');
const buf = fs.readFileSync(process.env.REAL_EXE_PATH || 'C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
const txt = buf.toString('latin1');

const TEXT_START = 0x400, TEXT_END = 0x7BC200;
const vaText = (f) => 0x140000000n + 0x1000n + BigInt(f - TEXT_START);
const vaRdata = (f) => 0x140000000n + 0x7bd000n + BigInt(f - 0x7bc200);
const vaOf = (f) => (f >= 0x7bc200 ? vaRdata(f) : vaText(f));

function ripXrefs(targetVaBig) {
  const hits = [];
  const low32 = Number(targetVaBig & 0xffffffffn);
  for (let P = TEXT_START; P < TEXT_END - 4; P++) {
    const D = (low32 - 0x140000000 - 0x1000 - (P + 4 - TEXT_START)) >>> 0;
    if (buf.readUInt32LE(P) === D) hits.push(P + 4);
  }
  return hits;
}

async function main() {
  await csmod.loadCapstone();
  const md = new csmod.Capstone(csmod.Const.CS_ARCH_X86, csmod.Const.CS_MODE_64);
  const out = [];

  function findStrAll(needle) {
    const res = [];
    let i = txt.indexOf(needle);
    while (i !== -1 && res.length < 6) { res.push(i); i = txt.indexOf(needle, i + 1); }
    return res;
  }

  function disasmAround(insnEndOff, pre, post, sink) {
    for (let s =insnEndOff - pre; s < insnEndOff; s++) {
      try {
        const rv = md.disasm(buf.slice(s, insnEndOff + post), 0);
        if (!rv || rv.length === 0) continue;
        let off = s;
        for (const i of rv) {
          let note = '';
          const ripm = i.opStr.match(/\[rip ([+-]) (0x[0-9a-f]+)\]/);
          if (ripm) {
            const disp = BigInt(parseInt(ripm[2], 16)) * (ripm[1] === '-' ? -1n : 1n);
            const tVA = vaText(off + i.size) + disp;
            const tFile = Number(tVA - 0x140000000n - (tVA > 0x1407bd000n ? 0x7bd000n : 0x1000n) + (tVA > 0x1407bd000n ? 0x7bc200n : 0x400n));
            if (tFile >= 0 && tFile < buf.length) {
              let s2 = '';
              for (let j = tFile; j < tFile + 96 && j < buf.length; j++) {
                const c = buf[j]; if (c >= 0x20 && c < 0x7f) s2 += String.fromCharCode(c); else break;
              }
              if (s2.length >= 4) note += `  --> "..."${'@0x' + tVA.toString(16)}: "${s2.slice(0, 70)}"`;
            }
          }
          sink.push(`0x${vaText(off).toString(16)}  ${i.mnemonic} ${i.opStr || ''}${note}`);
          off += i.size;
        }
        return true;
      } catch (e) { }
    }
    sink.push('(disasm failed near insnEnd 0x' + insnEndOff.toString(16) + ')');
    return false;
  }

  const TARGETS = [
    'key_enc_with_password_b64',
    'password_salt_b64',
    'key_enc_with_answers_b64',
    'has_device_key',
    'EncSettings',
    'argon2id',
    'argon2-0.5.3\\src\\lib.rs',
    'argon2-0.5.3\\src\\params.rs',
    'Wrong password or data corrupted',
    'Account vault key has an invalid length',
    'enc_settings.json',
    'device-key-v1',
  ];

  for (const t of TARGETS) {
    const occ = findStrAll(t);
    out.push(`\n===== "${t}" occurrences: ${occ.map(o => '0x' + o.toString(16)).join(', ') || '(none)'}`);
    for (const occOff of occ.slice(0, 2)) {
      const va = vaOf(occOff);
      out.push(`  occ file 0x${occOff.toString(16)} VA 0x${va.toString(16)} ${occOff >= 0x7bc200 ? '(.rdata)' : '(.text)'}`);
      if (occOff >= 0x7bc200) {
        const refs = ripXrefs(va);
        out.push(`  rip-rel refs: ${refs.map(r => '0x' + r.toString(16)).join(', ') || '(none)'}`);
        for (const r of refs.slice(0, 6)) {
          const sink = [];
          disasmAround(r, 24, 96, sink);
          out.push(`  --- context for ref insnEnd 0x${r.toString(16)} (VA 0x${vaText(r).toString(16)}) ---`);
          out.push(sink.map(l => '    ' + l).join('\n'));
        }
      }
    }
  }
  fs.writeFileSync('C:/Users/[name]/Documents/Default Project/Real-Reversed/disasm/vault-refs.txt', out.join('\n'));
  console.log('wrote vault-refs.txt,', out.length, 'lines');
}
main().catch(e => { console.error(e); process.exit(1); });
