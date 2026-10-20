// annotated disassembler -> writes file. args: startHex lenHex outFile
const fs = require('fs');
const csmod = require('capstone-wasm');
const buf = fs.readFileSync(process.env.REAL_EXE_PATH || 'C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
const start = parseInt(process.argv[2], 16), len = parseInt(process.argv[3], 16), outFile = process.argv[4];
const VA = (off) => '0x' + (0x140000000 + 0x1000 + off - 0x400).toString(16);
function vaToFile(va) {
  const rva = va - 0x140000000;
  if (rva >= 0x1000 && rva < 0x7bc440) return 0x400 + rva - 0x1000;
  if (rva >= 0x7bd000 && rva < 0xfdf000) return 0x7bc200 + rva - 0x7bd000;
  return -1;
}
function rdStr(off, max = 72) {
  if (off < 0 || off >= buf.length) return null;
  let s = '';
  for (let i = off; i < off + max && i < buf.length; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c); else break;
  }
  return s.length >= 3 ? s : null;
}
(async () => {
  await csmod.loadCapstone();
  const md = new csmod.Capstone(csmod.Const.CS_ARCH_X86, csmod.Const.CS_MODE_64);
  const lines = [];
  const rv = md.disasm(buf.slice(start, start + len), 0);
  let off = start;
  for (const i of rv) {
    let note = '';
    if (i.mnemonic === 'call' || i.mnemonic.startsWith('j')) {
      const m = i.opStr.match(/^0x([0-9a-f]+)$/);
      if (m) {
        const n = BigInt('0x' + m[1]);
        const ts = n > (1n << 63n) ? n - (1n << 64n) : n; // slice-relative signed target
        const tFile = start + Number(ts);
        note += `  =>file=0x${tFile.toString(16)} VA=0x${(0x140000000 + 0x1000 + tFile - 0x400).toString(16)}`;
      }
    }
    const ripm = i.opStr.match(/\[rip ([+-]) (0x[0-9a-f]+)\]/);
    if (ripm) {
      const nextOff = off + i.size;
      const disp = parseInt(ripm[2], 16) * (ripm[1] === '-' ? -1 : 1);
      const tVA = 0x140000000 + 0x1000 + (nextOff - 0x400) + disp;
      const tFile = vaToFile(tVA);
      const s = rdStr(tFile);
      note += `  [tgt ${'0x' + tVA.toString(16)}]` + (s ? ` str="${s.slice(0, 60)}"` : '');
      if (tFile >= 0 && tFile + 16 <= buf.length) {
        const p = buf.readBigUInt64LE(tFile), pl = buf.readBigUInt64LE(tFile + 8);
        if (p > 0x140000000n && p < 0x141000000n && pl > 0n && pl < 500n) {
          const pf = vaToFile(Number(p));
          if (pf >= 0) { const ps = rdStr(pf, Number(pl) + 4); if (ps) note += `  *ptr,len=${pl}: "${ps.slice(0, Number(pl))}"`; }
        }
      }
    }
    let a;
    const abs1 = i.opStr.match(/0x(140[0-9a-f]{8})/g);
    if (abs1) for (const hexv of abs1) {
      const tVA = parseInt(hexv, 16);
      const tFile = vaToFile(tVA);
      if (tFile >= 0) { const s = rdStr(tFile); if (s) note += `  imm=${hexv} str="${s.slice(0, 60)}"`; }
    }
    lines.push(`${VA(off)}  ${i.mnemonic} ${i.opStr || ''}${note}`);
    off += i.size;
  }
  fs.writeFileSync(outFile, lines.join('\n'));
  console.log('wrote', lines.length, 'lines to', outFile);
})();
