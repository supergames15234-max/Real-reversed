// disasm an arbitrary code range of Real.exe (file offset in, length in)
const fs = require('fs');
const csmod = require('capstone-wasm');
const buf = fs.readFileSync('C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
const TEXT_START = 0x400;
function vaFullText(fileOff) { return 0x140000000n + 0x1000n + BigInt(fileOff - TEXT_START); }
(async () => {
  await csmod.loadCapstone();
  const md = new csmod.Capstone(csmod.Const.CS_ARCH_X86, csmod.Const.CS_MODE_64);
  const start = parseInt(process.argv[2], 16), len = parseInt(process.argv[3], 16);
  const rv = md.disasm(buf.slice(start, start + len), 0);
  let off = start, out = [];
  for (const i of rv) {
    out.push(`0x${vaFullText(off).toString(16)}  ${i.mnemonic} ${i.opStr || ''}`);
    off += i.size;
  }
  console.log(out.join('\n'));
})();
