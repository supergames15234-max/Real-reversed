const csmod = require('capstone-wasm'); const fs=require('fs');
(async () => {
  await csmod.loadCapstone();
  const md = new csmod.Capstone(csmod.Const.CS_ARCH_X86, csmod.Const.CS_MODE_64);
  const buf = fs.readFileSync('C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
  const r = md.disasm(buf.slice(0x400, 0x400+96), 0x140000001000);
  console.log(JSON.stringify(r[2], null, 1));
})();
