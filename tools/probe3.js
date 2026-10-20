const csmod = require('capstone-wasm'); const fs=require('fs');
(async () => {
  await csmod.loadCapstone();
  const md = new csmod.Capstone(csmod.Const.CS_ARCH_X86, csmod.Const.CS_MODE_64);
  const buf = fs.readFileSync('C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
  // entry point RVA 0xBE00330E is bogus (my earlier parse??); just disasm at .text start
  const r = md.disasm(buf.slice(0x400, 0x400+96), 0x140000000+0x1000);
  console.log(typeof r, r && r.length);
  console.log((r||[]).slice(0, 12).map(i=>`0x${(0x140000000+0x1000+i.offset).toString(16)}  ${i.mnemonic} ${i.op_str}`).join('\n') || 'EMPTY');
  let err = md.getLastError ? md.getLastError() : null;
  console.log('lastError:', JSON.stringify(err));
})();
