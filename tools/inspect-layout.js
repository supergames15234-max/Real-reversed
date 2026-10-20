// Inspect bytes around occurrences of asset path strings to learn Tauri's static layout
const fs = require('fs');
const buf = fs.readFileSync('C:/Users/[name]/AppData/Local/Real/real-2.7.9/Real.exe');
const targets = ['/index.html', '/_app/immutable/assets/0.BklpfQz9.css', '/_app/immutable/chunks/'];
const offs = new Set();
for (const t of targets) {
  let i = buf.indexOf(Buffer.from(t, 'latin1'));
  while (i !== -1) { offs.add([i, t]); i = buf.indexOf(Buffer.from(t, 'latin1'), i + 1); if (offs.size > 12) break; }
}
for (const [off, t] of offs) {
  console.log(`=== ${t} @ 0x${off.toString(16)} ===`);
  const a = Math.max(0, off - 160), b = Math.min(buf.length, off + 160);
  for (let row = a; row < b; row += 16) {
    const line = buf.slice(row, Math.min(b, row + 16));
    const hex = [...line].map(x => x.toString(16).padStart(2, '0')).join(' ');
    const ascii = [...line].map(x => (x >= 32 && x <= 126) ? String.fromCharCode(x) : '.').join('');
    console.log(`${row.toString(16).padStart(8, '0')}  ${hex.padEnd(48, ' ')}  |${ascii}|`);
  }
}
