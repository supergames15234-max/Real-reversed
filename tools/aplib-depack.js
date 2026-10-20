// aPLib chunked depacker — replicates the packed-shell stub loader used by
// bin/Real.exe / bin/Spoofer.exe (v2.7.9).
//
// Layout:   [chunkCount byte][self-terminating aPLib stream] x chunkCount
// Depacked output lands in the shell's payload section (.real / .byfron),
// sequential chunks. usage:
//   node aplib-depack.js <inFile> <dataOffHex> <dstSizeHex> <outFile>
// e.g. bin/Real.exe: dataOff = EP_file_off + 0x1f0, dstSize = 0xc4e000
//
// Algorithm semantics: canonical aPLib (ibsensoftware) depack — literal byte,
// 4-bit dist tag, short-match byte ((offs&1)+2 length), gamma-coded ranges with
// the standard 32000/1280/128 length-class adjustments. Implemented directly
// from the public aPLib format; do not use to unpack materials you don't own.
const fs = require('fs');

function makeStream(data, si) { return { data, si }; }

function depackChunk(st, dst, dcur) {
  const src = st.data, d = dst;
  let len = 0;
  const put = (v) => { d[dcur + len++] = v & 0xff; };
  if (st.si >= src.length) return 0;
  put(src[st.si++]); // first byte verbatim

  let tag = 0, bitcount = 0, r0 = -1, lwm = 0, done = false;
  const getbit = () => {
    bitcount--;
    if (bitcount < 0) { tag = src[st.si++]; bitcount = 7; }
    const bit = (tag >> 7) & 1;
    tag = (tag << 1) & 0xffff;
    return bit;
  };
  const getgamma = () => {
    let result = 1;
    for (;;) {
      result = (result << 1) + getbit();
      if (!getbit()) break;
    }
    return result;
  };
  const backref = (offs) => put(d[dcur + len - offs]);

  while (!done) {
    if (getbit()) {
      if (getbit()) {
        if (getbit()) {                      // 4-bit distance, len 1, dist0 == literal 0
          let offs = 0;
          for (let i = 0; i < 4; i++) offs = (offs << 1) + getbit();
          if (offs) backref(offs); else put(0);
          lwm = 0;
        } else {                             // explicit byte: len=(b&1)+2, dist=b>>1, 0 → terminator
          let offs = src[st.si++];
          const length = 2 + (offs & 1);
          offs >>= 1;
          if (offs) { for (let i = 0; i < length; i++) backref(offs); }
          else done = true;
          r0 = offs;
          lwm = 1;
        }
      } else {                               // gamma-coded range
        let offs = getgamma();
        if (lwm === 0 && offs === 2) {       // reuse r0
          offs = r0;
          const length = getgamma();
          for (let i = 0; i < length; i++) backref(offs);
        } else {
          offs -= (lwm === 0) ? 3 : 2;
          offs <<= 8;
          offs += src[st.si++];
          let length = getgamma();
          if (offs >= 32000) length++;
          if (offs >= 1280) length++;
          if (offs < 128) length += 2;
          for (let i = 0; i < length; i++) backref(offs);
          r0 = offs;
        }
        lwm = 1;
      }
    } else {
      put(src[st.si++]);
      lwm = 0;
    }
  }
  return len;
}

function depackAll(path, dataOff, dstSize, outFile) {
  const src = fs.readFileSync(path);
  const count = src[dataOff];
  const dst = Buffer.alloc(dstSize);
  const st = makeStream(src, dataOff + 1);
  let dcur = 0;
  const parts = [];
  for (let i = 0; i < count; i++) {
    const n = depackChunk(st, dst, dcur);
    parts.push(n);
    dcur += n;
    if (!n) break;
  }
  console.log(`${path.split(/[\\/]/).pop()}: dataOff=0x${dataOff.toString(16)} chunks(count=${count})=[${parts.join(',')}] packedUsed=0x${(st.si - dataOff - 1).toString(16)} outLen=0x${dcur.toString(16)}`);
  if (outFile) fs.writeFileSync(outFile, dst.subarray(0, dcur));
  return dcur;
}

module.exports = { depackChunk, depackAll };
if (require.main === module) {
  const [inFile, offHex, sizeHex, outFile] = process.argv.slice(2);
  if (!inFile || offHex === undefined) { console.log('usage: node aplib-depack.js <inFile> <dataOffHex> [dstSizeHex] [outFile]'); process.exit(1); }
  depackAll(inFile, parseInt(offHex, 16), parseInt(sizeHex || 'c4e000', 16), outFile);
}
