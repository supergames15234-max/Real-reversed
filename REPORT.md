# Real (projectreal.gg) — Reverse-Engineering Report

**Target:** `C:\Users\[name]\AppData\Local\Real` (Roblox executor suite "Real", v2.7.9, app shell v2.5.4, build 180)
**Analysis date:** 2026-10-19
**Method:** static triage (PE headers, entropy, strings), asset extraction, on-disk format analysis.
**Scope agreement:** behavior analysis + near-source recovery + packed-payload status. No license circumvention, no clone building.

---

## 1. Identification

| Field | Value |
|---|---|
| Product | **Real** (Roblox script executor suite) |
| Vendor | projectreal (`projectreal.gg`, `api.projectreal.live`, `cdn.projectreal.live`, `dl.projectreal.live`, Discord `discord.gg/projectreal`) |
| Version files | `data\meta\current-version.txt` = 2.7.9, `current-build.txt` = 180 |
| Installer/updater | `Update.exe` v1.0.0 (D-language runtime artifacts, libcurl + OpenSSL, druntime strings) |
| App shell | `real-2.7.9\Real.exe` v2.5.4 — **Tauri 2 + WRY + tao**, WebView2 155.0.4283.x |
| UI framework | **SvelteKit** (app served from `http://tauri.localhost`, IndexedDB of webview confirms) |
| Editor | **Monaco** (`monaco/vs/editor/editor.main.js` embedded), Luau LSP: open-source `luau-lsp.exe` |
| Agent integration | `real-mcp.exe` — Rust binary (rustls-0.23.42, ring-0.17.14): MCP server for editor/VSCode/Cursor extensions |

## 2. Component map

| File | Size | Packed? | Role |
|---|---|---|---|
| `Update.exe` | 8.5MB | No | Installer/updater/repair (VC++, .NET, WebView2 checks), Defender exclusion manager, schtask registrar, downloads from `api/dl/download.projectreal.live`, posts `/installer/report` |
| `real-2.7.9\Real.exe` | 17MB | No | Tauri main app: window, editor UI, theme engine, workspace, autoexec, MCP wiring, Roblox multi-account manager UI (login/logout/2FA/password/account-info calls against Roblox web APIs), script-hub integrations |
| `real-2.7.9\bin\Real.exe` | 7.1MB | **YES (custom)** | Executor service process |
| `real-2.7.9\bin\Real.dll` | 4.5MB | **YES (custom)** | Payload injected into RobloxPlayerBeta |
| `real-2.7.9\bin\Spoofer.exe` | 3.2MB | **YES (custom)** | HWID spoofer (section literally named `.byfron` after Roblox's anticheat) |
| `bin\real-mcp.exe` | 1.7MB | No | MCP agent server (local tool bridge) |
| `bin\luau-lsp.exe` | 16.9MB | No | Standard open-source Luau LSP |

### Packing evidence (the "decrypted" part) — REVISED after phase 3
- `bin\Real.exe` / `bin\Spoofer.exe`: 12-section shell images — ten nameless sections (~7.5–8.0 entropy) plus capability sections with **raw = 0** (`.real` 0xC4E000 / `.byfron` 0x546000 virtual size — materialize only at runtime), the compressed payload in `.boot` (6.9 MB / 2.97 MB), `.idata`, `.tls`, `.rsrc`, stub `.reloc`. Entry point = `.boot + 0x58` in both files (identical stub bytes).
- `bin\Real.dll`: not a PE at all in shipped form — a whole-file repeating-key-XOR'd image that only materializes after decryption (see §7 for the key derivation).
- Conclusion: a **private two-layer packer**: (a) self-contained boot stubs deCOMPRESSING an aPLib stream into the raw=0 payload sections, and (b) a repeating-XOR obfuscation of the DLL. The *payloads* behind the boot stubs are additionally **Oreans WinLicense**-protected. Both layers were broken **statically** — no dynamic dump was required for the packer itself (see §7).

## 3. Persistence & defensive posture

1. **Scheduled task `Real\Launch`** → `Update.exe --via-task` (registered while elevated).
2. **Windows Defender exclusions** added for install root + temp dirs — embedded PowerShell in `Update.exe`:
   - `Add-MpPreference -ExclusionPath $p` (verified-present loop, removes stale entries).
   - Failure path logged: `[Defender] exclusions did NOT fully apply (tamper protection or policy)`.
3. Runs elevated (`elevated=1` in every session log).
4. Installer verifies an auth token (server `/verify`, "proof received") before install.

**Defensive flag:** auto-defender-excluding, HWID-spoofing, DLL-injecting software = treat as adversarial. Defender exclusions mean AV will not scan the app directory or its temp — repositories their whole update chain, not just the payload that legitimately needs it.

## 4. Network surface (recovered from embedded UI + installer strings)

Roblox account-automation APIs (what the multi-account manager uses):
`auth.roblox.com /v2/login, /v1/authentication-ticket, /v1/session/refresh`, `users.roblox.com`, `avatar.roblox.com` (set-body-colors/set-scales/avatar-type — avatar spoofing), `accountinformation.roblox.com` (birthdate/description/gender/promotion-channels edits), `accountsettings.roblox.com` (email/themes/trade-privacy), `presence.roblox.com`, `gamejoin.roblox.com/v1/join-game-instance`, `apis.roblox.com` search/marketplace/explore, `thumbnails.roblox.com`, `friends.roblox.com` (auto-accept/decline requests), `economy.roblox.com`, `premiumfeatures.roblox.com`.

Vendor + third-party:
- `api.projectreal.gg/auth/discord` (OAuth), `api.projectreal.live/client/version-ping`, `/update/check`, `/public/changelog`, `/public/featured-scripts`, `/public/rscripts`, `/installer/report` (status upload), `cdn.projectreal.live`.
- Script hubs: **scriptblox.com** (`/api/script`, `/api/script/raw`), **rscripts.net**, **robloxscripts.com** (`/api/v1`), **WEAO** (`weao.xyz/api/versions` — executor version tracking), `fast-api.rbxservers.xyz` (server join-link fetching), `api.rubis.app/v2/scrap`.
- Docs baked in for supported UI libraries: WindUI, Fluent, Luna-Interface-Suite, Maclib (fetched from GitHub raw at runtime), Mint (docs.sirius.menu), gitbook (fluent/maclib docs).
- `ipapi.co/json` (geo-IP), `ws://echo.websocket.events` (debug).

## 5. On-disk data formats (decrypted documentation)

### `data\enc_settings.json` (Real's own vault bootstrap, plaintext schema)
```json
{
  "initialized": true,
  "enabled": true,
  "password_salt_b64": "…44 chars",       // 32-byte argon2 salt (base64)
  "key_enc_with_password_b64": "enc:v1:<16-char b64 nonce>:<80-char b64 ct||tag>",   // 104 chars total
  "answers_salt_b64": "…44 chars",        // 32-byte argon2 salt for the recovery-answers path
  "key_enc_with_answers_b64": "enc:v1:<16-char b64 nonce>:<80-char b64 ct||tag>",
  "has_device_key": false
}
```
`enc:v1:<b64 12B nonce>:<b64 (ct || 16B GCM tag)>` — standard AES-256-GCM (J0 = nonce‖0x00000001, Ctr32BE, tag last). The wrap plaintext is **44 ASCII chars: a base64 encoding of the 32-byte key** (an extra encoding layer between GCM and the key bytes).

### `data\account-vault.dpapi` (298 B)
Genuine **Windows DPAPI blob** (magic `01 00 00 00 D0 8C 9D DF`), description `Real account vault`, entropy `Real-UI account vault key v1` (20 bytes), protected under the *current Windows user's* master keys. Its 32-byte payload is a **separate (legacy/DPAPI-mode) master key** — it is *not* the key that active password-mode unlocks with (verified: DPAPI key fails to open the password-mode wraps; argon2id output opens them, see §5b).

### `data\accounts.json`
Plaintext list of Roblox account records (id, username, user_id, display_name, avatar_url, sort_index, …). Each record carries its own secret as an `enc:v1:` token string (cookie field ≈1.6 KB: 12B nonce + ~1.2 KB ciphertext + 16B tag). Tokens are gated by the in-process master key (§5b); the same unwrap code path also probes for `dev:v1:` tokens (device-key-protected accounts, variant of `has_device_key=true`).

### `access.key` files (27 B, e.g. `FwMRul-OA5tKm-QP71BD-6JECIV`)
Script-hub access tokens (Luarmor gate keys), not Real license keys.

### `workspace\static_content_170926\init-d049a886a1f-ocmid.lua`
**Luarmor V4 bootstrapper** (third-party obfuscated bytecode; not Real's protection).

## 5b. Vault crypto — reverse-engineered end-to-end (static analysis, verified)

All addresses are Virtual Addresses in `Real.exe` v2.7.9 (`.text` file→VA delta +0x140000C00; `.rdata` +0x140000E00).

### KDF (password unlock)
- Cluster: async KDF future at **VA 0x140224b70** (tokio `spawn_blocking`) whose blocking worker writes a spec-correct RFC 9106 argon2 H0 at **VA 0x140225230** (write sequence `LE32(p), LE32(T), LE32(m), LE32(t), LE32(v), LE32(y)` = `1, 32, 0x10000, 3, 0x13, 2` → **argon2id, m = 0x10000 KiB = 64 MiB (block alloc `mov ecx,0x10000` + `shl rdx,0xa`), t = 3, v = 1.3, lanes = 1, 32-byte output**; password-then-salt order, per-1KiB block zeroing confirmed).
- Inputs: raw UTF-8 password bytes + the b64-decoded 32-byte salt from `password_salt_b64` (decode via VA 0x140224af0 → b64 helper VA 0x140198de0).
- Same future reused by backup import (direct callers VA 0x140247fcf / 0x14024d6d3) — the parameters noted near the backup cluster (VA 0x140247C00–0x140248200) are the same ones.

### Master-key materialization (unlock chain, VA 0x1402276da…0x140227837)
```
kdf     = argon2id(pw_utf8, salt32, m=65536KiB, t=3, p=1, out=32)
plain44 = AES-256-GCM_open(key=kdf, nonce=wrap_nonce(12B), ct||tag(16B), aad=∅)
master  = base64_decode(plain44)   // the wrap plaintext is a 44-char b64 string of the key
set_global(master)                 // VA 0x140193150 (length-checked, edx = 0x20)
```
The master key lives in a Once-guarded process global (block at **VA 0x140fe07f8**: once byte @+0, init flag @+1, `Option<Vec>` tag/ptr/len at +9/+17/+25). Getter **VA 0x1401904f0** returns `{initialized?, ptr, flag}` and the accounts loop unwraps the option via **VA 0x140190540**. The DPAPI blob's 32-byte payload is a **separate key slot** (DPAPI-mode key), not this master key.

### Per-secret unwrap (accounts loop, VA 0x14018c6e0)
```
if starts_with(token, "enc:v1:")   // VA 0x140190be0 → generic prefix check VA 0x1405f9340
    value = AES-256-GCM_open(key=global_master, nonce, ct||tag, aad=∅)  // VA 0x1401906f0
    // on failure the app logs: "[accounts] dev_decrypt failed for <field>"
```
`dev:v1:`-prefixed tokens take the alternate device-key path (Windows keyring, service `"real-executor"`, entry `"device-key"` — getter VA 0x140224960; used when `has_device_key=true`).

### Verification + repro (offline, no app execution)
- Replaying the chain on real `enc_settings.json` + `accounts.json` data: GCM tags verify (argon2id derivation bit-exact), the 44-char b64 plaintext decodes to a 32-byte key, and that key opens every per-account token to correct-length readable plaintext.
- Node sketch: `hash-wasm` `argon2id({password, salt, parallelism:1, iterations:3, memorySize:65536, hashLength:32, outputType:'binary'})`, then `crypto.createDecipheriv('aes-256-gcm', key, nonce, {authTagLength:16})` with tag = last 16 bytes of the decoded ct-field, no AAD.
- Pitfalls that break naive attempts: (1) wrap plaintext = 44-char **base64 string**, not the raw key; (2) wrap split = `scheme : b64(nonce 12B/16 chars) : b64(ct||tag)`; (3) GCM AAD is empty; (4) password bytes = raw UTF-8 (no pre-hash).

## 6. Near-source recovery (phase 2 result — DONE)

**396/419 embedded frontend assets extracted** to `Real-Reversed\ui-assets\` (brotli-decompressed out of the Tauri binary):

- `index.html` (1.7KB, intact, references `/_app/immutable/entry/start.BQzKT577.js` etc.)
- 48 SvelteKit `_app` bundles (chunks/nodes/entry/assets) — the actual UI application code (minified TS→JS with debug comments, e.g. `src/lib/fonts/web-fonts.ts`)
- Monaco editor (14 files), 255 flag SVGs, 21 backgrounds, 24 icons, macos-traffic-lights, fonts, providers (robloxscripts / rscripts / scriptblox / WEAO), launchers (voidstrap …), lottie splash animation
- `extension.js` = their **VSCode extension source** (manifest inline, `Real.attach` command), plus editor-bridge JS (`writeIpcFile('execute.txt')`, `sync_from_vscode.txt`, `open_tab.txt`) → confirms the `ipc\` folder is a file-based editor bridge
- `error.txt`, `real_game_action_debug.txt` assets

**IPC command surface:** standard Tauri plugin commands (window/event/image/opener/resources) are visible; app-specific commands are *not* invoked through Tauri's plugin IPC from the frontend — they ride through the file-based `ipc\` bridge + MCP (`real-mcp.exe`) + direct WebView2 navigation.

## 7. Phase-3 result: the three packed payloads — unpacked statically (DONE)

All three products in `bin\` were fully unwrapped **without executing anything** (pure byte-level static work). Vault crypto (§5b) was likewise resolved statically.

### 7.1 `bin\Real.dll` — repeating-key XOR → full PE (engine module)

- Shipped file is **not a PE**; it is a whole-file repeating-key XOR of a valid 32-bit DLL image.
- Key derived by known-plaintext (the canonical 16-byte DOS header `4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF`): **8-byte repeating key `55 17 AF E5 E3 64 41 4E`** — confirmed by 16+ consistent positions and by the unwrapped `e_lfanew = 0x108` landing exactly on a `PE\0\0` signature.
- The key itself is **not stored verbatim** in any sibling module (checked root `Real.exe`, `bin\Real.exe`, `Spoofer.exe`, `luau-lsp.exe`, `real-mcp.exe`) — the loader materializes it at runtime.
- Decrypted image: **PE32+, imageBase `0x180000000`, 7 real sections, entry `0x31ebbc`**: `.text` 3.6 MB (entropy 6.52 — plain code), `.rdata`, `.data`, `.pdata`, `.fptable`, `.rsrc`, `.reloc`. No export directory; 16 import DLLs: `CRYPT32, bcrypt, WS2_32, d3d11, KERNEL32, USER32, GDI32, ADVAPI32, SHELL32, ole32, IMM32, D3DCOMPILER_47, dcomp, WININET, IPHLPAPI, Secur32`.
- **What it is:** the executor's engine/UI module, near-fully recoverable statically:
  - Luau compiler + IR: C++ RTTI mangled names expose `real::ir::foldTablesInBlock`, `real::ir::stableLocalBindings`, a `RealVM` type with `Location`-tracking vectors, full Luau syntax/`DebugLuau*` flag strings;
  - script APIs: `Filesystem` (Open/Save/Load/Read/Write/Append file dialogs + async `*fileAsync`), `DrawingLib` (`QueueImageUri`), `WebSocket` client (`MakeYieldError`, `QueueIncoming`), `Yielding::YieldThread` (coroutines);
  - rendering: dear **ImGui + D3D11** overlay (vertex/PS shader HLSL text in `.rdata`, `ImGuiBackendFlags_RendererHasTextures` strings, font paths `arial/tahoma/segoeui/lucon/consola/verdana/IBMPlexSans`);
  - networking: embedded **libcurl** (schannel/SOCKS4 error strings, `SEC_E_ILLEGAL_MESSAGE` text, TLS-version warnings);
  - Roblox surface: XML place serializer template `<roblox xmlns:xmime=...`, `ModuleScript expected` (instance APIs), and HWID gathering (`SOFTWARE\Microsoft\Cryptography`, `MachineGuid`).

### 7.2 `bin\Real.exe` / `bin\Spoofer.exe` — boot stub + aPLib → payloads (WinLicense core)

- Entry stub (identical bytes in both, EP = `.boot + 0x58`): computes the payload-section base from its own address (`EP − 0xC4E058` / `EP − 0x546058`), probes a flag at `payload_base + 0x4f7bf2`, and on zero runs a **chunked aPLib depack loop**: `[count byte = 8]`, then 8 self-terminating aPLib streams; each depacked chunk advances a write cursor; final `ret` target = `payload_base + 0x4f7bf2` (the payload's own entry).
- The inline depacker is the canonical aPLib decompressor — identified by the `mov dl,0x80` tag-bit register, `adc dl,dl` bit reads, and the aPLib length-class constants `0x7d00` (32000) / `0x500` (1280) / `0x7f` (127).
- Unpack results (verified — output length equals the raw=0 section's virtual size **to the byte**):

| File | chunks | per-chunk output | total output | packed consumed |
|---|---|---|---|---|
| `bin\Real.exe` | 8 | 0x189C00 (1,612,800) | 0xC4E000 (`12902400`) | 0x69E67E of 0x69E7C7 avail |
| `bin\Spoofer.exe` | 8 | 0xA8C00 (691,200) | 0x546000 (`5529600`) | 0x2E4B0A of 0x2E4BC7 avail |

- Payload identification: both are **Oreans WinLicense**-protected images. Markers in the unpacked blobs: registry keys `Software\WinLicense`, `SOFTWARE\WLkt`, `WinLicenseVersion`, `WinLicenseDriverVersion`, `WinLicenseInstance`, `WLSoftwareVersion`, `WLProtectionDateTime`, `SplashClassName`, `/checkprotection`, `/skipactivexreg`, the WinLicense crash-handler contact text, and the leaked internal PDB path **`c:\miniprojects\x86il\il86\x64\release\IL86.pdb`** (Oreans' x86 instruction library used by their code-virtualization engine). The Spoofer payload additionally begins with a small self-modifying deobfuscation stub (`and r13,0x90 / xor r13,0x40 / mov byte [rbx],0 …`).
- Payload entropy profile (post-aPLib): ~5.0–6.8 blocks — compressed deobfuscation layers, not standard code; strings density ~1.5–5.6 K ≥6-char strings, with WinLicense markers intact.
- `.real` probe/`jmp rax` → payload entry RVAs: `0xCB000 + 0x4F7BF2` (Real.exe) — i.e. the payload entry lands at VA `0x1405C2BF2` in the shell's address space; `.byfron` payload entry = `0x63000 + 0x4f7bf2`.
- Root `Real.exe` (16.9 MB shell studied in phases 1–2) is **not** packed: standard 6-section PE, readable `.text` 0x7BBE00; the `luau-lsp.exe` (open-source Luau LSP) and `real-mcp.exe` (MCP helper) in `bin\` are normal stock PEs.

### 7.3 What remains after static unpacking (the honest ceiling)

- The WinLicense payloads: code sections are oreans-virtualized and API-obfuscated. Static triage beyond identification = not practical here; behavior goes through the data/APIs already documented (§2–5).
- Optional verification-only (if[!] a VM is provisioned later): run each shell in a disposable VM and confirm the aPLib dump matches memory (gold-check `payload_base + 0x4f7bf2`), then dump+deobfuscate application APIs — but **no output of this session requires it**.

## 8. Repro/extractor tooling (this session)

- `Real-Reversed\tools\extract-tauri-assets.js` — Tauri v2 asset extractor (layout: `<path-string><brotli stream>` in `.rdata`)
- `Real-Reversed\tools\inspect-layout.js`, `debug-decode.js`, `test-decode.js` — layout forensics
- `Real-Reversed\tools\unxor-pe.js` — repeating-key-XOR PE unwrapper (MZ-crib auto-derivation + PE-signature verification) — recovers `bin\Real.dll` (key `55 17 AF E5 E3 64 41 4E`, e_lfanew 0x108)
- `Real-Reversed\tools\pe-forensics.js` — PE section/entropy/EP audit for any number of files (used on all five `bin\` products + root shell)
- `Real-Reversed\tools\aplib-depack.js` — chunked aPLib depacker replicating the shell boot stub (`[count=8][8 streams]`, output = `.real`/`.byfron` payload)
- `Real-Reversed\tools\disasm-annot.js` — capstone annotated disassembler (start/len/out args, honors `REAL_EXE_PATH`)
- `Real-Reversed\ui-assets\_manifest.json` — extraction manifest (extracted + skipped)
- `Real-Reversed\ipc-commands.json` — plugin command surface + URL inventory
