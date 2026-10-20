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

### Packing evidence (the "decrypted" part)
- `bin\Real.exe`: nameless sections, ~7.96–7.98 entropy sections, custom `.real` (12.9MB virtual, 0 raw → materializes at runtime) + `.boot` (6.9MB unpack stub), stripped imports, no meaningful strings (strings triage yields ≤5% readable fragments).
- `bin\Real.dll`: same scheme; PE parse rejects standard offsets (non-standard/obfuscated header).
- `bin\Spoofer.exe`: same scheme + section `.byfron`; only readable string `@.byfron`.
- Conclusion: **a private, custom packer** (not VMProtect/Themida/Enigma — those strings conspicuous by absence). Payloads exist only decrypted in process memory at runtime; unwrapping requires *dynamic* dump from an isolated environment (see §7).

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

## 7. Remaining unknowns & phase-3 plan (packed payloads)

Vault crypto: **fully resolved statically** — see §5b (was an open question at phase-1 time; no app execution needed).

Static-only limits: `bin\Real.exe`, `bin\Real.dll`, `bin\Spoofer.exe` cannot be statically unpacked here; strings triage confirmed <5% readable content. What remains:
1. **Isolated VM run + memory dump** — launch each packed binary in a disposable VM (no Roblox present), dump the self-unpacked image from memory (`MiniDumpWriteDump` or hollowing-aware dumpers), sanitize/rebuild IAT, then normal static analysis.
2. **Ghidra** on dumped images → pseudocode for injection routines, spoofer BIOS table reads, executor Luau VM.
3. Confidence notes: payloads likely re-obfuscate APIs; expect syscall stubs + syscall induction; spoofer will touch `NtQuerySystemInformation`, WMI and SMBIOS tables.

## 8. Repro/extractor tooling (this session)

- `Real-Reversed\tools\extract-tauri-assets.js` — Tauri v2 asset extractor (layout: `<path-string><brotli stream>` in `.rdata`)
- `Real-Reversed\tools\inspect-layout.js`, `debug-decode.js`, `test-decode.js` — layout forensics
- `Real-Reversed\ui-assets\_manifest.json` — extraction manifest (extracted + skipped)
- `Real-Reversed\ipc-commands.json` — plugin command surface + URL inventory
