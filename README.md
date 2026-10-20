# Real-Reversed

Static reverse-engineering write-up of **"Real"** (`projectreal.gg`), a Tauri-based Roblox script-executor suite — v2.7.9, app shell v2.5.4 (build 180).

> **Standalone security research project.** No binaries are redistributed here — only extracted documentation, analysis notes, and purpose-built analysis tooling. Analyze software you own, in accordance with local law.

---

## What this is

A complete **static** analysis of Real's installer, main application, agent server and on-disk formats:

| Phase | Result |
|---|---|
| 1 — Triage | PE/entropy/strings analysis of all 7 binaries; packing identification; persistence & Defender-exclusion behavior |
| 2 — Near-source recovery | 396/419 embedded frontend assets recovered from the Tauri binary (full SvelteKit UI, Monaco editor, VSCode extension, provider integrations) |
| 2b — Vault crypto | Full local-vault key derivation + unwrapping scheme derived from disassembly and **verified offline against real vault data**: argon2id (64 MiB, t=3, p=1) → AES-256-GCM → base64-wrapped master key (REPORT §5b) |
| 3 — Packed payloads | **Unpacked statically.** `bin\Real.dll` (not a PE) = whole-file repeating-key XOR → **full engine module recovered** (Luau compiler+IR, `RealVM`, DrawingLib/Filesystem/WebSocket script APIs, libcurl, ImGui+D3D11 overlay, Roblox XML serializer). `bin\Real.exe` / `bin\Spoofer.exe` = boot-stub shells that aPLib-decompress **8 chunks each** into `.real`/`.byfron`; payloads identified as **Oreans WinLicense**-protected (incl. leaked `IL86.pdb` Oreans-VM PDB path). See REPORT §7 |

## Key findings (summary)

- **Architecture:** Tauri 2 + WRY + tao shell, SvelteKit UI served from `http://tauri.localhost`, Monaco editor, per-file IPC bridge (`ipc\*.txt`: `execute.txt`, `attach.txt`, `open_tab.txt`, `sync_from_vscode.txt`), companion MCP server (`real-mcp.exe`) for VSCode/Cursor extensions.
- **Packer (two layers, both broken statically):** the shell payloads are decompressed at runtime by an inline **aPLib depacker stub** (8 self-terminating streams → `.real`/`.byfron` raw=0 sections); `bin\Real.dll` is a whole-file **repeating-key XOR** (`4D 5A` known-plaintext → key verified against its PE signature). The unpacked shell payloads are additionally **Oreans WinLicense**-protected; the shipped DLL decrypts to an ordinary readable PE (engine module).
- **Behavior:** registers scheduled task `Real\Launch` → `Update.exe --via-task`; self-manages Windows Defender exclusions for its install/temp dirs; posts `/installer/report` telemetry; auth-token-gated installer flow.
- **Network surface:** Roblox account-automation endpoints (auth/users/avatar/accountinformation/presence/friends/economy…), vendor APIs (`api.projectreal.gg/live`, `dl./cdn.projectreal.live`), script hubs (ScriptBlox, rscripts.net, robloxscripts.com, WEAO), Luarmor V4 bootstrapper.
- **Vault format (on-disk):**
  - `data\enc_settings.json` — vault bootstrap: `password_salt_b64`, `key_enc_with_password_b64`, `answers_salt_b64`, `key_enc_with_answers_b64`, `has_device_key` (i.e. password path + recovery-question path + optional device-bound key).
  - `enc:v1` values = `<scheme>:<version>:<b64 12-byte nonce>:<b64 ciphertext||16-byte tag>` (AES-256-GCM via RustCrypto `aes-gcm-0.10.3` + `ctr-0.9.2` Ctr32BE + `aes-0.8.4` fixslice64 backend — confirmed from disassembly: U32 key assert, U12 nonce assert, J0 = nonce‖0x00000001, ctr32 keystream, 16-byte GHASH tag).
  - **Key derivation (README → REPORT §5b):** master key = `base64_decode( AES-256-GCM_open( argon2id(password_utf8, salt32, m=64MiB, t=3, p=1, out=32), wrap ))` — the GCM plaintext inside each wrap is a 44-char base64 string of the 32-byte key, which is then stored in a Once-guarded process global and used to unlock every per-account `enc:v1` token. Verified bit-exact offline (tag validation passes on real data).
  - `data\account-vault.dpapi` — genuine DPAPI blob (entropy `Real-UI account vault key v1`). Its 32-byte payload is a **separate DPAPI-mode key slot**, not the active password-mode master key.
  - `data\accounts.json` — plaintext account metadata (id/username/display_name); secret tokens live only inside the per-record `enc:v1` token strings.
- **Deprecation/migration hints:** `dev:v1` scheme + device-key path (`device-key-v1.dpapi`, `DEVICE_STORE_KEY`) exist alongside the account vault; legacy 16-byte account keys are migrated/rejected (`Account vault key has an invalid length`, `Migrated account vault key has an invalid length`).

Full details: **[REPORT.md](REPORT.md)**.

## Repository layout

```
Real-Reversed/
├── REPORT.md              # consolidated phase-1/2/3 deliverable
├── ipc-commands.json      # Tauri plugin command surface + host/package URL inventory
├── disasm/                # annotated capstone disassembly excerpts (vault crypto, accounts loop)
├── ui-assets/             # 396 recovered embedded frontend assets (+ _manifest.json)
├── tools/                 # analysis tooling (Node.js, capstone-wasm + hash-wasm)
├── package.json
├── LICENSE                # MIT
└── .gitignore             # secret-material exclusions (*.bin, *.dpapi, *.key, …)
```

## Tooling

All tools are Node.js scripts using [`capstone-wasm`](https://www.npmjs.com/package/capstone-wasm) and [`hash-wasm`](https://www.npmjs.com/package/hash-wasm) (`npm install` first).

| Tool | Purpose |
|---|---|
| `tools/extract-tauri-assets.js` | Tauri v2 asset extractor (`.rdata` layout: `<path-string><brotli stream>`) |
| `tools/inspect-layout.js`, `tools/debug-decode.js`, `tools/test-decode.js` | asset-layout forensics |
| `tools/disasm-annot.js` | annotated disassembler for arbitrary file-offset ranges |
| `tools/disasm-range.js` | quick disassembler with VA labels |
| `tools/unxor-pe.js` | repeating-key-XOR PE unwrapper (MZ-crib auto-derived key + PE-signature verify) |
| `tools/pe-forensics.js` | PE section/entropy/entry-point audit |
| `tools/aplib-depack.js` | chunked aPLib depacker (replicates the shell boot stub) |
| `tools/xref-scan.js`, `tools/enc-sym.js`, `tools/pool-scan.js` | RIP-relative cross-reference scanning for string VAs |
| `tools/find-vault-crypto.js` | locate vault/KDF strings in the binary and auto-xref them |
| `tools/probe3.js`, `tools/probe4.js` | misc disasm probes |

Scripts were written against a local install path — replace the `C:/Users/[name]/` placeholder with your own install location (or adjust as needed).

## Scope & ethics

- **No license circumvention, no cracking of access gates, no clone/re-implementation of the executor.** The goal is documentation and defensive awareness (this software defeats AV/Defender visibility and injects into Roblox).
- Personal/secret material (account data, vault keys, credentials) is absent from this repository by design — only generic on-disk *format* descriptions are included.
- Protected-payload analysis stayed **static throughout** (byte-level: XOR unwrap, aPLib depack, disassembly) — nothing in this repository was executed, and no game/anticheat was touched. The remaining WinLicense-protected layers would only be probed further (optionally, from a dump) in a disposable isolated VM.

## Status
**Real is safe to use**

- Phase 1 (triage): complete
- Phase 2 (asset recovery): complete — 396/419 assets in `ui-assets/`
- Vault crypto scheme: **verified offline** (see REPORT §5b)
- Phase 3 (packed payloads): **complete, static only** — DLL decrypted to a full readable PE; both shells depacked via aPLib; payloads identified as WinLicense/further-unpacking-left-for-VM work (see REPORT §7)
