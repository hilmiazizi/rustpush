# rustpush

Rust library and test CLI for Apple messaging infrastructure: IDS registration, iMessage lookup (`id-query`), APNs, and related services. The `rustpush-test` binary is the main entry point for registering an identity and running bulk phone/email lookups (same IDS API used by tools like p-radar).

## Requirements

| Requirement | Notes |
|-------------|--------|
| **Rust** | Stable toolchain (`rustup` recommended). Edition 2021. |
| **Build tools** | `build-essential`, `pkg-config`, `libssl-dev` (OpenSSL builds vendored, but headers help on some distros). |
| **Git submodules** | `apple-private-apis` and `open-absinthe` must be initialized. |
| **Network** | Outbound HTTPS to Apple (APNs, GSA, IDS), SideStore Anisette (`ani.sidestore.io`), and your registration relay. |
| **Registration relay + macOS VM** | Required for **first registration** only. A macOS host running [mac-registration-provider](https://github.com/beeper/mac-registration-provider) must be reachable through a Beeper-style relay. Lookup works from cached plists without the VM. |
| **Apple ID** | Account with iMessage enabled. Device 2FA / Circle approval during first login. |

Works on Linux (WSL2/Ubuntu tested). No physical iPhone required after initial plist bundle is saved.

## Install

```bash
git clone --recurse-submodules https://github.com/hilmiazizi/rustpush.git
cd rustpush

# If you already cloned without submodules:
git submodule update --init --recursive

cargo build --release \
  --features 'macos-validation-data,remote-anisette-v3' \
  --bin rustpush-test
```

Binary: `target/release/rustpush-test`

## Configure the registration relay

Registration needs a relay pairing code from your mac-registration-provider VM (one code per VM/identity).

```bash
# Fresh register (always fetches new hwconfig from relay)
RUST_LOG=info ./target/release/rustpush-test \
  --register \
  --relay-code=YOUR-RELAY-CODE

# Self-hosted relay (optional; default is https://registration-relay.beeper.com)
./target/release/rustpush-test \
  --register \
  --relay-host=https://relay.example.com \
  --relay-code=YOUR-RELAY-CODE
```

The Beeper access token is built into the binary. Override relay host/code via CLI or env:

- `RUSTPUSH_RELAY_CODE`
- `RUSTPUSH_RELAY_HOST`

After the first successful register, `hwconfig.plist` is cached. Lookup skips relay unless you pass `--register` again (which forces a fresh relay fetch).

## First-time registration

1. Start the macOS VM and registration relay bridge (mac-registration-provider connected to your relay).
2. From the repo root, run:

```bash
RUST_LOG=info ./target/release/rustpush-test --register --relay-code=YOUR-RELAY-CODE
```

3. Enter Apple ID and password when prompted (or pre-create `gsa.plist` — see below).
4. Complete Device 2FA / Circle sign-in when asked.
5. On success, the tool writes runtime state in the current directory:

| File | Purpose |
|------|---------|
| `config.plist` | IDS users, push state, identity keys |
| `hwconfig.plist` | Hardware/relay config (serial, OS version UA) |
| `keystore.plist` | Software keystore for signing keys |
| `gsa.plist` | Cached Apple ID credentials (SHA-256 password) |
| `id_cache.plist` | Lookup cache (created on use) |

These files are **local secrets** — do not commit them. After this step, the VM can stay off for lookup-only runs.

Optional `gsa.plist` format (skips interactive username/password):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>user</key>
  <string>you@icloud.com</string>
  <key>pass</key>
  <data><!-- SHA-256 of password as raw bytes --></data>
</dict>
</plist>
```

## IDS lookup (fast path)

When `config.plist`, `hwconfig.plist`, and `keystore.plist` exist with a registered user, lookup skips relay login, GSA, and re-registration:

```bash
RUST_LOG=info ./target/release/rustpush-test --test-lookup \
  tel:+15551234567 \
  tel:+15559876543 \
  mailto:friend@icloud.com
```

Targets can be passed as positional arguments or with `--target`:

```bash
./target/release/rustpush-test --test-lookup --target +15551234567
```

Phone numbers accept `tel:+1…`, `+1…`, or bare digits. Emails accept `mailto:…` or plain addresses.

Output prints `LOOKUP OK`, the registered self-handle, queried URIs, and `valid` (targets with at least one iMessage identity). Lookups go through Apple IDS via APNs in batches (library chunks of 18).

If plists are missing or empty, `--test-lookup` falls through to the full registration flow instead.

## BBOX: portable iMessage identity

A **BBOX** ("binary box") is a single self-contained, base64-encoded blob that bundles
everything needed to *act as* a registered iMessage identity, independent of the runtime
plists:

- the registered **self handle** (e.g. `mailto:you@icloud.com`) and **service** (`com.apple.madrid`)
- the device **serial** the identity was registered against
- the APNs **push token**
- the IDS **identity certificate** + its **private key** (and the EC/RSA key material p-radar signs with)

This is the same container format p-radar-style tooling consumes. Once exported, a BBOX can run
lookups on its own — no `config.plist`, no relay, no GSA login, no APNs session required.

> A BBOX contains private keys and grants full use of the identity. **Treat it as a secret.**
> All `*.json` bbox caches are git-ignored by default.

### Export a BBOX

After a successful registration (`config.plist` present):

```bash
./target/release/rustpush-test --export-bbox
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--output FILE` | `caches.json` | Where to write the JSON array. |
| `--serial SERIAL` | from `hwconfig.plist`/relay | Serial to stamp into the BBOX. Pass explicitly to skip the relay lookup. |
| `--main-id EMAIL` | from `config.plist` (falls back to `gsa.plist`) | Apple ID handle for the identity. |

```bash
./target/release/rustpush-test --export-bbox \
  --output mybox.json --serial F4JSDXCEHG7K --main-id you@icloud.com
```

Output is a JSON **array** (so multiple identities can be collected into one file); each element
is one base64 BBOX entry.

### Use a BBOX (offline lookup)

`--bbox-lookup` loads an identity straight from a BBOX file and runs a **pure-HTTP** `id-query`
(signed with the BBOX's own key) — no login, no APNs connection:

```bash
./target/release/rustpush-test --bbox-lookup --bbox-file caches.json \
  tel:+15551234567 mailto:friend@icloud.com
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--bbox-file FILE` | `caches_sample.json` | BBOX JSON array to load from. |
| `--bbox-index N` | `0` | Which entry in the array to use. |

It prints `query_status`, and for each target whether it is `REGISTERED` (with per-device push
token, NGM/identity versions, and capability flags) or `NOT registered`.

**`--bbox-lookup` (offline, BBOX) vs `--test-lookup` (live APNs, plists):** both hit the same IDS
`id-query`. `--bbox-lookup` is self-contained from a BBOX and signs over HTTP; `--test-lookup`
uses the live `config.plist` identity over an APNs session (the path p-radar uses). If a healthy
identity returns `status 0` but **zero identities for every target including known-valid handles
and itself**, the identity has been disabled by Apple at the account level (see `6009` below) —
it is not a query bug.

## Architecture (short)

```
┌─────────────────┐     validation/version     ┌──────────────────┐
│  rustpush-test  │ ◄──────────────────────────► │ Beeper relay     │
│  (Linux/WSL)    │                            │ → macOS VM       │
└────────┬────────┘                            └──────────────────┘
         │ GSA login headers
         ▼
┌─────────────────┐     id-query / messaging     ┌──────────────────┐
│ SideStore       │                            │ Apple APNs + IDS │
│ Anisette v3     │ ◄──────────────────────────► │                  │
└─────────────────┘                            └──────────────────┘
```

- **Relay + VM**: hardware serial and validation blob for registration.
- **Anisette**: Grand Slam / GSA request headers only.
- **APNs/IDS**: actual lookup and iMessage traffic.

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `DeviceNotFound` at startup | VM/relay not running or wrong relay code/token. |
| `6005` / bad authentication | Plist bundle does not match relay VM serial; re-register with matching pair. |
| `6009` | Apple temporarily blocked iMessage on this identity. |
| Panic on exit after lookup | Fixed in recent builds (graceful APS topic drop). Rebuild if you see `APS backed up??`. |
| Slow every lookup | Use fast path: ensure all three plists exist before `--test-lookup`. |
| `response too large` in logs | Library auto-splits batch; normal for large target lists. |

Set log level with `RUST_LOG=info` or `RUST_LOG=debug`.

## Library

Import `rustpush` from this repo as a path or git dependency. Core types: `IMClient`, `IDSUser`, `RelayConfig`, `register`, `APSConnectionResource`. See `src/lib.rs` exports.

Default crate features include `macos-validation-data`. Enable `remote-anisette-v3` for the SideStore Anisette provider used by the test binary.

## License

See repository license. Apple services are used at your own risk; comply with applicable terms of service.
