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

Before first registration, set your relay credentials in `src/test.rs` (constants near the top):

```rust
const RELAY_HOST: &str = "https://registration-relay.beeper.com";
const RELAY_CODE: &str = "YOUR-RELAY-CODE";
const RELAY_TOKEN: &str = "YOUR-RELAY-TOKEN";
```

Rebuild after changing these values. The relay must bridge to a macOS VM whose SMBIOS serial matches the validation data returned by `get-version-info`. A `DeviceNotFound` / 404 on version info usually means the VM relay is offline, not an Apple ID login failure.

## First-time registration

1. Start the macOS VM and registration relay bridge.
2. From the repo root, run:

```bash
RUST_LOG=info ./target/release/rustpush-test
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

## Export p-radar BBOX cache

After registration:

```bash
./target/release/rustpush-test --export-bbox
# optional: --output caches.json --serial SERIAL --main-id you@icloud.com
```

Writes a JSON array with one base64 BBOX entry for p-radar-style tooling.

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
