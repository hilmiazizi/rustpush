# rustpush

Rust library and test CLI for Apple messaging infrastructure: IDS registration, iMessage
lookup (`id-query`), APNs, and related services. The `rustpush-test` binary is the main
entry point for registering an iMessage identity and running phone/email lookups (the same
IDS API used by tools like p-radar).

This fork is wired for **off-device registration through a jailbroken iPhone relay** that
mints validation data on the spoofable `baa:false` (software Absinthe) path, so each Apple
ID is registered with a **rotatable, per-account device identity** instead of being bound to
one real device. No macOS VM is required.

---

## How it actually works

```
┌──────────────────┐   relay code   ┌─────────────────────┐   validation data   ┌──────────────┐
│  rustpush-test   │ ─────────────► │  Beeper relay        │ ──────────────────► │  iPhone      │
│  (Linux / WSL2)  │ ◄───────────── │  (registration-relay)│ ◄────────────────── │  beepserv*   │
└────────┬─────────┘  version-info  └─────────────────────┘    get-version-info  └──────────────┘
         │ GSA login (per-account anisette machine-id)
         ▼
┌──────────────────┐        id-register / id-query / iMessage        ┌──────────────────┐
│  Anisette v3      │ ◄────────────────────────────────────────────► │  Apple APNs + IDS │
│  (software ADI)   │                                                 │                  │
└──────────────────┘                                                 └──────────────────┘
```

\* The phone runs a spoofing fork of beepserv
([hilmiazizi/phone-registration-provider](https://github.com/hilmiazizi/phone-registration-provider)).

Two device identities are involved, and **both are spoofable/rotatable** in this setup:

| Identity | Used for | Source | Rotates per account? |
|----------|----------|--------|----------------------|
| **Validation data** (serial / UDID / IMEI) | IDS `id-register` | iPhone beepserv fork, `baa:false` path | Yes — on-phone, via rotate flag |
| **Anisette machine-id** (`X-Apple-I-MD-M`) | GSA Apple-ID login | software ADI, `anisette_test/<account>.plist` | Yes — per-account state file |

### Why `baa:false`

Apple's `baa:true` path attests the registration with the Secure Enclave against the real,
fused-in serial — **not spoofable**. The beepserv fork forces the **`baa:false` software
Absinthe path**, where the serial/UDID/IMEI are read from MobileGestalt (which the fork
hooks). That lets a **fabricated-but-valid iPhone identity** be folded into the validation
blob and accepted by Apple off-device. See the fork's docs for the hook details.

---

## Requirements

| Requirement | Notes |
|-------------|--------|
| **Rust** | Stable toolchain (`rustup`). Edition 2021. |
| **Build tools** | `build-essential`, `pkg-config`, `libssl-dev`. |
| **Git submodules** | `apple-private-apis` and `open-absinthe` must be initialized. |
| **Network** | Outbound HTTPS to Apple (APNs, GSA, IDS), an anisette-v3 server (default `ani.sidestore.io`), and your registration relay. |
| **iPhone relay** | Required for **registration only**. A jailbroken iPhone running the beepserv spoofing fork, paired to a relay, reachable by relay code. Lookup works from cached plists / BBOX without the phone. |
| **Apple ID** | Account with iMessage enabled; 2FA handled at first login. |

Works on Linux (WSL2/Ubuntu tested).

---

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

---

## Registration (one-shot, per account)

Registration needs a **relay code** from your paired iPhone beepserv fork. The phone supplies
both the `get-version-info` identity and the minted `baa:false` validation data; rustpush does
GSA login + Albert activation + IDS registration entirely off-device.

```bash
RUST_LOG=info ./target/release/rustpush-test \
  --register \
  --relay-code=YOUR-RELAY-CODE
```

```bash
# Self-hosted relay (optional; default is https://registration-relay.beeper.com)
./target/release/rustpush-test --register \
  --relay-host=https://relay.example.com \
  --relay-code=YOUR-RELAY-CODE
```

Relay host/code can also come from env:

- `RUSTPUSH_RELAY_CODE`
- `RUSTPUSH_RELAY_HOST`

The flow: enter Apple ID + password (or pre-seed `gsa.plist`), complete 2FA once, then the tool
authenticates **a single time** and registers. On success it writes local state:

| File | Purpose |
|------|---------|
| `config.plist` | IDS users, push state, identity keys |
| `hwconfig.plist` | Relay hardware config (the **spoofed serial**, OS UA) |
| `keystore.plist` | Software keystore for signing keys |
| `gsa.plist` | Cached Apple ID credentials (SHA-256 password) |
| `anisette_test/<account>.plist` | Per-account anisette machine identity |
| `id_cache.plist` | Lookup cache (created on use) |

These are **local secrets — do not commit them.**

### Per-account anisette machine-id

Each Apple ID provisions and persists its **own** software-ADI machine identity at
`anisette_test/<sanitized-email>.plist`. This stops every account sharing one
`X-Apple-I-MD-M` fingerprint (a strong cross-account correlation signal). The bound machine is
kept on disk so the account can be re-authed later. For real isolation at volume, also
self-host the anisette-v3 server (e.g. `dadoum/anisette-v3-server`) and vary egress IP instead
of using the shared public `ani.sidestore.io`.

### Single login on register

`--register` authenticates with GSA **once** and reuses that session. (Previously the flow did
a second back-to-back SRP login, which Apple throttles with `AuthSrpWithMessage(-36607)`
"Try again later" and crashed registration before it completed.)

---

## Rotating the device identity (per account)

The phone serves a **persisted** identity until you explicitly rotate it. Two daemons read the
spoof plist and **both** must be restarted, in order, or version-info and the minted blob will
report different serials:

```bash
# On the iPhone (rootful jailbreak shown; use /var/jb paths for rootless):
touch /var/mobile/.beepserv_rotate     # request a fresh identity
killall -9 beepservd                   # respawns -> generates new serial/UDID/IMEI, consumes flag
sleep 3                                 # let the new /var/mobile/.beepserv_spoof.plist land
killall -9 identityservicesd           # respawns -> re-reads the new plist for validation minting
```

```bash
# On Linux, before the next --register:
rm -f hwconfig.plist gsa.plist          # force fresh version-info + new account prompt
```

Then run `--register` for the new account. It re-fetches the new serial and mints validation
data bound to the same new identity. Combined with per-account anisette, each account gets a
unique serial **and** a unique machine-id.

> The beepserv fork keeps real per-MODEL parts (plant/config of the serial, IMEI TAC) and only
> randomizes per-UNIT fields, so the spoofed tuple stays a plausible `iPhone9,3`.

---

## IDS lookup (fast path)

When `config.plist`, `hwconfig.plist`, and `keystore.plist` exist with a registered user,
lookup skips relay, GSA, and re-registration:

```bash
RUST_LOG=info ./target/release/rustpush-test --test-lookup \
  tel:+15551234567 \
  tel:+15559876543 \
  mailto:friend@icloud.com
```

Targets can be positional or `--target`:

```bash
./target/release/rustpush-test --test-lookup --target +15551234567
```

Phone numbers accept `tel:+1…`, `+1…`, or bare digits. Emails accept `mailto:…` or plain
addresses. Output prints `LOOKUP OK`, the self-handle, queried URIs, and `valid` (targets with
at least one iMessage identity). Lookups go through IDS via APNs in batches (chunks of 18).

If plists are missing/empty, `--test-lookup` falls through to the full registration flow.

---

## BBOX: portable iMessage identity

A **BBOX** ("binary box") is a single base64 blob bundling everything needed to *act as* a
registered iMessage identity, independent of the runtime plists:

- the registered **self handle** (e.g. `mailto:you@icloud.com`) and **service** (`com.apple.madrid`)
- the device **serial** the identity was registered against
- the APNs **push token**
- the IDS **identity certificate** + **private key** (the EC/RSA material p-radar signs with)

Once exported, a BBOX runs lookups on its own — no `config.plist`, no relay, no GSA, no APNs
session.

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

Output is a JSON **array** (multiple identities can be collected in one file); each element is
one base64 BBOX entry.

### Use a BBOX (offline lookup)

`--bbox-lookup` loads an identity straight from a BBOX file and runs a **pure-HTTP** `id-query`
(signed with the BBOX's own key) — no login, no APNs:

```bash
./target/release/rustpush-test --bbox-lookup --bbox-file caches.json \
  tel:+15551234567 mailto:friend@icloud.com
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--bbox-file FILE` | `caches_sample.json` | BBOX JSON array to load from. |
| `--bbox-index N` | `0` | Which entry in the array to use. |

It prints `query_status` and, per target, `REGISTERED` (with push token, NGM/identity
versions, capability flags) or `NOT registered`.

**`--bbox-lookup` (offline) vs `--test-lookup` (live APNs):** both hit the same IDS `id-query`.
If a healthy identity returns `status 0` but **zero identities for every target including
known-valid handles and itself**, the identity/account has been disabled by Apple (see `6009`)
— not a query bug.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `DeviceNotFound` at startup | Phone/relay not paired/online, or wrong relay code. |
| `AuthSrpWithMessage(-36607)` | GSA login throttled ("Try again later"). Single-login is already the default; wait and retry, or rotate the per-account anisette state. |
| Same serial across accounts | Phone identity not rotated — set the rotate flag and restart both daemons (see Rotating). |
| Version-info serial ≠ minted serial | Only `beepservd` was restarted; restart `identityservicesd` too so `bp_spoof` re-reads the plist. |
| `6005` / bad authentication | BBOX/plist push token stale (later registrations on the same device invalidate earlier bboxes). Re-export from a current registration. |
| `6009` | Apple disabled iMessage on this account (account-level ban), not a device/spoof bug. |
| `MOBILEME_TERMS_OF_SERVICE_UPDATE` | Burner account ToS gate; the tool auto-accepts and retries. |
| Empty `valid: []` for known-good targets | Account is query-limited (low reputation) — registers fine, lookups return nothing. |

Set log level with `RUST_LOG=info` or `RUST_LOG=debug`.

Debug aids (env-gated, no-op when unset):

- `RUSTPUSH_REG_VALDATA_OUT=path` — dump the exact validation-data blob sent at `id-register`.

---

## Library

Import `rustpush` as a path or git dependency. Core types: `IMClient`, `IDSUser`,
`RelayConfig`, `register`, `APSConnectionResource`. See `src/lib.rs` exports.

Default features include `macos-validation-data`. Enable `remote-anisette-v3` for the software
anisette provider used by the test binary.

## License

See repository license. Apple services are used at your own risk; comply with applicable terms
of service.
