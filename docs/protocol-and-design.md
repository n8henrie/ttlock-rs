# TTLock BLE: protocol notes and design rationale

This document exists so that a person or model arriving with no context can pick the project up and keep going without re-deriving what has already been worked out.
It records three things that the code cannot record on its own: what the protocol actually is, which parts of that understanding are solid versus inferred, and *why* the library is shaped the way it is.

Read this before making protocol changes.
Several of the decisions below look arbitrary, or look like they could be simplified, and are not — the reasons are recorded here precisely because they are not obvious from the code.

Nothing in this file contains real credentials.
Every address is `AA:BB:CC:DD:EE:FF`, every AES key is the repository's test vector, and the one credential sample was already published elsewhere and is cited at its use site.
Please keep it that way; see [`SECURITY.md`](../SECURITY.md).

## 1. Orientation

| Path | What lives there |
| ---- | ---------------- |
| `crates/ttlock-core` | The whole protocol, transport-agnostic. No `tokio`, no `btleplug`. |
| `crates/ttlock` | The `ttlock` CLI binary and the MQTT daemon, driving the core over `btleplug`. |
| `crates/ttlock-py` | pyo3 bindings exposing the core to Python as `ttlock`. Not published to crates.io. |
| `custom_components/ttlock_ble` | Home Assistant integration, built on the Python bindings and HA's Bluetooth stack. |
| `packages.nix`, `module.nix`, `nix/` | Nix packaging, the NixOS service module, and the module's checks. |
| `scripts/` | `check-versions.sh` and `check-secrets.sh`, both wired into CI. |

Within `ttlock-core`, the layering is strict and worth preserving:

`crc` and `crypto` are leaves.
`packet` builds on both and owns the wire format.
`framing` reassembles byte chunks into frames and knows only the header shape.
`ops` composes `packet` into user-level operations.
`tracker` sits above `ops` and owns what is believed about a lock *between* exchanges — bolt position, battery, availability, and whether a command is in flight.
`policy` holds the constants every consumer must agree on.
`advertisement`, `credential`, `sciener`, and `config` are independent of the frame path.

## 2. Provenance, and how much to trust it

The protocol here was reverse engineered, originally by way of a Python proof of concept, and then re-derived and tested against real hardware during this port.
There is no specification.
That means the code encodes a mix of three very different confidence levels, and conflating them is the main way to break something:

**Confirmed against a real lock.**
The frame envelope, the CRC (including its quirk), AES-128-CBC with the key as IV, the two-step actuation handshake, the status command, and advertisement parsing for a V3 lock.
These have all round-tripped against physical hardware.

**Confirmed against public samples only.**
The credential obfuscation scheme, verified against a value posted publicly on the Home Assistant forum and against round-trip properties, but not against a second independent implementation.

**Inferred, plausible, untested.**
Field names and meanings taken from the vendor's own vocabulary, the non-V3 advertisement fallback path, `lock_flag_pos`, `uid`, and the exact semantics of most bytes in the check-user-time payload.
Treat these as labels, not as knowledge.

When you learn something that moves an item between those categories, update this file.
That is the single most valuable contribution a future maintainer can make here.

## 3. The protocol

### 3.1 Finding a lock

Locks advertise continuously and can be tracked entirely passively — bolt position and battery arrive without ever connecting.
This matters more than it sounds: connecting is slow and drains the lock's batteries, so the daemon holds a continuous passive scan and only connects to actuate.

**The `0x1910` service UUID is not advertised.**
It appears in the GATT table only after connecting.
This cost real debugging time: an OS-level scan filter on that UUID suppresses *every* advertisement report and the daemon silently sees nothing at all.
Scans must be unfiltered, with locks identified from the manufacturer payload — see `ttlock_scan_filter()` in `crates/ttlock/src/ble.rs`, which deliberately returns `ScanFilter::default()`.

Identification therefore comes from manufacturer-specific data.
The company identifier is *not* a real Bluetooth SIG assignment; TTLock packs protocol bytes into it, so parsers must prepend it (little-endian) back onto the payload before decoding.
Both `btleplug` and `bleak` hand the company ID over separately, which is why `parse_manufacturer_map` exists alongside `parse_manufacturer_data`.

Advertisement layout, after the company ID is prepended (requires at least 15 bytes total):

| Offset | Meaning |
| ------ | ------- |
| 0 | `protocol_type` |
| 1 | `protocol_version` |
| 2 | `scene` (V3 path only) |
| 3 | params bitfield: `0x01` unlocked, `0x02` has queued events, `0x04` in pairing/setting mode |
| 4 | battery, 0–100 |
| last 6 | MAC address, **byte-reversed** |

`(protocol_type, protocol_version)` of `(18, 25)` or `(0xff, 0xff)` means "not a lock advertisement"; bail out.
For anything that is not `(5, 3)`, the parser falls back to reading the type and version from offsets 4 and 5 and the scene from offset 7 — that path is inferred and has not been exercised against hardware.

`Advertisement` is a sum type over the shapes above — `Unrecognized`, `Dfu`, `Stateless`, `Stateful` — rather than a struct of optional fields.
A bolt position exists only on `Stateful`, which is the only shape the wire guarantees one for.
Reporting a door as locked because a field was absent is exactly the failure mode this project refuses to have, and §6.4 covers why that became a type rather than a convention.

### 3.2 Connecting

Service `0x1910`, write characteristic `fff2`, notify characteristic `fff4`.
Writes are chunked (20 bytes) and sent without response.
Responses arrive as notifications that must be reassembled.

### 3.3 The frame envelope

Every frame in both directions:

```
7f 5a | type | ver | scene | group_id(2, BE) | org_id(2, BE) | command | encrypt | len | payload(len) | crc | 0d 0a
  0 1 |   2  |  3  |   4   |      5   6      |     7   8     |    9    |   10    | 11  |   12..12+len |     |
```

- `encrypt` is `0xaa` for app-originated frames.
- `len` counts the *encrypted* payload, so it caps a frame at 255 payload bytes.
- `crc` covers every byte from index 0 through the end of the payload.
- The trailing `0d 0a` is stripped before parsing; `Envelope::parse` expects it gone.

**The version header is validated by the lock.**
This is the single most expensive lesson in the codebase.
A frame built with the wrong `protocol_type` / `protocol_version` / `scene` is not ignored and does not fail at the connection layer — the lock decrypts it, rejects it, and returns a failure response.
The symptom is `command failed with response byte 0x00` on the *handshake*, which looks like a credential problem and is not.
Always prefer the `LockVersion` parsed from an advertisement, and fall back to `LockVersion::default()` (type 5, version 3, scene 2, group 1, org 1) only when nothing has been seen.
The Home Assistant component shipped with this bug precisely because it skipped that step; `_op_version()` in `coordinator.py` is the fix.

### 3.4 Reassembly

`FrameAssembler` recognizes frames by the `7f5a` magic and the length field at byte 11 — **not** by scanning for the trailing CRLF.
That is deliberate: the payload is ciphertext and will eventually contain `0d 0a` by chance, and a CRLF-scanning assembler splits that frame in half and desynchronizes the stream forever.
There is a test for exactly this (`payload_containing_crlf_is_not_split`).

The assembler also resynchronizes by discarding bytes before the next `7f5a`, so one garbled chunk cannot wedge the connection permanently.

### 3.5 CRC, and the quirk

Standard CRC-8/MAXIM (Dallas/1-Wire, poly `0x31` reflected to `0x8c`, init 0, no final XOR) with one deviation: **table index 33 returns 7 instead of 31**.

This is not a transcription error and must not be "fixed".
It is present in the vendor firmware, and real locks reject frames whose CRC path crosses index 33 unless the quirk is reproduced.
`crc::table_value` is the single place this lives, and `credential.rs` reuses it — the credential mask derivation depends on the same table, quirk included.

### 3.6 Cryptography

AES-128-CBC, PKCS#7 padded, **with the key used as the IV**.
Empty plaintext encrypts to empty output rather than to a padding block; the lock expects that.

`DEFAULT_AES_KEY` in `crypto.rs` is the factory key, hardcoded in vendor firmware and identical across devices.
It is public knowledge, not a secret, and only applies to locks that have never been paired.

The security consequences of a static key and a fixed IV are real; they are the lock's design, not this project's, and are spelled out in [section 4](#4-security-properties).

### 3.7 Commands

| Byte | Name | Notes |
| ---- | ---- | ----- |
| `0x14` | `COMM_SEARCH_BICYCLE_STATUS` | Query state. The "bicycle" name is the vendor's, inherited from shared-bike hardware on the same protocol. |
| `0x47` | `COMM_UNLOCK` | Unlock. |
| `0x54` | `COMM_RESPONSE` | Generic response wrapper. |
| `0x55` | `COMM_CHECK_USER_TIME` | Handshake preceding every actuation; returns the challenge. |
| `0x58` | `COMM_FUNCTION_LOCK` | Lock. Note this is *not* `0x47` with a flag. |

Decrypted payloads are `[command_type, response, ...data]`, where `response == 1` means success and anything else is a rejection.
`parse_success_response` requires exactly `1`; treating "not zero" as success would report a failed actuation as a locked door.

**Status** sends the ASCII plaintext `SCIENER` and reads `data[1]`: `0` = locked, `1` = unlocked.
`data[0]` appears to be battery (a response of `0x63` = 99 shows up alongside a 99% advertisement) but this is inferred and unused.
Any other state byte becomes `LockState::Unknown(byte)` rather than being guessed at.

**Actuation is two steps**, and both must succeed:

1. Send `0x55` with a 17-byte check-user-time payload.
   The lock replies with a 4-byte big-endian challenge, `ps`.
2. Send `0x58` (lock) or `0x47` (unlock) with an 8-byte payload: `(ps + unlock_key)` as big-endian `u32` with wrapping addition, followed by the current Unix time as big-endian `u32`.

The unlock key never travels the wire directly, and the appended timestamp is also how the lock keeps its clock in sync.
Because `ps` changes per session, recorded actuation frames should not replay — see [section 4](#4-security-properties) for how much weight that deserves.

**A latent quirk in the check-user-time payload.**
`build_check_user_time_payload` writes overlapping ranges in a specific order: the start date at `[0..5]`, `lock_flag_pos` at `[9..13]`, the end date at `[5..10]`, and `uid` at `[13..17]`.
The end date's final byte therefore overwrites the first byte of `lock_flag_pos` at index 9.
With the values this project actually sends (`lock_flag_pos = 0`, end date ending in `00`) both writes are zero, so it is invisible — but anyone who starts passing a non-zero `lock_flag_pos` will hit it.
The ordering is a faithful port of the working proof of concept and was left alone on the principle that a working handshake beats a tidier one.

### 3.8 Known unknowns

- The non-V3 advertisement fallback path.
- The meaning of most check-user-time payload bytes, `uid`, and `lock_flag_pos`.
- Whether `ps` is a counter, a nonce, or time-derived, and how long it stays valid.
- Everything about pairing/initialization — this project reads credentials from the vendor app rather than pairing, and implements no pairing path.
- The operation-log commands (advertisements report that records are queued; nothing here reads them).
- Passcode, card, and fingerprint management.

## 4. Security properties

These follow from the protocol, not from this implementation, and none of them can be fixed here.
They determine what using this project can and cannot protect you from.
[`SECURITY.md`](../SECURITY.md) covers the part that *is* in this project's control: how the credentials are stored and passed around.

**A single static symmetric key protects everything.**
Each paired lock has one AES-128 key, used for every command for the life of the pairing, and this project provides no way to rotate it or the unlock key.
Anyone holding both can open the lock.

**The key is also the IV.**
Identical plaintexts therefore always produce identical ciphertexts, which leaks equality between messages and removes the semantic security CBC would otherwise give.
Using a real IV would make the lock reject the frame.

**Actuation is challenge-response, so captured frames should not replay.**
`ps` changes between sessions, so a recorded actuation frame should not open the lock a second time.
That is an observation of how the locks behave, not a guarantee from a specification: the freshness of `ps` has never been characterized (see [section 3.8](#38-known-unknowns)).
It offers nothing against an attacker who already has the AES key, who can simply decrypt the challenge and compute the answer.

**Advertisements are unencrypted and unauthenticated.**
Bolt position, battery, and MAC address are broadcast in the clear to anyone in radio range, and forged ones are equally cheap to transmit.
Since this project treats advertisements as evidence of lock state, someone in range can make Home Assistant display the wrong state.
They cannot actuate the lock that way — that path still requires the AES key.

**Unpaired locks accept the factory key.**
`DEFAULT_AES_KEY` is hardcoded in the vendor firmware and identical across devices, which is why it is published here rather than treated as a secret.
A lock that has never been paired will talk to anybody.

**The operate log stores keypad passcodes in plaintext, and reading it needs only the AES key.**
A `4 keyboard password unlock` record embeds the passcode as ASCII digits, twice, inside the record body.
So `0x25 GET_OPERATE_LOG` is not merely an audit trail: it hands over working door codes, including ones belonging to other people who have been given access.
`ttlock logs` reads the log for audit purposes and prints passcodes after a warning and a pause; `LogRecord::passcode` decodes the field so a consumer at least knows it is there.
Anything that *does* read it — a diagnostic script, a captured session, a saved log file — becomes as sensitive as `lockData.json` and should be handled the same way and deleted afterwards.

## 5. Credentials

### 4.1 `lockData.json`

Array of entries, snake_case, inherited from the Python proof of concept so the two stay interchangeable.
The fields that matter are `address` and `private_data.{aes_key, admin_ps, unlock_key}`; the rest are optional and default.
`sample-lockData.json` is the shape; a real one is git-ignored and holds the key to your door.

### 4.2 Importing from the vendor app

`ttlock import-credentials` reads the Sciener/TTLock iOS app's Core Data sqlite database strictly read-only and converts its `ZKEY` rows.
Splitting this in two was deliberate: `ttlock-core::sciener` does the pure column-to-`LockData` decoding and is fully unit-tested, while the CLI owns the sqlite I/O.

| Column | Field | Transform |
| ------ | ----- | --------- |
| `ZLOCKMAC` | `address` | as-is |
| `ZAESKEYSTR` | `private_data.aes_key` | comma-separated hex bytes → 32-char hex |
| `ZADMINPS` | `private_data.admin_ps` | base64 comma-list credential → `u32` |
| `ZLOCKKEY` | `private_data.unlock_key` | base64 comma-list credential → `u32` |
| `ZAUTOLOCKTIME` | `auto_lock_time` | integer |
| `ZRSSI` | `rssi` | integer |

Rows without a MAC or AES key are filtered out in SQL rather than failing the whole import — a phone's database contains keys for locks you no longer have.

### 4.3 The credential obfuscation, and a false lead worth remembering

`ZADMINPS` and `ZLOCKKEY` are base64-wrapped, comma-separated byte lists.
Decoding: the **last** byte is a seed; the remaining bytes are the credential's ASCII decimal digits XORed with `mask = crc_table_value(digit_count) ^ seed`.

The trap: against any single sample, the mask looks like a fixed constant (`0x74` for the commonly circulated example).
Hardcoding it passes one test and then silently fails on real data, because the mask depends on both the seed *and* the number of digits.
`mask_is_seed_dependent_not_a_fixed_constant` in `credential.rs` is a regression test for exactly that mistake, and it is worth keeping.

Values copied out of the app arrive with stray whitespace and a trailing `.`; both are tolerated.

## 6. Library design

### 5.1 Why sans-IO

`ttlock-core` performs no I/O whatsoever.
Operations are state machines: `start()` yields the first frame to write, then each reassembled response is fed back through `handle_frame()` until it yields `Step::Done`.

This is the design decision the whole project hangs on.
Three very different transports drive the identical protocol code: `btleplug` in the CLI, HA's `bleak`-based Bluetooth stack in the custom component, and whatever a Python user brings.
Without it, the protocol would have been implemented three times and would have drifted three ways — which is precisely how the Home Assistant component ended up with the protocol-version bug that the CLI never had.

If you are tempted to add async, a timeout, or a retry to `ttlock-core`, that belongs in the caller.

`tracker::LockTracker` is the same idea one layer up, and takes the same discipline: it reads no clock, so callers pass monotonic milliseconds in.
That is precisely what lets a tokio daemon and a Home Assistant coordinator share it — and what makes the conformance table replayable without either.

### 5.2 Operations are single-use, with one deliberate exception

An operation that has reached `Done` cannot be restarted, and a retry needs a fresh one.
Reusing a half-driven op fails on an unexpected frame instead of starting over, which is the correct behavior.

The exception is `TtlockError::CrcMismatch`.
`Envelope::parse` deliberately does *not* verify the CRC or decrypt; `ensure_crc()` and `decrypt_command()` are separate calls, and operations check the CRC **before** touching any of their own state.
That is what makes re-sending the previous frame safe: a corrupted response leaves the operation still waiting for the same response, so a retry resumes rather than desynchronizes.
Both the CLI and the HA component rely on this, and `test_crc_retry_resumes_the_same_step` in the Python suite pins it.

### 5.3 The error taxonomy is a retry policy

The distinction that matters is *retryable* versus *not*:

- **Retryable**: `CrcMismatch` (corruption on a weak link), connection failures, timeouts.
- **Not retryable**: `CommandFailed`, `UnexpectedCommand`, `AesDecrypt`, `BadHeader`.
  A lock that decrypted a command and rejected it will reject the identical bytes again; retrying just drains its batteries.

`CommandFailed` carries both the command byte and the response byte, because *which* command failed is the diagnosis.
A rejection at `0x55` points at the AES key or the protocol version; a rejection at `0x58` points at the unlock key.
Collapsing them loses that, which is why `lock_op_propagates_command_failure` and `lock_op_reports_actuation_failure_against_the_lock_command` are two separate tests.

The Python bindings mirror this: `CrcMismatch` is its own exception type subclassing `TtlockError`, so callers can tell corruption from rejection.

### 5.4 Making invalid states unrepresentable

The core is in Rust for this specifically, and for a while it was not delivering on it.

Three types now carry invariants that used to be conventions:

**`credential::AesKey`** wraps `[u8; 16]` instead of `Vec<u8>`.
The length check moved out of `crypto::aes_encrypt` and every builder downstream; `aes_encrypt` is now infallible and `TtlockError::AesEncrypt` no longer exists.
Both credential types also have hand-written `Debug` impls that redact.
That is not decoration: `ops::ActuateOp` derives `Debug` and holds the key, so a plain derive put the AES key one `{:?}` away from a log file.

**`credential::UnlockKey`** wraps `NonZeroU32`.
Zero is what an unfilled form field collapses to, and the actuation payload is `ps_from_lock + unlock_key` — so a zero key returns the lock's own challenge unchanged and gets refused.
That failure looks like a protocol fault, not a bad credential, and it reached a real lock: the only validation lived in the Home Assistant config flow, so the CLI and the MQTT daemon had none.
Now the rule lives in the core and Python reaches it through `ttlock.normalize_unlock_key`, which the config flow calls instead of reimplementing.

**`advertisement::Advertisement`** is a sum type over the payload shapes the wire actually produces — `Unrecognized`, `Dfu`, `Stateless`, `Stateful` — replacing a struct of six independent `Option`s.
The old shape admitted 64 combinations, most of which no payload can produce, and the impossible ones were where the bugs lived: a protocol family with no flags byte (pre-V3, and V2S at `5.1`) had its bolt position read out of whatever byte followed the header.
`Bolt` is a named enum rather than `is_unlock: bool` because the wire flag means *unlocked* while every consumer reasons in terms of *locked*; the value was being inverted in the parser and again in the tracker, and a missed inversion reports a door as secured while it stands open.
`Percent` rejects bytes above 100, since those are evidence of a misparse rather than a low battery.

`tracker::Knowledge` follows the same reasoning: `Option<Bolt>` beside `Option<Actuation>` was four combinations expressing three states, so `reported_state()` had an unreachable arm.
One enum makes it total, and the module's rule — *never report a bolt position that has not been observed* — becomes the shape of the type rather than a comment above it.

**Where this stops.** Typestate proper — a generic state parameter, `ActuateOp<AwaitingHandshake>` — was considered and rejected.
The `Operation` trait exists so one generic driver loop and the pyo3 bindings can hold any operation uniformly, and typestate does not survive `dyn`.
It would delete a single four-variant runtime enum that is fully tested and has never produced a bug, in exchange for an API that the bindings could not express.
Newtypes and sum types at the data boundaries are where "unrepresentable" pays here; the sequencing is already fine.

## 7. Transport realities

These are hard-won and none of them are visible from the protocol alone.

**macOS hides BLE addresses.**
CoreBluetooth reports opaque per-host UUIDs, so `btleplug` addresses come back all-zeros.
The MAC recovered from the advertisement payload is the only way to identify a specific lock there.
This is also why the filesystem cache was removed: it keyed on an address that does not exist on macOS.

**Weak reception breaks the connect, not the protocol.**
`le-connection-abort-by-local` and ATT error `0x0e` are routine, and usually clear on a later attempt.
`--connect-attempts` (default 6) with a growing backoff exists because of this; the backoff matters as much as the count, since the controller needs time to settle after an aborted connection.

**Bluetooth must not share a task with the MQTT event loop.**
A connect-and-actuate can take many seconds.
When that ran on the MQTT task it starved the keep-alive, the broker dropped the client, the retained Last-Will fired, and Home Assistant flipped the lock to *unavailable* every time you used it.
The `BleWorker` on its own task is the fix, and the split is load-bearing rather than stylistic.

**Time spent actuating must not count toward the offline timeout.**
The radio cannot hear advertisements while it is connecting, so a retry chain longer than `--offline-after-seconds` would flip the lock to unavailable and straight back.
`handle_command` credits that blind time back to `last_seen`.

**A failed scan must not make the daemon deaf.**
`start_continuous_scan` fails *before* the worker reaches its `select!`, so an early version returned straight into a bare `sleep` and retried.
Nothing polled the command channel and nothing ticked the offline timer for as long as the adapter stayed unusable: a `LOCK` from Home Assistant went into the channel and sat there unacknowledged, to be actuated whenever the radio came back, and the lock reported itself available forever while hearing nothing.
`idle_until_rescan` now services both while waiting to rebuild the scan.
This was found by the VM test, not by inspection, and is a good argument for keeping that test.

**A device's manufacturer-data map is accumulated, not replaced.**
Both `btleplug` and BlueZ keep a `{company_id: bytes}` map per peripheral and only ever *insert* into it.
An entry that stops being refreshed therefore sits there indefinitely beside a live one, and a lock can carry more than one.
Taking `.iter().next()` from a `HashMap` picked between them by hash order — which changes on resize — so reported state froze for as long as that ordering held.
The tell was a battery reading that alternated between 62 and 100 seventy-eight *microseconds* apart: not a battery, but two different byte strings being read.
`parse_manufacturer_map` now parses every entry and chooses explicitly: prefer a payload carrying state, prefer one whose decoded MAC matches the expected address, break remaining ties on the company identifier so the result never depends on iteration order.
The Python side reaches the same logic through `ttlock.select_advertisement`; it used to loop the entries and feed each to the tracker in turn, which let a stale entry overwrite a live one.

**One radio report is not one event.**
`btleplug` fans a single advertisement out into as many as five `CentralEvent`s — `DeviceDiscovered`, `DeviceUpdated`, `ManufacturerDataAdvertisement`, `ServiceDataAdvertisement`, `ServicesAdvertisement`.
Treating each as an advertisement meant parsing, matching and publishing the same report up to eight times inside a hundred microseconds.
Only the first and third can carry manufacturer data; the rest cannot carry a bolt position at all, and are now ignored.
Where the event carries the payload it is used directly, rather than reading the peripheral's accumulated properties back.

**The lock pushes unsolicited frames on the characteristic it replies on.**
One can land inside a command's response window, and every lock-to-phone frame carries `COMM_RESPONSE` (`0x54`) at the envelope level whatever it is about — only the decrypted plaintext says which command is being echoed.
So the transport cannot filter these; the operation must, and it does, because each `parse_*_response` checks the echoed command byte before anything else.
Consuming a push as the reply is a real hazard rather than a theoretical one: a parser that skipped that check would read a log push as a status reply — for a manual key turn, the second plaintext byte is the uid's high byte, usually zero, decoding as `LOCKED` while the door stands open — and would leave the genuine reply queued, putting every later exchange one frame behind.
`TtlockError::UnexpectedCommand` is therefore *resumable* in the same way `CrcMismatch` is, and `is_stale_frame()` says so, but the correct response is the opposite: re-send nothing, read the next frame.
Both drivers skip up to `policy::MAX_STRAY_FRAMES` of them on the **original** deadline — restarting it would let a chatty lock postpone a timeout indefinitely, and an unbounded skip would turn a genuine desynchronization into a silent timeout.

**Home Assistant Bluetooth proxies have finite connection slots.**
`No backend with an available connection slot` is a transient condition that clears on its own schedule; waiting is the fix and hammering is not.
The component also re-resolves the `BLEDevice` on every attempt, because which proxy can reach the lock changes as they move in and out of range, and a stale device pins you to one that may be out of slots.

## 7a. What the lock can and cannot sense

**This is the most important limitation in the project, it is not fixable from this side, and it is asymmetric in the dangerous direction.**

Measured over three sessions (~95 minutes, ~1400 advertisements, narrated on the same clock):

| Event | Detected? | Latency |
| --- | --- | --- |
| Bluetooth command (`lock` / `unlock`) | yes | ~8 s |
| Manual **lock**, by hand or key | yes, eventually | 4 m 27 s and 10 m 33 s |
| Manual **unlock**, by hand or key | **never** | not once in 31 m, 10 m, 11 m |
| `0x14` status query | **never** | returns a constant |

Every observation fits one rule: **the lock detects the bolt arriving in the locked position and nothing else.** Consistent with a limit switch at the locked end and no sensing anywhere else in the travel — common in deadbolt design.

Using a key rather than the thumbturn makes no difference. A key *unlock* at 16:43:26 went undetected for the remaining 11 minutes of the capture, exactly like a thumbturn unlock. The direction is what matters, not the mechanism.

### Why this is the dangerous asymmetry

After a manual unlock the advertisement keeps reporting `LOCKED`, indefinitely. So the integration will state that a door is secured while it stands open, and no amount of waiting corrects it — only a subsequent lock does.

The reverse error is self-correcting and harmless: after a manual lock we report `UNLOCKED` for a few minutes until the lock notices.

This is precisely the failure §8 exists to prevent, and §8 cannot prevent it. The tracker's rule is "never report a bolt position that has not been observed" — but an advertisement *is* an observation. It is simply an observation of a proposition the firmware gets wrong. There is no evidence available to contradict it.

Both consumers therefore declare an assumed state (`_attr_assumed_state`, and `"optimistic": true` in the MQTT discovery payload, which is the only lever that platform exposes). That is partly honesty and mostly function: without it Home Assistant offers only the action that contradicts the reported state, so a lock opened by hand while we believe it locked cannot be locked again from the dashboard card.

### `0x14` is inert on this hardware

`COMM_SEARCH_BICYCLE_STATUS` returned `lock state = 1 (UNLOCKED)` on every one of roughly a dozen invocations across every bolt position, including while the advertisement simultaneously reported `LOCKED`. Battery in the same reply is live and correct, so the response is not wholly canned — only the state byte is.

Nothing in the library depends on it: the tracker learns state from advertisements and command acknowledgements. Only the `ttlock status` CLI subcommand reads it, and on this lock its output should be disregarded.

### Two artefacts worth knowing

**Battery spikes to 100 about a minute after every connection.** Four occurrences, lags of 69 s, 65 s, 56 s, 67 s after a BLE connect, each lasting a few seconds before returning to the true 62. `Percent` accepts it because 100 is a legal percentage, so the battery sensor briefly reads full after every command. This also explains the `62 -> 100 -> 62` flip that originally suggested a second manufacturer-data entry: the lock really does broadcast it, and there was never a second entry.

**Flag bit `0x10` is undocumented.** Set alongside `LOCKED` in most samples here, absent in others, and neither this parser nor the reference implementation decodes it (both know only `0x01`, `0x02`, `0x04`). Left unparsed rather than guessed at.

Bit `0x02` ("records queued") has been set in every sample ever taken and never observed clear.

### `0x25 GET_OPERATE_LOG` is an audit trail, not a state source

This was the last untried channel, and the hope was that the lock's own audit trail would record what the advertisement misses. It does not. **Nothing here feeds the tracker, and nothing should.** It is implemented — `ttlock logs`, `ttlock_core::oplog` — purely so you can see who opened the door and when.

The log was walked to the present — 120 records, sequences 248 to 368, spanning 2026-07-27 to 2026-08-19, ending twelve seconds behind the lock's own clock — against a narrated test: a manual unlock, manual lock, manual unlock, keyed lock and keyed unlock, performed within about a minute, followed immediately by a `ttlock lock`. **Only the Bluetooth command was logged.** All six mechanical operations left no trace. An earlier session at 07:37 on 2026-08-18 did the same four-operation test with the same result. The documented mechanical codes, `27 OPERATE_KEY_UNLOCK` and `36 OPERATE_KEY_LOCK`, appear zero times in the entire log.

One rule accounts for every record observed: **the lock logs operations it performs, never bolt movement it observes.**

| code | operation | logged |
| --- | --- | --- |
| `1` | phone / app unlock | yes |
| `4` | keypad passcode unlock | yes |
| `7` | wrong keypad passcode | yes |
| `20` | fingerprint unlock | yes |
| `26` | Bluetooth lock (this project) | yes |
| `47` (`0x2f`) | keypad lock — see below | yes |
| `27` / `36` | key unlock / key lock | **never** |
| — | thumbturn, either direction | **never** |

Which is the same firmware limitation as the rest of this section, seen from a second angle: the mechanical path is not instrumented at all. The advertisement's limit switch at the locked end is genuinely the only mechanical sensing on this hardware, and it does not feed the log.

**Code `47` is a keypad lock**, and identifying it took a schedule rather than a packet. It carries no operator ID (8 bytes: type, six-byte date, battery) and it never fired during any deliberate test at the door, which is what made it look mechanical. But it lands at 08:45–08:51 and again at 15:58–16:00 on weekdays only, each time followed by a fingerprint unlock half an hour or a quarter of an hour later — the school run, locking up from outside with the keypad on the way out and coming back in on the fingerprint reader. No operator ID because locking from the keypad requires no identification. It is an electronic operation, so it fits the rule above; it is not evidence of mechanical sensing.

**Code `48` (`0x30`) is probably its failure counterpart**, unconfirmed. Adjacent code, identical eight-byte shape, two occurrences: one twenty seconds after a `7 error password unlock`, one a minute before somebody gave up and used the phone. Both read as a fumble at the keypad. Two samples is not a finding.

#### Cursor semantics

These cost four runs to work out, are not obvious from the vendor code, and each one is encoded in a type or a test rather than left as folklore.

**There are two kinds of cursor, and only one of them is stateful.**

- **An explicit sequence is a non-destructive, repeatable read.** Records stay in the lock; asking for the same range twice returns it twice. Confirmed directly: after three runs had already walked past sequence 249, a fresh read from 248 returned 249, 250, 251, 252 again. This is what makes `ttlock logs` an ordinary idempotent command with no local archive and no crash-safety machinery — an interrupted walk is just resumable.
- **`0xFFFF` is a bookmark meaning "since the last read", and reading with it moves the bookmark.** It persists across disconnection, so a fresh process continues where the previous one stopped — which makes repeated runs look like a log that is silently growing. It is exposed as `--since-last-read` and is not the default.

`0xFFFF` is therefore reserved and cannot also be a position, which is why `oplog::Sequence` rejects it at construction rather than letting a caller pass a `u16` that means something else.

**The bookmark can skip a record the walk never received.** Run 1 was refused at sequence 267; run 2's `0xFFFF` returned 268. Record 267 was never delivered, and no later sentinel read could reach it — it is recoverable only by explicit sequence. A second reason `--from` is the default.

**Cursor `0x0000` returns the oldest record the lock still holds.** Confirmed directly: it answered with sequence 1, dated 2026-05-19. This is what `ttlock logs` sends when `--from` is omitted.

**A cursor past the newest record has no defined behaviour — do not send one.** The same request bytes, a day apart, gave two different answers: on 2026-08-25 a cursor of 5000 returned record 374; on 2026-08-26 it returned the empty end-of-log page. Deterministic encryption means those were byte-identical requests. Whatever governs it, it is not the record range, and one of the two answers was a real record the walk had not asked for.

That killed an attempt to bisect for the newest sequence in sixteen probes rather than walking there in several hundred: a search has to probe above the end to find it, and those are exactly the cursors whose answers cannot be trusted. There is consequently **no way to read the end of the log without reading all of it**, which is why the CLI offers no `--last` — `ttlock logs | tail` costs the same round trips and is one fewer thing to maintain. The walk's tests assert it never sends a cursor above the newest sequence it has been shown.

**A refusal (`status = 0`) means "stale cursor", not "end of log".** Treating it as the end truncates the walk and reports a log that stops weeks in the past; this produced two wrong conclusions before it was caught. The walk retries the cursor once and then stops with the sequence to resume from, rather than either failing or pretending it finished.

**End of log is `status = 1` with `data = 0000`** — an empty page, unambiguous, and the only signal that should ever be believed.

Practically: one record per page, so the cost is one round trip per record, and the log is longer than it looks — the test lock held 374 records reaching back three months, so a full read runs to several minutes. `ttlock logs` streams records as they decode rather than buffering, so that time is visible rather than silent.

**A read of `0x25` discloses keypad passcodes.** See §4. The CLI prints them — this is a local tool for your own door — but warns and pauses first so the warning arrives *before* the codes rather than scrolling past with them; `--no-warn` skips the pause. Withholding was tried and removed: the same digits sit in the undecoded record body, so redacting one field without the other is theatre, and redacting both leaves a command whose output cannot be checked against the wire.

## 8. Evidence-based state

This is the project's central commitment, and it should survive refactors.
It now lives in exactly one place — `ttlock_core::tracker::LockTracker` — because it previously lived in two and they drifted apart three separate times.

**Never report a bolt position that has not been observed.**
Issuing a command produces `LOCKING` / `UNLOCKING` — claims that a command is in flight, not claims about the door.
The bolt advances to `LOCKED` / `UNLOCKED` only on evidence: the lock's own response (encrypted, CRC-checked, carrying a success code) or an advertisement.

**A failed command leaves the state in progress rather than reverting.**
A timeout or a mid-exchange disconnect means "outcome unknown", not "nothing happened" — the write may well have landed with only the reply lost.
Advertisements arrive frequently, so the next one settles it truthfully either way.

**In progress must reach the user, and must always have a way out.**
Both consumers publish the transitional state *before* the slow connect-and-actuate, not after: an actuation takes many seconds over a weak link, and a UI with nothing to show for the click looks broken.
Both then need an escape when a command fails and no advertisement follows, or an honest "outcome unknown" decays into a permanent `Locking…`, which is its own kind of lie.
The tracker provides it: anything that clears availability also clears the pending command.
The daemon triggers that from its own timer (`poll_availability`); the component from Home Assistant's `async_track_unavailable`, whose view of scanners and proxies is better than anything reimplemented here.
Only the trigger differs — the consequences are shared.

`optimistic: false` in the MQTT discovery payload is the same commitment expressed to Home Assistant, and `is_locking`/`is_unlocking` on the lock entity are its Home Assistant equivalent.
The VM test asserts the first, the conformance table (§9) asserts both.
This is a security property rather than a preference: an automation that locks the door and trusts an optimistic `LOCKED` would leave a door open while reporting it secured.

## 9. Keeping the three consumers in step

One version, `[workspace.package] version` in `Cargo.toml`, covers the Rust crates, the Python wheel (via maturin's dynamic version), and the Home Assistant component's manifest.
`scripts/check-versions.sh` asserts that the places which cannot derive it automatically agree, and CI runs it.

Behavioral parity is the harder problem, and checklists did not solve it.
Three bugs shipped from the same cause — a fix applied to the daemon and forgotten in the component, or vice versa:

1. The component built commands without the advertisement's `LockVersion`, so every command failed with `response byte 0x00`.
2. The component never implemented `is_locking`/`is_unlocking`, so the Home Assistant button looked dead for several seconds.
3. The component never expired availability; fixing that surfaced the daemon's mirror image, where a broker reconnect republished a retained `online` the worker knew to be false.

The structural answer is that neither consumer owns any of these rules.
`LockTracker` does, and both render from it, so a rule can no longer exist in one place and not the other.
`ttlock_core::policy` does the same for the constants — `WRITE_CHUNK`, `CRC_RETRIES`, the GATT UUIDs — which had already drifted.

What that cannot cover is the *rendering*: MQTT payload strings on one side, Home Assistant entity properties on the other.
`tests/conformance/state.json` pins those. It is a table of scenarios — events in, expected state out — driven from both `crates/ttlock/tests/conformance.rs` and `crates/ttlock-py/tests/test_conformance.py`.
Add a scenario and whichever side has not wired it up fails.
That file is the right place to record any future behavior both consumers must share.

**Tunables that legitimately differ.**
Not everything should be identical: Home Assistant usually reaches the lock through an ESPHome Bluetooth proxy, which is slower and busier than a local adapter.
These differ on purpose, and are listed here so the divergence stays deliberate rather than accidental:

| | CLI / daemon | HA component | why |
| --- | --- | --- | --- |
| response timeout | 10 s | 15 s | a proxy adds a Wi-Fi hop each way |
| connect attempts | 6 | 4 | see below |
| backoff base / max | 750 ms / 4 s | 2 s / 15 s | the dominant HA failure is an exhausted proxy connection slot, which frees on the proxy's own schedule — fewer, longer waits beat more, shorter ones |

Published as: `ttlock-core` and `ttlock` on crates.io, `ttlock` on PyPI (`import ttlock`), both via Trusted Publishing.
`crates/ttlock-py` is `publish = false`.

## 10. Testing, and what is not tested

**What is covered.**
Rust unit tests across the CLI and the core, plus a compile-checked doctest, and a Python suite that replays recorded frames through the sans-IO operations.
The Python tests build real response frames with `pycryptodome` and an independent CRC implementation, so they check the Rust against a second implementation rather than against itself.

**The conformance table** (`tests/conformance/state.json`) is driven from both languages and is what keeps the daemon and the Home Assistant component reporting the same thing; see §9.

**The NixOS module has two checks.**
`nix/checks/module-eval.nix` evaluates the module into two complete NixOS systems and asserts on the resulting unit — flags wired through, secrets by path only, no password on the command line, sandbox intact.
It is pure evaluation, so it runs on macOS and needs no KVM; it is what catches a renamed CLI flag.
`nix/checks/nixos-test.nix` boots a VM with a real mosquitto broker and drives the daemon end to end: authentication, retained discovery, a `LOCK` command over MQTT, the offline transition, and the sandbox as systemd actually applied it.
It has been run, and it earned its place immediately by catching the deaf-daemon bug described in section 7.

Running it needs Linux and KVM, so from macOS it goes through a Linux builder.
Pointing at the remote store has the fewest moving parts, since it bypasses the local daemon entirely:

```bash
nix build .#checks.aarch64-linux.nixos-module -L \
  --eval-store auto --store ssh-ng://linux-builder --no-link
```

`--builders` works too, but the machine spec has to advertise the `kvm` and `nixos-test` features that NixOS VM tests require — a bare `--builders 'host aarch64-linux'` declares none, and nix answers "Failed to find a machine for remote build".
Note also that the remote build hook runs as **root**, so root must be able to ssh to the builder unaided: any `ssh_config` under `/etc/ssh` must be root-owned, and the host key must be verifiable (passing it as the last spec field avoids touching root's `known_hosts`).
Every one of those failures surfaces as the same misleading "platform mismatch" against the local machine, printed once above a few hundred lines of "Cannot build" — read the head of the output, not the tail.

**The transport is tested without a radio, through a seam.**
The retry rules — re-send on a CRC failure, discard an unsolicited push *without* re-sending, and a deadline that spans a whole exchange rather than each read — are subtle, are implemented twice, and were untestable while `run_op` was welded to a concrete `BleConnection`.
The `Link` trait (`crates/ttlock/src/ble.rs`) is that seam and exists for this reason alone; `ScriptedLink` replays canned frames through it.
The Home Assistant side needed no such change, because `_async_drive` already takes a client: `FakeBleakClient` in `crates/ttlock-py/tests/test_coordinator_exchange.py` feeds replies back through the notify callback, and the coordinator is imported with stubbed Home Assistant modules so the code under test is the real code.
Both scripts are *bursts* of frames per write, since one command can be answered by several notifications.

The two suites use matching test names on purpose. When they drift — and they have, three times — a name present on one side and absent on the other is the cheapest possible signal.

These tests were mutation-checked when written: inverting the stray-frame branch and restarting the deadline each fail them on both sides.
That is worth repeating for anything added here, because a test that drives a fake is exactly the kind that can pass for the wrong reason.

**What is still not covered, and cannot be.**
Connecting, service discovery, notification delivery, and everything else that needs an actual radio.
CI has no radio and a VM has no adapter — the VM test deliberately asserts that a *missing* adapter is survivable rather than pretending to test BLE.
Advertisement parsing is tested against synthetic payloads only; the non-V3 path in particular is inferred (§2) and has never met hardware.
Anything about real radio behavior has been verified by hand, against one lock, by one person.
Be appropriately humble about changes to `ble.rs`.

## 11. Documentation conventions

Comments here explain *why*, and especially why an obvious-looking simplification is wrong.
Several of them exist to stop a future reader from "fixing" a deliberate quirk: the CRC index-33 deviation, the unfiltered scan, the seed-dependent credential mask, the separate CRC/decrypt steps.
If you remove one of those guards, you will probably be right that the code looks better and wrong that it still works.

Every public item in `ttlock-core` is documented; the crate sets `#![warn(missing_docs)]` and denies broken intra-doc links.
Markdown in this repository is written one sentence per line, per `AGENTS.md`.

## 12. Where to pick up

Reasonable next steps, roughly in order of value:

1. Read the operation log — advertisements already report when records are queued, and nothing consumes them.
2. Implement pairing/initialization, so a lock can be set up without the vendor app.
3. Characterize the non-V3 advertisement path against real hardware and move it out of "inferred".
   The parser now returns `Advertisement::Stateless` for those families rather than inventing a bolt position, so the open question is which of them genuinely carry status.
4. Passcode and card management commands.
5. Consider moving the retry loops themselves into the core. The tracker unified *what is reported*; connect-retry and CRC-retry policy is still written twice, once per transport, even though `policy::connect_backoff` is now shared.

Before any of that, run `nix flake check` and `./scripts/check-secrets.sh`.
The second one matters more than it looks: this repository's most likely bad day is a committed credential, not a failed build.
