# ttlock-py

Python bindings for the sans-IO [`ttlock-core`](../ttlock-core) protocol
engine, built with [maturin](https://www.maturin.rs) and [PyO3](https://pyo3.rs)
(abi3, Python ≥ 3.12).

The bindings expose the protocol as pure computation — no Bluetooth. A Home
Assistant custom component drives the protocol over Home Assistant's own
Bluetooth transport (bleak): it writes the frames each operation yields and
feeds notification bytes back in.

## Build & test

From within the workspace `nix develop` shell:

```bash
cd crates/ttlock-py
python3 -m venv --system-site-packages .venv && source .venv/bin/activate
maturin develop
python3 -m pytest        # run via `python3 -m` so the venv interpreter is used
```

## API

- `FrameAssembler` — `push(bytes)` notification chunks, `next_frame() -> bytes | None`.
- `StatusOp(aes_key, version=None)` — `start()` / `handle_frame(bytes)` return
  `("write", bytes)` steps, ending in `("done", "LOCKED" | "UNLOCKED" | "UNKNOWN:<n>")`.
- `LockOp(aes_key, unlock_key, version=None)` / `UnlockOp(...)` — same step
  protocol, ending in `("done", None)`.
- `parse_advertisement(manufacturer_id, data) -> Advertisement` with
  `.address`, `.battery`, `.is_unlocked`, `.lock_version`, etc. — for HA passive
  Bluetooth coordinators.
- `decode_credential(str) -> int`.
- `LockVersion(...)` / `LockVersion.default_version()`.
- `LockTracker()` — what to report about a lock, from evidence. See below.
- Protocol constants shared with the Rust side: `SERVICE_UUID`,
  `WRITE_CHARACTERISTIC`, `NOTIFY_CHARACTERISTIC`, `WRITE_CHUNK`,
  `CRC_RETRIES`, `CRC_RETRY_DELAY`, and `connect_backoff(attempt) -> float`.
  Import these rather than restating them; that is the point of them being here.
- Errors raise `TtlockError`, with `CrcMismatch` (a subclass) for the one
  protocol error worth retrying.

## Tracking a lock

`LockTracker` is the state machine above the operations: it holds bolt position,
battery, availability, protocol version, and whether a command is in flight, and
it is the same code the Rust MQTT daemon reports from. Using it is how a
component stays in step with the daemon instead of re-deriving the rules.

It reads no clock — pass monotonic milliseconds in.

```python
tracker = ttlock.LockTracker()
now = lambda: int(time.monotonic() * 1000)

# Passive, from an advertisement callback.
tracker.on_advertisement(now(), ttlock.parse_advertisement(company_id, mfr_data))

# A command: report progress, but never assume the outcome.
tracker.on_command_started("lock")          # -> reported_state == "LOCKING"
try:
    await run_op(client, ttlock.LockOp(aes_key, unlock_key, tracker.lock_version))
except Exception:
    tracker.on_command_failed()             # stays LOCKING: outcome unknown
    raise
tracker.on_command_acknowledged(now(), "lock")   # -> "LOCKED"

tracker.on_unavailable()      # nothing heard; also clears any pending command
```

Read it back with `.reported_state` (`"LOCKED"`, `"UNLOCKED"`, `"LOCKING"`,
`"UNLOCKING"`, or `None`), `.is_locked` (last *observed* bolt position, which
does not move while a command is in flight), `.pending` (`"lock"`, `"unlock"` or
`None`), `.available`, `.battery`, and `.lock_version`. Every mutating method
returns the set of names that changed, so a caller can publish only what moved.

## Wiring sketch (Home Assistant component)

```python
import ttlock

async def run_op(client, op):
    """Drive a sans-IO op over a bleak client with a notify characteristic."""
    assembler = ttlock.FrameAssembler()
    queue = asyncio.Queue()

    def on_notify(_char, data: bytearray):
        assembler.push(bytes(data))
        while (frame := assembler.next_frame()) is not None:
            queue.put_nowait(frame)

    await client.start_notify(NOTIFY_UUID, on_notify)
    kind, payload = op.start()
    while kind == "write":
        for chunk in (payload[i:i + 20] for i in range(0, len(payload), 20)):
            await client.write_gatt_char(WRITE_UUID, chunk, response=False)
        frame = await asyncio.wait_for(queue.get(), timeout=10)
        kind, payload = op.handle_frame(frame)
    return payload  # the ("done", result) value

state = await run_op(client, ttlock.StatusOp(aes_key))
await run_op(client, ttlock.UnlockOp(aes_key, unlock_key))
```

Note `tracker.lock_version` in the sketch above: the lock validates the protocol
version header and rejects a mismatch outright, which surfaces as a command
failure rather than anything connection-shaped. Let the tracker learn it from
advertisements rather than guessing.
