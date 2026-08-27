# ttlock-core

Transport-agnostic (sans-IO) implementation of the TTLock Bluetooth protocol:
packet framing and reassembly, AES-128-CBC encryption, CRC-8/MAXIM,
advertisement parsing, credential decoding, the `Operation` state machines for
status/lock/unlock, and the `LockTracker` above them.

It performs no I/O and pulls in no async runtime or Bluetooth stack. You drive
it: each `Operation` yields `Step::Write(frame)` for you to send, and you feed
responses back via `handle_frame`. That is what lets the same engine back a
`btleplug` CLI, Python bindings, and a Home Assistant component using its own
Bluetooth transport.

```rust
use ttlock_core::ops::{Operation, StatusOp, Step};
use ttlock_core::packet::LockVersion;

let mut op = StatusOp::new(aes_key, LockVersion::default());
let mut step = op.start()?;
loop {
    match step {
        Step::Write(frame) => {
            transport.write(&frame)?;
            step = op.handle_frame(&transport.read()?)?;
        }
        Step::Done(state) => break state,
    }
};
# Ok::<(), ttlock_core::error::TtlockError>(())
```

`Operation` covers a single exchange; `tracker::LockTracker` holds what is
believed about a lock *between* exchanges — bolt position, battery,
availability, and whether a command is in flight — from advertisements and
command outcomes. It reads no clock either (callers pass monotonic
milliseconds), which is what lets an async daemon and a Home Assistant
coordinator report identically instead of each re-deriving the rules.

The `ttlock` crate is the CLI built on this.

Full documentation: <https://github.com/n8henrie/ttlock-rs>

## License

MIT
