# ttlock-rs

Local control of my TTLock BLE door lock, providing a command-line tool, an MQTT daemon, and a home-assistant custom component.

Caveat emptor: This project was almost entirely vibe-coded with Claude, (Opus 4.7, 4.8, 5, and Fable).
In spite of this, I generally do not care for LLM-generated or LLM-assisted contributions.
Please divulge LLM involvement in any communication or code, and note that issues, PR, or other contributions may (or may not) be closed on this basis alone, with or without additional feedback from me.

Further, please note that the TTLock apparently **CANNOT** report manual locks and unlocks (by hand or by key), therefore **reported lock state will often be incorrect.**
This is a huge disappointment for me, if you know of a solution here please reach out.

I've been tinkering on this project on-and-off since 2021, more seriously for the last year or so.
A few months ago a project with similar goals was released, and it likely deserves some attention from anyone that has ended up here first: <https://github.com/roquerodrigo/ha-ttlock-ble>
It is also LLM-assisted, features Home Assistant integration, and seems to be seeing frequent updates.

Finally a note on obtaining your credentials: my approach was to install the official TTLock app on my MacBook.
After signing in and ensuring that I could toggle the lock with the official app, I found the database at `~/Library/Group Containers/group.tongtongsuo.app/sciener.sqlite` and used this to find the required secrets.
This process has been mostly automated in the CLI tool's `import-credentials` command as detailed below.

LLM-generated content below.

--------------------------------------------------------------------------------

Local control of a paired TTLock Bluetooth lock — no vendor cloud, no internet.
A Home Assistant integration, an MQTT bridge, a CLI, and the sans-IO protocol library underneath them, in Rust with Python bindings.

> **`lockData.json` is a key to your door.**
> It holds the lock's AES key and admin passcode in plaintext, because the protocol needs them that way.
> Anyone who can read that file can open the lock.
> Keep it `chmod 600`, keep it out of the Nix store and out of git, and see [`SECURITY.md`](SECURITY.md) before deploying it anywhere shared.

> **A manual unlock is never reported. This integration can say `LOCKED` while your door stands open.**
> Measured over ~95 minutes and ~1400 advertisements: the lock detects the bolt *arriving* in the locked position and nothing else.
> Bluetooth commands appear in about 8 seconds. A manual lock appears eventually (4–10 minutes). A manual unlock — thumbturn or key, it makes no difference — never appears at all.
> The connected status query (`0x14`) is worse: on the tested lock it returns a constant regardless of bolt position.
> This is the firmware, not this project; the other open-source implementation behaves the same way.
> The lock's own operate log is no help either: walked to the present, it records every electronic operation and not one mechanical one.
> Both consumers therefore mark the entity as having an assumed state. Treat it as "last known", and do not build a security automation on it.
> See [§7a of the design notes](docs/protocol-and-design.md) for the measurements.

## Home Assistant custom component

`custom_components/ttlock_ble` is a native integration that needs no MQTT broker: it tracks state and battery passively from advertisements over Home Assistant's own Bluetooth stack, and connects on demand to lock/unlock.
It is built on the `ttlock` Python bindings.

See the [component README](custom_components/ttlock_ble/README.md) for setup, credentials, and the NixOS wiring.

## Install

Prebuilt CLI binaries for Linux (x86-64, aarch64) and macOS (Apple silicon) are attached to each [release](https://github.com/n8henrie/ttlock-rs/releases).
The Linux builds are dynamically linked against a recent glibc; on an older distro, build from source or use the Nix package.
Intel Macs are not built.

```bash
cargo install ttlock          # CLI, from crates.io
pip install ttlock            # Python bindings, from PyPI
```

## Getting credentials

The lock's credentials live in the Sciener/TTLock phone app's local database.
`import-credentials` reads it strictly read-only and converts the stored keys:

```bash
ttlock import-credentials --db sciener.sqlite > lockData.json
chmod 600 lockData.json
```

The database defaults to the app's Group Containers copy under `$HOME`; copy it out or pass `--db`.
`sample-lockData.json` shows the format if you would rather write it by hand.

## Commands

| Command | |
| --- | --- |
| `import-credentials` | Convert the Sciener app's sqlite database into `lockData.json`. |
| `scan` | Scan for TTLock-like devices and show advertisement-derived data. |
| `listen` | Connect and reassemble notification frames without sending commands. |
| `status` | Connect and query the lock state. |
| `logs` | Read the lock's operate log — its audit trail of who opened the door, when, and how. |
| `timings` | Timing breakdown: discovery, connect, and the encrypted round-trip. |
| `lock` / `unlock` | Actuate the lock. |
| `daemon` | Long-lived MQTT bridge (below). |

```bash
ttlock scan --seconds 10
ttlock status --file lockData.json
ttlock unlock --file lockData.json
ttlock logs --file lockData.json --format text | tail        # the most recent
ttlock logs --file lockData.json | jq -r '[.at, .operation] | @tsv'
```

`logs` reads the lock's operate log: who opened the door, when, and how.
It is an audit trail and not a state source — the lock records operations it performs and never bolt movement it observes, so a thumbturn or a key leaves no trace either way.
Reading is non-destructive and repeatable, so `--from` costs round trips and nothing else — but it is one round trip per record and the log can hold hundreds going back months, so a full read takes minutes.
Records stream as they arrive, so `--limit`, a pipe into `head`, or Ctrl-C all work.
A `keyboard password unlock` record contains the code that was typed, and the command prints it, warning and pausing five seconds first; `--no-warn` skips the pause.
Treat the output as a credential.

## MQTT daemon

`ttlock daemon` bridges one lock to any MQTT broker.
It publishes Home Assistant discovery for a lock entity and a battery sensor, but nothing about it is HA-specific — the state, command, and availability topics are plain MQTT and work with anything.

```bash
ttlock daemon --file lockData.json --mqtt-host 192.0.2.10
```

It holds one continuous passive BLE scan and reports state and battery from each advertisement as it arrives, interrupting the scan only to actuate on a `LOCK`/`UNLOCK` command.
Reported state is always backed by evidence: a command publishes only `LOCKING`/`UNLOCKING` until the lock acknowledges it or an advertisement confirms the bolt position.

Broker settings also come from `TTLOCK_MQTT_HOST`, `TTLOCK_MQTT_PORT`, `TTLOCK_MQTT_USERNAME`, and `TTLOCK_MQTT_PASSWORD`; prefer these over `--mqtt-password`, which is visible in `ps`.
`--discovery-prefix` and `--base-topic` move the topics, `--connect-attempts` helps on a weak link, and `-v`/`-vv`/`RUST_LOG` control logging.
`ttlock daemon --help` covers the rest, and [`docs/protocol-and-design.md`](docs/protocol-and-design.md) explains why the defaults are what they are.

## NixOS module

`module.nix` (exported as `nixosModules.default`) runs the MQTT daemon under systemd.
**Secrets are referenced by path and read at runtime — never put lock credentials or broker passwords in the Nix store, where they are world readable.**
Both options take a [sops-nix](https://github.com/Mic92/sops-nix) secret path directly:

```nix
{
  inputs.ttlock.url = "github:n8henrie/ttlock-rs";
  # ... ttlock.nixosModules.default in your modules list ...

  services.ttlock = {
    enable = true;
    lockDataFile = config.sops.secrets.ttlock-lockdata.path;
    mqtt = {
      host = "10.0.0.5";
      # An EnvironmentFile holding TTLOCK_MQTT_USERNAME / TTLOCK_MQTT_PASSWORD,
      # so the password never reaches the store or the process command line.
      credentialsFile = config.sops.secrets.ttlock-mqtt.path;
    };
    connectAttempts = 8; # raise on a weak link
  };
}
```

The service runs as root because BlueZ denies D-Bus access to unprivileged callers; the unit is otherwise heavily sandboxed.

Packages are `ttlock`, `ttlock-python`, and `ttlock-ble-component` (Linux only), exported as flake outputs, an overlay, and a plain `packages.nix` for non-flake users.
To run Home Assistant with the component:

```nix
services.home-assistant = {
  enable = true;
  extraComponents = [ "bluetooth" ];
  customComponents = [ ttlock.packages.${pkgs.system}.ttlock-ble-component ];
};
```

## Workspace layout

- `crates/ttlock-core` — the protocol, transport-agnostic (sans-IO): framing, AES-128-CBC, CRC, advertisement parsing, credential decoding, the `Operation` state machines, and the `LockTracker` that decides what to report about a lock. No `tokio`, no `btleplug`, so it backs the CLI, the Python bindings, and the HA component alike — all three report from the same tracker rather than each reimplementing the rules.
- `crates/ttlock` — the `ttlock` CLI and MQTT daemon, driving the core over `btleplug`. On crates.io as **`ttlock`**.
- `crates/ttlock-py` — pyo3/maturin bindings ([README](crates/ttlock-py/README.md)). On PyPI as **`ttlock`** (`import ttlock`).
- `custom_components/ttlock_ble` — the Home Assistant integration.

All of them share one version, `[workspace.package] version` in `Cargo.toml`; `./scripts/check-versions.sh` asserts the places that cannot derive it agree.

[`docs/protocol-and-design.md`](docs/protocol-and-design.md) documents the reverse-engineered protocol, which parts of it are confirmed versus inferred, and why the library is shaped the way it is.
Read it before changing anything protocol-level.

## Contributing

Bug reports and patches are welcome.

This project was built with heavy LLM assistance, and I am not going to pretend otherwise.
That does not oblige me to review LLM output from anyone else: I may close LLM-generated issues and pull requests for no reason other than being LLM-generated, at my sole discretion.
If you use a model, understand and vouch for what you are submitting.

## License

MIT. See [LICENSE](LICENSE).
