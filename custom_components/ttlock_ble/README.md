# TTLock BLE — Home Assistant custom component

A local (`local_push`) Home Assistant integration for a paired TTLock
Bluetooth lock. It uses Home Assistant's own Bluetooth transport (no MQTT
broker, no extra daemon) and the [`ttlock`](../../crates/ttlock-py) Python bindings
over the sans-IO [`ttlock-core`](../../crates/ttlock-core) engine.

- **State + battery** are read passively from the lock's BLE advertisements, so
  they update without ever connecting.
- **Lock / unlock** connect on demand (via `bleak-retry-connector`) and run the
  `ttlock` operations.

## Requirements

- Home Assistant with a working Bluetooth integration (a local adapter or an
  ESPHome Bluetooth proxy in range of the lock).
- The `ttlock` Python package importable in Home Assistant's environment.
  On a pip-based install Home Assistant installs it from the `requirements`
  entry in `manifest.json`; on NixOS it is provided by the component package
  (below). Its version always matches the component's.

## Credentials

You need the lock's pairing credentials, the same ones the CLI reads from
`lockData.json`:

- **AES key** — 32 hex characters (16 bytes), e.g. `00112233445566778899aabbccddeeff`.
- **Unlock key** — the integer `unlock_key`.

Use the CLI's `import-credentials` to extract these from the Sciener/TTLock
app's database.

## Setup

1. Copy `custom_components/ttlock_ble` into your Home Assistant `config/custom_components/` directory (or install the Nix package below), and restart.
2. The lock should be discovered automatically once Home Assistant sees one of
   its advertisements. If it does not appear, add it from **Settings → Devices &
   Services → Add Integration → TTLock BLE**, which lists every TTLock-looking
   device currently in range.
3. Enter the AES key and unlock key when prompted.

A `lock` entity and a battery `sensor` appear under a `TTLock <address>` device.

Both are driven entirely by advertisements until you actuate: the lock reports
`Locking…`/`Unlocking…` while a command is in flight and only commits to
locked/unlocked once the lock itself acknowledges or an advertisement confirms
the bolt moved. If Home Assistant stops hearing the lock, both entities go
unavailable rather than continuing to show a stale state.

To correct a mistyped key later, use **Reconfigure** on the entry rather than
deleting and re-adding it.

## Options

**Settings → Devices & Services → TTLock BLE → Configure**:

- **Connection attempts per command** (default 4) — how many times to connect and
  run a command before giving up, with a growing delay between attempts. Raise
  this if commands fail on a weak signal, or if you see *"No backend with an
  available connection slot"*: a Bluetooth proxy that is out of slots frees one
  on its own schedule, so waiting and retrying is the fix.
- **Response timeout** (default 15s) — how long to wait for each response frame
  from the lock before treating the attempt as failed.

Both take effect on reload, which happens automatically when you save.

## Troubleshooting

Enable debug logging:

```yaml
logger:
  default: info
  logs:
    custom_components.ttlock_ble: debug
```

This logs every advertisement (RSSI, state, battery, protocol version), each
connection attempt and retry, and the raw response frames.

A response frame that fails its CRC check is re-sent up to twice before the
attempt is abandoned, matching the CLI. This is safe because the operation
verifies the CRC before advancing any of its own state, so a corrupted frame
leaves it waiting for the same response rather than desynchronized.

- **"command failed with response byte 0x00"** — the lock decrypted the command
  and rejected it. The usual causes are a wrong unlock key or a protocol version
  mismatch. The integration learns the protocol version from advertisements; if
  the debug log shows `version=None` when a command runs, it has not heard a
  usable advertisement yet and is falling back to a default the lock may not
  accept. Waiting for the lock to advertise before commanding it resolves that
  case.
- **"No backend with an available connection slot"** — no Bluetooth proxy or
  adapter in range has a free connection. Raise *Connection attempts per
  command*, or add another proxy nearer the lock.

## NixOS

The component is packaged with `buildHomeAssistantComponent` and its
`ttlock` dependency is built against Home Assistant's Python, so no pip
install happens. Add the flake's package to `customComponents`:

```nix
# flake input: ttlock-rs.url = "github:n8henrie/ttlock-rs";
services.home-assistant = {
  enable = true;
  extraComponents = [ "bluetooth" ];
  customComponents = [
    ttlock-rs.packages.${pkgs.system}.ttlock-ble-component
  ];
};
```

## Notes / limitations

- State is never optimistic: after a lock/unlock the state is updated only once
  the lock acknowledges the command, and is otherwise reconciled by
  advertisements.
- Only lock/unlock/state/battery are exposed — no passcode, IC-card,
  fingerprint, or management operations.
