# ttlock

Command-line control for paired TTLock Bluetooth locks, plus a long-lived MQTT
bridge for Home Assistant.

```bash
cargo install ttlock

ttlock scan                                  # find nearby locks
ttlock status --file lockData.json           # query lock state
ttlock unlock --file lockData.json
ttlock logs --file lockData.json           # the lock's own audit trail, as JSON
ttlock daemon --file lockData.json --mqtt-host 192.0.2.10
```

`lockData.json` holds the lock's AES key and unlock key; `ttlock
import-credentials` can extract them from the Sciener/TTLock app's local
database.

BLE is handled by [`btleplug`](https://crates.io/crates/btleplug) (BlueZ on
Linux, CoreBluetooth on macOS). The protocol itself lives in
[`ttlock-core`](https://crates.io/crates/ttlock-core), which is transport
agnostic.

Full documentation: <https://github.com/n8henrie/ttlock-rs>

## License

MIT
