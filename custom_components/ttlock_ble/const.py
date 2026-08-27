"""Constants for the TTLock BLE integration.

Protocol-level values are imported from `ttlock` rather than restated here.
They are properties of the locks, identical for every consumer, and keeping a
second copy is how this component and the Rust MQTT daemon drifted apart —
see `ttlock_core::policy`.

What remains below is either Home Assistant's own vocabulary or a transport
tunable that legitimately differs from the CLI's, because Home Assistant
usually reaches the lock through an ESPHome Bluetooth proxy rather than a local
adapter. `docs/protocol-and-design.md` tabulates those differences so they stay
deliberate.
"""

from __future__ import annotations

from ttlock import (
    CRC_RETRIES,
    CRC_RETRY_DELAY,
    MAX_STRAY_FRAMES,
    NOTIFY_CHARACTERISTIC,
    SERVICE_UUID,
    WRITE_CHARACTERISTIC,
    WRITE_CHUNK,
    WRITE_CHUNK_DELAY,
)

from homeassistant.const import Platform

__all__ = [
    "CRC_RETRIES",
    "CRC_RETRY_DELAY",
    "MAX_STRAY_FRAMES",
    "NOTIFY_CHARACTERISTIC",
    "SERVICE_UUID",
    "WRITE_CHARACTERISTIC",
    "WRITE_CHUNK",
    "WRITE_CHUNK_DELAY",
]

DOMAIN = "ttlock_ble"
PLATFORMS = [Platform.LOCK, Platform.SENSOR]

CONF_AES_KEY = "aes_key"
CONF_UNLOCK_KEY = "unlock_key"

# Tunables, exposed through the options flow.
CONF_CONNECT_ATTEMPTS = "connect_attempts"
CONF_COMMAND_TIMEOUT = "command_timeout"

# Seconds to wait for each response frame while running a command.
#
# Longer than the CLI's 10s: a Bluetooth proxy adds a Wi-Fi hop in each
# direction and is often relaying for several devices at once.
DEFAULT_COMMAND_TIMEOUT = 15
MIN_COMMAND_TIMEOUT = 5
MAX_COMMAND_TIMEOUT = 120

# How many times to connect-and-run a command before giving up.
#
# Fewer than the CLI's 6, and each wait is longer (see RETRY_BASE_DELAY): the
# dominant failure here is an exhausted proxy connection slot, which frees on
# the proxy's own schedule. Waiting is the fix; hammering is not.
DEFAULT_CONNECT_ATTEMPTS = 4
MIN_CONNECT_ATTEMPTS = 1
MAX_CONNECT_ATTEMPTS = 10

# Backoff between whole-command attempts: grows, then caps.
RETRY_BASE_DELAY = 2.0
RETRY_MAX_DELAY = 15.0
