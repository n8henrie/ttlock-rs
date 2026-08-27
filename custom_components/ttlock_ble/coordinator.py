"""Bluetooth coordinator for a single TTLock lock.

State and battery are tracked passively from advertisements (no connection);
lock/unlock connect on demand and drive the sans-IO ``ttlock`` operations
over Home Assistant's Bluetooth transport.

What the lock is believed to be doing lives in a ``ttlock.LockTracker`` — the
same state machine the Rust MQTT daemon reports from. This module decides only
*how* to move bytes and *when* to tell the tracker something; it holds no
opinion about what any of it means. That split is deliberate: when the rules
lived here as well, the two implementations drifted apart three separate times.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import pathlib
import time
from collections.abc import Callable
from typing import Any, Protocol

import ttlock
from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak_retry_connector import (
    BLEAK_RETRY_EXCEPTIONS,
    BleakClientWithServiceCache,
    establish_connection,
)

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import (
    BluetoothCallbackMatcher,
    BluetoothChange,
    BluetoothScanningMode,
    BluetoothServiceInfoBleak,
)
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError

from .const import (
    CRC_RETRIES,
    CRC_RETRY_DELAY,
    DEFAULT_COMMAND_TIMEOUT,
    DEFAULT_CONNECT_ATTEMPTS,
    MAX_STRAY_FRAMES,
    NOTIFY_CHARACTERISTIC,
    RETRY_BASE_DELAY,
    RETRY_MAX_DELAY,
    WRITE_CHARACTERISTIC,
    WRITE_CHUNK,
    WRITE_CHUNK_DELAY,
)

_LOGGER = logging.getLogger(__name__)

# Where this integration's own code lives, for telling our bugs apart from the
# link's failures — see `_raised_in_this_integration`.
_PACKAGE_DIR = str(pathlib.Path(__file__).parent)


class Operation(Protocol):
    """The sans-IO operation interface `ttlock` exposes.

    Spelled out rather than typed as `object` so a type checker can see through
    the driving code. `StatusOp`, `LockOp` and `UnlockOp` all satisfy it.
    """

    def start(self) -> tuple[str, Any]:
        """Produce the first `("write", frame)` step."""

    def handle_frame(self, frame: bytes) -> tuple[str, Any]:
        """Feed one reassembled response frame."""


def _raised_in_this_integration(err: BaseException) -> bool:
    """Whether `err` was raised by our own code rather than by the BLE stack.

    `bleak-retry-connector` lists `AttributeError` as retryable because bleak
    itself can raise one when a device disconnects mid-call. But an
    `AttributeError` from *this* package is a plain bug, and retrying it burns
    four Bluetooth connections before reporting a programming error in the
    language of a flaky link — which is exactly how a stale `self._lock_version`
    reference once masked the real protocol error underneath it.
    """
    innermost: str | None = None
    tb = err.__traceback__
    while tb is not None:
        innermost = tb.tb_frame.f_code.co_filename
        tb = tb.tb_next
    return innermost is not None and innermost.startswith(_PACKAGE_DIR)


class _TransientError(Exception):
    """A failure worth another attempt.

    Covers the two things that go wrong on a busy or distant link: the lock is
    momentarily unreachable (no proxy in range, or none with a free connection
    slot), and a response that never arrives. Both clear on their own.
    """


# Protocol errors are deliberately absent: a lock that decrypted a command and
# rejected it will reject the identical bytes again. `ttlock.CrcMismatch` is the
# exception and is handled a level down, in `_async_exchange`, because a re-send
# there resumes the exchange rather than restarting the whole command.
_RETRYABLE_ERRORS = (*BLEAK_RETRY_EXCEPTIONS, _TransientError)


class TTLockCoordinator:
    """Owns the passive advertisement subscription and connected commands."""

    def __init__(
        self,
        hass: HomeAssistant,
        address: str,
        aes_key: bytes,
        unlock_key: int,
        connect_attempts: int = DEFAULT_CONNECT_ATTEMPTS,
        command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
    ) -> None:
        self.hass = hass
        self.address = address
        self._aes_key = aes_key
        self._unlock_key = unlock_key
        self._connect_attempts = max(1, connect_attempts)
        self._command_timeout = command_timeout
        # Everything believed about the lock, including the protocol version to
        # build commands with. Shared with the Rust daemon via ttlock-core.
        self.tracker = ttlock.LockTracker()
        self._listeners: list[CALLBACK_TYPE] = []
        # Serialize BLE connections so overlapping commands don't collide.
        self._connect_lock = asyncio.Lock()

    @staticmethod
    def _now_ms() -> int:
        """Monotonic milliseconds for the tracker, which reads no clock itself."""
        return int(time.monotonic() * 1000)

    def _credit_blind_time(self, started: float) -> None:
        """Discount time spent connecting from the offline timeout.

        No advertisement *could* have arrived while the radio was busy, so
        counting that silence against the lock would flip it to unavailable and
        straight back on every command. Mirrors the daemon's `credit_blind_time`.
        """
        self.tracker.credit_blind_time(int((time.monotonic() - started) * 1000))

    @callback
    def async_start(self) -> CALLBACK_TYPE:
        """Subscribe to the lock's advertisements. Returns an unsubscribe callback.

        Both halves matter. Advertisements are the only evidence this integration
        ever has about the bolt, and their *absence* is what makes the entity
        unavailable — without that, a lock that went flat or out of range would
        keep reporting its last known state forever.
        """
        unsubscribes = [
            bluetooth.async_register_callback(
                self.hass,
                self._async_on_advertisement,
                BluetoothCallbackMatcher(address=self.address, connectable=False),
                BluetoothScanningMode.PASSIVE,
            ),
            bluetooth.async_track_unavailable(
                self.hass,
                self._async_on_unavailable,
                self.address,
                connectable=False,
            ),
        ]

        @callback
        def unsubscribe() -> None:
            for unsub in unsubscribes:
                unsub()

        return unsubscribe

    @callback
    def async_add_listener(self, update_callback: CALLBACK_TYPE) -> CALLBACK_TYPE:
        """Register an entity update callback. Returns a remove callback."""
        self._listeners.append(update_callback)

        @callback
        def remove() -> None:
            self._listeners.remove(update_callback)

        return remove

    @callback
    def _async_update_listeners(self) -> None:
        for update_callback in list(self._listeners):
            update_callback()

    @callback
    def _async_on_advertisement(
        self,
        service_info: BluetoothServiceInfoBleak,
        change: BluetoothChange,
    ) -> None:
        # One decision per advertisement, made by the library. Feeding every
        # entry through the tracker in turn let a stale entry overwrite a live
        # one, and which won depended on dict ordering: the same bug that froze
        # the daemon's reported state, in the same shape, on this side.
        advertisement = ttlock.select_advertisement(
            dict(service_info.manufacturer_data), self.address
        )
        changed = self.tracker.on_advertisement(self._now_ms(), advertisement)
        _LOGGER.debug(
            "%s: advertisement rssi=%s kind=%s entries=%d state=%s battery=%s "
            "version=%s changed=%s",
            self.address,
            service_info.rssi,
            advertisement.kind,
            len(service_info.manufacturer_data),
            self.tracker.reported_state,
            self.tracker.battery,
            self.tracker.lock_version,
            sorted(changed) or "nothing",
        )
        self._async_update_listeners()

    @callback
    def _async_on_unavailable(self, _service_info: BluetoothServiceInfoBleak) -> None:
        """Home Assistant has stopped hearing the lock."""
        _LOGGER.debug("%s: no advertisements; marking unavailable", self.address)
        self.tracker.on_unavailable()
        self._async_update_listeners()

    def _op_version(self) -> ttlock.LockVersion | None:
        """Protocol version to build outgoing packets with.

        ``None`` makes ``ttlock`` fall back to its built-in V3 default, which is
        a guess. The lock validates the version header, so a wrong guess is
        rejected outright — that surfaces as ``command failed with response byte
        0x00`` rather than as anything connection-shaped. Reading it from the
        tracker rather than tracking it here is what keeps this component and
        the CLI from disagreeing, which is exactly how this bug shipped once.
        """
        version = self.tracker.lock_version
        if version is None:
            _LOGGER.debug(
                "%s: no lock version learned from advertisements yet; "
                "falling back to the default, which the lock may reject",
                self.address,
            )
        return version

    async def async_lock(self) -> None:
        """Lock the lock, committing to LOCKED only once the lock acknowledges."""
        await self._async_actuate("lock")

    async def async_unlock(self) -> None:
        """Unlock the lock, committing to UNLOCKED only once it acknowledges."""
        await self._async_actuate("unlock")

    async def _async_actuate(self, action: str) -> None:
        """Run an actuation, reporting progress but never assuming the outcome.

        The tracker owns what each step means; this only reports what happened.
        Note the ordering: the in-progress state is published *before* the
        operation, because a connect-and-actuate over a weak link takes many
        seconds and Home Assistant has nothing to show in the meantime.
        """
        op_type = ttlock.LockOp if action == "lock" else ttlock.UnlockOp

        self.tracker.on_command_started(action)
        self._async_update_listeners()

        started = time.monotonic()
        try:
            await self._async_run_op(
                lambda: op_type(self._aes_key, self._unlock_key, self._op_version()),
                action,
            )
        except Exception:
            # Deliberately not reverting: a timeout or a mid-exchange disconnect
            # means "outcome unknown", not "nothing happened".
            self._credit_blind_time(started)
            self.tracker.on_command_failed()
            self._async_update_listeners()
            raise

        self._credit_blind_time(started)
        self.tracker.on_command_acknowledged(self._now_ms(), action)
        self._async_update_listeners()

    async def async_refresh_status(self) -> None:
        """Connect and query the current lock state."""
        result = await self._async_run_op(
            lambda: ttlock.StatusOp(self._aes_key, self._op_version()),
            "status",
        )
        # A status reply is evidence of the bolt position in the same way an
        # acknowledgement is, so record it as one.
        if result in ("LOCKED", "UNLOCKED"):
            action = "lock" if result == "LOCKED" else "unlock"
            self.tracker.on_command_acknowledged(self._now_ms(), action)
        self._async_update_listeners()

    async def _async_run_op(
        self, op_factory: Callable[[], Operation], description: str
    ) -> Any:
        """Connect and drive an operation, retrying transient BLE failures.

        ``op_factory`` builds the operation rather than receiving one, because the
        operations are single-use state machines: a retry needs a fresh one, and
        reusing a half-driven op would fail on an unexpected frame instead of
        starting over.
        """
        async with self._connect_lock:
            last_error: Exception | None = None
            for attempt in range(1, self._connect_attempts + 1):
                try:
                    _LOGGER.debug(
                        "%s: %s attempt %s/%s",
                        self.address,
                        description,
                        attempt,
                        self._connect_attempts,
                    )
                    return await self._async_connect_and_drive(op_factory())
                except _RETRYABLE_ERRORS as err:
                    if isinstance(err, AttributeError) and _raised_in_this_integration(
                        err
                    ):
                        raise
                    last_error = err
                    if attempt == self._connect_attempts:
                        break
                    delay = min(RETRY_BASE_DELAY * 2 ** (attempt - 1), RETRY_MAX_DELAY)
                    _LOGGER.debug(
                        "%s: %s attempt %s/%s failed (%s); retrying in %.1fs",
                        self.address,
                        description,
                        attempt,
                        self._connect_attempts,
                        err,
                        delay,
                    )
                    # A busy Bluetooth proxy frees its connection slot on its own
                    # schedule, so waiting is the fix; hammering it is not.
                    await asyncio.sleep(delay)

            _LOGGER.debug(
                "%s: %s failed after %s attempt(s)",
                self.address,
                description,
                self._connect_attempts,
            )
            raise HomeAssistantError(
                f"TTLock {self.address}: {description} failed after "
                f"{self._connect_attempts} attempt(s): "
                f"{type(last_error).__name__}: {last_error}"
            ) from last_error

    async def _async_connect_and_drive(self, op: Operation) -> Any:
        """One connect-and-run attempt."""

        # Resolved once up front so the callback below always has something to
        # fall back on: `establish_connection` requires a callback that returns a
        # device, not an optional one, and handing it `None` mid-retry is not
        # something it is documented to survive.
        initial = bluetooth.async_ble_device_from_address(
            self.hass, self.address, connectable=True
        )
        if initial is None:
            raise _TransientError(f"TTLock {self.address} is not in range to connect")

        def _ble_device() -> BLEDevice:
            # Re-resolved on every bleak-retry-connector attempt: which proxy can
            # reach the lock changes as they come in and out of range, and a stale
            # BLEDevice pins us to one that may be out of connection slots. If the
            # lookup comes up empty this instant, the device we started with is a
            # better answer than nothing.
            return (
                bluetooth.async_ble_device_from_address(
                    self.hass, self.address, connectable=True
                )
                or initial
            )

        client = await establish_connection(
            BleakClientWithServiceCache,
            initial,
            self.address,
            ble_device_callback=_ble_device,
            use_services_cache=True,
        )
        _LOGGER.debug("%s: connected", self.address)

        try:
            return await self._async_drive(client, op)
        finally:
            with contextlib.suppress(Exception):
                await client.stop_notify(NOTIFY_CHARACTERISTIC)
            with contextlib.suppress(Exception):
                await client.disconnect()
            _LOGGER.debug("%s: disconnected", self.address)

    async def _async_drive(self, client: BleakClient, op: Operation) -> Any:
        """Run one operation's write/response steps over an open client."""
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        assembler = ttlock.FrameAssembler()

        def on_notify(_char: Any, data: bytearray) -> None:
            assembler.push(bytes(data))
            frame = assembler.next_frame()
            while frame is not None:
                queue.put_nowait(frame)
                frame = assembler.next_frame()

        await client.start_notify(NOTIFY_CHARACTERISTIC, on_notify)

        try:
            kind, payload = op.start()
            while kind == "write":
                kind, payload = await self._async_exchange(client, queue, op, payload)
            return payload
        except ttlock.TtlockError as err:
            # The core error already names what a rejection implicates, and does
            # so per command byte — do not second-guess it here by listing every
            # credential, which is what this message used to do and what sent a
            # rejected actuation off chasing the protocol version.
            version = self.tracker.lock_version
            raise HomeAssistantError(
                f"TTLock {self.address}: {err} "
                f"(protocol version {version or 'default, none learned yet'})"
            ) from err

    async def _async_exchange(
        self,
        client: BleakClient,
        queue: asyncio.Queue[bytes],
        op: Operation,
        payload: bytes,
    ) -> tuple[str, Any]:
        """Write one frame and hand its response to the operation.

        Two frames are recoverable here, and they want opposite responses:

        * A response that fails its CRC check gets the frame re-sent, up to
          ``CRC_RETRIES`` times.
        * An *unsolicited* frame — the lock pushes notifications on the same
          characteristic it replies on — is discarded and the next one awaited,
          with nothing re-sent, up to ``MAX_STRAY_FRAMES`` times.

        Both are safe for the same reason: the operation validates the frame
        before touching any of its own state, so a rejected one leaves it still
        waiting for the same response. Mirrors ``run_op`` in the CLI, including
        the detail that the timeout covers the whole wait rather than each read
        — otherwise a chatty lock buys itself an unbounded extension.
        """
        loop = asyncio.get_running_loop()
        for crc_attempt in range(CRC_RETRIES + 1):
            _LOGGER.debug("%s: sending %s bytes", self.address, len(payload))
            for start in range(0, len(payload), WRITE_CHUNK):
                await client.write_gatt_char(
                    WRITE_CHARACTERISTIC,
                    payload[start : start + WRITE_CHUNK],
                    response=False,
                )
                # Pace the chunks, as the CLI does. These are writes *without*
                # response, so nothing upstream applies back-pressure: a slower
                # controller (or a proxy relaying over Wi-Fi) can drop one, and a
                # frame that arrives truncated is refused by the lock rather than
                # retried. Cheap insurance at two or three chunks per frame.
                await asyncio.sleep(WRITE_CHUNK_DELAY)

            deadline = loop.time() + self._command_timeout
            stray_frames = 0
            resend = False

            while not resend:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise _TransientError(
                        f"timed out after {self._command_timeout}s waiting for a "
                        f"response from TTLock {self.address}"
                    )
                try:
                    async with asyncio.timeout(remaining):
                        frame = await queue.get()
                except TimeoutError as err:
                    raise _TransientError(
                        f"timed out after {self._command_timeout}s waiting for a "
                        f"response from TTLock {self.address}"
                    ) from err

                _LOGGER.debug("%s: received frame %s", self.address, frame.hex())
                try:
                    return op.handle_frame(frame)
                except ttlock.UnexpectedCommand:
                    # Not our reply. Keep reading on the same deadline, and do
                    # not re-send: consuming a push as the response would report
                    # a state the lock never sent and leave the real reply
                    # queued, putting every later exchange one frame behind.
                    if stray_frames >= MAX_STRAY_FRAMES:
                        raise
                    stray_frames += 1
                    _LOGGER.debug(
                        "%s: discarding an unsolicited frame (%s/%s)",
                        self.address,
                        stray_frames,
                        MAX_STRAY_FRAMES,
                    )
                except ttlock.CrcMismatch:
                    if crc_attempt == CRC_RETRIES:
                        raise
                    _LOGGER.debug(
                        "%s: response failed its CRC check; re-sending (%s/%s)",
                        self.address,
                        crc_attempt + 1,
                        CRC_RETRIES,
                    )
                    await asyncio.sleep(CRC_RETRY_DELAY)
                    resend = True

        # Unreachable: the loop either returns or raises on its last iteration.
        raise AssertionError("CRC retry loop exited without a result")
