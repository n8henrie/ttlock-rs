"""Transport tests for the Home Assistant coordinator's exchange loop.

This is the half of the component that has never been exercised: `_async_drive`
and `_async_exchange` carry the retry rules — re-send on a CRC failure, discard
an unsolicited push *without* re-sending, and a deadline that covers the whole
exchange rather than each read — and there is no Bluetooth radio in the
development environment to test them against.

There does not need to be. `_async_drive` already takes a client, so a fake one
whose `write_gatt_char` feeds a canned reply back through the notify callback
exercises every branch with no change to the component at all. The frames are
real: correctly framed, AES-encrypted with the test key, and CRC'd, so this
tests the actual protocol path rather than a stand-in for it.

These deliberately mirror `ScriptedLink` in `crates/ttlock/src/ble.rs`. The two
implementations of this logic have drifted three times; matching test names on
both sides make a divergence visible.
"""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib
import sys
import types

import pytest
import ttlock
from test_smoke import AES_KEY, _response_frame

_REPO_ROOT = pathlib.Path(__file__).parents[3]
_COMPONENT_DIR = _REPO_ROOT / "custom_components" / "ttlock_ble"


def _stub_module(name: str, **attributes: object) -> types.ModuleType:
    module = types.ModuleType(name)
    for key, value in attributes.items():
        setattr(module, key, value)
    sys.modules[name] = module
    return module


class _StubHomeAssistantError(Exception):
    """Stands in for `homeassistant.exceptions.HomeAssistantError`."""


def _install_import_stubs() -> None:
    """Satisfy the imports the coordinator needs but this environment lacks.

    Home Assistant and bleak are not installed here (and bleak on darwin pulls a
    pyobjc package whose own tests abort), so the module cannot be imported
    directly. Only the *names* are stubbed — every line of coordinator logic
    under test is the real one.

    Nothing below is exercised by these tests; if the component starts depending
    on the behaviour of one of these rather than its existence, that belongs in
    a test against real Home Assistant, not here.
    """
    _stub_module("bleak", BleakClient=object)
    _stub_module("bleak.backends")
    _stub_module("bleak.backends.device", BLEDevice=object)
    _stub_module(
        "bleak_retry_connector",
        BLEAK_RETRY_EXCEPTIONS=(OSError,),
        BleakClientWithServiceCache=object,
        establish_connection=None,
    )

    bluetooth = _stub_module(
        "homeassistant.components.bluetooth",
        BluetoothCallbackMatcher=object,
        BluetoothChange=object,
        BluetoothScanningMode=types.SimpleNamespace(PASSIVE="passive"),
        BluetoothServiceInfoBleak=object,
        async_register_callback=None,
        async_track_unavailable=None,
        async_ble_device_from_address=None,
    )
    _stub_module("homeassistant")
    _stub_module("homeassistant.components", bluetooth=bluetooth)
    _stub_module(
        "homeassistant.core",
        CALLBACK_TYPE=object,
        HomeAssistant=object,
        callback=lambda func: func,
    )
    _stub_module("homeassistant.exceptions", HomeAssistantError=_StubHomeAssistantError)
    _stub_module(
        "homeassistant.const",
        Platform=types.SimpleNamespace(LOCK="lock", SENSOR="sensor"),
        CONF_ADDRESS="address",
    )


def _load_coordinator() -> types.ModuleType:
    """Import the real `coordinator.py` without running the package `__init__`.

    A synthetic parent package is registered so the module's relative
    `from .const import ...` resolves, but `__init__.py` — which pulls in far
    more of Home Assistant and none of what is under test — never executes.
    """
    _install_import_stubs()

    parent = types.ModuleType("custom_components")
    parent.__path__ = [str(_COMPONENT_DIR.parent)]
    sys.modules["custom_components"] = parent

    package = types.ModuleType("custom_components.ttlock_ble")
    package.__path__ = [str(_COMPONENT_DIR)]
    sys.modules["custom_components.ttlock_ble"] = package

    name = "custom_components.ttlock_ble.coordinator"
    spec = importlib.util.spec_from_file_location(
        name, _COMPONENT_DIR / "coordinator.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


coordinator = _load_coordinator()

LOCK_ADDRESS = "AA:BB:CC:DD:EE:FF"
STATUS_COMMAND = 0x14
UNLOCK_COMMAND = 0x47


def _wire_frame(command: int, plain: bytes) -> bytes:
    """A complete lock->app frame, terminator included, as a lock would send it."""
    return _response_frame(command, AES_KEY, plain) + b"\x0d\x0a"


def status_reply(state: int) -> bytes:
    """`[cmd_echo][status][battery][lock_state]` — 0 locked, 1 unlocked."""
    return _wire_frame(STATUS_COMMAND, bytes([STATUS_COMMAND, 0x01, 0x63, state]))


def unsolicited_push() -> bytes:
    """A real, well-formed frame that is simply not the reply being awaited."""
    return _wire_frame(UNLOCK_COMMAND, bytes([UNLOCK_COMMAND, 0x01, 0x00, 0x00]))


def rejection() -> bytes:
    """The lock decrypted the command and refused it."""
    return _wire_frame(STATUS_COMMAND, bytes([STATUS_COMMAND, 0x00, 0x00, 0x00]))


def corrupt_crc(frame: bytes) -> bytes:
    """Flip the CRC byte, which sits just before the terminator."""
    raw = bytearray(frame)
    raw[-3] ^= 0xFF
    return bytes(raw)


class FakeBleakClient:
    """A client that replays a script instead of talking to a radio.

    Records every frame written, so a test can assert not just the outcome but
    *how many times* something was sent — which is the entire difference between
    the CRC path (re-send) and the stray-frame path (do not).

    The script is a list of *bursts*, one per written frame, because that is how
    a real lock behaves: one command can be answered by several notifications —
    an unsolicited push and then the actual reply. A flat list would deadlock the
    moment the coordinator correctly declined to re-send.
    """

    def __init__(self, bursts: list[list[bytes]], delay: float = 0.0) -> None:
        self._bursts = [list(burst) for burst in bursts]
        # Seconds between frames within a burst. Zero for every test that is not
        # measuring the deadline, so none of them are racing the clock.
        self._delay = delay
        self._notify: object | None = None
        self._pending = ttlock.FrameAssembler()
        self._tasks: list[asyncio.Task] = []
        self.writes: list[bytes] = []

    def cancel_pending(self) -> None:
        """Drop any not-yet-delivered frames so the loop can close cleanly."""
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()

    async def start_notify(self, _char: str, callback) -> None:  # noqa: ANN001
        self._notify = callback

    async def stop_notify(self, _char: str) -> None:
        self._notify = None

    async def disconnect(self) -> None:
        self._notify = None

    async def write_gatt_char(
        self, _char: str, data: bytes, response: bool = True
    ) -> None:
        # Reassemble the chunks the coordinator writes, so a reply is emitted
        # once per *frame* rather than once per 20-byte GATT write.
        self._pending.push(bytes(data))
        frame = self._pending.next_frame()
        while frame is not None:
            self.writes.append(frame)
            if self._bursts and self._notify is not None:
                burst = self._bursts.pop(0)
                if self._delay:
                    self._tasks.append(asyncio.create_task(self._deliver(burst)))
                else:
                    for response in burst:
                        self._notify(None, bytearray(response))
            frame = self._pending.next_frame()

    async def _deliver(self, burst: list[bytes]) -> None:
        """Spread a burst out in time, so the caller's deadline actually erodes."""
        for response in burst:
            await asyncio.sleep(self._delay)
            if self._notify is not None:
                self._notify(None, bytearray(response))


def make_coordinator(command_timeout: float = 10):
    """A coordinator with just enough filled in to drive an exchange."""
    instance = coordinator.TTLockCoordinator.__new__(coordinator.TTLockCoordinator)
    instance.address = LOCK_ADDRESS
    instance._command_timeout = command_timeout
    instance.tracker = ttlock.LockTracker()
    return instance


def drive(bursts: list[list[bytes]], timeout: float = 10, delay: float = 0.0):
    """Run one status operation against a scripted client.

    Synchronous on purpose: `asyncio.run` keeps this suite free of a
    `pytest-asyncio` dependency, and each test drives exactly one exchange.
    """
    instance = make_coordinator(timeout)
    client = FakeBleakClient(bursts, delay=delay)

    async def go():
        try:
            return await instance._async_drive(client, ttlock.StatusOp(AES_KEY))
        finally:
            client.cancel_pending()

    return asyncio.run(go()), client


def test_a_clean_exchange_writes_once():
    result, client = drive([[status_reply(0)]])
    assert result == "LOCKED"
    assert len(client.writes) == 1


def test_a_crc_failure_re_sends_the_same_frame():
    result, client = drive([[corrupt_crc(status_reply(0))], [status_reply(0)]])
    assert result == "LOCKED"
    # Two identical writes: re-sending is the right answer to corruption, and it
    # is safe because the operation checks the CRC before advancing any state.
    assert len(client.writes) == 2
    assert client.writes[0] == client.writes[1]


def test_an_unsolicited_frame_is_skipped_without_re_sending():
    result, client = drive([[unsolicited_push(), status_reply(1)]])
    assert result == "UNLOCKED"
    # Exactly one write. Re-sending here would leave the lock answering a command
    # already asked, putting the exchange one frame behind for good.
    assert len(client.writes) == 1


def test_a_flood_of_unsolicited_frames_eventually_fails():
    # Bounded on purpose: an unlimited skip turns a genuine desynchronization
    # into a silent timeout, a worse diagnosis than an error naming the command
    # that did not match.
    flood = [unsolicited_push()] * (ttlock.MAX_STRAY_FRAMES + 2)
    with pytest.raises(_StubHomeAssistantError):
        drive([[*flood, status_reply(0)]])


def test_a_rejected_command_is_not_retried():
    # The lock decrypted the command and refused it; identical bytes are refused
    # identically, and retrying only drains its batteries.
    client = FakeBleakClient([[rejection()]])
    instance = make_coordinator()

    async def go():
        return await instance._async_drive(client, ttlock.StatusOp(AES_KEY))

    with pytest.raises(_StubHomeAssistantError):
        asyncio.run(go())
    assert len(client.writes) == 1


def test_a_silent_lock_raises_a_retryable_error_not_a_protocol_one():
    # A lock that never answers is a link problem, so it must surface as the
    # type the retry layer above catches — not as a protocol fault, which that
    # layer deliberately does not retry.
    with pytest.raises(coordinator._TransientError):
        drive([], timeout=0.05)


def test_skipping_a_push_does_not_extend_the_deadline():
    """The timeout covers the whole exchange, not each individual read.

    Timed so the two behaviours give opposite results rather than merely
    different numbers: the push lands at 0.2s of a 0.3s budget and the real
    reply at 0.4s. Carrying the deadline leaves 0.1s, so the reply is late and
    this raises. Restarting it would hand the second read a fresh 0.3s, and the
    reply would arrive comfortably inside it — which is exactly how a chatty
    lock could postpone failure indefinitely.
    """
    with pytest.raises(coordinator._TransientError):
        drive([[unsolicited_push(), status_reply(0)]], timeout=0.3, delay=0.2)
