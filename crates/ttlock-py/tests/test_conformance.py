"""Drives the shared conformance table and checks the Home Assistant rendering.

The Rust half lives in `crates/ttlock/tests/conformance.rs` and reads the same
file, checking what the MQTT daemon would publish. Between them they pin the two
rendering layers — the only place the daemon and the custom component can still
disagree, now that the state machine itself is shared.

The property expressions below are copied from
`custom_components/ttlock_ble/lock.py` and `sensor.py`. If those change shape,
change these with them; that coupling is the point of this test.
"""

import json
import pathlib

import pytest
import ttlock

FIXTURE_PATH = (
    pathlib.Path(__file__).parents[3] / "tests" / "conformance" / "state.json"
)
FIXTURE = json.loads(FIXTURE_PATH.read_text())

# 0x0305 little-endian is protocol_type 5, protocol_version 3 — the V3 header.
V3_COMPANY_ID = 0x0305


def _advertisement(spec):
    """Build a parsed advertisement matching a fixture spec.

    Deliberately goes through real manufacturer bytes rather than constructing
    the parsed form, so the fixture stays honest about what a lock can actually
    emit. An empty spec is an advertisement too short to carry any fields, which
    is why "no bolt position" and "locked" are distinguishable at all.
    """
    if not spec:
        return ttlock.parse_advertisement(V3_COMPANY_ID, b"\x00" * 4)

    params = 0x01 if spec.get("is_unlock") else 0x00
    payload = bytes(
        [
            0x02,
            params,
            spec.get("battery", 0),
            0,
            0,
            0,
            0,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
        ]
    )
    return ttlock.parse_advertisement(V3_COMPANY_ID, payload)


def replay(events, offline_after_ms):
    """Replay one scenario's events against a tracker."""
    tracker = ttlock.LockTracker()
    now_ms = 1000

    for event in events:
        key = next(iter(event))
        value = event[key]

        if key == "advertisement":
            tracker.on_advertisement(now_ms, _advertisement(value))
        elif key == "command_started":
            tracker.on_command_started(value)
        elif key == "command_acknowledged":
            tracker.on_command_acknowledged(now_ms, value)
        elif key == "command_failed":
            tracker.on_command_failed()
        elif key == "unavailable":
            tracker.on_unavailable()
        elif key == "elapsed_ms":
            now_ms += value
            tracker.poll_availability(now_ms, offline_after_ms)
        else:
            raise AssertionError(f"unknown event {key!r} in fixture")

    return tracker


@pytest.mark.parametrize("scenario", FIXTURE["scenarios"], ids=lambda s: s["name"])
def test_home_assistant_rendering(scenario):
    tracker = replay(scenario["events"], FIXTURE["offline_after_ms"])
    expect = scenario["expect"]

    # Exactly the expressions the lock entity uses.
    assert tracker.available is expect["available"]
    assert tracker.is_locked is expect["is_locked"]
    assert (tracker.pending == "lock") is expect["is_locking"]
    assert (tracker.pending == "unlock") is expect["is_unlocking"]

    # And the state the daemon publishes, so the two halves stay in step.
    assert tracker.reported_state == expect["reported_state"]

    if expect.get("battery") is not None:
        assert tracker.battery == expect["battery"]


def test_fixture_actually_loaded():
    """A fixture that failed to load would make every test above vacuous."""
    assert FIXTURE_PATH.is_file()
    assert len(FIXTURE["scenarios"]) >= 10
