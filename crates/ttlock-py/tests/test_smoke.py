"""End-to-end smoke tests for the ttlock bindings.

Run with `maturin develop` then `pytest`. These replay recorded frames
through the sans-IO operations rather than touching Bluetooth.
"""

import ttlock

# 16-byte test AES key matching the Rust unit tests.
AES_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def _crc8(data: bytes) -> int:
    # Mirrors ttlock_core::crc::crc8 (poly 0x31, refin/refout, init 0, xorout 0)
    # so the tests can build valid lock->app response frames.
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x01:
                crc = (crc >> 1) ^ 0x8C
            else:
                crc >>= 1
    return crc & 0xFF


def _response_frame(command: int, aes_key: bytes, plain: bytes) -> bytes:
    """Build a CRLF-stripped lock->app response frame carrying ``plain``."""
    from Crypto.Cipher import AES  # type: ignore

    cipher = AES.new(aes_key, AES.MODE_CBC, aes_key)
    padded = _pkcs7(plain)
    encrypted = cipher.encrypt(padded)
    body = (
        bytes(
            [
                0x7F,
                0x5A,
                0x05,
                0x03,
                0x02,
                0x00,
                0x01,
                0x00,
                0x01,
                command,
                0xAA,
                len(encrypted),
            ]
        )
        + encrypted
    )
    return body + bytes([_crc8(body)])


def _pkcs7(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def test_decode_credential():
    assert (
        ttlock.decode_credential("NjgsNjYsNjUsNzcsNjUsNzAsNjUsNjgsNjQsNjYsMTA=")
        == 659_525_046
    )


def test_frame_assembler_reassembles_split_frame():
    frame = _response_frame(0x14, AES_KEY, bytes([0x14, 0x01, 0x63, 0x00]))
    wire = frame + b"\x0d\x0a"
    asm = ttlock.FrameAssembler()
    asm.push(wire[:5])
    assert asm.next_frame() is None
    asm.push(wire[5:])
    assert asm.next_frame() == frame
    assert asm.next_frame() is None


def test_status_op_reports_locked():
    op = ttlock.StatusOp(AES_KEY)
    kind, payload = op.start()
    assert kind == "write"
    assert isinstance(payload, bytes) and payload[:2] == b"\x7f\x5a"

    response = _response_frame(0x14, AES_KEY, bytes([0x14, 0x01, 0x63, 0x00]))
    kind, state = op.handle_frame(response)
    assert kind == "done"
    assert state == "LOCKED"


def test_lock_op_runs_two_step_handshake():
    ps = 98_765
    unlock_key = 43_210
    op = ttlock.LockOp(AES_KEY, unlock_key)

    kind, first = op.start()
    assert kind == "write"

    cut = _response_frame(0x55, AES_KEY, bytes([0x55, 0x01]) + ps.to_bytes(4, "big"))
    kind, second = op.handle_frame(cut)
    assert kind == "write"

    done = _response_frame(0x58, AES_KEY, bytes([0x58, 0x01]))
    kind, result = op.handle_frame(done)
    assert kind == "done"
    assert result is None


def test_unlock_op_completes():
    ps = 1
    op = ttlock.UnlockOp(AES_KEY, 2)
    op.start()
    cut = _response_frame(0x55, AES_KEY, bytes([0x55, 0x01]) + ps.to_bytes(4, "big"))
    op.handle_frame(cut)
    done = _response_frame(0x47, AES_KEY, bytes([0x47, 0x01]))
    kind, result = op.handle_frame(done)
    assert kind == "done"
    assert result is None


def test_parse_advertisement_extracts_state_and_battery():
    # The binding prepends the little-endian company id, so the full buffer is
    # [0x05, 0x03] + data = protocol_type=5, protocol_version=3, scene=2,
    # params(is_unlock)=1, battery=0x63, then filler ending in a 6-byte MAC.
    # parse_manufacturer_data requires the full buffer to be >= 15 bytes.
    data = bytes([0x02, 0x01, 0x63, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    adv = ttlock.parse_advertisement(0x0305, data)
    assert adv.is_unlocked is True
    assert adv.battery == 0x63
    assert adv.lock_version is not None
    assert adv.lock_version.scene == 2


def test_error_is_raised_on_bad_frame():
    op = ttlock.StatusOp(AES_KEY)
    op.start()
    try:
        op.handle_frame(b"not a valid frame")
    except ttlock.TtlockError:
        return
    raise AssertionError("expected TtlockError")


def test_crc_mismatch_has_its_own_type():
    """A corrupted frame is retryable; callers need to tell it apart."""
    op = ttlock.StatusOp(AES_KEY)
    op.start()
    frame = bytearray(_response_frame(0x14, AES_KEY, bytes([0x14, 0x01, 0x63, 0x00])))
    frame[-1] ^= 0xFF  # corrupt the trailing CRC byte
    try:
        op.handle_frame(bytes(frame))
    except ttlock.CrcMismatch:
        # Subclassing TtlockError keeps existing handlers working.
        assert issubclass(ttlock.CrcMismatch, ttlock.TtlockError)
        return
    raise AssertionError("expected CrcMismatch")


def test_crc_retry_resumes_the_same_step():
    """A rejected frame must leave the operation waiting for the same response.

    This is what makes re-sending safe rather than desynchronizing: the CRC is
    checked before the operation touches its own state.
    """
    op = ttlock.StatusOp(AES_KEY)
    op.start()
    good = _response_frame(0x14, AES_KEY, bytes([0x14, 0x01, 0x63, 0x00]))
    corrupt = bytearray(good)
    corrupt[-1] ^= 0xFF
    try:
        op.handle_frame(bytes(corrupt))
    except ttlock.CrcMismatch:
        pass
    kind, state = op.handle_frame(good)
    assert kind == "done"
    assert state == "LOCKED"


def test_rejected_command_is_not_retryable():
    """A lock that decrypted and rejected a command must not look like corruption."""
    op = ttlock.StatusOp(AES_KEY)
    op.start()
    response = _response_frame(0x14, AES_KEY, bytes([0x14, 0x00, 0x00, 0x00]))
    try:
        op.handle_frame(response)
    except ttlock.CrcMismatch:
        raise AssertionError("a rejected command must not be reported as a CRC error")
    except ttlock.TtlockError:
        return
    raise AssertionError("expected TtlockError")


# Advertisement selection. A device can carry several manufacturer-data entries
# and the Bluetooth stack accumulates them, so a stale one sits indefinitely
# beside a live one. Picking arbitrarily froze reported state for as long as the
# dict ordering held — the bug these pin.

V3_COMPANY_ID = 0x0305
# The reserved documentation address, reversed: the firmware appends the MAC
# in reverse byte order. Never a real device — check-secrets.sh enforces it.
LOCK_MAC = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])
LOCK_ADDRESS = "AA:BB:CC:DD:EE:FF"


def _v3_payload(flags: int, battery: int) -> bytes:
    """The manufacturer-specific bytes that follow the company identifier."""
    return bytes([0x02, flags, battery, 0, 0, 0, 0]) + LOCK_MAC


def test_select_advertisement_ignores_a_stale_entry():
    live = _v3_payload(0x00, 62)
    stale = b"\x00" * 20  # unparseable, so it must never win

    for entries in (
        {V3_COMPANY_ID: live, 0x9999: stale},
        {0x9999: stale, V3_COMPANY_ID: live},
    ):
        chosen = ttlock.select_advertisement(entries, LOCK_ADDRESS)
        assert chosen.kind == "stateful"
        assert chosen.is_unlocked is False
        assert chosen.battery == 62


def test_select_advertisement_prefers_the_expected_address():
    ours = _v3_payload(0x00, 62)
    other = _v3_payload(0x01, 99)[:-6] + bytes([0xF0, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])

    chosen = ttlock.select_advertisement(
        {V3_COMPANY_ID: ours, V3_COMPANY_ID + 1: other}, LOCK_ADDRESS
    )
    assert chosen.address == LOCK_ADDRESS
    assert chosen.is_unlocked is False


def test_a_payload_that_cannot_report_state_says_so():
    """`None`, not `False`. Reporting a door as locked on no evidence is the
    failure mode this whole type exists to prevent."""
    empty = ttlock.select_advertisement({}, LOCK_ADDRESS)
    assert empty.kind == "unrecognized"
    assert empty.is_unlocked is None
    assert empty.battery is None
