"""Credential validation, from both ends.

The rules live in `ttlock-core` and are reached from Python through
`ttlock.normalize_aes_key` / `ttlock.normalize_unlock_key`. The Home Assistant
config flow is a thin wrapper that turns a rejection into `None` so the form can
show a field error. Both are tested here: the library because it is where the
rules are, and the wrapper because HA depends on the exception never escaping.

These exist because an unusable credential does not fail loudly. The lock
accepts the resulting command *frame* and simply refuses it, so a bad key
surfaces much later as a rejected actuation with nothing pointing back at the
form that accepted it.
"""

import ast
import pathlib

import pytest
import ttlock

_CONFIG_FLOW = (
    pathlib.Path(__file__).parents[3]
    / "custom_components"
    / "ttlock_ble"
    / "config_flow.py"
)


def _load_validators():
    """Lift the wrappers out of the component without importing it.

    Parsed rather than imported because `config_flow` imports Home Assistant and
    voluptuous, neither of which belongs in this test environment. Selecting the
    definitions by name from the AST — rather than slicing the file by text —
    means a reordered import or a new helper cannot silently change what runs.
    The real `ttlock` module is injected, so these tests exercise the actual
    binding rather than a stand-in.
    """
    wanted = {"_normalize_aes_key", "_normalize_unlock_key"}
    tree = ast.parse(_CONFIG_FLOW.read_text(), filename=str(_CONFIG_FLOW))
    kept = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert len(kept) == len(wanted), (
        f"expected {sorted(wanted)}, found {len(kept)} defs"
    )

    namespace: dict = {"ttlock": ttlock}
    exec(  # noqa: S102
        compile(ast.Module(body=kept, type_ignores=[]), str(_CONFIG_FLOW), "exec"),
        namespace,
    )
    return namespace["_normalize_aes_key"], namespace["_normalize_unlock_key"]


normalize_aes_key, normalize_unlock_key = _load_validators()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("00112233445566778899aabbccddeeff", "00112233445566778899aabbccddeeff"),
        (
            "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
            "00112233445566778899aabbccddeeff",
        ),
        ("  00112233445566778899AABBCCDDEEFF  ", "00112233445566778899aabbccddeeff"),
    ],
)
def test_aes_key_accepts_the_shapes_people_paste(raw, expected):
    assert normalize_aes_key(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "deadbeef",  # 4 bytes, not 16 — the old sample-lockData.json value
        "00112233445566778899aabbccddeeffgg",
        "not hex at all",
        "00112233445566778899aabbccddee",  # 15 bytes
    ],
)
def test_aes_key_rejects_anything_not_sixteen_bytes(raw):
    assert normalize_aes_key(raw) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("12345678", 12345678),
        (12345678, 12345678),
        ("  12345678  ", 12345678),
        ("1", 1),
        ("4294967295", 4294967295),
    ],
)
def test_unlock_key_accepts_valid_values(raw, expected):
    assert normalize_unlock_key(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        # Zero is the value an empty or unfilled field collapses to, and it is
        # what a reconfigure form that failed to prefill would submit back.
        0,
        "0",
        "",
        "   ",
        None,
        -1,
        "-12345678",
        4294967296,  # one past the u32 the protocol carries
        "12345678.9",
        "NjgsNjYsNjUsNzcsNjUsNzAsNjUsNjgsNjQsNjYsMTA=",  # the base64 form, undecoded
        True,  # bool is an int subclass; 1 is not a credential someone meant
    ],
)
def test_unlock_key_rejects_unusable_values(raw):
    assert normalize_unlock_key(raw) is None


# The library is where the rules actually live. The wrapper above only converts
# a rejection into `None`; these pin what it is converting.


@pytest.mark.parametrize("raw", [0, "0", "", None, -1, 4294967296, "12345678.9", True])
def test_library_raises_ttlock_error_for_bad_unlock_keys(raw):
    with pytest.raises(ttlock.TtlockError):
        ttlock.normalize_unlock_key(raw)


@pytest.mark.parametrize("raw", ["", "deadbeef", "not hex", None, 12345, b"\x00" * 15])
def test_library_raises_ttlock_error_for_bad_aes_keys(raw):
    # A single exception type for every rejection, including a wrong Python
    # type, is what lets the config flow catch one thing instead of guessing.
    with pytest.raises(ttlock.TtlockError):
        ttlock.normalize_aes_key(raw)


def test_library_accepts_raw_bytes_as_well_as_hex():
    assert (
        ttlock.normalize_aes_key(bytes(range(16))) == "000102030405060708090a0b0c0d0e0f"
    )


def test_zero_unlock_key_is_rejected_at_the_operation_too():
    # The form is not the only door: constructing an operation directly must
    # reject the same value, which is the half that was missing when this bug
    # reached a real lock.
    with pytest.raises(ttlock.TtlockError):
        ttlock.UnlockOp("00112233445566778899aabbccddeeff", 0)
