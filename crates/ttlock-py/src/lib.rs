//! Python bindings for `ttlock-core`.
//!
//! These wrap the sans-IO protocol engine so a Home Assistant custom component
//! can drive the `TTLock` protocol over Home Assistant's own Bluetooth transport
//! (bleak): feed notification bytes into [`FrameAssembler`], run an operation's
//! `start`/`handle_frame` steps, and write the `("write", bytes)` frames the
//! operation yields.

use std::collections::HashMap;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyString, PyTuple};
use ttlock_core::advertisement::{
    Advertisement as CoreAdvertisement, Bolt, parse_manufacturer_data, parse_manufacturer_map,
};
use ttlock_core::credential::{AesKey, UnlockKey, decode_base64_credential};
use ttlock_core::error::TtlockError as CoreError;
use ttlock_core::framing::FrameAssembler as CoreAssembler;
use ttlock_core::ops::{
    Actuation, LockOp as CoreLockOp, LockState, Operation, StatusOp as CoreStatusOp, Step,
    UnlockOp as CoreUnlockOp,
};
use ttlock_core::packet::LockVersion as CoreLockVersion;
use ttlock_core::policy;
use ttlock_core::tracker::{Changed, LockTracker as CoreTracker, ReportedState};

create_exception!(ttlock, TtlockError, PyException);
create_exception!(ttlock, CrcMismatch, TtlockError);
create_exception!(ttlock, UnexpectedCommand, TtlockError);

/// Map a core error to Python, giving CRC mismatches their own type.
///
/// A corrupted frame is the one protocol error worth retrying: the operation
/// checks the CRC before touching any of its state, so re-sending the same frame
/// is safe. Callers need to distinguish it from a lock that decrypted a command
/// and rejected it, which will reject the identical bytes again. `CrcMismatch`
/// subclasses `TtlockError`, so existing handlers keep working.
fn to_pyerr(error: &CoreError) -> PyErr {
    match error {
        CoreError::CrcMismatch { .. } => CrcMismatch::new_err(error.to_string()),
        // Its own type for the same reason as `CrcMismatch`: the caller's
        // response differs. A CRC failure means re-send the frame; this means
        // send nothing and read the next one.
        CoreError::UnexpectedCommand { .. } => UnexpectedCommand::new_err(error.to_string()),
        _ => TtlockError::new_err(error.to_string()),
    }
}

/// Accept an AES key as either 32 hex characters or 16 raw bytes.
///
/// Both shapes occur in practice: Home Assistant stores the key as hex in its
/// config entry, while a caller holding `bytes` should not have to re-hex it.
/// Either way this is the boundary where an unusable key is rejected, so the
/// core never sees one.
fn aes_key_arg(value: &Bound<'_, PyAny>) -> PyResult<AesKey> {
    if let Ok(text) = value.extract::<String>() {
        return AesKey::from_hex(&text).map_err(|error| to_pyerr(&error));
    }
    // Every rejection leaves here as `TtlockError`, including a value of the
    // wrong Python type. Callers then have exactly one exception to catch, which
    // is what lets Home Assistant's config flow turn this into a field error
    // rather than a traceback.
    let Ok(bytes) = value.extract::<Vec<u8>>() else {
        return Err(TtlockError::new_err(
            "AES key must be 32 hex characters or 16 bytes",
        ));
    };
    let length = bytes.len();
    let raw: [u8; 16] = bytes
        .try_into()
        .map_err(|_| to_pyerr(&CoreError::InvalidAesKeyLength(length)))?;
    Ok(AesKey::from_bytes(raw))
}

/// Accept an unlock key as an `int` or a decimal `str`, rejecting `0`.
///
/// `0` is what an empty or unfilled form field collapses to, and the lock
/// answers it with a bare rejection that looks like a protocol fault. Catching
/// it here means both consumers get the same answer from the same code.
fn unlock_key_arg(value: &Bound<'_, PyAny>) -> PyResult<UnlockKey> {
    // `bool` is an `int` subclass in Python, and `True` is not a credential
    // anyone meant to type.
    if value.is_instance_of::<PyBool>() {
        return Err(to_pyerr(&CoreError::InvalidUnlockKey));
    }
    if let Ok(number) = value.extract::<u32>() {
        return UnlockKey::new(number).ok_or_else(|| to_pyerr(&CoreError::InvalidUnlockKey));
    }
    let text: String = value
        .extract()
        .map_err(|_| to_pyerr(&CoreError::InvalidUnlockKey))?;
    text.parse::<UnlockKey>().map_err(|error| to_pyerr(&error))
}

/// Validate an AES key and return it in canonical form (32 lowercase hex chars).
///
/// Exposed so the Home Assistant config flow validates with the same code the
/// protocol uses, rather than a second implementation that can drift from it.
///
/// Raises `TtlockError` if the value is not a 16-byte key.
#[pyfunction]
fn normalize_aes_key(value: &Bound<'_, PyAny>) -> PyResult<String> {
    Ok(hex::encode(aes_key_arg(value)?.as_bytes()))
}

/// Validate an unlock key and return it as an `int`.
///
/// Raises `TtlockError` if the value cannot be a key — most importantly `0`.
#[pyfunction]
fn normalize_unlock_key(value: &Bound<'_, PyAny>) -> PyResult<u32> {
    Ok(unlock_key_arg(value)?.get())
}

/// Build a `(label, value)` step tuple for Python.
fn step_tuple(py: Python<'_>, label: &str, value: Py<PyAny>) -> PyResult<Py<PyAny>> {
    let label = label.into_pyobject(py)?.into_any().unbind();
    let tuple = PyTuple::new(py, [label, value])?;
    Ok(tuple.into_any().unbind())
}

fn write_step(py: Python<'_>, frame: &[u8]) -> PyResult<Py<PyAny>> {
    let value = PyBytes::new(py, frame).into_any().unbind();
    step_tuple(py, "write", value)
}

fn done_step(py: Python<'_>, value: Py<PyAny>) -> PyResult<Py<PyAny>> {
    step_tuple(py, "done", value)
}

/// `LockVersion` describes the protocol header used when framing commands.
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct LockVersion {
    inner: CoreLockVersion,
}

#[pymethods]
impl LockVersion {
    #[new]
    #[pyo3(signature = (protocol_type=5, protocol_version=3, scene=2, group_id=1, org_id=1))]
    const fn new(
        protocol_type: u8,
        protocol_version: u8,
        scene: u8,
        group_id: u16,
        org_id: u16,
    ) -> Self {
        Self {
            inner: CoreLockVersion {
                protocol_type,
                protocol_version,
                scene,
                group_id,
                org_id,
            },
        }
    }

    /// The default V3 lock version used when an advertisement does not provide
    /// one.
    #[staticmethod]
    fn default_version() -> Self {
        Self {
            inner: CoreLockVersion::default(),
        }
    }

    #[getter]
    const fn protocol_type(&self) -> u8 {
        self.inner.protocol_type
    }

    #[getter]
    const fn protocol_version(&self) -> u8 {
        self.inner.protocol_version
    }

    #[getter]
    const fn scene(&self) -> u8 {
        self.inner.scene
    }

    #[getter]
    const fn group_id(&self) -> u16 {
        self.inner.group_id
    }

    #[getter]
    const fn org_id(&self) -> u16 {
        self.inner.org_id
    }

    fn __repr__(&self) -> String {
        let v = &self.inner;
        format!(
            "LockVersion(protocol_type={}, protocol_version={}, scene={}, group_id={}, org_id={})",
            v.protocol_type, v.protocol_version, v.scene, v.group_id, v.org_id
        )
    }
}

fn resolve_version(version: Option<LockVersion>) -> CoreLockVersion {
    version.map_or_else(CoreLockVersion::default, |v| v.inner)
}

/// Parsed `TTLock` advertisement fields, used by HA passive Bluetooth
/// coordinators for state/battery without connecting.
///
/// Every state getter returns `None` when the payload could not carry that
/// fact, rather than a plausible-looking default. Read [`Self::kind`] to tell
/// "this lock reports itself locked" from "this payload cannot report a bolt
/// position at all".
#[pyclass]
pub struct Advertisement {
    inner: CoreAdvertisement,
}

#[pymethods]
impl Advertisement {
    /// Which shape of payload this was: `"unrecognized"`, `"dfu"`,
    /// `"stateless"`, or `"stateful"`.
    #[getter]
    const fn kind(&self) -> &'static str {
        match self.inner {
            CoreAdvertisement::Unrecognized => "unrecognized",
            CoreAdvertisement::Dfu => "dfu",
            CoreAdvertisement::Stateless(_) => "stateless",
            CoreAdvertisement::Stateful { .. } => "stateful",
        }
    }

    #[getter]
    fn address(&self) -> Option<String> {
        self.inner.address().map(ToOwned::to_owned)
    }

    #[getter]
    fn battery(&self) -> Option<u8> {
        self.inner
            .battery()
            .map(ttlock_core::advertisement::Percent::get)
    }

    /// `True` if the lock currently reports itself unlocked, `None` if the
    /// advertisement does not carry the flag.
    #[getter]
    fn is_unlocked(&self) -> Option<bool> {
        self.inner.bolt().map(|bolt| bolt == Bolt::Unlocked)
    }

    #[getter]
    fn has_events(&self) -> Option<bool> {
        self.inner.status().map(|status| status.has_events)
    }

    #[getter]
    fn is_setting_mode(&self) -> Option<bool> {
        self.inner.status().map(|status| status.is_setting_mode)
    }

    #[getter]
    fn lock_version(&self) -> Option<LockVersion> {
        self.inner.lock_version().map(|inner| LockVersion { inner })
    }
}

/// Reassembles complete protocol frames from BLE notification chunks.
#[pyclass]
pub struct FrameAssembler {
    inner: CoreAssembler,
}

#[pymethods]
impl FrameAssembler {
    #[new]
    fn new() -> Self {
        Self {
            inner: CoreAssembler::new(),
        }
    }

    /// Feed raw notification bytes.
    fn push(&mut self, data: &[u8]) {
        self.inner.push(data);
    }

    /// Return the next complete frame (CRLF stripped), or `None`.
    fn next_frame(&mut self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.inner
            .next_frame()
            .map(|frame| PyBytes::new(py, &frame).into_any().unbind())
    }
}

/// Convert a status result into a Python string.
fn lock_state_str(state: LockState) -> String {
    match state {
        LockState::Locked => "LOCKED".to_string(),
        LockState::Unlocked => "UNLOCKED".to_string(),
        LockState::Unknown(byte) => format!("UNKNOWN:{byte}"),
    }
}

/// Convert a [`Step`] into the `(label, value)` tuple Python sees.
///
/// `to_value` renders the operation's own output; everything else about the
/// conversion is identical across operations.
fn step_to_py<T>(
    py: Python<'_>,
    step: Step<T>,
    to_value: impl FnOnce(Python<'_>, T) -> Py<PyAny>,
) -> PyResult<Py<PyAny>> {
    match step {
        Step::Write(frame) => write_step(py, &frame),
        Step::Done(output) => done_step(py, to_value(py, output)),
    }
}

/// Actuation operations report only success, so their `done` value is `None`.
fn actuate_value(py: Python<'_>, (): ()) -> Py<PyAny> {
    py.None()
}

/// Status reports the lock state as a string.
fn status_value(py: Python<'_>, state: LockState) -> Py<PyAny> {
    PyString::new(py, &lock_state_str(state))
        .into_any()
        .unbind()
}

/// Query the lock state. Steps: `("write", bytes)` then `("done", str)` where
/// the string is `"LOCKED"`, `"UNLOCKED"`, or `"UNKNOWN:<n>"`.
#[pyclass]
pub struct StatusOp {
    inner: CoreStatusOp,
}

#[pymethods]
impl StatusOp {
    #[new]
    #[pyo3(signature = (aes_key, version=None))]
    fn new(aes_key: &Bound<'_, PyAny>, version: Option<LockVersion>) -> PyResult<Self> {
        Ok(Self {
            inner: CoreStatusOp::new(aes_key_arg(aes_key)?, resolve_version(version)),
        })
    }

    /// Produce the first frame to write.
    fn start(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        step_to_py(
            py,
            self.inner.start().map_err(|e| to_pyerr(&e))?,
            status_value,
        )
    }

    /// Feed one reassembled response frame (CRLF stripped).
    fn handle_frame(&mut self, py: Python<'_>, frame: &[u8]) -> PyResult<Py<PyAny>> {
        step_to_py(
            py,
            self.inner.handle_frame(frame).map_err(|e| to_pyerr(&e))?,
            status_value,
        )
    }
}

/// Define a pyclass wrapping one of the two actuation operations.
///
/// `LockOp` and `UnlockOp` have identical bindings — same constructor
/// signature, same step handling, same output — and differ only in which core
/// type they drive. Writing them out twice invites the two copies to drift.
macro_rules! actuate_op {
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Steps: `("write", bytes)` for the check-user-time handshake, `("write",
        /// bytes)` for the actuation itself, then `("done", None)`.
        #[pyclass]
        pub struct $name {
            inner: $inner,
        }

        #[pymethods]
        impl $name {
            #[new]
            #[pyo3(signature = (aes_key, unlock_key, version=None))]
            fn new(
                aes_key: &Bound<'_, PyAny>,
                unlock_key: &Bound<'_, PyAny>,
                version: Option<LockVersion>,
            ) -> PyResult<Self> {
                Ok(Self {
                    inner: <$inner>::new(
                        aes_key_arg(aes_key)?,
                        unlock_key_arg(unlock_key)?,
                        resolve_version(version),
                    ),
                })
            }

            /// Produce the first frame to write.
            fn start(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
                step_to_py(
                    py,
                    self.inner.start().map_err(|e| to_pyerr(&e))?,
                    actuate_value,
                )
            }

            /// Feed one reassembled response frame (CRLF stripped).
            fn handle_frame(&mut self, py: Python<'_>, frame: &[u8]) -> PyResult<Py<PyAny>> {
                step_to_py(
                    py,
                    self.inner.handle_frame(frame).map_err(|e| to_pyerr(&e))?,
                    actuate_value,
                )
            }
        }
    };
}

actuate_op!(LockOp, CoreLockOp, "Lock the lock.");
actuate_op!(UnlockOp, CoreUnlockOp, "Unlock the lock.");

/// Convert a Python `"lock"`/`"unlock"` string into an [`Actuation`].
fn parse_actuation(action: &str) -> PyResult<Actuation> {
    match action {
        "lock" => Ok(Actuation::Lock),
        "unlock" => Ok(Actuation::Unlock),
        other => Err(TtlockError::new_err(format!(
            "unknown actuation {other:?}: expected 'lock' or 'unlock'"
        ))),
    }
}

/// What a lock is believed to be doing, tracked from evidence.
///
/// Mirrors `ttlock_core::tracker::LockTracker`, and exists so a Home Assistant
/// integration reports state through exactly the same rules as the Rust MQTT
/// daemon instead of reimplementing them. Times are monotonic milliseconds
/// supplied by the caller (`time.monotonic() * 1000`); nothing here reads a
/// clock.
///
/// Each mutating method returns a `set` of the names that changed, drawn from
/// `{"state", "available", "battery"}`, so a caller can publish only what moved.
#[pyclass]
pub struct LockTracker {
    inner: CoreTracker,
}

/// Render a `Changed` as the set of field names Python sees.
fn changed_set(py: Python<'_>, changed: Changed) -> PyResult<Py<PyAny>> {
    let names = [
        ("state", changed.state),
        ("available", changed.available),
        ("battery", changed.battery),
    ];
    let set = pyo3::types::PySet::empty(py)?;
    for (name, did_change) in names {
        if did_change {
            set.add(name)?;
        }
    }
    Ok(set.into_any().unbind())
}

#[pymethods]
impl LockTracker {
    #[new]
    fn new() -> Self {
        Self {
            inner: CoreTracker::new(),
        }
    }

    /// Record an advertisement observed at `now_ms`.
    fn on_advertisement(
        &mut self,
        py: Python<'_>,
        now_ms: u64,
        advertisement: &Advertisement,
    ) -> PyResult<Py<PyAny>> {
        changed_set(
            py,
            self.inner.on_advertisement(now_ms, &advertisement.inner),
        )
    }

    /// Record that a `"lock"` or `"unlock"` command has been sent.
    fn on_command_started(&mut self, py: Python<'_>, action: &str) -> PyResult<Py<PyAny>> {
        changed_set(py, self.inner.on_command_started(parse_actuation(action)?))
    }

    /// Record that the lock acknowledged the command.
    fn on_command_acknowledged(
        &mut self,
        py: Python<'_>,
        now_ms: u64,
        action: &str,
    ) -> PyResult<Py<PyAny>> {
        changed_set(
            py,
            self.inner
                .on_command_acknowledged(now_ms, parse_actuation(action)?),
        )
    }

    /// Record that a command failed, leaving the outcome unknown. The reported
    /// state deliberately stays in progress rather than reverting.
    fn on_command_failed(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        changed_set(py, self.inner.on_command_failed())
    }

    /// Give back time during which the radio was busy connecting and could not
    /// have heard an advertisement.
    fn credit_blind_time(&mut self, blind_ms: u64) {
        self.inner
            .credit_blind_time(std::time::Duration::from_millis(blind_ms));
    }

    /// Expire availability if nothing has been heard for `offline_after_ms`.
    fn poll_availability(
        &mut self,
        py: Python<'_>,
        now_ms: u64,
        offline_after_ms: u64,
    ) -> PyResult<Py<PyAny>> {
        changed_set(
            py,
            self.inner
                .poll_availability(now_ms, std::time::Duration::from_millis(offline_after_ms)),
        )
    }

    /// Record that the lock can no longer be heard, clearing any pending
    /// command.
    fn on_unavailable(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        changed_set(py, self.inner.on_unavailable())
    }

    /// `"LOCKED"`, `"UNLOCKED"`, `"LOCKING"`, `"UNLOCKING"`, or `None` when
    /// nothing has been observed yet.
    #[getter]
    fn reported_state(&self) -> Option<&'static str> {
        self.inner.reported_state().map(ReportedState::payload)
    }

    /// Last observed bolt position, ignoring any command in flight.
    #[getter]
    const fn is_locked(&self) -> Option<bool> {
        self.inner.is_locked()
    }

    /// `"lock"`, `"unlock"`, or `None` when no command is in flight.
    #[getter]
    fn pending(&self) -> Option<&'static str> {
        self.inner.pending().map(|action| match action {
            Actuation::Lock => "lock",
            Actuation::Unlock => "unlock",
        })
    }

    #[getter]
    const fn available(&self) -> bool {
        self.inner.available()
    }

    #[getter]
    const fn battery(&self) -> Option<u8> {
        self.inner.battery()
    }

    /// Protocol version learned from advertisements, to build commands with.
    #[getter]
    fn lock_version(&self) -> Option<LockVersion> {
        self.inner.lock_version().map(|inner| LockVersion { inner })
    }
}

/// Decode a base64 comma-list `TTLock` credential into its integer form.
#[pyfunction]
fn decode_credential(value: &str) -> PyResult<u32> {
    decode_base64_credential(value).map_err(|e| to_pyerr(&e))
}

/// Parse a `TTLock` manufacturer-data advertisement. `manufacturer_id` is the
/// 16-bit company identifier; `data` is the manufacturer-specific payload that
/// follows it (as delivered by bleak).
#[pyfunction]
fn parse_advertisement(manufacturer_id: u16, data: &[u8]) -> Advertisement {
    let mut full = Vec::with_capacity(data.len() + 2);
    full.extend_from_slice(&manufacturer_id.to_le_bytes());
    full.extend_from_slice(data);
    Advertisement {
        inner: parse_manufacturer_data(&full),
    }
}

/// Choose the most informative entry from a whole manufacturer-data map.
///
/// Prefer this over calling [`parse_advertisement`] per entry and picking one.
/// A device can carry several entries and the Bluetooth stack accumulates them,
/// so a stale entry sits indefinitely beside a live one; this applies the same
/// selection rules the Rust daemon uses — prefer a payload carrying state,
/// prefer one whose decoded address matches `expected_address`, break ties on
/// the company identifier so the answer never depends on dict ordering.
#[pyfunction]
#[pyo3(signature = (manufacturer_data, expected_address=None))]
fn select_advertisement(
    manufacturer_data: &Bound<'_, PyAny>,
    expected_address: Option<&str>,
) -> PyResult<Advertisement> {
    let entries: HashMap<u16, Vec<u8>> = manufacturer_data.extract()?;
    Ok(Advertisement {
        inner: parse_manufacturer_map(&entries, expected_address),
    })
}

#[pymodule]
fn ttlock(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("TtlockError", m.py().get_type::<TtlockError>())?;
    m.add("CrcMismatch", m.py().get_type::<CrcMismatch>())?;
    m.add("UnexpectedCommand", m.py().get_type::<UnexpectedCommand>())?;
    m.add_class::<LockVersion>()?;
    m.add_class::<Advertisement>()?;
    m.add_class::<FrameAssembler>()?;
    m.add_class::<StatusOp>()?;
    m.add_class::<LockOp>()?;
    m.add_class::<UnlockOp>()?;
    m.add_class::<LockTracker>()?;
    m.add_function(wrap_pyfunction!(decode_credential, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_aes_key, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_unlock_key, m)?)?;
    m.add_function(wrap_pyfunction!(parse_advertisement, m)?)?;
    m.add_function(wrap_pyfunction!(select_advertisement, m)?)?;

    // Protocol-level constants, so a Python consumer never has to restate them
    // and cannot drift from the Rust one. Transport tunables (timeouts, attempt
    // counts) are deliberately absent — see `ttlock_core::policy`.
    m.add("SERVICE_UUID", policy::SERVICE_UUID)?;
    m.add("WRITE_CHARACTERISTIC", policy::WRITE_CHARACTERISTIC)?;
    m.add("NOTIFY_CHARACTERISTIC", policy::NOTIFY_CHARACTERISTIC)?;
    m.add("WRITE_CHUNK", policy::WRITE_CHUNK)?;
    m.add("CRC_RETRIES", policy::CRC_RETRIES)?;
    m.add("MAX_STRAY_FRAMES", policy::MAX_STRAY_FRAMES)?;
    m.add("CRC_RETRY_DELAY", policy::CRC_RETRY_DELAY.as_secs_f64())?;
    m.add("WRITE_CHUNK_DELAY", policy::WRITE_CHUNK_DELAY.as_secs_f64())?;
    m.add_function(wrap_pyfunction!(connect_backoff, m)?)?;
    Ok(())
}

/// Seconds to wait before connect attempt `attempt` (1-based).
#[pyfunction]
fn connect_backoff(attempt: u32) -> f64 {
    policy::connect_backoff(attempt).as_secs_f64()
}
