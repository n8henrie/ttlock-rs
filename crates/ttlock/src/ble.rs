use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use btleplug::api::{
    Central, CentralEvent, Characteristic, Manager as _, Peripheral as _, ScanFilter,
    ValueNotification, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};
use futures_util::{Stream, StreamExt};
use tokio::time;
use tokio::time::Instant;
use uuid::Uuid;

use ttlock_core::advertisement::{Advertisement, parse_manufacturer_map};
use ttlock_core::framing::FrameAssembler;
use ttlock_core::ops::{Operation, Step};
use ttlock_core::policy;

use crate::error::{CliError, Result};

/// How long to wait for the lock to answer a single command frame.
///
/// A transport tunable, not a protocol constant, so it lives here rather than in
/// [`ttlock_core::policy`]: a local adapter answers faster than a Home Assistant
/// Bluetooth proxy, and the two consumers set it differently on purpose. See the
/// table in `docs/protocol-and-design.md`.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// `TTLock`'s primary GATT service UUID. Only ever corroborates a match — never
/// filters (see [`ttlock_scan_filter`]).
const TTLOCK_SERVICE: Uuid = uuid::uuid!("00001910-0000-1000-8000-00805f9b34fb");

/// Scan unfiltered and identify locks from the advertisement payload instead of
/// asking the OS to filter by service UUID.
///
/// A `ScanFilter { services: [TTLOCK_SERVICE] }` becomes
/// `scanForPeripheralsWithServices:` on `CoreBluetooth` and a `BlueZ`
/// `SetDiscoveryFilter` UUID list on Linux. Both match only UUIDs present in the
/// *advertising* payload, and `0x1910` lives in the lock's GATT table — it is not
/// advertised — so such a filter silently suppresses every advertisement report.
/// Connecting still works (both stacks hand out already-known devices), which is
/// what makes the failure so confusing: commands succeed while passive state
/// tracking sees nothing.
fn ttlock_scan_filter() -> ScanFilter {
    ScanFilter::default()
}

/// Whether a scanned peripheral looks like a `TTLock`. Used in place of an
/// OS-level scan filter (see [`ttlock_scan_filter`]): a parseable `TTLock`
/// protocol header in the manufacturer data is the strongest signal, with the
/// advertised service and the stock `M`-prefixed name as fallbacks.
fn looks_like_ttlock(info: &PeripheralInfo, advertisement: &Advertisement) -> bool {
    advertisement.lock_version().is_some()
        || info.services.contains(&TTLOCK_SERVICE)
        || info
            .local_name
            .as_deref()
            .is_some_and(|name| name.contains('M') || name.to_ascii_uppercase().contains("LOCK"))
}

#[derive(Clone)]
pub struct ScannedLock {
    pub adapter: Adapter,
    pub peripheral: Peripheral,
    pub local_name: Option<String>,
    pub btleplug_address: String,
    pub advertisement: Advertisement,
}

#[derive(Debug)]
pub struct DisplayLock {
    pub local_name: Option<String>,
    pub btleplug_address: String,
    pub rssi: Option<i16>,
    /// Whatever the advertisement said, kept whole. Flattening it back into
    /// loose fields is how the "reported a bolt position that was never
    /// broadcast" bug got in.
    pub advertisement: Advertisement,
}

pub struct BleConnection {
    peripheral: Peripheral,
    write_char: Characteristic,
    notify_uuid: Uuid,
    notifications: Pin<Box<dyn Stream<Item = ValueNotification> + Send>>,
    assembler: FrameAssembler,
    debug: bool,
}

async fn first_adapter() -> Result<Adapter> {
    let manager = Manager::new().await?;
    let mut adapters = manager.adapters().await?;
    adapters.pop().ok_or(CliError::NoAdapter)
}

/// The advertisement-derived properties of a scanned peripheral.
struct PeripheralInfo {
    local_name: Option<String>,
    /// Address as reported by btleplug. Note that on macOS `CoreBluetooth` hides
    /// BLE addresses, so this is all zeros there and only
    /// the address parsed out of the manufacturer data
    /// identifies the lock.
    address: String,
    manufacturer_data: HashMap<u16, Vec<u8>>,
    services: Vec<Uuid>,
    rssi: Option<i16>,
}

async fn properties_for(peripheral: &Peripheral) -> Result<PeripheralInfo> {
    let props = peripheral.properties().await?;
    let address = peripheral.address().to_string();
    Ok(props.map_or_else(
        || PeripheralInfo {
            local_name: None,
            address: address.clone(),
            manufacturer_data: HashMap::new(),
            services: Vec::new(),
            rssi: None,
        },
        |p| PeripheralInfo {
            local_name: p.local_name,
            address: address.clone(),
            manufacturer_data: p.manufacturer_data,
            services: p.services,
            rssi: p.rssi,
        },
    ))
}

fn is_bluez_stale_object_error<E: std::fmt::Debug>(error: &E) -> bool {
    let rendered = format!("{error:?}");
    rendered.contains("UnknownObject")
        || rendered.contains("GetAll")
        || rendered.contains("No discovery started")
}

#[must_use]
pub fn matches_target(
    lock: &ScannedLock,
    target_address: Option<&str>,
    target_name: Option<&str>,
) -> bool {
    let address_match = target_address.is_some_and(|target| {
        lock.btleplug_address.eq_ignore_ascii_case(target)
            || lock
                .advertisement
                .address()
                .is_some_and(|address| address.eq_ignore_ascii_case(target))
    });
    let name_match = target_name.is_some_and(|target| {
        lock.local_name.as_deref().is_some_and(|name| {
            name.to_ascii_lowercase()
                .contains(&target.to_ascii_lowercase())
        })
    });
    address_match || name_match
}

pub async fn scan_locks(seconds: u64) -> Result<Vec<DisplayLock>> {
    let adapter = first_adapter().await?;
    adapter.start_scan(ttlock_scan_filter()).await?;
    time::sleep(Duration::from_secs(seconds)).await;

    let peripherals = adapter.peripherals().await?;
    let mut locks = Vec::new();

    // Read properties before stopping discovery. On BlueZ, Device1 objects can
    // disappear quickly after discovery is stopped, which can surface as
    // org.freedesktop.DBus.Error.UnknownObject during Properties.GetAll.
    for peripheral in peripherals {
        let Ok(info) = properties_for(&peripheral).await else {
            continue;
        };
        // No target during a discovery scan, so no address to prefer.
        let advertisement = parse_manufacturer_map(&info.manufacturer_data, None);
        if !looks_like_ttlock(&info, &advertisement) {
            continue;
        }
        locks.push(DisplayLock {
            local_name: info.local_name,
            btleplug_address: info.address,
            rssi: info.rssi,
            advertisement,
        });
    }

    let _ = adapter.stop_scan().await;
    Ok(locks)
}

/// Stream of adapter events (advertisements, discoveries) for a continuous scan.
pub type EventStream = Pin<Box<dyn Stream<Item = CentralEvent> + Send>>;

/// Start a single, continuous scan and return the adapter
/// together with its event stream. Unlike the short bursts of [`find_lock`],
/// this leaves the radio listening indefinitely so every advertisement the
/// (possibly weak) link delivers is captured. The caller drives the stream and
/// stops the scan by dropping the adapter (or calling [`stop_scan`]).
///
/// The event stream is obtained *before* the scan starts so no early
/// advertisement is missed.
pub async fn start_continuous_scan() -> Result<(Adapter, EventStream)> {
    let adapter = first_adapter().await?;
    let events = adapter.events().await?;
    adapter.start_scan(ttlock_scan_filter()).await?;
    Ok((adapter, events))
}

/// Best-effort stop of a running scan.
pub async fn stop_scan(adapter: &Adapter) {
    let _ = adapter.stop_scan().await;
}

/// A peripheral and, when the event carried one, its manufacturer-data payload.
type StateBearingEvent<'a> = (&'a PeripheralId, Option<&'a HashMap<u16, Vec<u8>>>);

/// The events worth deriving lock state from, and the payload they carry.
///
/// Only two of btleplug's event kinds can tell us anything about a `TTLock`.
/// One radio report fans out into as many as five events — `DeviceUpdated`,
/// `ServiceDataAdvertisement` and `ServicesAdvertisement` among them — and
/// treating each as an advertisement meant one report was parsed, matched and
/// published up to eight times, all within a hundred microseconds. None of
/// those three carries manufacturer data, so none of them can carry a bolt
/// position.
const fn state_bearing_event(event: &CentralEvent) -> Option<StateBearingEvent<'_>> {
    match event {
        CentralEvent::ManufacturerDataAdvertisement {
            id,
            manufacturer_data,
        } => Some((id, Some(manufacturer_data))),
        // First sighting: no payload on the event, so fall back to whatever the
        // adapter has already accumulated for the device.
        CentralEvent::DeviceDiscovered(id) => Some((id, None)),
        _ => None,
    }
}

/// If `event` is an advertisement from the target lock, return its parsed
/// [`Advertisement`] (bolt position, battery, ...). Returns `None` for
/// non-advertisement events or advertisements from other devices.
pub async fn advertisement_from_event(
    adapter: &Adapter,
    event: &CentralEvent,
    target_address: Option<&str>,
    target_name: Option<&str>,
) -> Option<Advertisement> {
    let (id, payload) = state_bearing_event(event)?;
    let peripheral = adapter.peripheral(id).await.ok()?;
    let info = properties_for(&peripheral).await.ok()?;
    // Parse the event's own payload when it has one. The peripheral's
    // `manufacturer_data` is *accumulated* by the Bluetooth stack rather than
    // replaced per advertisement, so reading it back can hand over an entry
    // that stopped being refreshed. Either way, prefer the entry belonging to
    // the lock we are tracking.
    let advertisement =
        parse_manufacturer_map(payload.unwrap_or(&info.manufacturer_data), target_address);
    let lock = ScannedLock {
        adapter: adapter.clone(),
        peripheral,
        local_name: info.local_name,
        btleplug_address: info.address,
        advertisement,
    };
    let matched = matches_target(&lock, target_address, target_name);

    // Log every device the scan surfaces, matched or not. Without this, a target
    // that never matches is indistinguishable from a radio that hears nothing —
    // both look like total silence.
    tracing::trace!(
        name = ?lock.local_name,
        btleplug_address = %lock.btleplug_address,
        ttlock_address = ?lock.advertisement.address(),
        matched,
        "scan reported a device"
    );

    matched.then_some(lock.advertisement)
}

pub async fn find_lock(
    target_address: Option<&str>,
    target_name: Option<&str>,
    seconds: u64,
) -> Result<ScannedLock> {
    let adapter = first_adapter().await?;
    adapter.start_scan(ttlock_scan_filter()).await?;

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut found = None;

    while Instant::now() < deadline {
        let peripherals = adapter.peripherals().await?;

        for peripheral in peripherals {
            let fallback_address = peripheral.address().to_string();

            // Fast path for saved lockData entries. If the caller already
            // knows the BLE address, avoid asking BlueZ for Device1 properties
            // just to match the device. Properties.GetAll is where BlueZ most
            // often reports transient org.freedesktop.DBus.Error.UnknownObject
            // for scan objects that appeared/disappeared quickly.
            if target_address.is_some_and(|target| fallback_address.eq_ignore_ascii_case(target)) {
                return Ok(ScannedLock {
                    adapter,
                    peripheral,
                    local_name: None,
                    btleplug_address: fallback_address,
                    advertisement: Advertisement::Unrecognized,
                });
            }

            let properties = properties_for(&peripheral).await;
            let info = match properties {
                Ok(info) => info,
                Err(_error) => {
                    let lock = ScannedLock {
                        adapter: adapter.clone(),
                        peripheral,
                        local_name: None,
                        btleplug_address: fallback_address,
                        advertisement: Advertisement::Unrecognized,
                    };
                    if matches_target(&lock, target_address, target_name) {
                        found = Some(lock);
                        break;
                    }
                    continue;
                }
            };

            let advertisement = parse_manufacturer_map(&info.manufacturer_data, target_address);
            let lock = ScannedLock {
                adapter: adapter.clone(),
                peripheral,
                local_name: info.local_name,
                btleplug_address: info.address,
                advertisement,
            };
            if matches_target(&lock, target_address, target_name) {
                found = Some(lock);
                break;
            }
        }

        if found.is_some() {
            break;
        }

        time::sleep(Duration::from_millis(250)).await;
    }

    if found.is_none() {
        let _ = adapter.stop_scan().await;
    }

    found.ok_or(CliError::DeviceNotFound)
}

fn parse_uuid(value: &str) -> Result<Uuid> {
    Ok(Uuid::parse_str(value)?)
}

fn find_characteristic(peripheral: &Peripheral, uuid: Uuid) -> Option<Characteristic> {
    peripheral
        .characteristics()
        .iter()
        .find(|characteristic| characteristic.uuid == uuid)
        .cloned()
}

impl BleConnection {
    pub async fn connect(scanned: ScannedLock, debug: bool) -> Result<Self> {
        let adapter = scanned.adapter;
        let peripheral = scanned.peripheral;

        // Do not call peripheral.is_connected() here. On Linux/btleplug that
        // goes through BlueZ Properties.GetAll on the Device1 object. Some
        // adapters remove transient Device1 objects during discovery, causing
        // exactly this error:
        //   org.freedesktop.DBus.Error.UnknownObject / GetAll doesn't exist
        // A direct connect is less fragile. If it fails, stop discovery and try
        // the same freshly-discovered object once more before returning the
        // error to the caller, which will rescan.
        if debug {
            eprintln!("BLE: connecting to {}", peripheral.address());
        }

        if let Err(first_error) = peripheral.connect().await {
            if debug {
                eprintln!(
                    "BLE: connect while scanning failed: {first_error}; stopping scan and retrying once"
                );
            }
            let _ = adapter.stop_scan().await;
            time::sleep(Duration::from_millis(300)).await;
            if let Err(second_error) = peripheral.connect().await {
                if debug {
                    eprintln!("BLE: connect retry failed: {second_error}");
                }
                // Prefer the second error if it is the BlueZ stale-object
                // symptom; otherwise return the first error that started the
                // failure chain.
                return if is_bluez_stale_object_error(&second_error) {
                    Err(second_error.into())
                } else {
                    Err(first_error.into())
                };
            }
        }

        // Try service discovery before StopDiscovery, then retry after
        // StopDiscovery. Different BlueZ/controller combinations fail in
        // opposite directions here, so this two-step is intentionally boring
        // and defensive.
        if debug {
            eprintln!("BLE: discovering services");
        }

        if let Err(first_error) = peripheral.discover_services().await {
            if debug {
                eprintln!(
                    "BLE: service discovery while scanning failed: {first_error}; stopping scan and retrying"
                );
            }
            let _ = adapter.stop_scan().await;
            time::sleep(Duration::from_millis(500)).await;
            if let Err(second_error) = peripheral.discover_services().await {
                if debug {
                    eprintln!("BLE: service discovery retry failed: {second_error}");
                }
                return if is_bluez_stale_object_error(&second_error) {
                    Err(second_error.into())
                } else {
                    Err(first_error.into())
                };
            }
        } else {
            let _ = adapter.stop_scan().await;
            time::sleep(Duration::from_millis(150)).await;
        }

        let write_uuid = parse_uuid(policy::WRITE_CHARACTERISTIC)?;
        let notify_uuid = parse_uuid(policy::NOTIFY_CHARACTERISTIC)?;
        let write_char = find_characteristic(&peripheral, write_uuid)
            .ok_or(CliError::WriteCharacteristicNotFound)?;
        let notify_char = find_characteristic(&peripheral, notify_uuid)
            .ok_or(CliError::NotifyCharacteristicNotFound)?;
        let notifications = peripheral.notifications().await?;
        peripheral.subscribe(&notify_char).await?;

        Ok(Self {
            peripheral,
            write_char,
            notify_uuid,
            notifications,
            assembler: FrameAssembler::new(),
            debug,
        })
    }

    pub async fn disconnect(self) -> Result<()> {
        // Like connect(), avoid is_connected() on BlueZ because it can trigger
        // the same stale Properties.GetAll path. A best-effort Disconnect() is
        // enough for CLI teardown; ignore the common stale-object/not-connected
        // cases so successful commands do not end with a cleanup error.
        if let Err(error) = self.peripheral.disconnect().await
            && !is_bluez_stale_object_error(&error)
        {
            return Err(error.into());
        }
        Ok(())
    }

    pub async fn next_frame(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(frame) = self.assembler.next_frame() {
                if self.debug {
                    eprintln!("Received response: {}", hex::encode(&frame));
                }
                return Ok(frame);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(CliError::Timeout);
            }
            let remaining = deadline.saturating_duration_since(now);
            let notification = time::timeout(remaining, self.notifications.next())
                .await
                .map_err(|_| CliError::Timeout)?
                .ok_or(CliError::Disconnected)?;
            if notification.uuid == self.notify_uuid {
                self.assembler.push(&notification.value);
            }
        }
    }
}

/// The two things driving an [`Operation`] needs from a transport.
///
/// A seam, not an abstraction for its own sake. [`run_op`] carries the retry
/// rules — CRC re-sends, discarding unsolicited frames, and the deadline that
/// covers a whole exchange rather than each read — and none of that could be
/// tested while it was welded to a concrete [`BleConnection`] holding a
/// `btleplug` peripheral. That code is subtle, it is duplicated in the Home
/// Assistant component, and this environment has no radio. With this trait a
/// scripted double exercises every branch.
pub trait Link {
    /// Write one complete frame, chunking as the transport requires.
    ///
    /// # Errors
    /// Returns an error if the write fails.
    async fn write_frame(&mut self, frame: &[u8]) -> Result<()>;

    /// Wait up to `timeout` for the next reassembled frame.
    ///
    /// # Errors
    /// Returns [`CliError::Timeout`] if none arrives in time, or
    /// [`CliError::Disconnected`] if the transport ends.
    async fn next_frame(&mut self, timeout: Duration) -> Result<Vec<u8>>;
}

impl Link for BleConnection {
    async fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        write_chunks(&self.peripheral, &self.write_char, frame, self.debug).await
    }

    async fn next_frame(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        Self::next_frame(self, timeout).await
    }
}

/// Drive a sans-IO [`Operation`] over a [`Link`]: write each frame the
/// operation produces, feed the response back, and recover from the two frames
/// that are recoverable — a CRC failure (re-send) and an unsolicited push
/// (discard and keep reading).
///
/// # Errors
/// Returns whatever the operation or the link reports, once it is past
/// recovering.
pub async fn run_op<L: Link + ?Sized, O: Operation>(link: &mut L, op: &mut O) -> Result<O::Output> {
    let mut step = op.start()?;
    loop {
        match step {
            Step::Write(frame) => {
                let mut crc_retries = 0_u32;
                let mut stray_frames = 0_u32;
                step = loop {
                    link.write_frame(&frame).await?;

                    // The deadline covers the whole wait, not each read. An
                    // unsolicited frame must not buy the lock another full
                    // timeout, or a chatty one postpones failure indefinitely.
                    let deadline = Instant::now() + RESPONSE_TIMEOUT;
                    let next = loop {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Err(CliError::Timeout);
                        }
                        let raw = link.next_frame(remaining).await?;
                        match op.handle_frame(&raw) {
                            Ok(next) => break Some(next),
                            // Not our reply: the lock pushes notifications on
                            // the characteristic it answers on. Discard it and
                            // keep reading — crucially without re-sending,
                            // which is what separates this from a CRC failure.
                            Err(error)
                                if error.is_stale_frame()
                                    && stray_frames < policy::MAX_STRAY_FRAMES =>
                            {
                                stray_frames += 1;
                                tracing::debug!(
                                    %error,
                                    stray_frames,
                                    "discarding an unsolicited frame and continuing to wait"
                                );
                            }
                            // Ask the error whether a re-send could help rather
                            // than matching variants here, so the CLI and the
                            // Home Assistant component classify failures
                            // identically.
                            Err(error)
                                if error.is_retryable() && crc_retries < policy::CRC_RETRIES =>
                            {
                                crc_retries += 1;
                                time::sleep(policy::CRC_RETRY_DELAY).await;
                                break None;
                            }
                            Err(error) => return Err(error.into()),
                        }
                    };
                    if let Some(next) = next {
                        break next;
                    }
                };
            }
            Step::Done(output) => return Ok(output),
        }
    }
}

/// Write a frame to the lock in 20-byte chunks, pacing writes slightly so
/// slower controllers do not drop packets.
async fn write_chunks(
    peripheral: &Peripheral,
    write_char: &Characteristic,
    data: &[u8],
    debug: bool,
) -> Result<()> {
    if debug {
        eprintln!("Sending command: {}", hex::encode(data));
    }
    for chunk in data.chunks(policy::WRITE_CHUNK) {
        peripheral
            .write(write_char, chunk, WriteType::WithoutResponse)
            .await?;
        time::sleep(policy::WRITE_CHUNK_DELAY).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Link, RESPONSE_TIMEOUT, run_op, time};
    use crate::error::{CliError, Result};
    use std::collections::VecDeque;
    use std::time::Duration;
    use ttlock_core::credential::AesKey;
    use ttlock_core::ops::{LockState, StatusOp};
    use ttlock_core::packet::{
        COMM_SEARCH_BICYCLE_STATUS, COMM_UNLOCK, LockVersion, build_envelope,
    };

    fn test_key() -> AesKey {
        AesKey::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    }

    /// A lock-to-app frame (CRLF stripped, as the assembler delivers it) whose
    /// decrypted plaintext is `plain`.
    fn frame(plain: &[u8]) -> Result<Vec<u8>> {
        let mut wire = build_envelope(LockVersion::default(), plain[0], plain, &test_key())?;
        wire.truncate(wire.len().saturating_sub(2));
        Ok(wire)
    }

    fn status_reply(state: u8) -> Result<Vec<u8>> {
        frame(&[COMM_SEARCH_BICYCLE_STATUS, 0x01, 0x63, state])
    }

    /// An unsolicited push: a real frame, correctly encrypted and CRC'd, that is
    /// simply not the reply being awaited.
    fn unsolicited_push() -> Result<Vec<u8>> {
        frame(&[COMM_UNLOCK, 0x01, 0x00, 0x00])
    }

    fn corrupt_crc(mut raw: Vec<u8>) -> Vec<u8> {
        if let Some(last) = raw.last_mut() {
            *last ^= 0xff;
        }
        raw
    }

    /// A [`Link`] that replays a script instead of talking to a radio.
    ///
    /// Records every frame written so a test can assert not just the outcome but
    /// *how many times* something was sent — which is the whole difference
    /// between the CRC path (re-send) and the stray-frame path (do not).
    struct ScriptedLink {
        responses: VecDeque<Vec<u8>>,
        writes: Vec<Vec<u8>>,
        /// Total time the caller has asked to wait, to check that a deadline is
        /// carried across reads rather than restarted on each one.
        requested: Vec<Duration>,
        /// How long each read "takes". Zero unless a test is measuring the
        /// deadline, so other tests are not fighting the clock.
        read_cost: Duration,
    }

    impl ScriptedLink {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses: responses.into(),
                writes: Vec::new(),
                requested: Vec::new(),
                read_cost: Duration::ZERO,
            }
        }

        /// Make each read consume `cost` of the caller's budget, as a real one
        /// would. Only meaningful under `#[tokio::test(start_paused = true)]`,
        /// where `sleep` advances the clock instantly.
        const fn costing(mut self, cost: Duration) -> Self {
            self.read_cost = cost;
            self
        }
    }

    impl Link for ScriptedLink {
        // `clippy::unused_async_trait_impl` fires here on an `async` that is not
        // optional: the `Link` trait declares these methods `async`, so an impl
        // must match even when it has nothing to await.
        //
        // Clippy's suggested rewrite is to return `impl Future` and wrap the body
        // in `std::future::ready`. That reads fine for a one-liner like this one,
        // but not for the sibling double in `oplog.rs`, whose body uses `?` and
        // would need an immediately-invoked closure to keep it — worse code, in
        // test scaffolding, to satisfy a lint about test scaffolding. Both doubles
        // therefore allow it and stay the same shape.
        //
        // `unknown_lints` is load-bearing rather than defensive: the lint is new
        // in Rust 1.98, the flake currently pins 1.97, and 1.97 rejects the bare
        // name outright with `error: unknown lint`. Both toolchains are clean with
        // it. It can go once the pinned Rust reaches 1.98.
        //
        // AGENTS.md requires an `allow` to carry strong reasoning and explicit
        // confirmation; this one was raised and approved rather than assumed.
        #[allow(unknown_lints, clippy::unused_async_trait_impl)]
        async fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
            self.writes.push(frame.to_vec());
            Ok(())
        }

        async fn next_frame(&mut self, timeout: Duration) -> Result<Vec<u8>> {
            self.requested.push(timeout);
            if !self.read_cost.is_zero() {
                time::sleep(self.read_cost).await;
            }
            self.responses.pop_front().ok_or(CliError::Timeout)
        }
    }

    #[tokio::test]
    async fn a_clean_exchange_writes_once() -> Result<()> {
        let mut link = ScriptedLink::new(vec![status_reply(0)?]);
        let mut op = StatusOp::new(test_key(), LockVersion::default());

        assert_eq!(run_op(&mut link, &mut op).await?, LockState::Locked);
        assert_eq!(link.writes.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_crc_failure_re_sends_the_same_frame() -> Result<()> {
        let mut link = ScriptedLink::new(vec![corrupt_crc(status_reply(0)?), status_reply(0)?]);
        let mut op = StatusOp::new(test_key(), LockVersion::default());

        assert_eq!(run_op(&mut link, &mut op).await?, LockState::Locked);
        // Two identical writes: re-sending is the correct response to corruption,
        // and it is safe because the operation checks the CRC before advancing.
        assert_eq!(link.writes.len(), 2);
        assert_eq!(link.writes.first(), link.writes.get(1));
        Ok(())
    }

    #[tokio::test]
    async fn an_unsolicited_frame_is_skipped_without_re_sending() -> Result<()> {
        let mut link = ScriptedLink::new(vec![unsolicited_push()?, status_reply(1)?]);
        let mut op = StatusOp::new(test_key(), LockVersion::default());

        assert_eq!(run_op(&mut link, &mut op).await?, LockState::Unlocked);
        // Exactly one write. This is the property that separates a push from a
        // CRC failure: re-sending here would leave the lock answering a command
        // we had already asked, putting the exchange one frame behind for good.
        assert_eq!(link.writes.len(), 1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn skipping_a_push_does_not_extend_the_deadline() -> Result<()> {
        // Each read burns a third of the budget. On a paused clock that is
        // exact, so the assertion below is about the arithmetic rather than
        // about how fast the test machine happens to be.
        let cost = RESPONSE_TIMEOUT / 3;
        let mut link = ScriptedLink::new(vec![unsolicited_push()?, status_reply(0)?]).costing(cost);
        let mut op = StatusOp::new(test_key(), LockVersion::default());
        run_op(&mut link, &mut op).await?;

        let second = link.requested.get(1).copied().unwrap_or(RESPONSE_TIMEOUT);
        // The second read gets the *remainder*. Restarting the deadline would
        // hand it the full timeout again, and a chatty lock could then postpone
        // failure indefinitely — so this must be strictly less.
        assert!(
            second <= RESPONSE_TIMEOUT.saturating_sub(cost),
            "deadline restarted: second read got {second:?} of a {RESPONSE_TIMEOUT:?} budget"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_flood_of_unsolicited_frames_eventually_fails() -> Result<()> {
        // Bounded on purpose: an unlimited skip turns a genuine desynchronization
        // into a silent timeout, which is a worse diagnosis than an error naming
        // the command that did not match.
        let mut responses = Vec::new();
        for _ in 0..ttlock_core::policy::MAX_STRAY_FRAMES + 2 {
            responses.push(unsolicited_push()?);
        }
        responses.push(status_reply(0)?);

        let mut link = ScriptedLink::new(responses);
        let mut op = StatusOp::new(test_key(), LockVersion::default());
        assert!(run_op(&mut link, &mut op).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn a_rejected_command_is_not_retried() -> Result<()> {
        // The lock decrypted the command and refused it; identical bytes get
        // refused identically, and retrying only drains its batteries.
        let mut link = ScriptedLink::new(vec![frame(&[COMM_SEARCH_BICYCLE_STATUS, 0x00, 0, 0])?]);
        let mut op = StatusOp::new(test_key(), LockVersion::default());

        assert!(run_op(&mut link, &mut op).await.is_err());
        assert_eq!(link.writes.len(), 1);
        Ok(())
    }
}
