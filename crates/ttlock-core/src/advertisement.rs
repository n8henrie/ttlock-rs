//! Parsing the manufacturer-specific data in a `TTLock` advertisement.
//!
//! Locks broadcast their state continuously, so lock/unlock status and battery
//! can be tracked without ever connecting — which matters because connecting is
//! slow and drains the lock's batteries.
//!
//! Note that the `0x1910` service UUID is *not* advertised; it only appears in
//! the GATT table after connecting. Scans must therefore be unfiltered and
//! locks identified from this payload.
//!
//! # Why this is a sum type
//!
//! Not every payload can carry a bolt position. Pre-V3 protocol families and
//! the V2S line have no flags byte at all, and a firmware-update beacon is not a
//! lock report in any sense. Modelling the result as a struct of independent
//! `Option`s let those cases produce a *fabricated* reading — whatever byte
//! happened to follow the header — and made "too short to parse" indistinguish-
//! able from "parsed, and reported nothing". [`Advertisement`] instead names the
//! shapes the wire actually produces, so a bolt position exists only where the
//! format guarantees one.

use std::collections::HashMap;

use crate::packet::LockVersion;

/// Which way the bolt is sitting.
///
/// A named pair rather than a `bool`. The flag on the wire means *unlocked*
/// while every consumer reasons in terms of *locked*, so the value was being
/// inverted in the parser and again in the tracker; one type that says which is
/// which turns a missed inversion into a compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bolt {
    /// The bolt is thrown.
    Locked,
    /// The bolt is retracted.
    Unlocked,
}

impl Bolt {
    /// Whether the bolt is thrown.
    #[must_use]
    pub const fn is_locked(self) -> bool {
        matches!(self, Self::Locked)
    }
}

/// A battery charge level, 0-100.
///
/// Validated because a byte outside that range is not a low battery, it is
/// evidence of a misparse — which is exactly how a stale manufacturer-data entry
/// announced itself: a reading that jumped between 62 and 100 microseconds
/// apart. Out-of-range values become "not reported" rather than a plausible
/// looking number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Percent(u8);

impl Percent {
    /// Wrap a raw byte, rejecting anything above 100.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value <= 100 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// The percentage.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Which lock an advertisement came from, and which protocol dialect it speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockIdentity {
    /// The lock's MAC address, recovered from the last six bytes of the payload.
    ///
    /// Worth having even when the OS reports an address: macOS hides BLE
    /// addresses behind opaque UUIDs, so this is the only way to identify a
    /// specific lock there.
    pub address: Option<String>,
    /// Protocol version to build outgoing packets with.
    ///
    /// Not cosmetic: the lock validates this header and rejects commands built
    /// with the wrong version, which surfaces as
    /// [`TtlockError::CommandFailed`](crate::error::TtlockError::CommandFailed)
    /// rather than as anything connection-shaped.
    pub version: LockVersion,
}

/// What a lock reported about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockStatus {
    /// The bolt position.
    pub bolt: Bolt,
    /// Battery charge, or `None` if the byte was not a valid percentage.
    pub battery: Option<Percent>,
    /// `true` when the lock has unread operation records queued.
    pub has_events: bool,
    /// `true` when the lock is in pairing/setting mode, i.e. unpaired and
    /// accepting an initialization.
    pub is_setting_mode: bool,
}

/// One parsed advertisement payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advertisement {
    /// Not a `TTLock` payload, or too short to identify one. Advertisements
    /// arrive continuously from every nearby device, so this is an ordinary
    /// result rather than an error.
    Unrecognized,
    /// A lock in firmware-update mode. Identifiable as ours, but it reports no
    /// state while it is in DFU.
    Dfu,
    /// A lock whose protocol family carries no status flags, so nothing can be
    /// said about the bolt. Reporting one anyway is the bug this variant exists
    /// to prevent.
    Stateless(LockIdentity),
    /// A lock reporting its state.
    Stateful {
        /// Which lock, and which dialect.
        identity: LockIdentity,
        /// What it reported.
        status: LockStatus,
    },
}

impl Advertisement {
    /// The lock's identity, when the payload identified one.
    #[must_use]
    pub const fn identity(&self) -> Option<&LockIdentity> {
        match self {
            Self::Stateless(identity) | Self::Stateful { identity, .. } => Some(identity),
            Self::Unrecognized | Self::Dfu => None,
        }
    }

    /// The reported state, when the payload carried one.
    #[must_use]
    pub const fn status(&self) -> Option<&LockStatus> {
        match self {
            Self::Stateful { status, .. } => Some(status),
            Self::Unrecognized | Self::Dfu | Self::Stateless(_) => None,
        }
    }

    /// The protocol version, when known.
    #[must_use]
    pub fn lock_version(&self) -> Option<LockVersion> {
        self.identity().map(|identity| identity.version)
    }

    /// The decoded MAC address, when the payload carried one.
    #[must_use]
    pub fn address(&self) -> Option<&str> {
        self.identity()
            .and_then(|identity| identity.address.as_deref())
    }

    /// The bolt position, when the payload reported one.
    #[must_use]
    pub fn bolt(&self) -> Option<Bolt> {
        self.status().map(|status| status.bolt)
    }

    /// The battery level, when the payload reported a valid one.
    #[must_use]
    pub fn battery(&self) -> Option<Percent> {
        self.status().and_then(|status| status.battery)
    }

    /// Whether this payload matches an expected address, case-insensitively.
    fn matches(&self, expected: Option<&str>) -> bool {
        match (self.address(), expected) {
            (Some(address), Some(expected)) => address.eq_ignore_ascii_case(expected),
            _ => false,
        }
    }

    /// How useful this payload is, for choosing between several on one device.
    /// Higher wins.
    const fn rank(&self, matches: bool) -> u8 {
        match self {
            Self::Stateful { .. } if matches => 5,
            Self::Stateful { .. } => 4,
            Self::Stateless(_) if matches => 3,
            Self::Stateless(_) => 2,
            Self::Dfu => 1,
            Self::Unrecognized => 0,
        }
    }
}

/// Parse a BLE manufacturer-data map, as handed over by `btleplug` or `bleak`,
/// choosing the most informative entry.
///
/// A device can carry more than one entry, and the map is *accumulated* by the
/// Bluetooth stack rather than replaced per advertisement — so an entry that
/// stopped being refreshed sits there indefinitely next to a live one. Picking
/// an arbitrary one (`.iter().next()` on a `HashMap`, which reorders on resize)
/// meant reporting a frozen bolt position for as long as that ordering held.
///
/// Selection is therefore explicit and total: prefer a payload carrying state,
/// prefer one whose decoded MAC matches `expected_address`, and break remaining
/// ties on the company identifier so the result never depends on iteration
/// order.
///
/// The company identifier is not a real Bluetooth SIG assignment here — `TTLock`
/// packs protocol bytes into it — so it is prepended back onto each payload
/// before parsing.
#[must_use]
pub fn parse_manufacturer_map<S: std::hash::BuildHasher>(
    manufacturer_data: &HashMap<u16, Vec<u8>, S>,
    expected_address: Option<&str>,
) -> Advertisement {
    let mut best: Option<(u8, u16, Advertisement)> = None;

    for (company_id, bytes) in manufacturer_data {
        let mut full = Vec::with_capacity(bytes.len() + 2);
        full.extend_from_slice(&company_id.to_le_bytes());
        full.extend_from_slice(bytes);
        let parsed = parse_manufacturer_data(&full);
        let rank = parsed.rank(parsed.matches(expected_address));

        let better = best.as_ref().is_none_or(|(best_rank, best_id, _)| {
            rank > *best_rank || (rank == *best_rank && company_id < best_id)
        });
        if better {
            best = Some((rank, *company_id, parsed));
        }
    }

    best.map_or(Advertisement::Unrecognized, |(_, _, parsed)| parsed)
}

/// Whether this protocol family carries a status flags byte at all.
///
/// Families below 5 predate it, and V2S (`5.1`) omits it. Reading the byte that
/// happens to follow the header on those produces a bolt position out of thin
/// air.
const fn carries_status(protocol_type: u8, protocol_version: u8) -> bool {
    protocol_type >= 5 && !(protocol_type == 5 && protocol_version == 1)
}

/// Parse a raw manufacturer-data payload, company identifier included.
#[must_use]
pub fn parse_manufacturer_data(data: &[u8]) -> Advertisement {
    // Below this there is not enough room for the header, the flags byte, the
    // battery byte and the trailing MAC, so nothing can be said with confidence.
    if data.len() < 15 {
        return Advertisement::Unrecognized;
    }

    let mut protocol_type = data[0];
    let mut protocol_version = data[1];

    if (protocol_type == 18 && protocol_version == 25)
        || (protocol_type == 0xff && protocol_version == 0xff)
    {
        return Advertisement::Dfu;
    }

    // Two layouts: V3 puts the scene immediately after the header, everything
    // else repeats the version further in.
    let (scene, offset) = if protocol_type == 5 && protocol_version == 3 {
        (data[2], 3)
    } else {
        protocol_type = data[4];
        protocol_version = data[5];
        (data[7], 8)
    };

    // The firmware appends the address in reverse byte order.
    let address = data.get(data.len() - 6..).map(|tail| {
        tail.iter()
            .rev()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<String>>()
            .join(":")
    });

    let identity = LockIdentity {
        address,
        version: LockVersion {
            protocol_type,
            protocol_version,
            scene,
            group_id: 1,
            org_id: 1,
        },
    };

    if !carries_status(protocol_type, protocol_version) {
        return Advertisement::Stateless(identity);
    }

    let (Some(&flags), Some(&battery)) = (data.get(offset), data.get(offset + 1)) else {
        return Advertisement::Stateless(identity);
    };

    Advertisement::Stateful {
        identity,
        status: LockStatus {
            bolt: if flags & 0x01 == 0 {
                Bolt::Locked
            } else {
                Bolt::Unlocked
            },
            battery: Percent::new(battery),
            has_events: flags & 0x02 != 0,
            is_setting_mode: flags & 0x04 != 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{Advertisement, Bolt, Percent, parse_manufacturer_data, parse_manufacturer_map};
    use std::collections::HashMap;

    /// The reserved-looking documentation address, reversed: the firmware
    /// appends the MAC to the payload in reverse byte order. Never a real
    /// device's address — `scripts/check-secrets.sh` enforces that.
    const LOCK_MAC: [u8; 6] = [0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa];
    const LOCK_ADDRESS: &str = "AA:BB:CC:DD:EE:FF";

    /// A V3 (`5.3`) payload, company identifier included, as the parser sees it.
    fn v3_payload(flags: u8, battery: u8) -> Vec<u8> {
        let mut data = vec![5, 3, 2, flags, battery];
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&LOCK_MAC);
        data
    }

    /// The same payload split as a manufacturer-data map entry: the company
    /// identifier is the first two bytes, little-endian.
    fn as_entry(payload: &[u8]) -> (u16, Vec<u8>) {
        (
            u16::from_le_bytes([payload[0], payload[1]]),
            payload[2..].to_vec(),
        )
    }

    #[test]
    fn parses_a_v3_payload() {
        let parsed = parse_manufacturer_data(&v3_payload(0x03, 62));
        assert_eq!(parsed.bolt(), Some(Bolt::Unlocked));
        assert_eq!(parsed.battery(), Percent::new(62));
        assert_eq!(parsed.address(), Some(LOCK_ADDRESS));
        let status = parsed.status().copied();
        assert_eq!(status.map(|s| s.has_events), Some(true));
        assert_eq!(status.map(|s| s.is_setting_mode), Some(false));
    }

    #[test]
    fn bolt_polarity_follows_the_flag() {
        // Bit 0x01 means *unlocked* on the wire. Getting this backwards reports
        // a door as secured while it stands open, so pin both directions.
        assert_eq!(
            parse_manufacturer_data(&v3_payload(0x00, 62)).bolt(),
            Some(Bolt::Locked)
        );
        assert_eq!(
            parse_manufacturer_data(&v3_payload(0x01, 62)).bolt(),
            Some(Bolt::Unlocked)
        );
    }

    /// A non-V3 payload. Anything whose leading header is not `5.3` repeats the
    /// real protocol type and version at offsets 4 and 5, with the scene at 7
    /// and the flags at 8.
    fn other_family_payload(
        protocol_type: u8,
        protocol_version: u8,
        flags: u8,
        battery: u8,
    ) -> Vec<u8> {
        let mut data = vec![
            0x11,
            0x22,
            0x33,
            0x44,
            protocol_type,
            protocol_version,
            0x00,
            2,
            flags,
            battery,
        ];
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&LOCK_MAC);
        data
    }

    #[test]
    fn families_without_a_flags_byte_report_no_bolt_position() {
        // V2S is `5.1`, and anything below family 5 predates the flags byte.
        // Previously these read whatever byte followed the header and presented
        // it as a bolt position — a fabricated reading, on a door.
        for (protocol_type, protocol_version) in [(5_u8, 1_u8), (3, 1), (4, 9)] {
            let parsed = parse_manufacturer_data(&other_family_payload(
                protocol_type,
                protocol_version,
                0x01,
                62,
            ));
            assert!(
                matches!(parsed, Advertisement::Stateless(_)),
                "{protocol_type}.{protocol_version} should carry no status"
            );
            assert_eq!(parsed.bolt(), None);
            // Still identified as a lock, so the address and version survive.
            assert_eq!(parsed.address(), Some(LOCK_ADDRESS));
        }
    }

    #[test]
    fn later_families_still_report_status() {
        // The exclusion is specific, not "anything that is not 5.3": a newer
        // family must not silently lose its bolt position.
        let parsed = parse_manufacturer_data(&other_family_payload(10, 1, 0x00, 62));
        assert_eq!(parsed.bolt(), Some(Bolt::Locked));
        assert_eq!(parsed.battery(), Percent::new(62));
    }

    #[test]
    fn dfu_and_short_payloads_are_not_locks() {
        assert_eq!(
            parse_manufacturer_data(&[18, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Advertisement::Dfu
        );
        assert_eq!(parse_manufacturer_data(&[0xff; 15]), Advertisement::Dfu);
        assert_eq!(
            parse_manufacturer_data(&[5, 3, 2]),
            Advertisement::Unrecognized
        );
        assert_eq!(parse_manufacturer_data(&[]), Advertisement::Unrecognized);
    }

    #[test]
    fn implausible_battery_is_reported_as_absent_not_as_a_number() {
        let parsed = parse_manufacturer_data(&v3_payload(0x01, 200));
        assert_eq!(parsed.battery(), None);
        // The bolt reading is still usable; only the battery byte was rejected.
        assert_eq!(parsed.bolt(), Some(Bolt::Unlocked));
    }

    #[test]
    fn a_stale_entry_never_wins_over_a_live_one() {
        // The bug this exists to prevent: a device carrying two manufacturer
        // entries, one of which stopped being refreshed. `.iter().next()` picked
        // between them by hash order, so state froze for as long as that
        // ordering held — and the battery flipped between the two readings.
        let (live_id, live) = as_entry(&v3_payload(0x00, 62));
        let stale = vec![0u8; 20]; // parses as Unrecognized

        // Build the map both ways round; neither insertion order may matter.
        for reversed in [false, true] {
            let mut pair = vec![(live_id, live.clone()), (0x9999, stale.clone())];
            if reversed {
                pair.reverse();
            }
            let map: HashMap<u16, Vec<u8>> = pair.into_iter().collect();
            let parsed = parse_manufacturer_map(&map, Some(LOCK_ADDRESS));
            assert_eq!(parsed.bolt(), Some(Bolt::Locked));
            assert_eq!(parsed.battery(), Percent::new(62));
        }
    }

    #[test]
    fn the_entry_matching_the_expected_address_wins() {
        let (ours_id, ours) = as_entry(&v3_payload(0x00, 62));

        // Another lock's payload, same protocol, different MAC and battery.
        let mut other = v3_payload(0x01, 99);
        let length = other.len();
        other[length - 6..].copy_from_slice(&[0xf0, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]);
        let (other_id, other_bytes) = as_entry(&other);
        // Same company identifier, so only the address can break the tie.
        assert_eq!(ours_id, other_id);

        let map: HashMap<u16, Vec<u8>> = [(ours_id, ours), (other_id.wrapping_add(1), other_bytes)]
            .into_iter()
            .collect();
        let parsed = parse_manufacturer_map(&map, Some(LOCK_ADDRESS));
        assert_eq!(parsed.address(), Some(LOCK_ADDRESS));
        assert_eq!(parsed.bolt(), Some(Bolt::Locked));
    }

    #[test]
    fn an_empty_map_is_unrecognized() {
        let map: HashMap<u16, Vec<u8>> = HashMap::new();
        assert_eq!(
            parse_manufacturer_map(&map, None),
            Advertisement::Unrecognized
        );
    }
}
