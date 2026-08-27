//! What we believe about a lock, and why.
//!
//! [`LockTracker`] is the sans-IO state machine one layer above
//! [`crate::ops`]: operations own a single protocol exchange, this owns the
//! lock's *reported state* across many of them. It exists because the MQTT
//! daemon and the Home Assistant component had implemented the same rules
//! twice, in two languages, and drifted apart three separate times — a missing
//! protocol version, a missing in-progress state, and availability that could
//! never expire.
//!
//! Like the rest of this crate it performs no I/O and reads no clock: the
//! caller supplies monotonic milliseconds, exactly as it supplies bytes to
//! [`crate::ops::Operation`]. That is what lets one implementation back a
//! tokio daemon and a Home Assistant coordinator.
//!
//! # The rule
//!
//! **Never report a bolt position that has not been observed.** Sending a
//! command produces [`ReportedState::Locking`] or [`ReportedState::Unlocking`],
//! which claim only that a command is in flight. The bolt itself moves only on
//! evidence: the lock's own acknowledgement (encrypted, CRC-checked, carrying a
//! success code) or an advertisement. This is a safety property, not a
//! preference — an automation that locks a door and trusts an optimistic
//! `LOCKED` would leave it open while reporting it secured.

use std::time::Duration;

use crate::advertisement::{Advertisement, Bolt, Percent};
use crate::ops::Actuation;
use crate::packet::LockVersion;

/// The state to report to a home-automation system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedState {
    /// The bolt was observed thrown.
    Locked,
    /// The bolt was observed retracted.
    Unlocked,
    /// A lock command is in flight. Says nothing about the bolt.
    Locking,
    /// An unlock command is in flight. Says nothing about the bolt.
    Unlocking,
}

impl ReportedState {
    /// The payload string used on the MQTT state topic, and the matching
    /// `state_*` keys in Home Assistant's discovery config.
    #[must_use]
    pub const fn payload(self) -> &'static str {
        match self {
            Self::Locked => "LOCKED",
            Self::Unlocked => "UNLOCKED",
            Self::Locking => "LOCKING",
            Self::Unlocking => "UNLOCKING",
        }
    }
}

/// Which observable facts changed, so a caller can publish only those.
///
/// Returned by every mutating method. A caller that wants to publish
/// unconditionally — after reconnecting to a broker, say — should ignore this
/// and read the accessors directly; see [`LockTracker::reported_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changed {
    /// [`LockTracker::reported_state`] differs.
    pub state: bool,
    /// [`LockTracker::available`] differs.
    pub available: bool,
    /// [`LockTracker::battery`] differs.
    pub battery: bool,
}

impl Changed {
    /// Everything, for a caller that must publish unconditionally — after
    /// reconnecting to a broker whose retained values may be stale or absent.
    pub const ALL: Self = Self {
        state: true,
        available: true,
        battery: true,
    };

    /// Whether anything at all changed.
    #[must_use]
    pub const fn any(self) -> bool {
        self.state || self.available || self.battery
    }
}

/// What is known about the bolt.
///
/// One value rather than an `Option<Bolt>` beside an `Option<Actuation>`: that
/// pairing had four combinations expressing three states, and the fourth —
/// "a command is in flight" with no way to say what preceded it — was carried
/// implicitly. Here the module's rule (*never report a bolt position that has
/// not been observed*) is the shape of the type rather than a comment above it,
/// and [`LockTracker::reported_state`] becomes total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Knowledge {
    /// Nothing has ever reported a position.
    #[default]
    Unknown,
    /// A position was observed, and no command is in flight.
    Observed(Bolt),
    /// A command is in flight; its outcome is not yet known.
    InProgress {
        /// The last observed position, still worth showing underneath a
        /// "Locking…" label.
        last_observed: Option<Bolt>,
        /// Which way the in-flight command is moving the bolt.
        action: Actuation,
    },
}

impl Knowledge {
    /// The last observed position, ignoring any command in flight.
    const fn observed(self) -> Option<Bolt> {
        match self {
            Self::Unknown => None,
            Self::Observed(bolt) => Some(bolt),
            Self::InProgress { last_observed, .. } => last_observed,
        }
    }

    /// The command in flight, if any.
    const fn pending(self) -> Option<Actuation> {
        match self {
            Self::InProgress { action, .. } => Some(action),
            Self::Unknown | Self::Observed(_) => None,
        }
    }
}

/// An immutable view of everything a caller can publish, used to diff a
/// mutation against the state that preceded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    state: Option<ReportedState>,
    available: bool,
    battery: Option<Percent>,
}

/// Tracks one lock's state from advertisements and command outcomes.
///
/// See the [module documentation](self) for the rule this enforces.
#[derive(Debug, Default)]
pub struct LockTracker {
    /// Everything believed about the bolt, in one value.
    knowledge: Knowledge,
    battery: Option<Percent>,
    version: Option<LockVersion>,
    available: bool,
    /// Monotonic milliseconds at the last advertisement, as supplied by the
    /// caller.
    last_seen_ms: Option<u64>,
}

impl LockTracker {
    /// A tracker that has heard nothing yet: unavailable, with no known bolt
    /// position.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    const fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: self.reported_state(),
            available: self.available,
            battery: self.battery,
        }
    }

    fn diff(before: Snapshot, after: Snapshot) -> Changed {
        Changed {
            state: before.state != after.state,
            available: before.available != after.available,
            battery: before.battery != after.battery,
        }
    }

    /// Record an advertisement, received at `now_ms` on the caller's monotonic
    /// clock.
    ///
    /// Advertisements are the only passive evidence there is, so this both
    /// refreshes availability and settles any command that was in flight — an
    /// observed bolt position is exactly what such a command was waiting for,
    /// whether or not it reported success. An advertisement that carries no
    /// bolt position leaves a pending command alone.
    pub fn on_advertisement(&mut self, now_ms: u64, advertisement: &Advertisement) -> Changed {
        let before = self.snapshot();

        if let Some(status) = advertisement.status() {
            // Observing a position settles whatever was in flight: that
            // observation is exactly what the command was waiting for, whether
            // or not the command itself reported success.
            self.knowledge = Knowledge::Observed(status.bolt);
            if let Some(battery) = status.battery {
                self.battery = Some(battery);
            }
        }
        if let Some(version) = advertisement.lock_version() {
            self.version = Some(version);
        }
        self.last_seen_ms = Some(now_ms);
        self.available = true;

        Self::diff(before, self.snapshot())
    }

    /// Record that a command has been sent and its outcome is not yet known.
    pub fn on_command_started(&mut self, action: Actuation) -> Changed {
        let before = self.snapshot();
        self.knowledge = Knowledge::InProgress {
            last_observed: self.knowledge.observed(),
            action,
        };
        Self::diff(before, self.snapshot())
    }

    /// Record that the lock acknowledged a command.
    ///
    /// This is the one path other than an advertisement that may move the bolt,
    /// and it is trustworthy for the same reason: the acknowledgement is
    /// encrypted, CRC-checked, and carries a success code that
    /// [`crate::packet::parse_success_response`] requires to be 1. It also
    /// counts as hearing from the lock, so it refreshes availability.
    pub fn on_command_acknowledged(&mut self, now_ms: u64, action: Actuation) -> Changed {
        let before = self.snapshot();
        self.knowledge = Knowledge::Observed(match action {
            Actuation::Lock => Bolt::Locked,
            Actuation::Unlock => Bolt::Unlocked,
        });
        self.last_seen_ms = Some(now_ms);
        self.available = true;
        Self::diff(before, self.snapshot())
    }

    /// Record that a command failed, leaving the outcome genuinely unknown.
    ///
    /// Deliberately does *not* revert to the previous bolt position. A timeout
    /// or a mid-exchange disconnect means "we do not know", not "nothing
    /// happened" — the write may well have landed with only the reply lost.
    /// The state stays in progress until an advertisement settles it, or until
    /// the lock goes unavailable. It therefore changes nothing — the method
    /// exists so that decision is written at every call site rather than being
    /// an absence someone later "fixes".
    pub fn on_command_failed(&mut self) -> Changed {
        let before = self.snapshot();
        Self::diff(before, self.snapshot())
    }

    /// Give back time during which the radio could not possibly have heard an
    /// advertisement, because it was busy connecting.
    ///
    /// Without this, a retry chain longer than the offline timeout flips the
    /// lock to unavailable and straight back every time it is used.
    pub fn credit_blind_time(&mut self, blind: Duration) {
        if let Some(last_seen) = self.last_seen_ms {
            let blind_ms = u64::try_from(blind.as_millis()).unwrap_or(u64::MAX);
            self.last_seen_ms = Some(last_seen.saturating_add(blind_ms));
        }
    }

    /// Expire availability if nothing has been heard for `offline_after`.
    ///
    /// For callers that own a timer — the MQTT daemon polls this. Callers whose
    /// platform tells them directly should use [`Self::on_unavailable`]
    /// instead; both funnel into the same rules.
    pub fn poll_availability(&mut self, now_ms: u64, offline_after: Duration) -> Changed {
        let timeout_ms = u64::try_from(offline_after.as_millis()).unwrap_or(u64::MAX);
        let expired = self
            .last_seen_ms
            .is_none_or(|seen| now_ms.saturating_sub(seen) >= timeout_ms);
        if expired {
            self.on_unavailable()
        } else {
            Changed::default()
        }
    }

    /// Record that the lock can no longer be heard.
    ///
    /// Clearing the pending command here is what stops an honest "outcome
    /// unknown" from decaying into a permanent `Locking…`: once nothing can be
    /// heard, no advertisement is coming to settle it, and an entity that
    /// admits it is unavailable must not also claim to be mid-command.
    pub fn on_unavailable(&mut self) -> Changed {
        let before = self.snapshot();
        self.available = false;
        // Drop any in-flight command but keep what was last observed: nothing
        // is coming to settle it, and an entity that admits it is unavailable
        // must not also claim to be mid-command.
        if let Some(bolt) = self.knowledge.observed() {
            self.knowledge = Knowledge::Observed(bolt);
        } else {
            self.knowledge = Knowledge::Unknown;
        }
        Self::diff(before, self.snapshot())
    }

    /// What to report, or `None` if nothing has ever been observed.
    #[must_use]
    pub const fn reported_state(&self) -> Option<ReportedState> {
        match self.knowledge {
            Knowledge::Unknown => None,
            Knowledge::Observed(Bolt::Locked) => Some(ReportedState::Locked),
            Knowledge::Observed(Bolt::Unlocked) => Some(ReportedState::Unlocked),
            Knowledge::InProgress {
                action: Actuation::Lock,
                ..
            } => Some(ReportedState::Locking),
            Knowledge::InProgress {
                action: Actuation::Unlock,
                ..
            } => Some(ReportedState::Unlocking),
        }
    }

    /// The last observed bolt position, ignoring any command in flight.
    ///
    /// Home Assistant wants this and [`Self::pending`] separately: a lock that
    /// is mid-command still displays its last known position underneath the
    /// "Locking…" label.
    #[must_use]
    pub const fn is_locked(&self) -> Option<bool> {
        match self.knowledge.observed() {
            Some(bolt) => Some(bolt.is_locked()),
            None => None,
        }
    }

    /// The command in flight, if any.
    #[must_use]
    pub const fn pending(&self) -> Option<Actuation> {
        self.knowledge.pending()
    }

    /// Whether the lock has been heard from recently.
    #[must_use]
    pub const fn available(&self) -> bool {
        self.available
    }

    /// Battery percentage from the most recent advertisement that carried one.
    #[must_use]
    pub const fn battery(&self) -> Option<u8> {
        match self.battery {
            Some(percent) => Some(percent.get()),
            None => None,
        }
    }

    /// Protocol version learned from advertisements.
    ///
    /// Commands must be built with this when it is known: the lock validates
    /// the version header and rejects a mismatch outright. Reading it from here
    /// rather than re-deriving it per consumer is what stops the original
    /// version-mismatch bug from recurring.
    #[must_use]
    pub const fn lock_version(&self) -> Option<LockVersion> {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use super::{LockTracker, ReportedState};
    use crate::advertisement::{Advertisement, Bolt, LockIdentity, LockStatus, Percent};
    use crate::ops::Actuation;
    use crate::packet::LockVersion;
    use std::time::Duration;

    /// `is_unlock: None` models an advertisement whose protocol family carries
    /// no flags byte — and therefore no battery byte either, since the two are
    /// adjacent on the wire.
    fn advertisement(is_unlock: Option<bool>, battery: Option<u8>) -> Advertisement {
        let identity = LockIdentity {
            address: None,
            version: LockVersion::default(),
        };
        match is_unlock {
            Some(unlocked) => Advertisement::Stateful {
                identity,
                status: LockStatus {
                    bolt: if unlocked {
                        Bolt::Unlocked
                    } else {
                        Bolt::Locked
                    },
                    battery: battery.and_then(Percent::new),
                    has_events: false,
                    is_setting_mode: false,
                },
            },
            None => Advertisement::Stateless(identity),
        }
    }

    #[test]
    fn starts_knowing_nothing() {
        let tracker = LockTracker::new();
        assert_eq!(tracker.reported_state(), None);
        assert_eq!(tracker.is_locked(), None);
        assert!(!tracker.available());
    }

    #[test]
    fn advertisement_sets_state_battery_and_availability() {
        let mut tracker = LockTracker::new();
        let changed = tracker.on_advertisement(1_000, &advertisement(Some(true), Some(97)));
        assert!(changed.state && changed.available && changed.battery);
        assert_eq!(tracker.reported_state(), Some(ReportedState::Unlocked));
        assert_eq!(tracker.battery(), Some(97));
        assert!(tracker.available());
    }

    #[test]
    fn command_reports_in_progress_without_touching_the_bolt() {
        let mut tracker = LockTracker::new();
        tracker.on_advertisement(0, &advertisement(Some(true), None));
        assert_eq!(tracker.is_locked(), Some(false));

        tracker.on_command_started(Actuation::Lock);
        assert_eq!(tracker.reported_state(), Some(ReportedState::Locking));
        // The bolt has not been observed to move, so it must still read as it did.
        assert_eq!(tracker.is_locked(), Some(false));
    }

    #[test]
    fn only_an_acknowledgement_commits_the_bolt() {
        let mut tracker = LockTracker::new();
        tracker.on_command_started(Actuation::Lock);
        assert_eq!(tracker.is_locked(), None);

        tracker.on_command_acknowledged(500, Actuation::Lock);
        assert_eq!(tracker.reported_state(), Some(ReportedState::Locked));
        assert_eq!(tracker.is_locked(), Some(true));
        assert!(tracker.available());
    }

    #[test]
    fn failure_stays_in_progress_rather_than_reverting() {
        let mut tracker = LockTracker::new();
        tracker.on_advertisement(0, &advertisement(Some(true), None));
        tracker.on_command_started(Actuation::Lock);
        tracker.on_command_failed();

        // "Outcome unknown", not "nothing happened".
        assert_eq!(tracker.reported_state(), Some(ReportedState::Locking));
        assert_eq!(tracker.is_locked(), Some(false));
    }

    #[test]
    fn advertisement_settles_a_failed_command() {
        let mut tracker = LockTracker::new();
        tracker.on_command_started(Actuation::Lock);
        tracker.on_command_failed();
        // The command failed, but it had in fact landed.
        tracker.on_advertisement(100, &advertisement(Some(false), None));
        assert_eq!(tracker.reported_state(), Some(ReportedState::Locked));
    }

    #[test]
    fn advertisement_without_bolt_position_leaves_a_command_pending() {
        let mut tracker = LockTracker::new();
        tracker.on_command_started(Actuation::Unlock);
        // Availability still refreshes — the lock was heard from — but nothing
        // about the bolt is learned, so the command stays in flight.
        let changed = tracker.on_advertisement(100, &advertisement(None, Some(50)));
        assert_eq!(tracker.reported_state(), Some(ReportedState::Unlocking));
        assert!(changed.available);
        assert!(!changed.state);
        // This assertion used to be `changed.battery`. A payload with no flags
        // byte has no battery byte either — they are adjacent on the wire — so
        // that combination was only ever reachable by hand-building the old
        // struct of independent `Option`s. The sum type makes it unrepresentable.
        assert!(!changed.battery);
    }

    #[test]
    fn going_unavailable_clears_a_pending_command() {
        let mut tracker = LockTracker::new();
        tracker.on_advertisement(0, &advertisement(Some(false), None));
        tracker.on_command_started(Actuation::Unlock);
        tracker.on_unavailable();

        // Otherwise a failed command on a lock that then goes silent shows
        // "Unlocking…" forever.
        assert!(!tracker.available());
        assert_eq!(tracker.reported_state(), Some(ReportedState::Locked));
    }

    #[test]
    fn availability_expires_only_after_the_timeout() {
        let mut tracker = LockTracker::new();
        tracker.on_advertisement(1_000, &advertisement(Some(false), None));

        assert!(
            !tracker
                .poll_availability(5_000, Duration::from_secs(10))
                .any()
        );
        assert!(tracker.available());

        assert!(
            tracker
                .poll_availability(11_000, Duration::from_secs(10))
                .available
        );
        assert!(!tracker.available());
    }

    #[test]
    fn a_tracker_that_never_heard_anything_expires_immediately() {
        let mut tracker = LockTracker::new();
        tracker.on_advertisement(0, &advertisement(Some(false), None));
        tracker.on_unavailable();
        // last_seen is set, but availability already false: no spurious change.
        assert!(
            !tracker
                .poll_availability(999_999, Duration::from_secs(1))
                .any()
        );
    }

    #[test]
    fn blind_time_does_not_count_toward_the_offline_timeout() {
        let mut tracker = LockTracker::new();
        tracker.on_advertisement(1_000, &advertisement(Some(false), None));
        // Eight seconds spent connecting, during which no advertisement could
        // possibly have been heard.
        tracker.credit_blind_time(Duration::from_secs(8));
        assert!(
            !tracker
                .poll_availability(10_000, Duration::from_secs(10))
                .any()
        );
        assert!(tracker.available());
    }

    #[test]
    fn lock_version_is_remembered_from_advertisements() {
        let mut tracker = LockTracker::new();
        assert_eq!(tracker.lock_version(), None);

        let version = LockVersion {
            scene: 7,
            ..LockVersion::default()
        };
        let info = Advertisement::Stateless(LockIdentity {
            address: None,
            version,
        });
        tracker.on_advertisement(0, &info);

        assert_eq!(tracker.lock_version().map(|v| v.scene), Some(7));
    }

    #[test]
    fn redundant_updates_report_no_change() {
        let mut tracker = LockTracker::new();
        tracker.on_advertisement(0, &advertisement(Some(false), Some(80)));
        let changed = tracker.on_advertisement(1_000, &advertisement(Some(false), Some(80)));
        assert!(!changed.any(), "{changed:?}");
    }

    #[test]
    fn every_reported_state_has_a_distinct_payload() {
        let payloads = [
            ReportedState::Locked.payload(),
            ReportedState::Unlocked.payload(),
            ReportedState::Locking.payload(),
            ReportedState::Unlocking.payload(),
        ];
        let mut unique = payloads.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), payloads.len());
    }
}
