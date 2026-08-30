//! Pure MQTT topic/payload logic for the Home Assistant bridge.
//!
//! This module performs no I/O: it builds the topic strings and retained
//! discovery payloads, maps advertisements to reported state, and parses
//! inbound commands. The async daemon in [`crate::daemon`] wires it to a
//! broker and the BLE transport.

use serde_json::{Value, json};
use ttlock_core::ops::Actuation;
use ttlock_core::tracker::ReportedState;

/// Command received on the HA command topic.
///
/// Deliberately separate from [`Actuation`]: this is MQTT's vocabulary,
/// parsed from a payload that Home Assistant controls, and it is converted at
/// the boundary rather than leaking the transport's shape into the BLE layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// The `LOCK` payload.
    Lock,
    /// The `UNLOCK` payload.
    Unlock,
}

impl From<Command> for Actuation {
    fn from(command: Command) -> Self {
        match command {
            Command::Lock => Self::Lock,
            Command::Unlock => Self::Unlock,
        }
    }
}

/// `LOCK` / `UNLOCK` command payloads advertised in discovery.
pub const PAYLOAD_LOCK: &str = "LOCK";
pub const PAYLOAD_UNLOCK: &str = "UNLOCK";
pub const PAYLOAD_AVAILABLE: &str = "online";
pub const PAYLOAD_NOT_AVAILABLE: &str = "offline";

/// Parse an inbound command-topic payload.
#[must_use]
pub fn parse_command(payload: &str) -> Option<Command> {
    match payload.trim().to_ascii_uppercase().as_str() {
        PAYLOAD_LOCK => Some(Command::Lock),
        PAYLOAD_UNLOCK => Some(Command::Unlock),
        _ => None,
    }
}

/// Sanitize a lock address into an MQTT-safe object/node id
/// (lowercase alphanumerics; other characters become `_`).
#[must_use]
pub fn node_id(address: &str) -> String {
    let cleaned: String = address
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("ttlock_{cleaned}")
}

/// All MQTT topics for one lock, derived from the HA discovery prefix, the
/// state/command base topic, and the lock's node id.
#[derive(Debug, Clone)]
pub struct Topics {
    discovery_prefix: String,
    base_topic: String,
    node_id: String,
}

impl Topics {
    /// `discovery_prefix` is where retained HA MQTT-discovery configs are
    /// published (default `homeassistant`); `base_topic` is the prefix for this
    /// lock's state/command/availability topics (default `ttlock`).
    #[must_use]
    pub fn new(discovery_prefix: &str, base_topic: &str, address: &str) -> Self {
        Self {
            discovery_prefix: discovery_prefix.trim_end_matches('/').to_string(),
            base_topic: base_topic.trim_end_matches('/').to_string(),
            node_id: node_id(address),
        }
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    #[must_use]
    pub fn lock_discovery(&self) -> String {
        format!("{}/lock/{}/config", self.discovery_prefix, self.node_id)
    }

    #[must_use]
    pub fn battery_discovery(&self) -> String {
        format!(
            "{}/sensor/{}_battery/config",
            self.discovery_prefix, self.node_id
        )
    }

    #[must_use]
    pub fn base(&self) -> String {
        format!("{}/{}", self.base_topic, self.node_id)
    }

    #[must_use]
    pub fn state(&self) -> String {
        format!("{}/state", self.base())
    }

    #[must_use]
    pub fn command(&self) -> String {
        format!("{}/set", self.base())
    }

    #[must_use]
    pub fn battery(&self) -> String {
        format!("{}/battery", self.base())
    }

    #[must_use]
    pub fn availability(&self) -> String {
        format!("{}/availability", self.base())
    }
}

/// The `device` block shared by every entity so Home Assistant groups them.
fn device_block(topics: &Topics, address: &str) -> Value {
    json!({
        "identifiers": [topics.node_id()],
        "name": format!("TTLock {address}"),
        "manufacturer": "TTLock",
        "model": "BLE lock",
    })
}

/// Retained MQTT discovery payload for the lock entity.
#[must_use]
pub fn lock_discovery_payload(topics: &Topics, address: &str) -> Value {
    json!({
        "name": null,
        "unique_id": topics.node_id(),
        "command_topic": topics.command(),
        "state_topic": topics.state(),
        "payload_lock": PAYLOAD_LOCK,
        "payload_unlock": PAYLOAD_UNLOCK,
        "state_locked": ReportedState::Locked.payload(),
        "state_unlocked": ReportedState::Unlocked.payload(),
        "state_locking": ReportedState::Locking.payload(),
        "state_unlocking": ReportedState::Unlocking.payload(),
        // Not optimism about the command — optimism about the *bolt*.
        //
        // The lock advertises the state it was last commanded into, not the
        // state it is physically in: a key or thumbturn moves the bolt without
        // the firmware noticing. So whatever we publish on the state topic is
        // "last known", and Home Assistant should not treat it as ground truth.
        //
        // `optimistic` is the only lever the MQTT lock platform exposes for
        // that: it is what sets `assumed_state`, which makes the dashboard offer
        // both actions rather than only the one contradicting our reported
        // state. Without it, a lock opened by hand while we believe it locked
        // cannot be locked again from the card.
        //
        // The cost is that Home Assistant also assumes success the instant the
        // button is pressed. The window is tiny — `handle_command` publishes
        // LOCKING before it even begins connecting — and a failed command
        // settles back to LOCKING rather than a bolt position, so nothing
        // durable is claimed without evidence.
        //
        // `nix/checks/nixos-test.nix` asserts this value too. That check builds
        // only on Linux, so `nix flake check` on a macOS machine skips it
        // silently — the two assertions once disagreed for a while and only CI
        // noticed. Change both together.
        "optimistic": true,
        "availability_topic": topics.availability(),
        "payload_available": PAYLOAD_AVAILABLE,
        "payload_not_available": PAYLOAD_NOT_AVAILABLE,
        "device": device_block(topics, address),
    })
}

/// Retained MQTT discovery payload for the battery sensor.
#[must_use]
pub fn battery_discovery_payload(topics: &Topics, address: &str) -> Value {
    json!({
        "name": "Battery",
        "unique_id": format!("{}_battery", topics.node_id()),
        "state_topic": topics.battery(),
        "device_class": "battery",
        "unit_of_measurement": "%",
        "state_class": "measurement",
        "availability_topic": topics.availability(),
        "payload_available": PAYLOAD_AVAILABLE,
        "payload_not_available": PAYLOAD_NOT_AVAILABLE,
        "device": device_block(topics, address),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands_case_insensitively() {
        assert_eq!(parse_command("LOCK"), Some(Command::Lock));
        assert_eq!(parse_command(" unlock\n"), Some(Command::Unlock));
        assert_eq!(parse_command("open"), None);
    }

    #[test]
    fn node_id_is_mqtt_safe() {
        assert_eq!(node_id("AA:BB:CC:DD:EE:FF"), "ttlock_aa_bb_cc_dd_ee_ff");
    }

    #[test]
    fn topics_are_derived_from_prefix_and_address() {
        let topics = Topics::new("homeassistant/", "ttlock", "AA:BB:CC:DD:EE:FF");
        assert_eq!(
            topics.lock_discovery(),
            "homeassistant/lock/ttlock_aa_bb_cc_dd_ee_ff/config"
        );
        assert_eq!(
            topics.battery_discovery(),
            "homeassistant/sensor/ttlock_aa_bb_cc_dd_ee_ff_battery/config"
        );
        assert_eq!(topics.state(), "ttlock/ttlock_aa_bb_cc_dd_ee_ff/state");
        assert_eq!(topics.command(), "ttlock/ttlock_aa_bb_cc_dd_ee_ff/set");
    }

    #[test]
    fn base_topic_is_configurable() {
        let topics = Topics::new("homeassistant", "locks/front", "AA:BB:CC:DD:EE:FF");
        assert_eq!(topics.state(), "locks/front/ttlock_aa_bb_cc_dd_ee_ff/state");
        assert_eq!(topics.command(), "locks/front/ttlock_aa_bb_cc_dd_ee_ff/set");
        assert_eq!(
            topics.availability(),
            "locks/front/ttlock_aa_bb_cc_dd_ee_ff/availability"
        );
        // Discovery prefix is unaffected by the base topic.
        assert_eq!(
            topics.lock_discovery(),
            "homeassistant/lock/ttlock_aa_bb_cc_dd_ee_ff/config"
        );
    }

    #[test]
    fn lock_discovery_payload_wires_topics_and_payloads() {
        let topics = Topics::new("homeassistant", "ttlock", "AA:BB");
        let payload = lock_discovery_payload(&topics, "AA:BB");
        assert_eq!(payload["command_topic"], topics.command());
        assert_eq!(payload["state_topic"], topics.state());
        assert_eq!(payload["payload_lock"], PAYLOAD_LOCK);
        assert_eq!(payload["state_locked"], "LOCKED");
        assert_eq!(payload["availability_topic"], topics.availability());
        assert_eq!(payload["device"]["identifiers"][0], topics.node_id());
    }

    #[test]
    fn lock_discovery_payload_declares_transitional_states() {
        // Without these, HA has no mapping for the payloads the daemon publishes
        // while a command is in flight and would log them as invalid.
        let topics = Topics::new("homeassistant", "ttlock", "AA:BB");
        let payload = lock_discovery_payload(&topics, "AA:BB");
        assert_eq!(payload["state_locking"], "LOCKING");
        assert_eq!(payload["state_unlocking"], "UNLOCKING");
        // Set so Home Assistant marks the entity assumed-state and offers both
        // actions; see the comment on the field for why that is not optimism
        // about the command succeeding.
        assert_eq!(payload["optimistic"], true);
    }

    #[test]
    fn battery_discovery_payload_is_a_battery_sensor() {
        let topics = Topics::new("homeassistant", "ttlock", "AA:BB");
        let payload = battery_discovery_payload(&topics, "AA:BB");
        assert_eq!(payload["device_class"], "battery");
        assert_eq!(payload["unit_of_measurement"], "%");
        assert_eq!(payload["state_topic"], topics.battery());
    }
}
