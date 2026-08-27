//! Drives the shared conformance table through the tracker and checks what the
//! MQTT daemon would publish.
//!
//! The Python half lives in `crates/ttlock-py/tests/test_conformance.py` and
//! reads the same file. Between them they pin the two rendering layers — the
//! only place the daemon and the Home Assistant component can still disagree,
//! now that the state machine itself is shared.
//!
//! Everything here returns `Result` rather than unwrapping, matching the rest of
//! the workspace: a malformed fixture should report *what* is wrong with it, not
//! just which line panicked.

use std::error::Error;
use std::time::Duration;

use serde_json::Value;
use ttlock_core::advertisement::{Advertisement, Bolt, LockIdentity, LockStatus, Percent};
use ttlock_core::ops::Actuation;
use ttlock_core::tracker::{LockTracker, ReportedState};

/// The fixture is checked in at the repository root so neither language owns it.
const FIXTURE: &str = include_str!("../../../tests/conformance/state.json");

type TestResult = Result<(), Box<dyn Error>>;

fn bad(message: impl Into<String>) -> Box<dyn Error> {
    message.into().into()
}

fn actuation(value: &Value) -> Result<Actuation, Box<dyn Error>> {
    match value.as_str() {
        Some("lock") => Ok(Actuation::Lock),
        Some("unlock") => Ok(Actuation::Unlock),
        other => Err(bad(format!("unknown actuation {other:?} in fixture"))),
    }
}

fn battery_of(value: &Value, key: &str) -> Result<Option<u8>, Box<dyn Error>> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|raw| u8::try_from(raw).map_err(|_| bad(format!("{key} {raw} does not fit in u8"))))
        .transpose()
}

/// Replay one scenario's events against a fresh tracker.
fn replay(events: &[Value], offline_after: Duration) -> Result<LockTracker, Box<dyn Error>> {
    let mut tracker = LockTracker::new();
    let mut now_ms = 1_000_u64;

    for event in events {
        let object = event
            .as_object()
            .ok_or_else(|| bad("event is not an object"))?;
        let (key, value) = object
            .iter()
            .next()
            .ok_or_else(|| bad("event object is empty"))?;

        match key.as_str() {
            "advertisement" => {
                // A scenario omitting `is_unlock` models a payload whose
                // protocol family carries no flags byte — and therefore no
                // battery byte either, the two being adjacent on the wire.
                let identity = LockIdentity {
                    address: None,
                    version: ttlock_core::packet::LockVersion::default(),
                };
                let info = match value.get("is_unlock").and_then(Value::as_bool) {
                    Some(unlocked) => Advertisement::Stateful {
                        identity,
                        status: LockStatus {
                            bolt: if unlocked {
                                Bolt::Unlocked
                            } else {
                                Bolt::Locked
                            },
                            battery: battery_of(value, "battery")?.and_then(Percent::new),
                            has_events: false,
                            is_setting_mode: false,
                        },
                    },
                    None => Advertisement::Stateless(identity),
                };
                tracker.on_advertisement(now_ms, &info);
            }
            "command_started" => {
                tracker.on_command_started(actuation(value)?);
            }
            "command_acknowledged" => {
                tracker.on_command_acknowledged(now_ms, actuation(value)?);
            }
            "command_failed" => {
                tracker.on_command_failed();
            }
            "unavailable" => {
                tracker.on_unavailable();
            }
            "elapsed_ms" => {
                now_ms += value
                    .as_u64()
                    .ok_or_else(|| bad("elapsed_ms is not a number"))?;
                tracker.poll_availability(now_ms, offline_after);
            }
            other => return Err(bad(format!("unknown event {other:?} in fixture"))),
        }
    }

    Ok(tracker)
}

fn fixture() -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(FIXTURE)?)
}

fn scenarios(fixture: &Value) -> Result<&Vec<Value>, Box<dyn Error>> {
    fixture["scenarios"]
        .as_array()
        .ok_or_else(|| bad("scenarios is not an array"))
}

#[test]
fn daemon_renders_every_conformance_scenario() -> TestResult {
    let fixture = fixture()?;
    let offline_after = Duration::from_millis(
        fixture["offline_after_ms"]
            .as_u64()
            .ok_or_else(|| bad("offline_after_ms is not a number"))?,
    );
    let scenarios = scenarios(&fixture)?;
    assert!(!scenarios.is_empty(), "fixture has no scenarios");

    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap_or("<unnamed>");
        let events = scenario["events"]
            .as_array()
            .ok_or_else(|| bad(format!("events missing in scenario {name:?}")))?;
        let expect = &scenario["expect"];

        let tracker = replay(events, offline_after)?;

        // Exactly what the daemon puts on the state topic.
        assert_eq!(
            tracker.reported_state().map(ReportedState::payload),
            expect["reported_state"].as_str(),
            "reported_state in scenario {name:?}"
        );
        assert_eq!(
            tracker.available(),
            expect["available"]
                .as_bool()
                .ok_or_else(|| bad(format!("available missing in scenario {name:?}")))?,
            "available in scenario {name:?}"
        );
        if let Some(battery) = battery_of(expect, "battery")? {
            assert_eq!(
                tracker.battery(),
                Some(battery),
                "battery in scenario {name:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn every_scenario_names_the_entity_properties_the_python_side_checks() -> TestResult {
    // Guards against a scenario added with only the MQTT half filled in, which
    // would pass here and silently skip the Home Assistant rendering.
    let fixture = fixture()?;
    for scenario in scenarios(&fixture)? {
        let name = scenario["name"].as_str().unwrap_or("<unnamed>");
        let expect = &scenario["expect"];
        for key in [
            "reported_state",
            "available",
            "is_locked",
            "is_locking",
            "is_unlocking",
        ] {
            assert!(
                expect.get(key).is_some(),
                "scenario {name:?} is missing expectation {key:?}"
            );
        }
    }
    Ok(())
}
