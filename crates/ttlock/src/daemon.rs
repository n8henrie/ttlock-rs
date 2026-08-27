//! Long-lived MQTT bridge between the lock and Home Assistant.
//!
//! Bluetooth is slow (a connect-and-actuate can take many seconds), so it runs
//! on its own task, decoupled from the MQTT event loop. The main task does
//! nothing but pump rumqttc's event loop — announcing on connect and forwarding
//! `LOCK`/`UNLOCK` commands to the BLE worker over a channel — so MQTT
//! keep-alives are never starved by a BLE operation. The [`BleWorker`] owns all
//! Bluetooth access: it holds one continuous passive scan and publishes
//! state/battery from each advertisement as it arrives, tearing the scan down
//! only to actuate the lock on a forwarded command, then rebuilding it.
//!
//! Keeping the event loop responsive is what stops Home Assistant from marking
//! the lock unavailable (via the retained Last-Will) whenever a slow BLE action
//! would otherwise block the keep-alive ping.

use std::time::Duration;

use btleplug::api::CentralEvent;
use btleplug::platform::Adapter;
use futures_util::StreamExt;
use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS};
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep};

use ttlock_core::advertisement::Percent;
use ttlock_core::tracker::{Changed, LockTracker};

use crate::ble::{advertisement_from_event, start_continuous_scan, stop_scan};
use crate::error::{CliError, Result};
use crate::mqtt::{self, Command, PAYLOAD_AVAILABLE, PAYLOAD_NOT_AVAILABLE, Topics};
use crate::{ConnectOpts, actuate};

/// Everything the daemon needs to run, assembled from CLI arguments.
pub struct DaemonConfig {
    pub connect: ConnectOpts,
    pub mqtt_host: String,
    pub mqtt_port: u16,
    pub mqtt_username: Option<String>,
    pub mqtt_password: Option<String>,
    pub discovery_prefix: String,
    pub base_topic: String,
    pub offline_after_seconds: u64,
}

/// Longest backoff between MQTT event-loop reconnect attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// MQTT keep-alive interval.
const KEEP_ALIVE: Duration = Duration::from_mins(1);
/// How long to wait before rebuilding a scan that failed to start.
const SCAN_RETRY_DELAY: Duration = Duration::from_secs(2);

pub async fn run(config: DaemonConfig) -> Result<()> {
    let target = resolve_target(&config.connect)?;
    let address = target.id().to_string();
    let topics = Topics::new(&config.discovery_prefix, &config.base_topic, &address);

    let mut options = MqttOptions::new(
        format!("ttlock-daemon-{}", topics.node_id()),
        &config.mqtt_host,
        config.mqtt_port,
    );
    options.set_keep_alive(KEEP_ALIVE);
    options.set_last_will(rumqttc::LastWill::new(
        topics.availability(),
        PAYLOAD_NOT_AVAILABLE,
        QoS::AtLeastOnce,
        true,
    ));
    if let Some(username) = &config.mqtt_username {
        options.set_credentials(username, config.mqtt_password.clone().unwrap_or_default());
    }

    let (client, mut eventloop) = AsyncClient::new(options, 16);

    tracing::info!(
        %address,
        target_address = ?target.address,
        target_name = ?target.name,
        host = %config.mqtt_host,
        port = config.mqtt_port,
        node = %topics.node_id(),
        "daemon bridging lock to MQTT"
    );

    // Bluetooth runs on its own task so a slow connect never blocks the MQTT
    // event loop below. Commands — and republish requests — are forwarded to it
    // over this channel.
    let (message_tx, message_rx) = mpsc::channel::<WorkerMessage>(8);
    let worker = BleWorker {
        connect: config.connect.clone(),
        target,
        topics: topics.clone(),
        client: client.clone(),
        offline_after: Duration::from_secs(config.offline_after_seconds),
    };
    let worker_handle = tokio::spawn(worker.run(message_rx));

    // Main task: pump the MQTT event loop only.
    let mut backoff = Duration::from_secs(1);
    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                backoff = Duration::from_secs(1);
                tracing::info!("connected to MQTT broker");
                if let Err(error) = announce(&client, &topics, &address).await {
                    tracing::error!(%error, "failed to announce to broker");
                }
                // Discovery is static, but availability and state are not, and
                // only the worker knows them. Ask it to republish rather than
                // assuming anything here — see `announce`.
                if message_tx.send(WorkerMessage::Republish).await.is_err() {
                    tracing::error!("BLE worker stopped; exiting");
                    break;
                }
            }
            Ok(Event::Incoming(Incoming::Publish(publish))) => {
                if publish.topic == topics.command() {
                    let text = String::from_utf8_lossy(&publish.payload);
                    match mqtt::parse_command(&text) {
                        Some(command) => {
                            tracing::debug!(?command, "received MQTT command");
                            // Never blocks on BLE: if the worker is mid-action,
                            // the command simply queues.
                            if message_tx
                                .send(WorkerMessage::Command(command))
                                .await
                                .is_err()
                            {
                                tracing::error!("BLE worker stopped; exiting");
                                break;
                            }
                        }
                        None => {
                            tracing::warn!(payload = %text, "ignoring unknown command payload");
                        }
                    }
                }
            }
            Ok(other) => tracing::trace!(event = ?other, "MQTT event"),
            Err(error) => {
                tracing::warn!(%error, ?backoff, "MQTT connection error; retrying");
                sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }

    worker_handle.abort();
    Ok(())
}

/// What the MQTT task asks the Bluetooth worker to do.
#[derive(Debug, Clone, Copy)]
enum WorkerMessage {
    /// Actuate the lock.
    Command(Command),
    /// Publish everything the worker currently believes, whether or not it has
    /// changed. Sent after every broker (re)connection.
    Republish,
}

/// Owns all Bluetooth access for the daemon, on a task separate from the MQTT
/// event loop.
struct BleWorker {
    connect: ConnectOpts,
    /// Who to match advertisements against. Resolved up front rather than read
    /// from `connect`, whose `--address`/`--name` are usually both unset.
    target: Target,
    topics: Topics,
    client: AsyncClient,
    offline_after: Duration,
}

impl BleWorker {
    /// Run until the message channel closes. Maintains one continuous BLE scan,
    /// publishing state from each advertisement as it arrives; tears the scan
    /// down only to actuate on a command, then rebuilds it.
    async fn run(self, mut messages: mpsc::Receiver<WorkerMessage>) {
        // The single source of truth for what this daemon believes. Shared with
        // the Home Assistant component through `ttlock-core`, so the two cannot
        // drift the way they repeatedly did when each kept its own copy.
        let mut tracker = LockTracker::new();
        let started = Instant::now();

        loop {
            match self
                .scan_until_interrupt(&mut messages, &mut tracker, started)
                .await
            {
                Interrupt::Message(message) => {
                    self.handle_message(message, &mut tracker, started).await;
                }
                Interrupt::ChannelClosed => {
                    tracing::debug!("command channel closed; BLE worker exiting");
                    break;
                }
                Interrupt::ScanError(error) => {
                    tracing::warn!(%error, "BLE scan failed; retrying shortly");
                    if !self
                        .idle_until_rescan(&mut messages, &mut tracker, started)
                        .await
                    {
                        tracing::debug!("command channel closed; BLE worker exiting");
                        break;
                    }
                }
            }
        }
    }

    /// Monotonic milliseconds since the worker started, for the tracker.
    ///
    /// The tracker reads no clock of its own — that is what keeps it sans-IO and
    /// usable from Python — so time is supplied here.
    fn now_ms(started: Instant) -> u64 {
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Hold a continuous scan and publish advertisements until a message arrives
    /// (a command needs exclusive use of the radio), the channel closes, or the
    /// scan errors. On return the scan has been stopped.
    async fn scan_until_interrupt(
        &self,
        messages: &mut mpsc::Receiver<WorkerMessage>,
        tracker: &mut LockTracker,
        started: Instant,
    ) -> Interrupt {
        let (adapter, mut events) = match start_continuous_scan().await {
            Ok(pair) => pair,
            Err(error) => return Interrupt::ScanError(error),
        };
        tracing::debug!("continuous scan started");

        // Fires periodically to flip the lock to unavailable once advertisements
        // stop arriving for `offline_after`.
        let mut offline_timer = interval(self.offline_check_interval());
        offline_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let interrupt = loop {
            tokio::select! {
                event = events.next() => {
                    match event {
                        Some(event) => self.on_event(&adapter, &event, tracker, started).await,
                        None => break Interrupt::ScanError(CliError::DeviceNotFound),
                    }
                }
                _ = offline_timer.tick() => self.check_offline(tracker, started).await,
                message = messages.recv() => match message {
                    // A republish needs no radio, so it is served in place. Only
                    // a command does, and only that is worth tearing the scan
                    // down for. Breaking on both meant the broker's first
                    // ConnAck immediately killed the scan we had just started —
                    // two `continuous scan started` lines at every launch, and a
                    // window at startup where advertisements were missed.
                    Some(WorkerMessage::Republish) => {
                        tracing::debug!("republishing current state after broker (re)connect");
                        self.publish(tracker, Changed::ALL).await;
                    }
                    Some(message) => break Interrupt::Message(message),
                    None => break Interrupt::ChannelClosed,
                },
            }
        };

        stop_scan(&adapter).await;
        interrupt
    }

    /// Wait out [`SCAN_RETRY_DELAY`] before rebuilding a failed scan, without
    /// going deaf in the meantime. Returns `false` if the channel closed.
    ///
    /// An adapter that is missing, broken, or still coming up must not stop the
    /// daemon doing the two jobs that do not need a working radio: honouring
    /// commands, and letting availability expire.
    ///
    /// This used to be a bare `sleep`, which was wrong in both directions. The
    /// scan fails *before* [`Self::scan_until_interrupt`] reaches its `select!`,
    /// so nothing polled the channel — a `LOCK` from Home Assistant went in and
    /// stayed there, unacknowledged, until the radio came back and it actuated a
    /// door on a long-stale command. Nothing ticked the offline timer either, so
    /// the lock reported itself available forever while hearing nothing at all.
    async fn idle_until_rescan(
        &self,
        messages: &mut mpsc::Receiver<WorkerMessage>,
        tracker: &mut LockTracker,
        started: Instant,
    ) -> bool {
        let mut offline_timer = interval(self.offline_check_interval());
        offline_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let retry = sleep(SCAN_RETRY_DELAY);
        tokio::pin!(retry);

        loop {
            tokio::select! {
                () = &mut retry => return true,
                _ = offline_timer.tick() => self.check_offline(tracker, started).await,
                message = messages.recv() => match message {
                    // Attempted even though the last scan failed: actuating opens
                    // its own scan and connection, so the adapter may well be
                    // usable again. If it is not, the command fails and the entity
                    // stays in progress, which is the truth.
                    Some(message) => self.handle_message(message, tracker, started).await,
                    None => return false,
                },
            }
        }
    }

    /// How often to re-check the offline timeout; frequent enough to be timely,
    /// capped so it isn't wasteful.
    fn offline_check_interval(&self) -> Duration {
        self.offline_after
            .min(Duration::from_secs(10))
            .max(Duration::from_secs(1))
    }

    /// Handle one advertisement event: if it is our lock, hand it to the tracker
    /// and publish whatever that changed.
    async fn on_event(
        &self,
        adapter: &Adapter,
        event: &CentralEvent,
        tracker: &mut LockTracker,
        started: Instant,
    ) {
        let Some(info) = advertisement_from_event(
            adapter,
            event,
            self.target.address.as_deref(),
            self.target.name.as_deref(),
        )
        .await
        else {
            return;
        };

        // `-v` surfaces advertisements carrying lock status; `-vv` also logs
        // those that don't, so a lock that never reports state is
        // distinguishable from a radio that hears nothing.
        if let Some(status) = info.status() {
            tracing::debug!(
                bolt = ?status.bolt,
                battery = ?status.battery.map(Percent::get),
                has_events = status.has_events,
                "advertisement (with status)"
            );
        } else {
            tracing::trace!(
                advertisement = ?info,
                "advertisement (no status)"
            );
        }

        let changed = tracker.on_advertisement(Self::now_ms(started), &info);
        self.publish(tracker, changed).await;
    }

    /// Let availability expire once no advertisement has arrived for
    /// `offline_after`.
    async fn check_offline(&self, tracker: &mut LockTracker, started: Instant) {
        let changed = tracker.poll_availability(Self::now_ms(started), self.offline_after);
        self.publish(tracker, changed).await;
    }

    async fn handle_message(
        &self,
        message: WorkerMessage,
        tracker: &mut LockTracker,
        started: Instant,
    ) {
        match message {
            WorkerMessage::Command(command) => {
                self.handle_command(command, tracker, started).await;
            }
            WorkerMessage::Republish => {
                tracing::debug!("republishing current state after broker (re)connect");
                self.publish(tracker, Changed::ALL).await;
            }
        }
    }

    /// Handle a `LOCK`/`UNLOCK` command: report the transitional state, then
    /// connect and run the operation. The passive scan is already stopped by the
    /// caller, so the radio is free for the connect.
    ///
    /// Nothing here reports a bolt position without evidence; the tracker
    /// enforces that, and the rules are documented on it.
    async fn handle_command(&self, command: Command, tracker: &mut LockTracker, started: Instant) {
        let action = command.into();
        tracing::info!(?command, "actuating lock");

        let changed = tracker.on_command_started(action);
        self.publish(tracker, changed).await;

        let begin = Instant::now();
        let result = actuate(self.connect.clone(), action).await;

        // Credit back the time spent actuating. The radio was busy connecting, so
        // no advertisement *could* have arrived, and counting that silence toward
        // the offline timeout would flip the lock to unavailable and straight back
        // — easy to hit now that a retry chain can outlast `--offline-after-seconds`.
        tracker.credit_blind_time(begin.elapsed());

        let changed = match result {
            Ok(()) => {
                // Not optimism: the lock's response is encrypted, CRC-checked and
                // carries its own success code, which
                // `ttlock_core::packet::parse_success_response` requires to be 1.
                tracing::info!(?command, "lock acknowledged command");
                tracker.on_command_acknowledged(Self::now_ms(started), action)
            }
            Err(error) => {
                tracing::error!(
                    ?command,
                    %error,
                    "command failed; leaving state in progress until an advertisement resolves it"
                );
                tracker.on_command_failed()
            }
        };
        self.publish(tracker, changed).await;
    }

    /// Publish the parts of the tracker's view named by `changed`.
    ///
    /// Everything the daemon reports goes through here, reading the tracker
    /// rather than any cached copy. That is what makes [`Changed::ALL`] a
    /// correct republish: there is no second source of truth to fall out of step
    /// with the broker's retained values.
    async fn publish(&self, tracker: &LockTracker, changed: Changed) {
        if changed.available {
            let available = tracker.available();
            let payload = if available {
                PAYLOAD_AVAILABLE
            } else {
                PAYLOAD_NOT_AVAILABLE
            };
            tracing::info!(available, "publishing availability");
            let _ = self
                .client
                .publish(self.topics.availability(), QoS::AtLeastOnce, true, payload)
                .await;
        }

        if changed.state
            && let Some(state) = tracker.reported_state()
        {
            tracing::debug!(state = state.payload(), "publishing lock state");
            let _ = self
                .client
                .publish(self.topics.state(), QoS::AtLeastOnce, true, state.payload())
                .await;
        }

        if changed.battery
            && let Some(battery) = tracker.battery()
        {
            tracing::debug!(battery, "publishing battery");
            let _ = self
                .client
                .publish(
                    self.topics.battery(),
                    QoS::AtLeastOnce,
                    true,
                    battery.to_string(),
                )
                .await;
        }
    }
}

/// Why [`BleWorker::scan_until_interrupt`] returned.
enum Interrupt {
    Message(WorkerMessage),
    ChannelClosed,
    ScanError(CliError),
}

/// Publish retained discovery and subscribe to commands. Called on every
/// (re)connection so Home Assistant recovers after a broker restart.
///
/// Deliberately publishes nothing about availability or lock state. It used to
/// publish a retained `online` here, which was a guess dressed up as a fact: on
/// a reconnect while the lock was silent, the broker would retain `online`
/// while the worker knew otherwise, and the worker's own change-detection then
/// suppressed the correction forever. State is the worker's to report, so the
/// caller follows this with [`WorkerMessage::Republish`].
async fn announce(client: &AsyncClient, topics: &Topics, address: &str) -> Result<()> {
    let lock = mqtt::lock_discovery_payload(topics, address);
    let battery = mqtt::battery_discovery_payload(topics, address);
    client
        .publish(
            topics.lock_discovery(),
            QoS::AtLeastOnce,
            true,
            serde_json::to_vec(&lock)?,
        )
        .await?;
    client
        .publish(
            topics.battery_discovery(),
            QoS::AtLeastOnce,
            true,
            serde_json::to_vec(&battery)?,
        )
        .await?;
    client.subscribe(topics.command(), QoS::AtLeastOnce).await?;
    Ok(())
}

/// Which lock the daemon tracks, resolved once at startup.
#[derive(Clone)]
struct Target {
    address: Option<String>,
    name: Option<String>,
}

impl Target {
    /// Identifier for MQTT topics; prefers the address, falling back to the name.
    fn id(&self) -> &str {
        self.address
            .as_deref()
            .or(self.name.as_deref())
            .unwrap_or_default()
    }
}

/// Resolve which lock to track from the CLI flags, falling back to
/// `lockData.json` exactly as [`select_and_connect`] does.
///
/// The fallback is the whole point: `--address` is optional (the README's own
/// example omits it), and without resolving it here the daemon would try to match
/// advertisements against `None`/`None` — matching nothing, forever, while
/// commands still worked because they resolve the address separately.
fn resolve_target(connect: &ConnectOpts) -> Result<Target> {
    let name = connect.name.clone().filter(|n| !n.is_empty());
    let mut address = connect.address.clone().filter(|a| !a.is_empty());

    if address.is_none() {
        let locks = ttlock_core::config::load_lock_data(&connect.file)?;
        let selected = ttlock_core::config::select_lock(&locks, None)?;
        address = Some(selected.address.clone()).filter(|a| !a.is_empty());
    }

    if address.is_none() && name.is_none() {
        return Err(CliError::Core(ttlock_core::error::TtlockError::Message(
            "daemon needs a lock address (in lockData.json or via --address) or a --name to match advertisements".to_string(),
        )));
    }

    Ok(Target { address, name })
}
