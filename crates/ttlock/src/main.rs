mod ble;
mod daemon;
mod error;
mod mqtt;
mod oplog;
mod sciener;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use ttlock_core::advertisement::{Bolt, Percent};
use ttlock_core::config::{LockData, load_lock_data, select_lock};
use ttlock_core::error::TtlockError;
use ttlock_core::oplog::{LogCursor, Sequence};
use ttlock_core::ops::{Actuation, LockState, StatusOp};
use ttlock_core::packet::LockVersion;

use crate::ble::{BleConnection, find_lock, run_op, scan_locks};
use crate::error::{CliError, Result};

#[derive(Debug, Parser)]
#[command(
    name = "ttlock",
    version,
    about = "Control a paired TTLock Bluetooth lock"
)]
struct Cli {
    /// Increase log verbosity (to stderr). `-v` adds lock/MQTT activity
    /// (advertisements carrying status, commands, state changes); `-vv` also
    /// logs advertisements without status and every MQTT event. `RUST_LOG`
    /// overrides this.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Read the Sciener/TTLock app's local sqlite database (read-only) and
    /// convert its stored keys into `lockData.json` entries.
    ImportCredentials {
        /// Path to the app database (sciener.sqlite). Defaults to the app's
        /// Group Containers copy under $HOME.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Write the JSON here instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Scan for nearby TTLock-like BLE advertisements.
    Scan {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 20)]
        seconds: u64,
    },

    /// Connect and print reassembled notification frames without sending commands.
    Listen {
        #[arg(short, long, default_value = "lockData.json")]
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 20)]
        seconds: u64,
        #[arg(long)]
        debug: bool,
    },

    /// Query the lock status.
    Status {
        #[command(flatten)]
        connect: ConnectOpts,
    },

    /// Read the lock's operate log — its own audit trail of who opened the
    /// door, when, and how.
    ///
    /// This is an audit trail and NOT a source of lock state: the lock records
    /// operations it performs and never bolt movement it observes, so a
    /// thumbturn or a key leaves no trace in either direction.
    ///
    /// Reading by sequence does not consume anything, so this is safe to run as
    /// often as you like and a interrupted walk can be resumed with `--from`.
    ///
    /// A `keyboard password unlock` record contains the passcode that was
    /// entered, and it is printed in the clear. The command warns and pauses
    /// five seconds before doing so; --no-warn skips that.
    Logs {
        #[command(flatten)]
        connect: ConnectOpts,
        /// Start after this sequence number. Omit to read from the oldest
        /// record the lock still holds; pass the value printed by an
        /// interrupted run to resume it.
        #[arg(long, value_name = "SEQUENCE")]
        from: Option<u16>,
        /// Read only what the lock has not handed over since the last such
        /// read.
        ///
        /// Unlike --from this is stateful: it advances a bookmark inside the
        /// lock, and a page refused mid-walk can leave the bookmark past a
        /// record that was never delivered. Prefer --from unless "what is new"
        /// is genuinely the question.
        #[arg(long, conflicts_with = "from")]
        since_last_read: bool,
        /// Stop after this many records.
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
        #[arg(long, value_enum, default_value_t = oplog::Format::Jsonl)]
        format: oplog::Format,
        /// Skip the warning and the pause before printing passcodes.
        #[arg(long)]
        no_warn: bool,
    },

    /// Measure where the time goes on a full command: discovery (scan to first
    /// matching advertisement), BLE connect + service discovery, and the
    /// encrypted status round-trip.
    Timings {
        #[command(flatten)]
        connect: ConnectOpts,
    },

    /// Lock the paired lock.
    Lock {
        #[command(flatten)]
        connect: ConnectOpts,
    },

    /// Unlock the paired lock.
    Unlock {
        #[command(flatten)]
        connect: ConnectOpts,
    },

    /// Run a long-lived bridge that mirrors the lock to Home Assistant over
    /// MQTT: passive state/battery from advertisements plus lock/unlock on
    /// command.
    Daemon {
        #[command(flatten)]
        connect: ConnectOpts,

        /// MQTT broker host.
        #[arg(long, default_value = "localhost", env = "TTLOCK_MQTT_HOST")]
        mqtt_host: String,
        /// MQTT broker port.
        #[arg(long, default_value_t = 1883, env = "TTLOCK_MQTT_PORT")]
        mqtt_port: u16,
        #[arg(long, env = "TTLOCK_MQTT_USERNAME")]
        mqtt_username: Option<String>,
        #[arg(long, env = "TTLOCK_MQTT_PASSWORD", hide_env_values = true)]
        mqtt_password: Option<String>,
        /// Home Assistant MQTT discovery prefix (where retained discovery
        /// configs are published).
        #[arg(long, default_value = "homeassistant")]
        discovery_prefix: String,
        /// Base topic for this lock's state/command/availability topics.
        #[arg(long, default_value = "ttlock")]
        base_topic: String,
        /// Seconds without an advertisement before the lock is marked offline.
        #[arg(long, default_value_t = 120)]
        offline_after_seconds: u64,
    },
}

/// Options shared by every command that connects to the lock.
#[derive(Debug, Clone, clap::Args)]
pub struct ConnectOpts {
    #[arg(short, long, default_value = "lockData.json")]
    file: PathBuf,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    address: Option<String>,
    #[arg(long, default_value_t = 20)]
    scan_seconds: u64,
    /// How many scan-and-connect attempts to make before giving up. A weak link
    /// commonly fails the first few with `le-connection-abort-by-local` or ATT
    /// error `0x0e` and then succeeds, so this is worth raising rather than
    /// letting a command fail. Each attempt costs a scan plus a connect, so a
    /// high value can take minutes to exhaust when the lock is truly absent.
    #[arg(long, default_value_t = 6)]
    connect_attempts: u32,
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    dispatch(cli.command).await
}

/// Install a stderr `tracing` subscriber. The `-v` count selects the level for
/// this crate's spans; `RUST_LOG`, when set, takes precedence.
fn init_tracing(verbose: u8) {
    let directive = match verbose {
        0 => "ttlock=info",
        1 => "ttlock=debug",
        _ => "ttlock=trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(directive));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

async fn dispatch(command: Commands) -> Result<()> {
    match command {
        Commands::ImportCredentials { db, output } => import_credentials(db, output.as_deref())?,
        Commands::Scan {
            name,
            address,
            seconds,
        } => scan(name.as_deref(), address.as_deref(), seconds).await?,
        Commands::Listen {
            file,
            name,
            address,
            seconds,
            debug,
        } => listen(file, name.as_deref(), address.as_deref(), seconds, debug).await?,
        Commands::Status { connect } => status(connect).await?,
        Commands::Logs {
            connect,
            from,
            since_last_read,
            limit,
            format,
            no_warn,
        } => {
            logs(LogsOpts {
                connect,
                from,
                since_last_read,
                limit,
                format,
                no_warn,
            })
            .await?;
        }
        Commands::Timings { connect } => timings(connect).await?,
        Commands::Lock { connect } => actuate_and_report(connect, Actuation::Lock).await?,
        Commands::Unlock { connect } => {
            actuate_and_report(connect, Actuation::Unlock).await?;
        }
        Commands::Daemon {
            connect,
            mqtt_host,
            mqtt_port,
            mqtt_username,
            mqtt_password,
            discovery_prefix,
            base_topic,
            offline_after_seconds,
        } => {
            daemon::run(daemon::DaemonConfig {
                connect,
                mqtt_host,
                mqtt_port,
                mqtt_username,
                mqtt_password,
                discovery_prefix,
                base_topic,
                offline_after_seconds,
            })
            .await?;
        }
    }
    Ok(())
}

/// Default location of the Sciener app's database inside its iOS/macOS
/// Group Containers directory.
fn default_sciener_db_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join("Library/Group Containers/group.tongtongsuo.app/sciener.sqlite")
}

/// Read the Sciener database and emit `lockData.json` entries as JSON, either
/// to `output` or to stdout.
fn import_credentials(db: Option<PathBuf>, output: Option<&Path>) -> Result<()> {
    let db_path = db.unwrap_or_else(default_sciener_db_path);
    let locks = sciener::read_sciener_db(&db_path)?;
    let json = serde_json::to_string_pretty(&locks)?;
    if let Some(path) = output {
        std::fs::write(path, format!("{json}\n"))?;
        eprintln!(
            "wrote {} lock entr{} to {}",
            locks.len(),
            if locks.len() == 1 { "y" } else { "ies" },
            path.display()
        );
    } else {
        println!("{json}");
    }
    Ok(())
}

async fn scan(name: Option<&str>, address: Option<&str>, seconds: u64) -> Result<()> {
    let locks = scan_locks(seconds).await?;
    for lock in locks.iter().filter(|lock| {
        let name_ok = name.is_none_or(|target| {
            lock.local_name
                .as_deref()
                .is_some_and(|n| n.contains(target))
        });
        let address_ok = address.is_none_or(|target| {
            lock.btleplug_address.eq_ignore_ascii_case(target)
                || lock
                    .advertisement
                    .address()
                    .is_some_and(|a| a.eq_ignore_ascii_case(target))
        });
        name_ok && address_ok
    }) {
        let state = match lock.advertisement.bolt() {
            Some(Bolt::Unlocked) => "UNLOCKED",
            Some(Bolt::Locked) => "LOCKED",
            // Not "unknown state" but "this advertisement does not carry one":
            // a family without a flags byte, a DFU beacon, or not a lock.
            None => "?",
        };
        println!(
            "name={:?} btleplug_address={} ttlock_address={:?} rssi={:?} state={state} battery={:?} has_events={:?} version={:?}",
            lock.local_name,
            lock.btleplug_address,
            lock.advertisement.address(),
            lock.rssi,
            lock.advertisement.battery().map(Percent::get),
            lock.advertisement.status().map(|status| status.has_events),
            lock.advertisement.lock_version()
        );
    }
    Ok(())
}

/// Resolve the target lock, connect over BLE, and return the live connection
/// plus the lock's protocol version and credentials.
///
/// The lock is matched on the stable MAC embedded in its advertisement (from
/// `lockData.json`), which works cross-platform. There is no address cache:
/// on macOS btleplug never exposes a usable per-device address (it reports
/// `00:00:00:00:00:00`), so a cache saved nothing and only added a stale
/// fast-path that could slow things down.
///
/// # Errors
/// Returns an error if the lock data cannot be loaded, no matching device is
/// found, or the BLE connection cannot be established.
pub async fn select_and_connect(
    opts: ConnectOpts,
) -> Result<(BleConnection, LockVersion, LockData)> {
    let ConnectOpts {
        file,
        name,
        address,
        scan_seconds,
        connect_attempts,
        debug,
    } = opts;
    let name = name.as_deref();
    let address = address.as_deref();

    let locks = load_lock_data(&file)?;
    let selected = select_lock(&locks, address)?;
    let target_address =
        address.or_else(|| (!selected.address.is_empty()).then_some(selected.address.as_str()));

    let attempts = connect_attempts.max(1);
    let mut last_error = None;
    for attempt in 1..=attempts {
        match connect_once(target_address, name, scan_seconds, debug).await {
            Ok((connection, version)) => return Ok((connection, version, selected.clone())),
            Err(error) => {
                if attempt == attempts {
                    return Err(error);
                }
                let backoff = connect_backoff(attempt);
                // The error itself distinguishes a failed scan (DeviceNotFound)
                // from a failed connect, so one message covers both.
                tracing::warn!(
                    attempt,
                    attempts,
                    %error,
                    ?backoff,
                    "BLE attempt failed; retrying"
                );
                last_error = Some(error);
                tokio::time::sleep(backoff).await;
            }
        }
    }

    Err(last_error.unwrap_or(CliError::DeviceNotFound))
}

/// One scan-and-connect attempt.
async fn connect_once(
    target_address: Option<&str>,
    name: Option<&str>,
    scan_seconds: u64,
    debug: bool,
) -> Result<(BleConnection, LockVersion)> {
    let scanned = find_lock(target_address, name, scan_seconds).await?;
    let version = scanned.advertisement.lock_version().unwrap_or_default();
    let connection = BleConnection::connect(scanned, debug).await?;
    Ok((connection, version))
}

/// How long to wait before the next scan-and-connect attempt.
///
/// This grows because the failures worth retrying are not independent: after an
/// aborted connection the controller and the lock both need a moment to settle,
/// and retrying instantly tends to reproduce the same abort. Capped so a large
/// `--connect-attempts` spends its budget on attempts rather than on waiting.
fn connect_backoff(attempt: u32) -> Duration {
    const BASE: Duration = Duration::from_millis(750);
    const MAX: Duration = Duration::from_secs(4);
    // saturating_sub keeps a 0 from underflowing; attempts are 1-based.
    (BASE * 2_u32.pow(attempt.saturating_sub(1).min(3))).min(MAX)
}

async fn listen(
    file: PathBuf,
    name: Option<&str>,
    address: Option<&str>,
    seconds: u64,
    debug: bool,
) -> Result<()> {
    let locks = load_lock_data(&file)?;
    let selected = select_lock(&locks, address)?;
    let target_address =
        address.or_else(|| (!selected.address.is_empty()).then_some(selected.address.as_str()));
    let scanned = find_lock(target_address, name, 10).await?;
    let mut connection = BleConnection::connect(scanned, debug).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match connection.next_frame(remaining).await {
            Ok(frame) => println!("{}", hex::encode(frame)),
            Err(CliError::Timeout) => break,
            Err(error) => return Err(error),
        }
    }
    connection.disconnect().await?;
    Ok(())
}

async fn status(opts: ConnectOpts) -> Result<()> {
    let (mut connection, version, lock_data) = select_and_connect(opts).await?;
    eprintln!("using lock version: {version:?}");
    let mut op = StatusOp::new(lock_data.aes_key()?, version);
    let state = run_op(&mut connection, &mut op).await?;
    let label = match state {
        LockState::Locked => "LOCKED (0)".to_string(),
        LockState::Unlocked => "UNLOCKED (1)".to_string(),
        LockState::Unknown(byte) => format!("UNKNOWN ({byte})"),
    };
    println!("Lock status: {label}");
    // Not a hedge: on the lock this was developed against, `0x14` answered
    // UNLOCKED on every invocation across every bolt position, including while
    // the advertisement simultaneously reported LOCKED. Battery in the same
    // reply is live, so only the state byte is inert. `ttlock scan` reads the
    // advertisement instead, which is wrong less often — see §7a of
    // docs/protocol-and-design.md.
    eprintln!(
        "note: some locks answer this command with a constant. \
         Cross-check with `ttlock scan` before trusting it."
    );
    connection.disconnect().await?;
    Ok(())
}

struct LogsOpts {
    connect: ConnectOpts,
    from: Option<u16>,
    since_last_read: bool,
    limit: Option<usize>,
    format: oplog::Format,
    no_warn: bool,
}

/// How long to leave the passcode warning on screen before printing them.
const SECRET_WARNING_PAUSE: Duration = Duration::from_secs(5);

/// Warn that door codes are about to be printed, and give the user time to stop
/// it.
///
/// The pause is the point: the warning is only useful if it arrives before the
/// passcodes rather than scrolling past with them. Goes to stderr so that
/// redirecting stdout does not hide it.
async fn warn_before_printing_secrets() {
    eprintln!(
        "\nThis prints keypad passcodes in plaintext. A `keyboard password unlock`\n\
         record contains the code that was typed, including codes belonging to\n\
         other people, so whatever this output lands in becomes as sensitive as\n\
         lockData.json.\n\n\
         Starting in {} seconds — Ctrl-C to cancel, --no-warn to skip this.\n",
        SECRET_WARNING_PAUSE.as_secs()
    );
    tokio::time::sleep(SECRET_WARNING_PAUSE).await;
}

/// Read the operate log.
///
/// Records stream to stdout as they arrive: a full walk is one round trip per
/// page and can take a couple of minutes, so buffering would leave the user
/// looking at nothing. Progress and warnings go to stderr, keeping stdout a
/// clean machine-readable stream.
async fn logs(opts: LogsOpts) -> Result<()> {
    let LogsOpts {
        connect,
        from,
        since_last_read,
        limit,
        format,
        no_warn,
    } = opts;

    let start = if since_last_read {
        LogCursor::SinceLastRead
    } else {
        match from {
            // 0xffff is the sentinel, so it cannot also be a position. Say so
            // rather than silently reading something else.
            Some(value) => LogCursor::After(Sequence::new(value).ok_or_else(|| {
                TtlockError::Message(format!(
                    "--from {value} is the reserved 'since last read' sentinel; \
                     use --since-last-read if that is what you meant"
                ))
            })?),
            None => LogCursor::Beginning,
        }
    };

    if !no_warn {
        warn_before_printing_secrets().await;
    }

    let (mut connection, version, lock_data) = select_and_connect(connect).await?;
    let aes_key = lock_data.aes_key()?;

    // `io::stdout()` rather than a locked handle: the guard is not `Send` and
    // this future is held across awaits. Stdout is line-buffered and `emit`
    // flushes, so records still stream.
    let mut sink = io::stdout();
    let mut collected: Vec<serde_json::Value> = Vec::new();

    let outcome = oplog::walk(&mut connection, aes_key, version, start, limit, |record| {
        if format == oplog::Format::Json {
            collected.push(oplog::to_json(record));
            Ok(())
        } else {
            oplog::emit(&mut sink, record, format)
        }
    })
    .await;

    connection.disconnect().await?;
    let outcome = outcome?;

    if format == oplog::Format::Json {
        writeln!(sink, "{}", serde_json::to_string_pretty(&collected)?)?;
    }

    match outcome.ending {
        oplog::Ending::Exhausted => {
            eprintln!("read {} record(s); log exhausted.", outcome.records);
        }
        oplog::Ending::LimitReached | oplog::Ending::Refused => {
            let reason = if outcome.ending == oplog::Ending::Refused {
                "the lock refused the cursor twice"
            } else {
                "the limit was reached"
            };
            eprint!(
                "read {} record(s); stopped because {reason}.",
                outcome.records
            );
            // Reading by sequence consumes nothing, so an unfinished walk costs
            // only the round trips already spent.
            match outcome.resume_from {
                Some(sequence) => eprintln!(" Resume with --from {}.", sequence.get()),
                None => eprintln!(),
            }
        }
    }
    Ok(())
}

/// Timing breakdown: discovery, connect, and the status round-trip.
async fn timings(opts: ConnectOpts) -> Result<()> {
    let locks = load_lock_data(&opts.file)?;
    let selected = select_lock(&locks, opts.address.as_deref())?;
    let target_address = opts
        .address
        .as_deref()
        .or_else(|| (!selected.address.is_empty()).then_some(selected.address.as_str()));
    let name = opts.name.as_deref();

    let overall = std::time::Instant::now();

    let discover_start = std::time::Instant::now();
    let scanned = find_lock(target_address, name, opts.scan_seconds).await?;
    let discover = discover_start.elapsed();
    let btleplug_address = scanned.btleplug_address.clone();
    let version = scanned.advertisement.lock_version().unwrap_or_default();

    let connect_start = std::time::Instant::now();
    let mut connection = BleConnection::connect(scanned, opts.debug).await?;
    let connect = connect_start.elapsed();

    let protocol_start = std::time::Instant::now();
    let mut op = StatusOp::new(selected.aes_key()?, version);
    let state = run_op(&mut connection, &mut op).await?;
    let protocol = protocol_start.elapsed();

    connection.disconnect().await?;
    let total = overall.elapsed();

    println!("btleplug_address: {btleplug_address}");
    println!("lock status:      {state:?}");
    println!("discovery (scan -> first matching advert): {discover:.3?}");
    println!("connect + service discovery:               {connect:.3?}");
    println!("status round-trip (encrypted):             {protocol:.3?}");
    println!("total:                                     {total:.3?}");
    Ok(())
}

/// How long to wait for the lock's trailing unsolicited frame before giving up
/// on it.
const POST_ACTUATION_DRAIN: Duration = Duration::from_secs(4);

/// Connect, run one actuation to completion, and disconnect cleanly.
///
/// Shared by the `lock` and `unlock` subcommands and by the MQTT daemon, so the
/// connect / drive / drain / disconnect sequence — and in particular the
/// easy-to-forget drain below — exists in exactly one place.
///
/// # Errors
/// Returns an error if the lock cannot be found or connected to, or if it
/// rejects the command.
pub async fn actuate(opts: ConnectOpts, action: Actuation) -> Result<()> {
    let (mut connection, version, lock_data) = select_and_connect(opts).await?;
    tracing::debug!(?version, ?action, "actuating");

    let aes_key = lock_data.aes_key()?;
    let unlock_key = lock_data.unlock_key()?;
    let mut op = action.op(aes_key, unlock_key, version);
    run_op(&mut connection, &mut op).await?;

    // The lock usually sends one more unsolicited frame after actuating. Drain
    // it so the disconnect is clean, but do not require it: its absence is not
    // a failure, and waiting forever would be.
    let _ = connection.next_frame(POST_ACTUATION_DRAIN).await;
    connection.disconnect().await?;
    Ok(())
}

/// Past-tense label for user-facing output. Lives here rather than on
/// [`Actuation`] because it is CLI presentation, not protocol.
const fn past_tense(action: Actuation) -> &'static str {
    match action {
        Actuation::Lock => "Lock",
        Actuation::Unlock => "Unlock",
    }
}

/// Run an actuation from the CLI, reporting the outcome on stdout.
async fn actuate_and_report(opts: ConnectOpts, action: Actuation) -> Result<()> {
    actuate(opts, action).await?;
    println!("{} command completed", past_tense(action));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Duration, connect_backoff};

    #[test]
    fn connect_backoff_grows_then_caps() {
        assert_eq!(connect_backoff(1), Duration::from_millis(750));
        assert_eq!(connect_backoff(2), Duration::from_millis(1500));
        assert_eq!(connect_backoff(3), Duration::from_secs(3));
        // Capped, so raising --connect-attempts buys attempts rather than waiting.
        assert_eq!(connect_backoff(4), Duration::from_secs(4));
        assert_eq!(connect_backoff(50), Duration::from_secs(4));
    }

    #[test]
    fn connect_backoff_does_not_underflow_at_zero() {
        // Attempts are 1-based; guard the arithmetic anyway.
        assert_eq!(connect_backoff(0), Duration::from_millis(750));
    }
}
