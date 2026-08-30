//! Walking the lock's operate log, and rendering it.
//!
//! The protocol lives in `ttlock_core::oplog`; this is the multi-page walk on
//! top of it, because [`Operation`] is single-shot and only a caller can decide
//! how to recover.
//!
//! Two properties of `0x25` shape everything here, both established the hard
//! way (§7a of the design notes):
//!
//! * **Reading by sequence is non-destructive and repeatable.** Records stay in
//!   the lock. So a walk that dies halfway needs no local archive and no
//!   crash-safety machinery — it is resumable with `--from`, and this module
//!   prints the sequence to resume from rather than silently losing anything.
//! * **A refusal means the cursor went stale, not that the log ended.** The
//!   only trustworthy end-of-log signal is an empty page. Treating a refusal as
//!   the end truncates the walk and reports a log that stops weeks in the past,
//!   which produced two wrong conclusions during the investigation.

use std::io::Write;

use serde_json::{Map, Value, json};
use ttlock_core::credential::AesKey;
use ttlock_core::error::TtlockError;
use ttlock_core::oplog::{LogCursor, LogPage, LogPageOp, LogRecord, Sequence};
use ttlock_core::packet::LockVersion;

use crate::ble::{Link, run_op};
use crate::error::{CliError, Result};

/// How a walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The lock reported an empty page: the log really is exhausted.
    Exhausted,
    /// The lock refused the cursor twice running. Records remain; resume from
    /// [`Walk::resume_from`].
    Refused,
    /// `--limit` was reached.
    LimitReached,
}

/// What a walk did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Walk {
    /// How many records were handed to the callback.
    pub records: usize,
    /// Why it stopped.
    pub ending: Ending,
    /// The cursor to resume from, when the walk did not reach the end.
    pub resume_from: Option<Sequence>,
}

/// Page through the log from `start`, calling `on_record` for each record as it
/// arrives.
///
/// Records are delivered as they decode rather than collected, so a long walk
/// streams instead of going quiet for ninety round trips.
///
/// # Errors
/// Returns transport and protocol errors as they occur. A refused cursor is
/// *not* an error — it is [`Ending::Refused`], because the records already
/// delivered are good and the walk is resumable.
pub async fn walk<L: Link + ?Sized>(
    link: &mut L,
    aes_key: AesKey,
    version: LockVersion,
    start: LogCursor,
    limit: Option<usize>,
    mut on_record: impl FnMut(&LogRecord) -> Result<()>,
) -> Result<Walk> {
    let mut cursor = start;
    let mut last: Option<Sequence> = None;
    let mut records = 0_usize;

    loop {
        let Some(page) = fetch_page(link, aes_key, version, cursor).await? else {
            tracing::warn!("lock refused the cursor twice; stopping with the log unfinished");
            return Ok(Walk {
                records,
                ending: Ending::Refused,
                resume_from: last,
            });
        };

        for record in &page.records {
            on_record(record)?;
            records += 1;
            if limit.is_some_and(|max| records >= max) {
                // Resume from the page *before* this one, so a limit reached
                // mid-page re-reads the whole page rather than skipping the
                // records after it. Reading by sequence consumes nothing, so a
                // duplicate costs one round trip; a gap loses a record.
                return Ok(Walk {
                    records,
                    ending: Ending::LimitReached,
                    resume_from: last,
                });
            }
        }

        let Some(next) = page.next else {
            return Ok(Walk {
                records,
                ending: Ending::Exhausted,
                resume_from: None,
            });
        };
        // A page that advances nowhere would spin forever.
        if last == Some(next) {
            return Ok(Walk {
                records,
                ending: Ending::Refused,
                resume_from: last,
            });
        }
        last = Some(next);
        cursor = LogCursor::After(next);
    }
}

/// Fetch one page, retrying a refused cursor once.
///
/// `Ok(None)` means the lock refused twice running — a stale cursor, which is
/// an outcome rather than a failure. Every other error propagates.
async fn fetch_page<L: Link + ?Sized>(
    link: &mut L,
    aes_key: AesKey,
    version: LockVersion,
    cursor: LogCursor,
) -> Result<Option<LogPage>> {
    for attempt in 0..2 {
        let mut op = LogPageOp::new(aes_key, version, cursor);
        match run_op(link, &mut op).await {
            Ok(page) => return Ok(Some(page)),
            // Not the end of the log: the cursor went stale, and one retry is
            // worth the round trip before giving up on it.
            Err(CliError::Core(TtlockError::CommandFailed { response, .. })) if attempt == 0 => {
                tracing::debug!(response, "lock refused the cursor; retrying once");
            }
            Err(CliError::Core(TtlockError::CommandFailed { .. })) => return Ok(None),
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

/// How to render records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// One JSON object per line, written as each record arrives. The default:
    /// a long walk stays readable under `jq`, and a partial run is still valid.
    Jsonl,
    /// A single JSON array. Buffers until the walk finishes.
    Json,
    /// Aligned columns for reading by eye.
    Text,
}

/// Turn one record into its JSON object.
///
/// **This includes keypad passcodes**, decoded from the record body — a
/// `keyboard password unlock` record carries the code that was typed. The
/// caller is expected to have warned; see `SECURITY.md`.
#[must_use]
pub fn to_json(record: &LogRecord) -> Value {
    let mut object = Map::new();
    object.insert("sequence".into(), json!(record.sequence.get()));
    object.insert("code".into(), json!(record.code));
    object.insert("operation".into(), json!(record.description()));
    object.insert("at".into(), json!(record.at.to_string()));
    object.insert("battery".into(), json!(record.battery.get()));
    if let Some(passcode) = record.passcode() {
        object.insert("passcode".into(), json!(passcode));
    }
    if !record.tail.is_empty() {
        object.insert("tail".into(), json!(hex::encode(&record.tail)));
    }
    Value::Object(object)
}

/// One record as an aligned line.
#[must_use]
pub fn to_text(record: &LogRecord) -> String {
    let name = record.description().map_or_else(
        || format!("unknown code {}", record.code),
        ToString::to_string,
    );
    let passcode = record
        .passcode()
        .map_or_else(String::new, |code| format!("  passcode={code}"));
    format!(
        "{:>6}  {}  {:>3}%  [{:>3}] {name}{passcode}",
        record.sequence.get(),
        record.at,
        record.battery.get(),
        record.code,
    )
}

/// Write one record in `format`, flushing so a long walk streams.
///
/// # Errors
/// Returns an error if the sink cannot be written to.
pub fn emit(sink: &mut impl Write, record: &LogRecord, format: Format) -> Result<()> {
    match format {
        Format::Jsonl => writeln!(sink, "{}", to_json(record))?,
        Format::Text => writeln!(sink, "{}", to_text(record))?,
        // Buffered by the caller into one array; nothing to write per record.
        Format::Json => return Ok(()),
    }
    sink.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use ttlock_core::credential::AesKey;
    use ttlock_core::crypto::aes_decrypt;
    use ttlock_core::oplog::{LogCursor, parse_page};
    use ttlock_core::packet::{COMM_GET_OPERATE_LOG, Envelope, LockVersion, build_envelope};

    use super::{Ending, Format, Walk, to_json, to_text, walk};
    use crate::ble::Link;
    use crate::error::{CliError, Result};

    fn test_key() -> AesKey {
        AesKey::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    }

    fn unexpected(message: &str) -> CliError {
        CliError::Core(ttlock_core::error::TtlockError::Message(
            message.to_string(),
        ))
    }

    /// `[code][YY MM DD HH MM SS][battery]` plus tail, behind its length byte.
    /// Every value synthetic.
    fn record(code: u8, tail: &[u8]) -> Vec<u8> {
        let mut body = vec![code, 26, 7, 30, 11, 59, 46, 62];
        body.extend_from_slice(tail);
        let mut framed = vec![u8::try_from(body.len()).unwrap_or(u8::MAX)];
        framed.extend_from_slice(&body);
        framed
    }

    /// A `keyboard password unlock` record: the passcode, length-prefixed
    /// ASCII, twice, exactly as the lock stores it.
    fn passcode_record() -> Vec<u8> {
        let mut tail = vec![8];
        tail.extend_from_slice(b"90210555");
        tail.push(8);
        tail.extend_from_slice(b"90210555");
        record(4, &tail)
    }

    /// Wrap a response plaintext into a lock-to-app frame.
    fn frame(plain: &[u8]) -> Result<Vec<u8>> {
        let mut wire = build_envelope(LockVersion::default(), plain[0], plain, &test_key())?;
        wire.truncate(wire.len().saturating_sub(2));
        Ok(wire)
    }

    fn page_frame(sequence: u16, records: &[Vec<u8>]) -> Result<Vec<u8>> {
        let body: Vec<u8> = records.concat();
        let total = u16::try_from(2 + body.len()).unwrap_or(u16::MAX);
        let mut plain = vec![COMM_GET_OPERATE_LOG, 0x01];
        plain.extend_from_slice(&total.to_be_bytes());
        plain.extend_from_slice(&sequence.to_be_bytes());
        plain.extend_from_slice(&body);
        frame(&plain)
    }

    fn end_of_log_frame() -> Result<Vec<u8>> {
        frame(&[COMM_GET_OPERATE_LOG, 0x01, 0x00, 0x00])
    }

    fn refusal_frame() -> Result<Vec<u8>> {
        frame(&[COMM_GET_OPERATE_LOG, 0x00, 0x01])
    }

    /// A lock that answers by cursor rather than replaying a fixed script,
    /// because the walk's behaviour depends on *which* cursor it sent.
    struct LogLink {
        /// `(sequence, framed record)`, ascending.
        records: Vec<(u16, Vec<u8>)>,
        /// How many more times to refuse each cursor, decremented as it fires.
        refusals: HashMap<u16, u32>,
        /// Every cursor requested, in order.
        cursors: Vec<u16>,
        pending: Option<Vec<u8>>,
        /// Answer every cursor with this same page, modelling a lock whose
        /// sequence never advances.
        stuck: Option<(u16, Vec<u8>)>,
    }

    impl LogLink {
        fn new(records: Vec<(u16, Vec<u8>)>) -> Self {
            Self {
                records,
                refusals: HashMap::new(),
                cursors: Vec::new(),
                pending: None,
                stuck: None,
            }
        }

        fn stuck_at(mut self, sequence: u16, body: Vec<u8>) -> Self {
            self.stuck = Some((sequence, body));
            self
        }

        fn refusing(mut self, cursor: u16, times: u32) -> Self {
            self.refusals.insert(cursor, times);
            self
        }

        fn answer(&mut self, cursor: u16) -> Result<Vec<u8>> {
            if let Some(remaining) = self.refusals.get_mut(&cursor).filter(|n| **n > 0) {
                *remaining -= 1;
                return refusal_frame();
            }
            if let Some((sequence, body)) = self.stuck.clone() {
                return page_frame(sequence, std::slice::from_ref(&body));
            }
            match self.records.iter().find(|(sequence, _)| *sequence > cursor) {
                Some((sequence, body)) => page_frame(*sequence, std::slice::from_ref(body)),
                None => end_of_log_frame(),
            }
        }
    }

    impl Link for LogLink {
        // As in `ble.rs`: the `Link` trait declares these `async`, so the impl
        // must match even with nothing to await. Clippy would have this return
        // `impl Future` instead, which for a body using `?` means wrapping it in
        // an immediately-invoked closure — worse code to satisfy a lint about a
        // test double.
        //
        // `unknown_lints` because the lint is new in Rust 1.98 while the flake
        // pins 1.97, where the bare name is an error. Reviewed and confirmed per
        // AGENTS.md; see `ble.rs` for the full reasoning.
        #[allow(unknown_lints, clippy::unused_async_trait_impl)]
        async fn write_frame(&mut self, raw: &[u8]) -> Result<()> {
            let envelope = Envelope::parse(raw)?;
            let plain = aes_decrypt(&envelope.data, &test_key())?;
            let [high, low] = plain[..] else {
                return Err(unexpected("cursor was not two bytes"));
            };
            let cursor = u16::from_be_bytes([high, low]);
            self.cursors.push(cursor);
            self.pending = Some(self.answer(cursor)?);
            Ok(())
        }

        // Same trait-imposed `async` as above.
        #[allow(unknown_lints, clippy::unused_async_trait_impl)]
        async fn next_frame(&mut self, _timeout: Duration) -> Result<Vec<u8>> {
            self.pending.take().ok_or(CliError::Timeout)
        }
    }

    fn three_records() -> Vec<(u16, Vec<u8>)> {
        vec![
            (10, record(47, &[])),
            (11, record(20, &[0x29, 0xa5, 0x39, 0x0a, 0x00, 0x01])),
            (12, record(26, &[])),
        ]
    }

    async fn walk_collecting(
        link: &mut LogLink,
        start: LogCursor,
        limit: Option<usize>,
    ) -> Result<(Walk, Vec<u16>)> {
        let mut seen = Vec::new();
        let outcome = walk(
            link,
            test_key(),
            LockVersion::default(),
            start,
            limit,
            |record| {
                seen.push(record.sequence.get());
                Ok(())
            },
        )
        .await?;
        Ok((outcome, seen))
    }

    #[tokio::test]
    async fn walks_to_the_empty_page_and_reports_it_exhausted() -> Result<()> {
        let mut link = LogLink::new(three_records());
        let (outcome, seen) = walk_collecting(&mut link, LogCursor::Beginning, None).await?;

        assert_eq!(seen, vec![10, 11, 12]);
        assert_eq!(outcome.ending, Ending::Exhausted);
        assert_eq!(outcome.records, 3);
        assert_eq!(outcome.resume_from, None);
        // Starts at the beginning, then follows each page's sequence.
        assert_eq!(link.cursors, vec![0, 10, 11, 12]);
        Ok(())
    }

    #[tokio::test]
    async fn a_refused_cursor_is_retried_and_the_walk_continues() -> Result<()> {
        // The property the whole investigation turned on: a refusal means the
        // cursor went stale, NOT that the log ended. Stopping here truncates
        // the log and reports one that stops weeks in the past.
        let mut link = LogLink::new(three_records()).refusing(11, 1);
        let (outcome, seen) = walk_collecting(&mut link, LogCursor::Beginning, None).await?;

        assert_eq!(seen, vec![10, 11, 12], "a refusal must not end the walk");
        assert_eq!(outcome.ending, Ending::Exhausted);
        // Cursor 11 was sent twice: refused, then retried.
        assert_eq!(link.cursors.iter().filter(|c| **c == 11).count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn two_refusals_stop_the_walk_without_failing_it() -> Result<()> {
        let mut link = LogLink::new(three_records()).refusing(11, u32::MAX);
        let (outcome, seen) = walk_collecting(&mut link, LogCursor::Beginning, None).await?;

        // The records already read are good, so this is an outcome and not an
        // error — and the caller is told where to pick up.
        assert_eq!(seen, vec![10, 11]);
        assert_eq!(outcome.ending, Ending::Refused);
        assert_eq!(
            outcome.resume_from.map(ttlock_core::oplog::Sequence::get),
            Some(11)
        );
        assert_eq!(link.cursors.iter().filter(|c| **c == 11).count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_limit_stops_early_and_resumes_without_a_gap() -> Result<()> {
        let mut link = LogLink::new(three_records());
        let (outcome, seen) = walk_collecting(&mut link, LogCursor::Beginning, Some(2)).await?;

        assert_eq!(seen, vec![10, 11]);
        assert_eq!(outcome.ending, Ending::LimitReached);
        // Resumes from the page *before* the last one read: re-reading a record
        // costs a round trip, skipping one loses it.
        assert_eq!(
            outcome.resume_from.map(ttlock_core::oplog::Sequence::get),
            Some(10)
        );

        let mut again = LogLink::new(three_records());
        let (_, rest) = walk_collecting(&mut again, LogCursor::After(seq(10)), None).await?;
        assert_eq!(rest, vec![11, 12], "resuming must not skip a record");
        Ok(())
    }

    #[tokio::test]
    async fn an_explicit_start_skips_what_came_before() -> Result<()> {
        let mut link = LogLink::new(three_records());
        let (_, seen) = walk_collecting(&mut link, LogCursor::After(seq(10)), None).await?;
        assert_eq!(seen, vec![11, 12]);
        Ok(())
    }

    #[tokio::test]
    async fn the_sentinel_is_sent_verbatim() -> Result<()> {
        let mut link = LogLink::new(three_records());
        let (_, _) = walk_collecting(&mut link, LogCursor::SinceLastRead, None).await?;
        assert_eq!(link.cursors.first(), Some(&0xffff));
        Ok(())
    }

    #[tokio::test]
    async fn a_page_that_does_not_advance_does_not_spin_forever() -> Result<()> {
        // A lock that keeps answering with the same sequence would otherwise
        // loop until the process is killed.
        let mut link = LogLink::new(Vec::new()).stuck_at(10, record(47, &[]));
        let (outcome, _) = walk_collecting(&mut link, LogCursor::Beginning, None).await?;
        assert_eq!(outcome.ending, Ending::Refused);
        Ok(())
    }

    fn seq(value: u16) -> ttlock_core::oplog::Sequence {
        ttlock_core::oplog::Sequence::new(value).unwrap_or_else(|| {
            // 0 is a legal sequence, so this fallback cannot mask a rejection.
            ttlock_core::oplog::Sequence::new(0).unwrap_or_else(|| unreachable!())
        })
    }

    // --- rendering ---------------------------------------------------------

    fn only_record(data: &[u8]) -> Result<ttlock_core::oplog::LogRecord> {
        let page = parse_page(data)?;
        page.records
            .into_iter()
            .next()
            .ok_or_else(|| unexpected("page carried no records"))
    }

    fn page_bytes(sequence: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = records.concat();
        let total = u16::try_from(2 + body.len()).unwrap_or(u16::MAX);
        let mut data = Vec::new();
        data.extend_from_slice(&total.to_be_bytes());
        data.extend_from_slice(&sequence.to_be_bytes());
        data.extend_from_slice(&body);
        data
    }

    #[tokio::test]
    async fn a_keypad_record_decodes_its_passcode() -> Result<()> {
        // The CLI warns before this reaches a terminal; the decoding itself is
        // the point of the field.
        let entry = only_record(&page_bytes(273, &[passcode_record()]))?;

        let rendered = to_json(&entry).to_string();
        assert!(rendered.contains("90210555"));
        assert!(rendered.contains("tail"));
        assert!(to_text(&entry).contains("passcode=90210555"));
        Ok(())
    }

    #[tokio::test]
    async fn ordinary_records_render_their_fields() -> Result<()> {
        let entry = only_record(&page_bytes(270, &[record(47, &[])]))?;
        let rendered = to_json(&entry);

        assert_eq!(rendered["sequence"], 270);
        assert_eq!(rendered["code"], 47);
        assert_eq!(rendered["operation"], "keypad lock");
        assert_eq!(rendered["at"], "2026-07-30 11:59:46");
        assert_eq!(rendered["battery"], 62);
        assert!(rendered.get("passcode").is_none());

        assert!(to_text(&entry).contains("keypad lock"));
        Ok(())
    }

    #[tokio::test]
    async fn an_unknown_code_is_named_as_unknown_rather_than_guessed() -> Result<()> {
        let entry = only_record(&page_bytes(270, &[record(200, &[])]))?;
        assert_eq!(to_json(&entry)["operation"], serde_json::Value::Null);
        assert!(to_text(&entry).contains("unknown code 200"));
        Ok(())
    }

    #[tokio::test]
    async fn json_format_writes_nothing_per_record() -> Result<()> {
        // The array is assembled by the caller, so `emit` must stay silent or
        // the document is preceded by loose objects.
        let entry = only_record(&page_bytes(270, &[record(47, &[])]))?;
        let mut sink = Vec::new();
        super::emit(&mut sink, &entry, Format::Json)?;
        assert!(sink.is_empty());

        let mut streamed = Vec::new();
        super::emit(&mut streamed, &entry, Format::Jsonl)?;
        assert!(String::from_utf8_lossy(&streamed).ends_with('\n'));
        Ok(())
    }
}
