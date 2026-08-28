//! The operate log (`0x25 COMM_GET_OPERATE_LOG`): the lock's own audit trail.
//!
//! Read [section 7a of the design notes][notes] before extending this. Two
//! findings there constrain everything here:
//!
//! * **The log records operations the lock performs, never bolt movement it
//!   observes.** A thumbturn or a key leaves no trace, in either direction, so
//!   this is useless for lock state and is not wired into the tracker. It is an
//!   audit trail and nothing more.
//! * **A record can disclose a keypad passcode.** [`LogRecord::passcode`]
//!   decodes it, so a caller at least knows the field is there.
//!
//! [notes]: https://github.com/n8henrie/ttlock-rs/blob/master/docs/protocol-and-design.md

use chrono::NaiveDate;
use chrono::NaiveDateTime;

use crate::advertisement::Percent;
use crate::credential::AesKey;
use crate::error::{Result, TtlockError};
use crate::ops::{Operation, Step};
use crate::packet::{COMM_GET_OPERATE_LOG, Envelope, LockVersion, build_envelope};

/// A record's position in the log.
///
/// `0xFFFF` is reserved on the wire as the "since last read" sentinel, so it
/// cannot also be a position — hence the constructor rather than a bare `u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sequence(u16);

impl Sequence {
    /// The value the wire reserves for [`LogCursor::SinceLastRead`].
    const SENTINEL: u16 = 0xFFFF;

    /// Wrap a sequence number, rejecting the reserved sentinel.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        if value == Self::SENTINEL {
            None
        } else {
            Some(Self(value))
        }
    }

    /// The sequence number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Where to begin reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogCursor {
    /// Everything the lock still holds, from the oldest record on.
    ///
    /// Non-destructive and repeatable: records stay in the lock and can be read
    /// again as often as you like.
    Beginning,
    /// Everything after `Sequence`, which is how a walk advances page to page.
    ///
    /// Also non-destructive.
    After(Sequence),
    /// Records the lock has not handed over since the last sentinel read.
    ///
    /// **This one is stateful.** The lock keeps a bookmark and this advances
    /// it, so a second read returns only what arrived in between — and if a
    /// page is refused mid-walk the bookmark can still move past the record
    /// that was never delivered. Sequence 267 was skipped exactly this way
    /// during the investigation and only [`LogCursor::After`] could recover it.
    /// Prefer the other two unless "what is new" is genuinely the question.
    SinceLastRead,
}

impl LogCursor {
    /// The two-byte cursor as the lock expects it.
    #[must_use]
    pub const fn to_wire(self) -> [u8; 2] {
        let value = match self {
            Self::Beginning => 0,
            Self::After(sequence) => sequence.get(),
            Self::SinceLastRead => Sequence::SENTINEL,
        };
        value.to_be_bytes()
    }
}

/// One entry in the lock's audit trail.
///
/// The first eight bytes — code, six-byte date, battery — are confirmed across
/// 120 real records. Everything after them varies by code and is kept as
/// [`LogRecord::tail`] rather than guessed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// Position in the log, from the page header.
    pub sequence: Sequence,
    /// What happened, as the lock's own operation code.
    pub code: u8,
    /// When, on the lock's clock — which has no NTP and is not necessarily
    /// right. Compare against `COMM_GET_LOCK_TIME` before trusting it.
    pub at: NaiveDateTime,
    /// Battery level at the time of the operation.
    pub battery: Percent,
    /// Code-specific bytes following the confirmed header, undecoded.
    pub tail: Vec<u8>,
}

impl LogRecord {
    /// A human-readable name for [`LogRecord::code`], or `None` for a code
    /// absent from the vendor's table.
    #[must_use]
    pub const fn description(&self) -> Option<&'static str> {
        describe(self.code)
    }

    /// The keypad passcode this record discloses, if it discloses one.
    ///
    /// A `4 keyboard password unlock` record carries the passcode as
    /// length-prefixed ASCII, twice — a working door code, readable by anyone
    /// holding the AES key. Decoded here because the same digits are in the
    /// raw record body anyway; withholding it would be theatre. See
    /// `SECURITY.md` for what that means for saved output.
    #[must_use]
    pub fn passcode(&self) -> Option<&str> {
        if self.code != CODE_KEYBOARD_PASSCODE_UNLOCK {
            return None;
        }
        let length = usize::from(*self.tail.first()?);
        let digits = self.tail.get(1..1 + length)?;
        let text = core::str::from_utf8(digits).ok()?;
        text.chars().all(|c| c.is_ascii_digit()).then_some(text)
    }
}

/// One page of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogPage {
    /// The records it carried. Empty when the lock reports the log exhausted.
    pub records: Vec<LogRecord>,
    /// The sequence to continue from, or `None` at the end of the log.
    pub next: Option<Sequence>,
}

impl LogPage {
    /// Whether the lock reported no further records.
    ///
    /// This is the *only* trustworthy end-of-log signal. A refusal
    /// (`response != 1`, surfaced as [`TtlockError::CommandFailed`]) means the
    /// cursor went stale, not that the log ended — treating one as the other
    /// truncates the walk and silently reports a log that stops weeks in the
    /// past.
    #[must_use]
    pub const fn is_end_of_log(&self) -> bool {
        self.next.is_none()
    }
}

const CODE_KEYBOARD_PASSCODE_UNLOCK: u8 = 4;

/// Fetch one page of the operate log.
///
/// One page per operation, because [`Operation`] is single-shot; walking the
/// whole log means driving a fresh `LogPageOp` per page and is the caller's
/// job, since only the caller can reconnect.
#[derive(Debug)]
pub struct LogPageOp {
    aes_key: AesKey,
    version: LockVersion,
    cursor: LogCursor,
    awaiting_response: bool,
}

impl LogPageOp {
    /// Read the page following `cursor`.
    #[must_use]
    pub const fn new(aes_key: AesKey, version: LockVersion, cursor: LogCursor) -> Self {
        Self {
            aes_key,
            version,
            cursor,
            awaiting_response: false,
        }
    }
}

impl Operation for LogPageOp {
    type Output = LogPage;

    fn start(&mut self) -> Result<Step<LogPage>> {
        let frame = build_envelope(
            self.version,
            COMM_GET_OPERATE_LOG,
            &self.cursor.to_wire(),
            &self.aes_key,
        )?;
        self.awaiting_response = true;
        Ok(Step::Write(frame))
    }

    fn handle_frame(&mut self, raw: &[u8]) -> Result<Step<LogPage>> {
        if !self.awaiting_response {
            return Err(TtlockError::Message(
                "received a frame when none was expected".to_string(),
            ));
        }
        let envelope = Envelope::parse(raw)?;
        envelope.ensure_crc()?;
        let command = envelope.decrypt_command(&self.aes_key)?;
        crate::packet::parse_success_response(&command, COMM_GET_OPERATE_LOG)?;
        let page = parse_page(&command.data)?;
        self.awaiting_response = false;
        Ok(Step::Done(page))
    }
}

/// Decode one page body: `[total_len u16][sequence u16]` then repeated
/// `[record_len u8][record_len bytes]`.
///
/// # Errors
/// Returns an error if the page is truncated or a record's date does not
/// decode — both mean the layout assumption has broken, which should be loud
/// rather than silently producing fewer records.
pub fn parse_page(data: &[u8]) -> Result<LogPage> {
    let Some(header) = data.get(0..2) else {
        return Err(page_error("page has no length header"));
    };
    let total_length = u16::from_be_bytes([header[0], header[1]]);
    if total_length == 0 {
        // The lock's explicit "nothing further" answer. Distinct from a
        // refusal, and the only reliable end-of-log signal.
        return Ok(LogPage {
            records: Vec::new(),
            next: None,
        });
    }

    let Some(sequence_bytes) = data.get(2..4) else {
        return Err(page_error("page claims records but carries no sequence"));
    };
    let raw_sequence = u16::from_be_bytes([sequence_bytes[0], sequence_bytes[1]]);
    let Some(sequence) = Sequence::new(raw_sequence) else {
        return Err(page_error("page sequence is the reserved sentinel"));
    };

    let mut records = Vec::new();
    let mut index = 4;
    while index < data.len() {
        let record_length = usize::from(data[index]);
        index += 1;
        // A record is code + six-byte date + battery at minimum.
        if record_length < 8 {
            return Err(page_error("record is shorter than its fixed header"));
        }
        let Some(body) = data.get(index..index + record_length) else {
            return Err(page_error("record runs past the end of the page"));
        };
        records.push(parse_record(sequence, body)?);
        index += record_length;
    }

    if records.is_empty() {
        return Err(page_error("page header promised records but none decoded"));
    }
    Ok(LogPage {
        records,
        next: Some(sequence),
    })
}

fn parse_record(sequence: Sequence, body: &[u8]) -> Result<LogRecord> {
    let code = body[0];
    let at = decode_date(&body[1..7])?;
    let raw_battery = body[7];
    let Some(battery) = Percent::new(raw_battery) else {
        return Err(page_error("record battery byte exceeds 100"));
    };
    Ok(LogRecord {
        sequence,
        code,
        at,
        battery,
        tail: body[8..].to_vec(),
    })
}

/// Six bytes of `YY MM DD HH MM SS`, with the year offset from 2000.
fn decode_date(bytes: &[u8]) -> Result<NaiveDateTime> {
    let year = 2000 + i32::from(bytes[0]);
    NaiveDate::from_ymd_opt(year, u32::from(bytes[1]), u32::from(bytes[2]))
        .and_then(|date| {
            date.and_hms_opt(
                u32::from(bytes[3]),
                u32::from(bytes[4]),
                u32::from(bytes[5]),
            )
        })
        .ok_or_else(|| page_error("record carries an impossible date"))
}

fn page_error(reason: &str) -> TtlockError {
    TtlockError::Message(format!("operate log: {reason}"))
}

/// The vendor's operation-code table, plus the two codes this project
/// identified from behaviour.
///
/// Returns `None` for anything absent, so a caller can say "unknown" rather
/// than print a wrong name.
#[must_use]
pub const fn describe(code: u8) -> Option<&'static str> {
    let name = match code {
        1 => "mobile unlock",
        3 => "server unlock",
        4 => "keyboard password unlock",
        5 => "keyboard modify password",
        6 => "keyboard remove single password",
        7 => "error password unlock",
        8 => "keyboard remove all passwords",
        9 => "keyboard password kicked",
        10 => "use delete code",
        11 => "passcode expired",
        12 => "space insufficient",
        13 => "passcode in black list",
        14 => "door reboot",
        15 => "add ic",
        16 => "clear ic succeed",
        17 => "ic unlock succeed",
        18 => "delete ic succeed",
        19 => "bong unlock",
        20 => "fr unlock succeed",
        21 => "add fr",
        22 => "fr unlock failed",
        23 => "delete fr succeed",
        24 => "clear fr succeed",
        25 => "ic unlock failed",
        26 => "operate ble lock",
        27 => "operate key unlock",
        28 => "gateway unlock",
        29 => "illegal unlock",
        30 => "door sensor lock",
        31 => "door sensor unlock",
        32 => "door go out",
        33 => "fr lock",
        34 => "passcode lock",
        35 => "ic lock",
        36 => "operate key lock",
        37 => "remote control key",
        38 => "passcode unlock failed lock reverse",
        39 => "ic unlock failed lock reverse",
        40 => "fr unlock failed lock reverse",
        41 => "app unlock failed lock reverse",
        // 47 and 48 are absent from the vendor table. 47 was identified from
        // its schedule, not from a packet: it lands at 08:45-08:51 and again at
        // 15:58-16:00 on weekdays only, each time followed by a fingerprint
        // unlock a quarter to half an hour later, and it carries no operator
        // id because locking from the keypad identifies nobody. 48 is adjacent,
        // identically shaped, and was seen twice, both times right after
        // somebody fumbled at the keypad — hence the hedge. See section 7a.
        47 => "keypad lock",
        48 => "keypad lock failed (unconfirmed)",
        51 => "ic unlock failed blacklist",
        52 => "app dead lock",
        55 => "wireless key fob",
        56 => "wireless key pad",
        57 => "qr code unlock success",
        58 => "qr code unlock failed",
        67 => "face 3d unlock success",
        68 => "face 3d unlock failed lock reverse",
        69 => "face 3d lock",
        70 => "face 3d add success",
        71 => "face 3d unlock failed invalid time",
        72 => "face 3d delete success",
        73 => "face 3d clear success",
        74 => "cpu card unlock failed",
        75 => "app auth key unlock success",
        76 => "gateway auth key unlock success",
        77 => "double check key unlock",
        78 => "double check passcode unlock",
        79 => "double check finger print unlock",
        80 => "double check card unlock",
        81 => "double check face unlock",
        82 => "double check key fob unlock",
        83 => "double check palm vein unlock",
        84 => "palm vein unlock success",
        85 => "palm vein unlock failed lock reverse",
        86 => "palm vein lock",
        87 => "palm vein add success",
        88 => "palm vein unlock failed",
        89 => "palm vein delete success",
        90 => "palm vein clear success",
        91 => "card unlock failed",
        92 => "admin code unlock",
        93 => "add passcode successfully",
        94 => "third device unlock success",
        95 => "third device lock success",
        96 => "third device unlock failed lock reverse",
        97 => "third device unlock failed invalid time",
        98 => "double check third device verify",
        99 => "add third device",
        100 => "delete third device",
        101 => "clear third device",
        _ => return None,
    };
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::{LogCursor, LogPageOp, Sequence, describe, parse_page};
    use crate::credential::AesKey;
    use crate::error::{Result, TtlockError};
    use crate::ops::{Operation, Step};
    use crate::packet::{COMM_GET_OPERATE_LOG, Envelope, LockVersion, build_envelope};

    fn test_key() -> AesKey {
        AesKey::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    }

    fn unexpected(message: &str) -> TtlockError {
        TtlockError::Message(message.to_string())
    }

    /// A sequence by value, without an `unwrap` (the workspace denies them).
    /// Falls back to 0, which is a legal sequence and so cannot mask a
    /// rejection of the sentinel.
    fn sequence(value: u16) -> Sequence {
        Sequence::new(value).unwrap_or(Sequence(0))
    }

    /// `[code][YY MM DD HH MM SS][battery]` plus a code-specific tail, wrapped
    /// in its length byte. Mirrors the layout confirmed on real hardware; every
    /// value here is synthetic.
    fn record(code: u8, battery: u8, tail: &[u8]) -> Vec<u8> {
        let mut body = vec![code, 26, 7, 30, 11, 59, 46, battery];
        body.extend_from_slice(tail);
        let mut framed = vec![u8::try_from(body.len()).unwrap_or(u8::MAX)];
        framed.extend_from_slice(&body);
        framed
    }

    /// `[total_len u16][sequence u16]` then the records.
    fn page(sequence: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = records.concat();
        let total = u16::try_from(2 + body.len()).unwrap_or(u16::MAX);
        let mut data = Vec::new();
        data.extend_from_slice(&total.to_be_bytes());
        data.extend_from_slice(&sequence.to_be_bytes());
        data.extend_from_slice(&body);
        data
    }

    fn response_frame(plain: &[u8]) -> Result<Vec<u8>> {
        let mut wire = build_envelope(LockVersion::default(), plain[0], plain, &test_key())?;
        wire.truncate(wire.len().saturating_sub(2));
        Ok(wire)
    }

    // --- cursors ---------------------------------------------------------

    #[test]
    fn sentinel_cannot_be_mistaken_for_a_position() {
        assert!(Sequence::new(0xffff).is_none());
        assert_eq!(Sequence::new(0xfffe).map(Sequence::get), Some(0xfffe));
        assert_eq!(Sequence::new(0).map(Sequence::get), Some(0));
    }

    #[test]
    fn cursors_encode_to_the_wire_values() {
        assert_eq!(LogCursor::Beginning.to_wire(), [0x00, 0x00]);
        assert_eq!(LogCursor::After(sequence(0x010e)).to_wire(), [0x01, 0x0e]);
        assert_eq!(LogCursor::SinceLastRead.to_wire(), [0xff, 0xff]);
    }

    // --- page decoding ---------------------------------------------------

    #[test]
    fn decodes_a_single_record_page() -> Result<()> {
        // The shape of a keypad-lock record: no operator id, so eight bytes.
        let decoded = parse_page(&page(270, &[record(47, 65, &[])]))?;
        assert_eq!(decoded.next, Some(sequence(270)));
        assert!(!decoded.is_end_of_log());

        let [entry] = decoded.records.as_slice() else {
            return Err(unexpected("expected exactly one record"));
        };
        assert_eq!(entry.code, 47);
        assert_eq!(entry.battery.get(), 65);
        assert_eq!(entry.at.to_string(), "2026-07-30 11:59:46");
        assert!(entry.tail.is_empty());
        assert_eq!(entry.description(), Some("keypad lock"));
        Ok(())
    }

    #[test]
    fn decodes_several_records_in_one_page() -> Result<()> {
        let decoded = parse_page(&page(
            271,
            &[
                record(20, 62, &[0x29, 0xa5, 0x39, 0x0a, 0x00, 0x01]),
                record(47, 62, &[]),
            ],
        ))?;
        let codes: Vec<u8> = decoded.records.iter().map(|r| r.code).collect();
        assert_eq!(codes, vec![20, 47]);
        // Every record on a page shares the page's sequence number.
        assert!(decoded.records.iter().all(|r| r.sequence == sequence(271)));
        Ok(())
    }

    #[test]
    fn zero_length_page_is_the_end_of_the_log() -> Result<()> {
        let decoded = parse_page(&[0x00, 0x00])?;
        assert!(decoded.is_end_of_log());
        assert!(decoded.records.is_empty());
        Ok(())
    }

    #[test]
    fn keeps_the_undecoded_tail_rather_than_guessing() -> Result<()> {
        let tail = [0x29, 0xa5, 0x39, 0x0a, 0x00, 0x01];
        let decoded = parse_page(&page(271, &[record(20, 62, &tail)]))?;
        let [entry] = decoded.records.as_slice() else {
            return Err(unexpected("expected exactly one record"));
        };
        assert_eq!(entry.tail, tail);
        Ok(())
    }

    #[test]
    fn unknown_codes_are_reported_as_unknown_not_guessed() {
        assert_eq!(describe(20), Some("fr unlock succeed"));
        assert_eq!(describe(200), None);
        assert_eq!(describe(0), None);
    }

    // --- malformed pages are loud ----------------------------------------

    #[test]
    fn rejects_a_record_running_past_the_page() {
        let mut data = page(270, &[record(47, 65, &[])]);
        data.truncate(data.len() - 3);
        assert!(parse_page(&data).is_err());
    }

    #[test]
    fn rejects_an_impossible_date() {
        // Month 13: the layout assumption has broken, and that should be loud
        // rather than quietly yielding fewer records.
        let mut framed = record(47, 65, &[]);
        framed[3] = 13;
        assert!(parse_page(&page(270, &[framed])).is_err());
    }

    #[test]
    fn rejects_a_battery_byte_above_one_hundred() {
        assert!(parse_page(&page(270, &[record(47, 101, &[])])).is_err());
    }

    #[test]
    fn rejects_a_page_whose_sequence_is_the_sentinel() {
        assert!(parse_page(&page(0xffff, &[record(47, 65, &[])])).is_err());
    }

    // --- passcode disclosure ---------------------------------------------

    #[test]
    fn exposes_the_passcode_a_keypad_record_discloses() -> Result<()> {
        // Length-prefixed ASCII, twice, exactly as the lock stores it.
        let mut tail = vec![8];
        tail.extend_from_slice(b"90210555");
        tail.push(8);
        tail.extend_from_slice(b"90210555");

        let decoded = parse_page(&page(273, &[record(4, 62, &tail)]))?;
        let [entry] = decoded.records.as_slice() else {
            return Err(unexpected("expected exactly one record"));
        };
        assert_eq!(entry.passcode(), Some("90210555"));
        Ok(())
    }

    #[test]
    fn records_without_a_passcode_report_none() -> Result<()> {
        let decoded = parse_page(&page(
            270,
            &[record(47, 65, &[]), record(20, 62, &[1, 2, 3, 4])],
        ))?;
        assert!(decoded.records.iter().all(|r| r.passcode().is_none()));
        Ok(())
    }

    // --- the operation ---------------------------------------------------

    #[test]
    fn op_writes_the_cursor_then_yields_the_page() -> Result<()> {
        let mut op = LogPageOp::new(
            test_key(),
            LockVersion::default(),
            LogCursor::After(sequence(0x010e)),
        );
        let Step::Write(frame) = op.start()? else {
            return Err(unexpected("start did not yield a write"));
        };
        let envelope = Envelope::parse(&frame)?;
        assert_eq!(envelope.command_type, COMM_GET_OPERATE_LOG);
        let plain = crate::crypto::aes_decrypt(&envelope.data, &test_key())?;
        assert_eq!(&plain, &[0x01, 0x0e]);

        let mut body = vec![COMM_GET_OPERATE_LOG, 0x01];
        body.extend_from_slice(&page(271, &[record(47, 65, &[])]));
        let step = op.handle_frame(&response_frame(&body)?)?;
        let Step::Done(decoded) = step else {
            return Err(unexpected("op did not complete"));
        };
        assert_eq!(decoded.records.len(), 1);
        Ok(())
    }

    #[test]
    fn op_surfaces_a_refusal_as_an_error_not_an_empty_page() -> Result<()> {
        // The distinction the whole walk depends on: a refusal means the cursor
        // went stale, and treating it as end-of-log truncates the log silently.
        let mut op = LogPageOp::new(test_key(), LockVersion::default(), LogCursor::SinceLastRead);
        let _ = op.start()?;
        let step = op.handle_frame(&response_frame(&[COMM_GET_OPERATE_LOG, 0x00, 0x01])?);
        assert!(matches!(step, Err(TtlockError::CommandFailed { .. })));
        Ok(())
    }

    #[test]
    fn op_rejects_a_frame_before_start() -> Result<()> {
        let mut op = LogPageOp::new(test_key(), LockVersion::default(), LogCursor::Beginning);
        let mut body = vec![COMM_GET_OPERATE_LOG, 0x01];
        body.extend_from_slice(&page(271, &[record(47, 65, &[])]));
        assert!(op.handle_frame(&response_frame(&body)?).is_err());
        Ok(())
    }
}
