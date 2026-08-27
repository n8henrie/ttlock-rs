//! Transport-agnostic (sans-IO) implementation of the `TTLock` BLE protocol.
//!
//! This crate contains packet framing, encryption, advertisement parsing, and
//! lock-data handling, but performs no I/O itself. Callers (a btleplug CLI, a
//! bleak-based Home Assistant integration, ...) move bytes between the lock
//! and this crate.
//!
//! # Driving an operation
//!
//! [`ops::Operation`] is the entry point. Ask it for a frame, write that frame
//! however your transport writes bytes, hand back the reassembled response, and
//! repeat until it reports [`ops::Step::Done`]:
//!
//! ```no_run
//! use ttlock_core::credential::AesKey;
//! use ttlock_core::error::TtlockError;
//! use ttlock_core::framing::FrameAssembler;
//! use ttlock_core::ops::{Operation, StatusOp, Step};
//! use ttlock_core::packet::LockVersion;
//!
//! # fn example(
//! #     aes_key: AesKey,
//! #     write: impl Fn(&[u8]),
//! #     read_notification: impl Fn() -> Vec<u8>,
//! # ) -> Result<(), TtlockError> {
//! let mut op = StatusOp::new(aes_key, LockVersion::default());
//! let mut assembler = FrameAssembler::new();
//! let mut step = op.start()?;
//!
//! let state = loop {
//!     match step {
//!         Step::Write(frame) => {
//!             write(&frame);
//!             // BLE delivers notifications in chunks, so keep feeding the
//!             // assembler until a whole frame falls out.
//!             let response = loop {
//!                 assembler.push(&read_notification());
//!                 if let Some(frame) = assembler.next_frame() {
//!                     break frame;
//!                 }
//!             };
//!             step = op.handle_frame(&response)?;
//!         }
//!         Step::Done(state) => break state,
//!     }
//! };
//! println!("lock is {state:?}");
//! # Ok(())
//! # }
//! ```
//!
//! # Which errors are worth retrying
//!
//! Only [`error::TtlockError::CrcMismatch`]: it means the reply arrived
//! corrupted, and because operations verify the CRC before advancing any state,
//! re-sending the same frame resumes the exchange rather than desynchronizing
//! it. Everything else means the lock decrypted the command and rejected it —
//! identical bytes will be rejected identically — or indicates a bug. Ask
//! [`error::TtlockError::is_retryable`] rather than matching by hand.
//!
//! # Tracking a lock over time
//!
//! [`ops::Operation`] covers one exchange. [`tracker::LockTracker`] sits above
//! it and holds what is believed about the lock *between* exchanges — bolt
//! position, battery, availability, and whether a command is in flight — from
//! advertisements and command outcomes. Every consumer should report from a
//! tracker rather than deriving these rules again; the daemon and the Home
//! Assistant component drifted apart three times before it existed.

#![warn(missing_docs)]
// Doc links are part of the published API surface: a broken one ships a dead
// link to docs.rs.
#![deny(rustdoc::broken_intra_doc_links)]

pub mod advertisement;
pub mod config;
pub mod crc;
pub mod credential;
pub mod crypto;
pub mod error;
pub mod framing;
pub mod oplog;
pub mod ops;
pub mod packet;
pub mod policy;
pub mod sciener;
pub mod tracker;
