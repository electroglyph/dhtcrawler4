//! BitTorrent peer-wire metadata fetcher (BEP 3, BEP 10, BEP 9).
//!
//! [`fetch_metadata`] connects to one peer, performs the handshake and the
//! extension-protocol handshake, downloads the info dictionary with
//! `ut_metadata`, and returns it only after it has been verified against the
//! DHT key (SHA-1, or truncated SHA-256 for v2 torrents).
//!
//! Every read is bounded (R7 in `docs/01-first-principles.md`): frame lengths
//! are checked before any buffer is allocated, non-extended messages are
//! discarded without buffering, `metadata_size` is capped, received pieces can
//! draw on a shared byte budget, and the whole fetch runs under
//! [`FetchLimits::total`].
//!
//! [`seeder`] is a small, correct `ut_metadata` server used by tests, with
//! switchable misbehaviours.
#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects)]

mod assembly;
mod fetch;
pub mod seeder;
mod wire;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use dc4_core::DhtKey;
use sha1::{Digest, Sha1};
use sha2::Sha256;

pub use fetch::{fetch_metadata, fetch_metadata_with_hook};

/// Default TCP connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Default time allowed, after connecting, to complete the BitTorrent handshake
/// and receive the peer's extended handshake.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
/// Default bound on a whole fetch, from connect through verification.
pub const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
/// Default maximum accepted `metadata_size` (8 MiB).
pub const DEFAULT_MAX_METADATA: usize = 8 * 1024 * 1024;

/// Size of one `ut_metadata` piece (BEP 9).
pub const METADATA_PIECE_LEN: usize = 16 * 1024;
/// Largest peer-wire frame accepted before the peer's extended handshake.
pub const MAX_FRAME_BEFORE_EXT_HANDSHAKE: usize = 64 * 1024;
/// Largest peer-wire frame accepted after the peer's extended handshake
/// (one metadata piece plus 1 KiB for the message header and dictionary).
pub const MAX_FRAME_AFTER_EXT_HANDSHAKE: usize = METADATA_PIECE_LEN + 1024;
/// Largest non-extended message accepted (4 MiB, a bitfield for 2^25
/// pieces). Such messages are read and discarded, never buffered.
pub const MAX_DISCARD_FRAME: usize = 4 * 1024 * 1024;
/// Most `ut_metadata` rejects we send on one connection; later incoming
/// requests are ignored.
pub const MAX_REJECTS_SENT: usize = 8;
/// Bytes per permit of [`FetchLimits::byte_budget`] (1 KiB).
pub const BYTE_BUDGET_UNIT: usize = 1024;
/// Maximum number of outstanding `ut_metadata` requests.
pub const MAX_PIPELINED_REQUESTS: usize = 4;
/// Extension message ID we advertise for `ut_metadata`; data arrives with it.
pub const OUR_UT_METADATA_ID: u8 = 1;
/// Client version string sent in our extended handshake (`v`).
pub const CLIENT_VERSION: &str = "dhtcrawler4/0.1";
/// Request-queue depth we advertise in our extended handshake (`reqq`).
pub const ADVERTISED_REQQ: i64 = 250;
/// Prefix of our randomly generated peer IDs (Azureus style).
pub const PEER_ID_PREFIX: &[u8; 8] = b"-DC0100-";

/// Time and size limits for one [`fetch_metadata`] call.
#[derive(Debug, Clone)]
pub struct FetchLimits {
    /// TCP connect timeout.
    pub connect: Duration,
    /// Time after connecting to finish the handshake and receive the extended handshake.
    pub handshake: Duration,
    /// Bound on the whole fetch, from connect through verification.
    pub total: Duration,
    /// Largest `metadata_size` accepted, in bytes.
    pub max_metadata: usize,
    /// Shared budget for metadata bytes in flight, in permits of
    /// [`BYTE_BUDGET_UNIT`] (KiB). Each piece not yet kept takes its size
    /// in KiB, rounded up, before it is stored; redundant copies of an
    /// already-stored piece are free. The permits are released when
    /// [`fetch_metadata`] returns. Waiting counts against `total`.
    /// `None` means no budget.
    pub byte_budget: Option<Arc<tokio::sync::Semaphore>>,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            connect: DEFAULT_CONNECT_TIMEOUT,
            handshake: DEFAULT_HANDSHAKE_TIMEOUT,
            total: DEFAULT_TOTAL_TIMEOUT,
            max_metadata: DEFAULT_MAX_METADATA,
            byte_budget: None,
        }
    }
}

/// Why a fetch failed. Each variant has a stable [`label`](FetchError::label) for metrics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The TCP connection could not be established.
    #[error("connect failed: {0}")]
    Connect(std::io::ErrorKind),
    /// A connect, handshake or total deadline passed.
    #[error("timed out")]
    Timeout,
    /// Reading or writing failed (including the peer closing the connection).
    #[error("i/o error: {0}")]
    Io(std::io::ErrorKind),
    /// The peer's handshake was malformed.
    #[error("malformed handshake")]
    BadHandshake,
    /// The peer's handshake named a different infohash.
    #[error("peer answered with a different infohash")]
    WrongInfoHash,
    /// The peer does not set the extension-protocol (BEP 10) bit.
    #[error("peer does not support the extension protocol")]
    NoExtensionSupport,
    /// The peer's extended handshake does not offer `ut_metadata`.
    #[error("peer does not support ut_metadata")]
    NoMetadataSupport,
    /// `metadata_size` is missing or outside `1..=max_metadata`.
    #[error("invalid metadata_size {0}")]
    MetadataSizeInvalid(i64),
    /// A frame's length prefix exceeds the current maximum.
    #[error("message of {len} bytes exceeds limit of {max}")]
    MessageTooLarge { len: usize, max: usize },
    /// The peer violated the protocol.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// The peer rejected a metadata request.
    #[error("peer rejected a metadata request")]
    Rejected,
    /// The assembled metadata does not hash to the key.
    #[error("metadata does not match the key")]
    HashMismatch,
    /// The byte budget semaphore was closed (the crawler is shutting down).
    #[error("byte budget closed")]
    BudgetClosed,
}

impl FetchError {
    /// A short, stable label for metrics.
    pub fn label(&self) -> &'static str {
        match self {
            FetchError::Connect(_) => "connect",
            FetchError::Timeout => "timeout",
            FetchError::Io(_) => "io",
            FetchError::BadHandshake => "bad_handshake",
            FetchError::WrongInfoHash => "wrong_info_hash",
            FetchError::NoExtensionSupport => "no_extension_support",
            FetchError::NoMetadataSupport => "no_metadata_support",
            FetchError::MetadataSizeInvalid(_) => "metadata_size_invalid",
            FetchError::MessageTooLarge { .. } => "message_too_large",
            FetchError::Protocol(_) => "protocol",
            FetchError::Rejected => "rejected",
            FetchError::HashMismatch => "hash_mismatch",
            FetchError::BudgetClosed => "budget_closed",
        }
    }
}

impl From<std::io::Error> for FetchError {
    fn from(e: std::io::Error) -> Self {
        FetchError::Io(e.kind())
    }
}

/// True when SHA-1(`info`) equals `key`, or the first 20 bytes of SHA-256(`info`) do.
pub fn verify_metadata(key: &DhtKey, info: &[u8]) -> bool {
    if Sha1::digest(info).as_slice() == key.0.as_slice() {
        return true;
    }
    Sha256::digest(info).get(..DhtKey::LEN) == Some(key.0.as_slice())
}

/// Entry points for the fuzz harness (`fuzz/`). Not a stable API.
///
/// Each function feeds arbitrary bytes through the pure wire parsers and
/// returns a small summary. None of them may panic.
#[doc(hidden)]
pub mod fuzzing {
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use crate::wire::{self, Frame, Message};
    use crate::{DEFAULT_MAX_METADATA, MAX_FRAME_AFTER_EXT_HANDSHAKE};

    /// Most frames taken from one input, so a run stays short.
    const MAX_FRAMES: usize = 4096;

    /// Parses `data` as a 68-byte handshake. Returns whether it parsed and,
    /// if so, whether the peer supports extensions.
    pub fn handshake(data: &[u8]) -> Option<bool> {
        wire::parse_handshake(data)
            .ok()
            .map(|h| h.supports_extensions())
    }

    /// Checks a 4-byte length prefix against `max`.
    pub fn frame_len(header: [u8; 4], max: usize) -> Option<usize> {
        wire::check_frame_len(header, max).ok()
    }

    /// Splits `data` into frames with the reader's caps (`ext_max` for
    /// extension frames, the discard budget for anything else) and
    /// classifies each one, parsing extension bodies as an extended
    /// handshake or a `ut_metadata` message. Returns the number of whole
    /// frames seen.
    pub fn frames(data: &[u8], max: usize) -> usize {
        let mut rest = data;
        let mut count = 0usize;
        while count < MAX_FRAMES {
            let Ok(Some((payload, used))) = wire::split_frame(rest, max) else {
                break;
            };
            count = count.saturating_add(1);
            message(payload);
            // `used` counts the 4-byte header, so every step makes progress.
            rest = rest.get(used..).unwrap_or_default();
        }
        count
    }

    /// Classifies one frame payload and parses an extension body.
    pub fn message(payload: &[u8]) {
        if let Ok(Message::Extended { id, body }) = wire::parse_message(payload) {
            if id == wire::EXT_HANDSHAKE_ID {
                ext_handshake(body);
            } else {
                metadata_message(body);
            }
        }
    }

    /// Parses and validates an extended-handshake body. Returns the peer's
    /// `ut_metadata` ID and metadata size when valid.
    pub fn ext_handshake(body: &[u8]) -> Option<(u8, usize)> {
        wire::parse_ext_handshake(body)
            .ok()?
            .validate(DEFAULT_MAX_METADATA)
            .ok()
    }

    /// Parses a `ut_metadata` message body. Returns whether it parsed.
    pub fn metadata_message(body: &[u8]) -> bool {
        wire::parse_metadata_message(body).is_ok()
    }

    /// Runs the async frame reader over `data` until it fails or the input
    /// ends. Returns the number of frames read.
    pub fn read_frames(data: &[u8]) -> usize {
        let mut reader = data;
        let mut count = 0usize;
        let mut cx = Context::from_waker(Waker::noop());
        while count < MAX_FRAMES {
            let fut = pin!(wire::read_frame(&mut reader, MAX_FRAME_AFTER_EXT_HANDSHAKE));
            // A byte slice reader never waits, so one poll finishes the read.
            let Poll::Ready(result) = fut.poll(&mut cx) else {
                break;
            };
            match result {
                Ok(Frame::Extended(payload)) => message(&payload),
                Ok(Frame::KeepAlive | Frame::Discarded { .. }) => {}
                Err(_) => break,
            }
            count = count.saturating_add(1);
        }
        count
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn hooks_parse_valid_and_invalid_input() {
            let mut hs = vec![19u8];
            hs.extend_from_slice(b"BitTorrent protocol");
            hs.extend_from_slice(&[0, 0, 0, 0, 0, 0x10, 0, 0]);
            hs.extend_from_slice(&[7u8; 40]);
            assert_eq!(handshake(&hs), Some(true));
            assert_eq!(handshake(&hs[1..]), None);
            assert_eq!(frame_len([0, 0, 0, 5], 4), None);
            assert_eq!(frame_len([0, 0, 0, 4], 4), Some(4));

            let body = b"d1:md11:ut_metadatai3ee13:metadata_sizei100ee";
            assert_eq!(ext_handshake(body), Some((3, 100)));
            let mut stream = wire::extended_frame(wire::EXT_HANDSHAKE_ID, body).unwrap();
            stream.extend_from_slice(&[0, 0, 0, 0]); // keep-alive
            stream.extend_from_slice(&[0, 0, 0, 2, 4, 9]); // "have", discarded
            stream.extend_from_slice(&[0, 0, 0, 9]); // truncated
            assert_eq!(frames(&stream, 1024), 3);
            assert_eq!(read_frames(&stream), 3);
            assert!(metadata_message(b"d8:msg_typei0e5:piecei0ee"));
            assert!(!metadata_message(b"d5:piecei0ee"));
        }
    }
}
