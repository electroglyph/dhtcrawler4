//! The metadata fetch sequence (design §8).

use std::future::Future;
use std::net::SocketAddr;

use dc4_core::DhtKey;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;

use crate::assembly::Assembly;
use crate::wire::{
    self, EXT_HANDSHAKE_ID, Frame, HANDSHAKE_LEN, Message, MetadataMessage, PEER_ID_LEN,
};
use crate::{
    ADVERTISED_REQQ, BYTE_BUDGET_UNIT, CLIENT_VERSION, FetchError, FetchLimits,
    MAX_FRAME_AFTER_EXT_HANDSHAKE, MAX_FRAME_BEFORE_EXT_HANDSHAKE, MAX_REJECTS_SENT,
    OUR_UT_METADATA_ID, PEER_ID_PREFIX, verify_metadata,
};

/// Read buffer size for the peer connection.
const READ_BUFFER_LEN: usize = 32 * 1024;

/// Fetches and verifies the info dictionary for `key` from `peer`.
///
/// The returned bytes hash to `key` (SHA-1, or the first 20 bytes of SHA-256).
/// The whole call, connect through verification, is bounded by `limits.total`.
/// Permits taken from `limits.byte_budget` are released before it returns.
pub async fn fetch_metadata(
    peer: SocketAddr,
    key: DhtKey,
    limits: &FetchLimits,
) -> Result<Vec<u8>, FetchError> {
    fetch_metadata_with_hook(peer, key, limits, || {}).await
}

/// [`fetch_metadata`] with a hook run once the TCP connect succeeds, before
/// the handshake. The fetch worker feeds the sampler's live ring here so a
/// hint peer that connected but fails later still counts as live.
pub async fn fetch_metadata_with_hook(
    peer: SocketAddr,
    key: DhtKey,
    limits: &FetchLimits,
    on_connect: impl FnOnce() + Send,
) -> Result<Vec<u8>, FetchError> {
    let result = match tokio::time::timeout(
        limits.total,
        fetch_inner(peer, key, limits, on_connect),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(FetchError::Timeout),
    };
    if let Err(e) = &result {
        tracing::debug!(%key, reason = e.label(), "metadata fetch failed");
    }
    result
}

/// Runs `f` until `deadline` (if any), mapping expiry to [`FetchError::Timeout`].
async fn within<F: Future>(deadline: Option<Instant>, f: F) -> Result<F::Output, FetchError> {
    match deadline {
        Some(d) => tokio::time::timeout_at(d, f)
            .await
            .map_err(|_| FetchError::Timeout),
        None => Ok(f.await),
    }
}

fn our_peer_id() -> [u8; PEER_ID_LEN] {
    let mut id = [0u8; PEER_ID_LEN];
    let random: [u8; PEER_ID_LEN] = rand::random();
    let n = PEER_ID_PREFIX.len();
    id[..n].copy_from_slice(PEER_ID_PREFIX);
    id[n..].copy_from_slice(&random[n..]);
    id
}

/// A per-operation deadline for phase 2, so a peer that stalls after the
/// extended handshake cannot hold a fetch worker for the whole `total`
/// budget. Each stalled read or write costs at most `handshake`.
fn op_deadline(limits: &FetchLimits) -> Option<Instant> {
    Instant::now().checked_add(limits.handshake)
}

async fn fetch_inner(
    peer: SocketAddr,
    key: DhtKey,
    limits: &FetchLimits,
    on_connect: impl FnOnce() + Send,
) -> Result<Vec<u8>, FetchError> {
    let stream = match tokio::time::timeout(limits.connect, TcpStream::connect(peer)).await {
        Err(_) => return Err(FetchError::Timeout),
        Ok(Err(e)) => return Err(FetchError::Connect(e.kind())),
        Ok(Ok(s)) => s,
    };
    on_connect();
    // Best effort: requests are small and latency-sensitive.
    let _ = stream.set_nodelay(true);
    // If the addition overflows, only the total deadline applies.
    let handshake_deadline = Instant::now().checked_add(limits.handshake);

    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::with_capacity(READ_BUFFER_LEN, rd);

    let ours = wire::handshake_bytes(wire::our_reserved(), &key, &our_peer_id());
    within(handshake_deadline, wr.write_all(&ours)).await??;

    let mut theirs = [0u8; HANDSHAKE_LEN];
    within(
        handshake_deadline,
        tokio::io::AsyncReadExt::read_exact(&mut rd, &mut theirs),
    )
    .await??;
    let hs = wire::parse_handshake(&theirs)?;
    if hs.info_hash != key.0 {
        return Err(FetchError::WrongInfoHash);
    }
    if !hs.supports_extensions() {
        return Err(FetchError::NoExtensionSupport);
    }

    let body = wire::ext_handshake_body(
        OUR_UT_METADATA_ID,
        None,
        Some(CLIENT_VERSION),
        Some(ADVERTISED_REQQ),
    );
    let frame = wire::extended_frame(EXT_HANDSHAKE_ID, &body)?;
    within(handshake_deadline, wr.write_all(&frame)).await??;

    // Phase 1: wait for the peer's extended handshake.
    let (peer_ut_id, mut assembly) = loop {
        let frame = within(
            handshake_deadline,
            wire::read_frame(&mut rd, MAX_FRAME_BEFORE_EXT_HANDSHAKE),
        )
        .await??;
        // Keep-alives and non-extended messages (bitfield, have, ...) are skipped.
        let Frame::Extended(payload) = frame else {
            continue;
        };
        match wire::parse_message(&payload)? {
            Message::Extended {
                id: EXT_HANDSHAKE_ID,
                body,
            } => {
                let (id, size) = wire::parse_ext_handshake(body)?.validate(limits.max_metadata)?;
                break (id, Assembly::new(size)?);
            }
            // Other extension messages before the handshake are skipped. A
            // metadata request cannot be answered yet: we lack the peer's ID.
            Message::KeepAlive | Message::Other(_) | Message::Extended { .. } => {}
        }
    };

    // Phase 2: download pieces. Every read and write has its own
    // handshake-scale deadline; only a fully idle peer costs `total`.
    let mut budget = Budget::new(limits.byte_budget.as_ref());
    let mut rejects_sent = 0usize;
    within(
        op_deadline(limits),
        send_requests(&mut wr, &mut assembly, peer_ut_id),
    )
    .await??;
    loop {
        let Frame::Extended(payload) = within(
            op_deadline(limits),
            wire::read_frame(&mut rd, MAX_FRAME_AFTER_EXT_HANDSHAKE),
        )
        .await??
        else {
            continue;
        };
        let body = match wire::parse_message(&payload)? {
            Message::Extended {
                id: OUR_UT_METADATA_ID,
                body,
            } => body,
            // Later extended handshakes, other extensions and other messages are ignored.
            Message::KeepAlive | Message::Other(_) | Message::Extended { .. } => continue,
        };
        match wire::parse_metadata_message(body)? {
            MetadataMessage::Data {
                piece,
                total_size,
                payload,
            } => {
                // Redundant copies of a stored piece are free: charge the
                // shared byte budget only for data not yet kept, so a peer
                // answering our own retry (or spamming duplicates) cannot
                // drain it and starve other fetches. No await runs between
                // the probe and `accept`, so the check is exact.
                if !assembly.is_received(piece) {
                    budget.acquire(payload.len()).await?;
                }
                assembly.accept(piece, total_size, payload)?;
                if assembly.is_complete() {
                    break;
                }
                within(
                    op_deadline(limits),
                    send_requests(&mut wr, &mut assembly, peer_ut_id),
                )
                .await??;
            }
            MetadataMessage::Reject { piece } => {
                // Only a reject for a piece we asked for fails the fetch;
                // unsolicited rejects (never requested, already received)
                // are ignored.
                if assembly.is_awaiting(piece) {
                    return Err(FetchError::Rejected);
                }
            }
            // We hold no metadata, so BEP 9 asks us to reject requests.
            // Out-of-range pieces are never reflected back: they are
            // ignored instead of echoed into a reject.
            MetadataMessage::Request { piece } => {
                if assembly.has_piece(piece) && rejects_sent < MAX_REJECTS_SENT {
                    rejects_sent = rejects_sent.saturating_add(1);
                    let frame =
                        wire::extended_frame(peer_ut_id, &wire::metadata_reject_body(piece))?;
                    within(op_deadline(limits), wr.write_all(&frame)).await??;
                }
            }
            MetadataMessage::Unknown(_) => {}
        }
    }
    drop(wr);

    let info = assembly.finish()?;
    if !verify_metadata(&key, &info) {
        return Err(FetchError::HashMismatch);
    }
    // Permits are held through verification and released here.
    drop(budget);
    Ok(info)
}

/// Permits held from [`FetchLimits::byte_budget`] for one fetch.
struct Budget {
    semaphore: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    held: Option<OwnedSemaphorePermit>,
}

impl Budget {
    fn new(semaphore: Option<&std::sync::Arc<tokio::sync::Semaphore>>) -> Self {
        Self {
            semaphore: semaphore.cloned(),
            held: None,
        }
    }

    /// Waits for permits covering `bytes`, in KiB rounded up.
    async fn acquire(&mut self, bytes: usize) -> Result<(), FetchError> {
        let Some(semaphore) = &self.semaphore else {
            return Ok(());
        };
        // A piece is at most one frame long, far below u32::MAX KiB.
        let permits = u32::try_from(bytes.div_ceil(BYTE_BUDGET_UNIT))
            .map_err(|_| FetchError::Protocol("piece too large for the byte budget".into()))?;
        if permits == 0 {
            return Ok(());
        }
        let permit = std::sync::Arc::clone(semaphore)
            .acquire_many_owned(permits)
            .await
            .map_err(|_| FetchError::BudgetClosed)?;
        match &mut self.held {
            // `merge` panics only for permits of different semaphores; every
            // permit here comes from `self.semaphore`.
            Some(held) => held.merge(permit),
            None => self.held = Some(permit),
        }
        Ok(())
    }
}

async fn send_requests<W: AsyncWriteExt + Unpin>(
    wr: &mut W,
    assembly: &mut Assembly,
    peer_ut_id: u8,
) -> Result<(), FetchError> {
    let mut out = Vec::new();
    for piece in assembly.next_requests() {
        let piece = i64::try_from(piece)
            .map_err(|_| FetchError::Protocol("piece index overflow".into()))?;
        out.extend_from_slice(&wire::extended_frame(
            peer_ut_id,
            &wire::metadata_request_body(piece),
        )?);
    }
    if !out.is_empty() {
        wr.write_all(&out).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_peer_id_carries_prefix_and_random_tail() {
        let a = our_peer_id();
        let b = our_peer_id();
        assert_eq!(&a[..PEER_ID_PREFIX.len()], PEER_ID_PREFIX);
        assert_eq!(&b[..PEER_ID_PREFIX.len()], PEER_ID_PREFIX);
        // 96 random tail bits collide with negligible probability.
        assert_ne!(&a[PEER_ID_PREFIX.len()..], &b[PEER_ID_PREFIX.len()..]);
    }
}
