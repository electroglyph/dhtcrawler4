//! BEP 15 UDP tracker wire codec.
//!
//! Requests the crawler sends: `connect`, multi-hash `scrape` (up to 74
//! infohashes per datagram), one-shot `announce` (`started`, one hash).
//! Deliberate subset: no announce loop, no stats reporting.

use std::net::SocketAddr;

use dc4_core::DhtKey;

/// Magic connection ID every `connect` request starts with.
pub const CONNECT_MAGIC: u64 = 0x4172_7101_980;
/// Max infohashes per scrape request: 16-byte header + 20 bytes each fits
/// one datagram at 74 ("up to about 74 torrents at once" per the BEP).
pub const MAX_SCRAPE_HASHES: usize = 74;
/// Peers requested per announce: the BEP default (-1, ~50) is needlessly
/// small for harvesting; trackers clamp anyway.
pub const ANNOUNCE_NUM_WANT: i32 = 200;

const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;
const ACTION_SCRAPE: u32 = 2;
const ACTION_ERROR: u32 = 3;
const EVENT_STARTED: u32 = 2;

/// One scrape result row: (seeders, completed, leechers).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrapeRow {
    pub seeders: u32,
    pub completed: u32,
    pub leechers: u32,
}

/// A decoded announce reply: re-announce floor plus compact peers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnounceReply {
    pub interval_secs: u32,
    pub peers: Vec<SocketAddr>,
}

/// A decoded tracker reply, matched by callers on transaction ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Connect { connection_id: u64 },
    Announce(AnnounceReply),
    Scrape(Vec<ScrapeRow>),
}

/// Error text of an `error` action reply.
pub fn error_text(packet: &[u8]) -> Option<String> {
    let (action, _txn) = split_header(packet)?;
    if action != ACTION_ERROR {
        return None;
    }
    String::from_utf8(packet[8..].to_vec()).ok()
}

fn split_header(packet: &[u8]) -> Option<(u32, u32)> {
    if packet.len() < 8 {
        return None;
    }
    Some((
        u32::from_be_bytes(packet[0..4].try_into().ok()?),
        u32::from_be_bytes(packet[4..8].try_into().ok()?),
    ))
}

/// Encodes a `connect` request with `txn`.
pub fn encode_connect(txn: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&CONNECT_MAGIC.to_be_bytes());
    out[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
    out[12..16].copy_from_slice(&txn.to_be_bytes());
    out
}

/// Encodes a `scrape` request for up to [`MAX_SCRAPE_HASHES`] keys.
/// Longer slices are truncated to the datagram limit.
pub fn encode_scrape(connection_id: u64, txn: u32, keys: &[DhtKey]) -> Vec<u8> {
    let n = keys.len().min(MAX_SCRAPE_HASHES);
    let mut out = Vec::with_capacity(16 + 20 * n);
    out.extend_from_slice(&connection_id.to_be_bytes());
    out.extend_from_slice(&ACTION_SCRAPE.to_be_bytes());
    out.extend_from_slice(&txn.to_be_bytes());
    for k in &keys[..n] {
        out.extend_from_slice(&k.0);
    }
    out
}

/// Encodes a one-shot `started` announce for `key`.
pub fn encode_announce(
    connection_id: u64,
    txn: u32,
    key: &DhtKey,
    peer_id: &[u8; 20],
    port: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(100);
    out.extend_from_slice(&connection_id.to_be_bytes());
    out.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    out.extend_from_slice(&txn.to_be_bytes());
    out.extend_from_slice(&key.0);
    out.extend_from_slice(peer_id);
    out.extend_from_slice(&0u64.to_be_bytes()); // downloaded
    out.extend_from_slice(&0u64.to_be_bytes()); // left (unknown)
    out.extend_from_slice(&0u64.to_be_bytes()); // uploaded
    out.extend_from_slice(&EVENT_STARTED.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // ip (default)
    out.extend_from_slice(&rand_key().to_be_bytes());
    out.extend_from_slice(&ANNOUNCE_NUM_WANT.to_be_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // extensions
    out
}

fn rand_key() -> u32 {
    rand::random()
}

/// Decodes a `connect` reply body (past the 8-byte header).
pub fn decode_connect(packet: &[u8]) -> Option<u64> {
    if packet.len() < 16 {
        return None;
    }
    let (action, _) = split_header(packet)?;
    if action != ACTION_CONNECT {
        return None;
    }
    Some(u64::from_be_bytes(packet[8..16].try_into().ok()?))
}

/// Decodes an `announce` reply body: interval plus IPv4 peers.
pub fn decode_announce(packet: &[u8]) -> Option<AnnounceReply> {
    if packet.len() < 20 {
        return None;
    }
    let (action, _) = split_header(packet)?;
    if action != ACTION_ANNOUNCE {
        return None;
    }
    let interval_secs = u32::from_be_bytes(packet[8..12].try_into().ok()?);
    let rest = &packet[20..];
    let mut peers = Vec::with_capacity(rest.len() / 6);
    for chunk in rest.chunks_exact(6) {
        let ip = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let port = u16::from_be_bytes([chunk[4], chunk[5]]);
        if port != 0 {
            peers.push(SocketAddr::from((ip, port)));
        }
    }
    Some(AnnounceReply {
        interval_secs,
        peers,
    })
}

/// Decodes a `scrape` reply body into per-hash rows.
pub fn decode_scrape(packet: &[u8], want: usize) -> Option<Vec<ScrapeRow>> {
    if packet.len() < 8 {
        return None;
    }
    let (action, _) = split_header(packet)?;
    if action != ACTION_SCRAPE {
        return None;
    }
    let mut rows = Vec::with_capacity(want.min(MAX_SCRAPE_HASHES));
    for chunk in packet[8..].chunks_exact(12).take(want) {
        rows.push(ScrapeRow {
            seeders: u32::from_be_bytes(chunk[0..4].try_into().ok()?),
            completed: u32::from_be_bytes(chunk[4..8].try_into().ok()?),
            leechers: u32::from_be_bytes(chunk[8..12].try_into().ok()?),
        });
    }
    Some(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> DhtKey {
        DhtKey([b; 20])
    }

    #[test]
    fn connect_round_trip() {
        let req = encode_connect(0x1234);
        assert_eq!(&req[0..8], &CONNECT_MAGIC.to_be_bytes());
        assert_eq!(&req[8..12], &0u32.to_be_bytes());
        assert_eq!(&req[12..16], &0x1234u32.to_be_bytes());
        let mut reply = vec![0u8; 16];
        reply[0..4].copy_from_slice(&0u32.to_be_bytes());
        reply[4..8].copy_from_slice(&0x1234u32.to_be_bytes());
        reply[8..16].copy_from_slice(&0xdead_beef_cafe_f00du64.to_be_bytes());
        assert_eq!(decode_connect(&reply), Some(0xdead_beef_cafe_f00d));
        assert_eq!(decode_connect(&reply[..10]), None);
    }

    #[test]
    fn scrape_truncates_at_capacity() {
        let keys: Vec<DhtKey> = (0..100u8).map(key).collect();
        let req = encode_scrape(7, 9, &keys);
        assert_eq!(req.len(), 16 + 20 * MAX_SCRAPE_HASHES);
        assert_eq!(&req[..8], &7u64.to_be_bytes());
        // Response with two rows.
        let mut reply = vec![0u8; 8 + 24];
        reply[0..4].copy_from_slice(&2u32.to_be_bytes());
        reply[8..12].copy_from_slice(&5u32.to_be_bytes());
        reply[12..16].copy_from_slice(&11u32.to_be_bytes());
        reply[16..20].copy_from_slice(&1u32.to_be_bytes());
        let rows = decode_scrape(&reply, 74).unwrap();
        assert_eq!(
            rows,
            vec![
                ScrapeRow {
                    seeders: 5,
                    completed: 11,
                    leechers: 1
                },
                ScrapeRow::default(),
            ]
        );
        assert_eq!(decode_scrape(&reply, 1).unwrap().len(), 1);
    }

    #[test]
    fn announce_round_trip_with_peers() {
        let peer_id = [7u8; 20];
        let req = encode_announce(0xabcd, 42, &key(3), &peer_id, 6881);
        assert_eq!(req.len(), 100);
        assert_eq!(&req[8..12], &1u32.to_be_bytes());
        assert_eq!(&req[16..36], &[3u8; 20]);
        assert_eq!(&req[36..56], &peer_id);
        assert_eq!(&req[80..84], &EVENT_STARTED.to_be_bytes());
        assert_eq!(&req[92..96], &ANNOUNCE_NUM_WANT.to_be_bytes());
        assert_eq!(&req[96..98], &6881u16.to_be_bytes());
        // Reply: interval + leechers + seeders + two peers (one port-0).
        let mut reply = vec![0u8; 20 + 12];
        reply[0..4].copy_from_slice(&1u32.to_be_bytes());
        reply[8..12].copy_from_slice(&1800u32.to_be_bytes());
        reply[20..24].copy_from_slice(&[1, 2, 3, 4]);
        reply[24..26].copy_from_slice(&6881u16.to_be_bytes());
        reply[26..30].copy_from_slice(&[5, 6, 7, 8]);
        let out = decode_announce(&reply).unwrap();
        assert_eq!(out.interval_secs, 1800);
        assert_eq!(
            out.peers,
            vec!["1.2.3.4:6881".parse().unwrap()],
            "port-0 peers are dropped"
        );
    }

    #[test]
    fn error_text_parses() {
        let mut reply = b"\x00\x00\x00\x03\x00\x00\x00\x07failure reason".to_vec();
        assert_eq!(error_text(&reply).as_deref(), Some("failure reason"));
        reply[3] = 1;
        assert_eq!(error_text(&reply), None);
        assert_eq!(error_text(&reply[..4]), None);
    }
}
