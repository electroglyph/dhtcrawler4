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
/// `Error` carries the tracker's `error`-action text: callers treat it
/// as failure and retry with a fresh connection ID (the demux loop
/// already dropped the cached ID when the text reports an invalid one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Connect { connection_id: u64 },
    Announce(AnnounceReply),
    Scrape(Vec<ScrapeRow>),
    Error(String),
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
    // left: we hold no bytes, so advertise as a leecher. 0 would claim
    // seeder (complete) and pollute tracker seeder stats; the exact
    // amount is irrelevant since we never serve.
    out.extend_from_slice(&1u64.to_be_bytes()); // left (leecher)
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
        // Layout: downloaded 56..64, left 64..72, uploaded 72..80.
        assert_eq!(&req[56..64], &0u64.to_be_bytes(), "downloaded");
        assert_eq!(
            u64::from_be_bytes(req[64..72].try_into().unwrap()),
            1,
            "left must be nonzero (leecher): 0 would falsely claim seeder"
        );
        assert_eq!(&req[72..80], &0u64.to_be_bytes(), "uploaded");
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
    fn scrape_handles_max_capacity_rows() {
        // 74-hash max-capacity response vector: every row decodes.
        let mut reply = vec![0u8; 8 + 12 * MAX_SCRAPE_HASHES];
        reply[0..4].copy_from_slice(&2u32.to_be_bytes());
        for i in 0..MAX_SCRAPE_HASHES {
            reply[8 + 12 * i..12 + 12 * i].copy_from_slice(&(i as u32).to_be_bytes());
            reply[12 + 12 * i..16 + 12 * i].copy_from_slice(&((i * 2) as u32).to_be_bytes());
            reply[16 + 12 * i..20 + 12 * i].copy_from_slice(&((i * 3) as u32).to_be_bytes());
        }
        let rows = decode_scrape(&reply, MAX_SCRAPE_HASHES).unwrap();
        assert_eq!(rows.len(), MAX_SCRAPE_HASHES);
        assert_eq!(
            rows[0],
            ScrapeRow {
                seeders: 0,
                completed: 0,
                leechers: 0
            }
        );
        assert_eq!(rows[73].seeders, 73);
        assert_eq!(rows[73].completed, 146);
        assert_eq!(rows[73].leechers, 219);
        // Asking for fewer rows truncates the decode, not the packet.
        assert_eq!(decode_scrape(&reply, 1).unwrap().len(), 1);
    }

    #[test]
    fn error_text_parses() {
        let mut reply = b"\x00\x00\x00\x03\x00\x00\x00\x07failure reason".to_vec();
        assert_eq!(error_text(&reply).as_deref(), Some("failure reason"));
        reply[3] = 1;
        assert_eq!(error_text(&reply), None);
        assert_eq!(error_text(&reply[..4]), None);
    }

    /// Hex-decodes a literal packet. Panics on odd length or bad digits;
    /// test-only, so a panic is the assertion.
    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd-length hex literal");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
            .collect()
    }

    #[test]
    fn wire_vectors_match_bep15_byte_for_byte() {
        // Every literal below was written out by hand from the BEP 15
        // layout, independent of the encoder: if any field drifts (magic,
        // action, order, width, endianness) the whole-packet comparison
        // fails. A round-trip test cannot catch that — an encoder bug
        // mirrored in the decoder would pass — so these vectors pin the
        // wire format, not just self-consistency.
        //
        // Connect request: magic 0x41727101980, action 0, txn 0x04030201.
        let req = encode_connect(0x0403_0201);
        assert_eq!(
            req.as_slice(),
            unhex(concat!(
                "0000041727101980", // magic 0x41727101980
                "00000000", // action: connect
                "04030201", // txn
            ))
            .as_slice()
        );

        // Scrape request: conn 0x0102..08, action 2, txn 0x0a0b0c0d,
        // then two infohashes with sequential bytes 0x00-0x13, 0x14-0x27.
        let keys = [
            DhtKey(std::array::from_fn(|i| i as u8)),
            DhtKey(std::array::from_fn(|i| (20 + i) as u8)),
        ];
        let req = encode_scrape(0x0102_0304_0506_0708, 0x0a0b_0c0d, &keys);
        assert_eq!(req.len(), 16 + 2 * 20);
        assert_eq!(
            req,
            unhex(concat!(
                "0102030405060708", // connection id
                "00000002", // action: scrape
                "0a0b0c0d", // txn
                "000102030405060708090a0b0c0d0e0f10111213", // key 1
                "1415161718191a1b1c1d1e1f2021222324252627", // key 2
            ))
        );

        // Announce request: fixed key (0xaa * 20), peer id (0xbb * 20),
        // port 6881. Bytes 88..92 are the random per-request key, so the
        // literal pins all 96 other bytes and the total length.
        let req = encode_announce(
            0x0102_0304_0506_0708,
            0x0a0b_0c0d,
            &DhtKey([0xaa; 20]),
            &[0xbb; 20],
            6881,
        );
        assert_eq!(req.len(), 100);
        assert_eq!(
            &req[..88],
            unhex(concat!(
                "0102030405060708", // connection id
                "00000001", // action: announce
                "0a0b0c0d", // txn
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // infohash
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // peer id
                "0000000000000000", // downloaded
                "0000000000000001", // left: leecher, never 0 (seeder)
                "0000000000000000", // uploaded
                "00000002", // event: started
                "00000000", // ip: default
            ))
            .as_slice()
        );
        assert_eq!(
            &req[92..],
            unhex(concat!(
                "000000c8", // num_want: 200
                "1ae1", // port: 6881
                "0000", // extensions
            ))
            .as_slice()
        );

        // Connect reply: action 0, txn, connection id.
        let reply = unhex(concat!(
            "00000000", // action: connect
            "0a0b0c0d", // txn
            "0102030405060708", // connection id
        ));
        assert_eq!(decode_connect(&reply), Some(0x0102_0304_0506_0708));

        // Scrape reply: action 2, txn, two 12-byte rows
        // (seeders, completed, leechers).
        let reply = unhex(concat!(
            "00000002", // action: scrape
            "0a0b0c0d", // txn
            "00000001", "00000002", "00000003", // row 1: 1/2/3
            "00000000", "00000000", "00000000", // row 2: zeros
        ));
        assert_eq!(
            decode_scrape(&reply, 74),
            Some(vec![
                ScrapeRow {
                    seeders: 1,
                    completed: 2,
                    leechers: 3
                },
                ScrapeRow::default(),
            ])
        );

        // Announce reply: action 1, txn, interval 1800, 4-byte
        // leechers/seeders counts, then compact peers; the port-0 peer
        // is dropped.
        let reply = unhex(concat!(
            "00000001", // action: announce
            "0a0b0c0d", // txn
            "00000708", // interval: 1800
            "00000005", // leechers
            "00000007", // seeders
            "01020304", "1ae1", // 1.2.3.4:6881
            "05060708", "0000", // 5.6.7.8:0 (dropped)
        ));
        let out = decode_announce(&reply).expect("literal announce reply");
        assert_eq!(out.interval_secs, 1800);
        assert_eq!(out.peers, vec!["1.2.3.4:6881".parse().unwrap()]);

        // Error reply: action 3, txn, raw message text.
        let mut reply = unhex(concat!(
            "00000003", // action: error
            "0a0b0c0d", // txn
        ));
        reply.extend_from_slice(b"failure reason");
        assert_eq!(error_text(&reply).as_deref(), Some("failure reason"));
    }
}
