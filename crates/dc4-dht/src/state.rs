//! Persistent node state: node IDs, external IPs and contacts.
//!
//! Stored as JSON `{version, v4: [{id, external_ip, nodes: [{id, addr}]}], v6: …}`
//! (one entry per identity, in bind order) and written atomically (temporary
//! file, fsync, rename). A missing file is normal; an unreadable, oversized
//! or malformed one is ignored with a warning — including older versions,
//! which are never migrated. Peer-store contents are never written (R11).

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::compact::Family;
use crate::node_id::NodeId;

/// Format version written and accepted.
pub(crate) const STATE_VERSION: u32 = 2;
/// Contacts kept per address family.
pub(crate) const MAX_SAVED_NODES: usize = 300;
/// Largest state file we read.
const MAX_STATE_FILE_BYTES: u64 = 1024 * 1024;
/// File name used when the configured path has none.
const FALLBACK_FILE_NAME: &str = "dht-state.json";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateFile {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) v4: Vec<IdentityState>,
    #[serde(default)]
    pub(crate) v6: Vec<IdentityState>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityState {
    pub(crate) id: NodeId,
    #[serde(default)]
    pub(crate) external_ip: Option<IpAddr>,
    #[serde(default)]
    pub(crate) nodes: Vec<SavedNode>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SavedNode {
    pub(crate) id: NodeId,
    pub(crate) addr: SocketAddr,
}

impl StateFile {
    /// Saved identities of `family`, in bind order.
    pub(crate) fn identities(&self, family: Family) -> &[IdentityState] {
        match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }

    /// Drops entries of the wrong family and caps the contact lists.
    fn sanitized(mut self) -> Self {
        for (family, states) in [(Family::V4, &mut self.v4), (Family::V6, &mut self.v6)] {
            for s in states.iter_mut() {
                s.nodes.retain(|n| Family::of(&n.addr) == family);
                s.nodes.truncate(MAX_SAVED_NODES);
                if s.external_ip
                    .is_some_and(|ip| Family::of(&SocketAddr::new(ip, 0)) != family)
                {
                    s.external_ip = None;
                }
            }
        }
        self
    }
}

/// Reads the state file. Returns `None` (after logging) when it is missing or unusable.
pub(crate) fn load(path: &Path) -> Option<StateFile> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "cannot open DHT state file; starting fresh");
            return None;
        }
    };
    let mut bytes = Vec::new();
    if let Err(e) = file
        .take(MAX_STATE_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        tracing::warn!(path = %path.display(), error = %e, "cannot read DHT state file; starting fresh");
        return None;
    }
    if u64::try_from(bytes.len()).map_or(true, |n| n > MAX_STATE_FILE_BYTES) {
        tracing::warn!(path = %path.display(), "DHT state file is too large; ignoring it");
        return None;
    }
    match serde_json::from_slice::<StateFile>(&bytes) {
        Ok(state) if state.version == STATE_VERSION => Some(state.sanitized()),
        Ok(state) => {
            tracing::warn!(path = %path.display(), version = state.version, "unsupported DHT state file version; ignoring it");
            None
        }
        Err(e) => {
            // The error text may quote the file, which holds node addresses.
            let (kind, line, column) = (e.classify(), e.line(), e.column());
            tracing::warn!(path = %path.display(), ?kind, line, column, "malformed DHT state file; ignoring it");
            tracing::trace!(error = %e, "DHT state file error");
            None
        }
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| FALLBACK_FILE_NAME.into(), ToOwned::to_owned);
    name.push(".tmp");
    path.with_file_name(name)
}

/// Writes the state file atomically.
pub(crate) fn save(path: &Path, state: &StateFile) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
    let tmp = temp_path(path);
    let written = File::create(&tmp).and_then(|mut f| {
        f.write_all(&json)?;
        f.sync_all()
    });
    let result = written.and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        // Best effort: do not leave a partial temporary file behind.
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StateFile {
        StateFile {
            version: STATE_VERSION,
            v4: vec![IdentityState {
                id: NodeId([1; 20]),
                external_ip: Some("8.8.8.8".parse().unwrap()),
                nodes: vec![SavedNode {
                    id: NodeId([2; 20]),
                    addr: "9.9.9.9:6881".parse().unwrap(),
                }],
            }],
            v6: vec![],
        }
    }

    #[test]
    fn round_trip_and_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dht.json");
        assert_eq!(load(&path), None);
        save(&path, &sample()).unwrap();
        assert_eq!(load(&path), Some(sample()));
        assert!(!dir.path().join("dht.json.tmp").exists());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"version\": 2"));
        assert!(text.contains(&"01".repeat(20)));
        // Overwrite.
        let mut other = sample();
        other.v6 = vec![IdentityState {
            id: NodeId([3; 20]),
            external_ip: None,
            nodes: vec![],
        }];
        save(&path, &other).unwrap();
        assert_eq!(load(&path), Some(other));
    }

    #[test]
    fn bad_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dht.json");
        for bad in [
            "",
            "not json",
            "{\"version\": 3}",
            // The old single-identity shape is never migrated: the object
            // no longer parses as a list, so it is ignored like any other
            // unusable file and the IDs regenerate.
            "{\"version\": 1, \"v4\": {\"id\": \"ab00000000000000000000000000000000000000\"}}",
            "{\"version\": 2, \"v4\": {\"id\": \"zz\"}}",
            "[]",
        ] {
            fs::write(&path, bad).unwrap();
            assert_eq!(load(&path), None, "{bad}");
        }
        fs::write(&path, vec![b' '; (MAX_STATE_FILE_BYTES + 10) as usize]).unwrap();
        assert_eq!(load(&path), None);
        // A directory is not a state file.
        assert_eq!(load(dir.path()), None);
        // Saving into a missing directory fails cleanly.
        assert!(save(&dir.path().join("missing/dht.json"), &sample()).is_err());
    }

    #[test]
    fn loading_sanitizes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dht.json");
        let mut s = sample();
        let v4 = &mut s.v4[0];
        v4.external_ip = Some("2a00::1".parse().unwrap());
        v4.nodes.push(SavedNode {
            id: NodeId([4; 20]),
            addr: "[2a00::2]:1".parse().unwrap(),
        });
        for i in 0..400u32 {
            let ip = std::net::Ipv4Addr::from(0x0808_0000 + i);
            v4.nodes.push(SavedNode {
                id: NodeId::random(),
                addr: SocketAddr::new(ip.into(), 1),
            });
        }
        save(&path, &s).unwrap();
        let loaded = load(&path).unwrap();
        let v4 = &loaded.identities(Family::V4)[0];
        assert_eq!(v4.external_ip, None);
        assert_eq!(v4.nodes.len(), MAX_SAVED_NODES);
        assert!(v4.nodes.iter().all(|n| n.addr.is_ipv4()));
        assert!(loaded.identities(Family::V6).is_empty());
        // Minimal files are accepted.
        fs::write(
            &path,
            format!(
                "{{\"version\":2,\"v4\":[{{\"id\":\"{}\"}}]}}",
                "ab".repeat(20)
            ),
        )
        .unwrap();
        let minimal = load(&path).unwrap();
        assert_eq!(minimal.v4[0].id, NodeId([0xab; 20]));
    }
}
