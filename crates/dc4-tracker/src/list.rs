//! Tracker list: vendored snapshot, parsing, refresh, liveness.
//!
//! Cold start works with zero network: a copy of the public list is baked
//! in. Refresh fetches the configured URL when set (plain HTTP only — the
//! tree has no TLS client, so an `https://` URL is rejected with a log and
//! the snapshot stays in force). Empty URL disables refresh.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Vendored copy of the public list, taken at build time.
pub const VENDORED_LIST: &str = include_str!("../trackers_best.txt");

/// One `udp://host:port` tracker from the list.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrackerEntry {
    pub host: String,
    pub port: u16,
}

impl TrackerEntry {
    pub fn addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Parse list text: trim, skip blanks, keep `udp://host:port`, dedupe by
/// host:port. Paths (`/announce`) are ignored — UDP has none. Returns the
/// entries plus counts of skipped `http` lines and unparsable lines.
pub fn parse_list(text: &str) -> (Vec<TrackerEntry>, usize, usize) {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut http = 0usize;
    let mut bad = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("udp://") else {
            if line.starts_with("http://") || line.starts_with("https://") {
                http += 1;
            } else {
                bad += 1;
            }
            continue;
        };
        let hostport = rest.split('/').next().unwrap_or("");
        let Some((host, port)) = hostport.split_once(':') else {
            bad += 1;
            continue;
        };
        let (host, port) = (host.trim(), port.trim());
        let Ok(port) = port.parse::<u16>() else {
            bad += 1;
            continue;
        };
        if host.is_empty() || port == 0 {
            bad += 1;
            continue;
        }
        if seen.insert((host.to_owned(), port)) {
            out.push(TrackerEntry {
                host: host.to_owned(),
                port,
            });
        }
    }
    (out, http, bad)
}

/// Fetches list text over plain HTTP. `https://` is rejected: no TLS here.
pub async fn fetch_list(url: &str, timeout: Duration) -> Result<String, String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        "tracker list refresh needs plain http (no TLS client); keeping the last set".to_owned()
    })?;
    let (hostport, path) = match rest.find('/').map(|i| rest.split_at(i)) {
        Some((h, p)) => (h, p),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => (
            h.to_owned(),
            p.parse::<u16>()
                .map_err(|_| format!("bad port in tracker list URL {url:?}"))?,
        ),
        None => (hostport.to_owned(), 80),
    };
    let mut stream = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| format!("tracker list fetch to {url:?} timed out"))?
    .map_err(|e| format!("tracker list fetch to {url:?} failed: {e}"))?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("tracker list request to {url:?} failed: {e}"))?;
    let mut body = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut body))
        .await
        .map_err(|_| format!("tracker list read from {url:?} timed out"))?
        .map_err(|e| format!("tracker list read from {url:?} failed: {e}"))?;
    let text = String::from_utf8_lossy(&body);
    let Some(pos) = text.find("\r\n\r\n") else {
        return Err(format!("tracker list reply from {url:?} has no header"));
    };
    Ok(text[pos + 4..].to_owned())
}

/// Resolves one entry to socket addresses (first successful lookup wins).
pub async fn resolve(entry: &TrackerEntry) -> Vec<SocketAddr> {
    let addr = entry.addr_string();
    tokio::net::lookup_host(addr.as_str())
        .await
        .map(|i| i.collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_vendored_snapshot() {
        let (entries, http, bad) = parse_list(VENDORED_LIST);
        assert_eq!(entries.len(), 17, "17 usable UDP entries expected");
        assert_eq!(http, 3, "3 http lines skipped");
        assert_eq!(bad, 0);
        assert!(entries.iter().all(|e| e.port != 0 && !e.host.is_empty()));
    }

    #[test]
    fn parse_handles_blanks_dupes_and_paths() {
        let text = "# comment\n\nudp://a.example:80/announce\nudp://a.example:80\nudp://b.example:6969/other\nhttp://c.example:1/x\njunk\nudp://d.example:0\n";
        let (entries, http, bad) = parse_list(text);
        assert_eq!(
            entries,
            vec![
                TrackerEntry {
                    host: "a.example".into(),
                    port: 80
                },
                TrackerEntry {
                    host: "b.example".into(),
                    port: 6969
                },
            ]
        );
        assert_eq!(http, 1);
        assert_eq!(bad, 2, "junk + port-0");
    }

    #[test]
    fn https_refresh_is_rejected() {
        let err = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(fetch_list(
                "https://example.com/list.txt",
                Duration::from_secs(1),
            ));
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn http_refresh_round_trip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let _ = s.read(&mut buf).await;
            let body = "udp://x.example:80/announce\n";
            let reply = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(reply.as_bytes()).await;
        });
        let url = format!("http://127.0.0.1:{}/list.txt", addr.port());
        let text = fetch_list(&url, Duration::from_secs(5)).await.unwrap();
        let (entries, _, _) = parse_list(&text);
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn http_refresh_failure_is_an_error_for_caller_to_ignore() {
        // A closed port must fail fast so run_refresh can keep the last set.
        let err = fetch_list("http://127.0.0.1:9/list.txt", Duration::from_millis(300)).await;
        assert!(err.is_err());
    }
}
