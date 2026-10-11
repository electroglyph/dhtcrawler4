//! Admin subcommands (design §13; 04-operations §3). They connect with the
//! `[database]` credentials, which compose sets to the owner for admin runs.

use std::io::Write;

use dc4_core::AnyKey;
use dc4_store::{Store, StoreError};

use crate::config::{Config, DbRole};

/// Default number of rows listed.
pub const DEFAULT_LIST_LIMIT: i64 = 100;
/// Days shown by `stats`.
pub const STATS_DAYS: u32 = 7;

/// Why an admin command failed.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cannot write output: {0}")]
    Output(#[from] std::io::Error),
    #[error("{0}")]
    Refused(String),
}

type Out<'a> = &'a mut (dyn Write + Send);

/// `migrate`: applies the migrations.
pub async fn migrate(store: &Store, out: Out<'_>) -> Result<(), AdminError> {
    store.migrate().await?;
    tracing::info!("database migrated");
    writeln!(out, "migrations applied")?;
    Ok(())
}

/// `stats`.
pub async fn stats(store: &Store, out: Out<'_>) -> Result<(), AdminError> {
    let s = store.stats().await?;
    writeln!(out, "torrents      {}", s.torrents)?;
    writeln!(out, "pending       {}", s.pending)?;
    writeln!(out, "gave up       {}", s.gave_up)?;
    writeln!(out)?;
    writeln!(
        out,
        "{:<10}  {:>12}  {:>12}  {:>12}",
        "day (UTC)", "discovered", "fetched", "failed"
    )?;
    for d in store.daily_stats(STATS_DAYS).await? {
        writeln!(
            out,
            "{:<10}  {:>12}  {:>12}  {:>12}",
            d.day.to_string(),
            d.discovered,
            d.fetched,
            d.fetch_failed
        )?;
    }
    Ok(())
}

/// `check-config`: prints the configuration (passwords are never read or
/// shown) and the warnings.
pub fn check_config(cfg: &Config, out: Out<'_>) -> Result<(), AdminError> {
    let text = cfg
        .to_redacted_toml()
        .map_err(|e| AdminError::Refused(e.to_string()))?;
    writeln!(
        out,
        "# Effective configuration (environment overrides applied)"
    )?;
    writeln!(out, "{}", text.trim_end())?;
    writeln!(out)?;
    for (label, role) in [
        ("single-role and admin commands", DbRole::Main),
        ("all: crawl", DbRole::Crawler),
        ("all: index", DbRole::Indexer),
        ("all: web", DbRole::Web),
    ] {
        let (user, password_file) = cfg.credentials(role);
        let password = if password_file.as_os_str().is_empty() {
            "no password file".to_owned()
        } else {
            format!("password from {}", password_file.display())
        };
        writeln!(out, "# database user for {label}: {user} ({password})")?;
    }
    let warnings = cfg.warnings();
    writeln!(
        out,
        "# packet budgets: crawl {}/s + fetch {}/s + scrape {}/s (separate buckets)",
        cfg.crawl.max_packets_per_sec,
        cfg.crawl.fetch_packets_per_sec,
        cfg.crawl.scrape_packets_per_sec
    )?;
    if warnings.is_empty() {
        writeln!(out, "# no warnings")?;
    }
    for w in warnings {
        writeln!(out, "warning: {w}")?;
    }
    Ok(())
}

/// Parses a key given on the command line.
pub fn parse_key(text: &str) -> Result<AnyKey, String> {
    text.trim()
        .parse::<AnyKey>()
        .map_err(|e| format!("not a 40-hex, 32-base32 or 64-hex key: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let v1 = parse_key(&"AB".repeat(20)).unwrap();
        assert!(matches!(v1, AnyKey::V1OrDht(_)));
        let v2 = parse_key(&"cd".repeat(32)).unwrap();
        assert!(matches!(v2, AnyKey::V2(_)));
        assert!(parse_key("xyz").is_err());
        assert!(parse_key(&"a".repeat(41)).is_err());
    }

    #[test]
    fn check_config_output() {
        let mut cfg = Config::default();
        cfg.database.url = Some("postgres://u:topsecret@h/db".into());
        let mut out = Vec::new();
        check_config(&cfg, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("topsecret"), "{text}");
        assert!(text.contains("postgres://u@h/db"), "{text}");
        assert!(text.contains("[crawl]"), "{text}");
        assert!(
            text.contains("warning: web.trusted_proxies is empty"),
            "{text}"
        );
        assert!(
            text.contains("password from /run/secrets/db_password"),
            "{text}"
        );
        assert!(
            text.contains("# packet budgets: crawl "),
            "footer must name the budgets: {text}"
        );
        assert!(
            text.contains("+ fetch ") && text.contains("+ scrape "),
            "footer must list all three separate buckets (crawl/fetch/scrape): {text}"
        );
        // The printed configuration parses back to the same values.
        let body: String = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.starts_with("warning:"))
            .map(|l| format!("{l}\n"))
            .collect();
        let mut parsed = crate::config::from_toml_str(&body, Vec::new()).unwrap();
        parsed.database.url = cfg.database.url.clone();
        assert_eq!(parsed, cfg);
    }
}
