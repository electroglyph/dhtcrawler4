//! Configuration (design §13): the file `deploy/config/dhtcrawler4.toml`,
//! environment overrides and validation.
//!
//! Every key has a default equal to the shipped example file, so a missing
//! file (allowed only when `--config` was not given) yields a working
//! development configuration.
//!
//! Environment variables named `DC4_<SECTION>__<KEY>`, or
//! `DC4_DATABASE__<ROLE>__<KEY>` for `[database.crawler]`,
//! `[database.indexer]` and `[database.web]`, override the file. Only names
//! containing `__` are considered. The value type comes from the defaults:
//! integers, booleans, strings, and lists given as comma-separated strings.
//! Unknown sections and keys are errors, in the file and in overrides.
//!
//! Secrets never appear in the file: passwords are read from the files that
//! `password_file` names. Error messages never include a password or an
//! override value.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use dc4_store::PgConnectOptions;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The config file read when `--config` is not given.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/dhtcrawler4/dhtcrawler4.toml";
/// Prefix of environment overrides.
pub const ENV_PREFIX: &str = "DC4_";
/// Separator between section, role and key in an override name.
pub const ENV_SEPARATOR: &str = "__";
/// Separator between list items in an override value.
pub const ENV_LIST_SEPARATOR: char = ',';
/// Largest config file accepted.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Largest password file accepted.
pub const MAX_PASSWORD_BYTES: u64 = 4096;
/// Largest `database.max_connections`.
pub const MAX_DB_CONNECTIONS: u32 = 1024;
/// Smallest `crawl.max_metadata_bytes`: one `ut_metadata` piece.
pub const MIN_METADATA_BYTES: usize = 16 * 1024;
/// Largest `crawl.max_metadata_bytes`.
pub const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;
/// Smallest `crawl.max_inflight_metadata_bytes`.
pub const MIN_INFLIGHT_METADATA_BYTES: usize = 64 * 1024;
/// Largest `crawl.max_inflight_metadata_bytes`.
pub const MAX_INFLIGHT_METADATA_BYTES: usize = 64 * 1024 * 1024 * 1024;
/// Largest `crawl.fetch_workers`.
pub const MAX_FETCH_WORKERS: usize = 4096;
/// Largest `crawl.max_connections`.
pub const MAX_PEER_CONNECTIONS: usize = 65_536;
/// Most entries in `crawl.bootstrap`.
pub const MAX_BOOTSTRAP_HOSTS: usize = 64;
/// Smallest `index.writer_heap_bytes` (Tantivy needs 15 MB per thread).
pub const MIN_WRITER_HEAP_BYTES: usize = dc4_search::WRITER_PROBE_HEAP_BYTES;
/// Largest `index.writer_heap_bytes`.
pub const MAX_WRITER_HEAP_BYTES: usize = 3 * 1024 * 1024 * 1024;
/// Largest `index.batch_size`.
pub const MAX_INDEX_BATCH: i64 = dc4_store::MAX_FEED_PAGE;
/// Largest `index.poll_interval_ms` (one hour).
pub const MAX_POLL_INTERVAL_MS: u64 = 3_600_000;
/// Largest `web.site_name`, in characters.
pub const MAX_SITE_NAME_CHARS: usize = 200;
/// Most entries in `web.trusted_proxies`.
pub const MAX_TRUSTED_PROXIES: usize = 1024;
/// Name of the DHT state file inside `crawl.state_dir`.
pub const DHT_STATE_FILE: &str = "dht-state.json";
/// Replaces a password when a URL is printed.
pub const REDACTED: &str = "REDACTED";

/// Why a configuration could not be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("config file {path} is larger than {max} bytes")]
    TooLarge { path: PathBuf, max: u64 },
    #[error("config file {path} is not valid TOML ({message})")]
    Syntax { path: PathBuf, message: String },
    #[error("invalid configuration: {0}")]
    Parse(String),
    #[error("environment variable {var}: {reason}")]
    Env { var: String, reason: String },
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("password file {path}: {reason}")]
    Password { path: PathBuf, reason: String },
}

/// The whole configuration.
//
// No `Eq`: `crawl.sampler_live_share: f64` cannot be `Eq`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub database: DatabaseConfig,
    pub crawl: CrawlConfig,
    pub index: IndexConfig,
    pub web: WebSettings,
    pub metrics: MetricsConfig,
    pub log: LogConfig,
}

/// `[database]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub name: String,
    pub user: String,
    /// File holding the password; empty means no password.
    pub password_file: PathBuf,
    pub max_connections: u32,
    /// `postgres://host:port/name`; overrides host, port and name. The user
    /// comes from `user` and the password from `password_file`: a URL with
    /// a `user:password@` section is refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Credentials of the crawl role in `all`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crawler: Option<RoleCredentials>,
    /// Credentials of the index role in `all`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexer: Option<RoleCredentials>,
    /// Credentials of the web role in `all`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web: Option<RoleCredentials>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "db".into(),
            port: 5432,
            name: "dc4".into(),
            user: "dc4_crawler".into(),
            password_file: PathBuf::from("/run/secrets/db_password"),
            max_connections: 8,
            url: None,
            crawler: None,
            indexer: None,
            web: None,
        }
    }
}

/// `[database.crawler]`, `[database.indexer]` or `[database.web]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RoleCredentials {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_file: Option<PathBuf>,
}

/// `[crawl]`.
//
// No `Eq`: `sampler_live_share: f64` cannot be `Eq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CrawlConfig {
    pub dht_port: u16,
    /// IPv4 address of the DHT socket; empty disables IPv4.
    pub bind_v4: String,
    /// IPv6 address of the DHT socket; empty disables IPv6.
    pub bind_v6: String,
    pub bootstrap: Vec<String>,
    /// Directory of the DHT state file; empty keeps no state.
    pub state_dir: PathBuf,
    pub max_packets_per_sec: u32,
    /// Concurrent BEP 51 queries.
    pub sampler_concurrency: usize,
    /// In-process DHT identities. Each binds `dht_port + i` per family with
    /// its own node ID and routing table. 1 is today's behavior.
    pub identities: u32,
    /// Fraction of sampler picks that probe a live address directly instead
    /// of traversing the frontier (default 0.10). Validated
    /// manually to 0.0..=1.0 (NaN rejected) — `check_range` is integer-only
    /// in effect and NaN slips through comparisons.
    pub sampler_live_share: f64,
    pub read_only: bool,
    pub fetch_workers: usize,
    pub max_connections: usize,
    pub max_metadata_bytes: usize,
    pub max_inflight_metadata_bytes: usize,
    pub max_pending: i64,
    /// Dedicated BEP 33 scrape workers (1 by default).
    pub scrape_workers: usize,
    /// Minimum age of an estimate before a row is re-scraped.
    pub scrape_interval_secs: u64,
    /// Rows claimed per scrape round.
    pub scrape_batch: usize,
    /// Consecutive dead scrapes before a tombstone.
    pub max_scrape_failures: u32,
    /// A swarm is dead when its seeder estimate is at most this.
    pub scrape_seeder_threshold: u32,
    /// Per-RPC timeout of scrape queries.
    pub scrape_query_timeout_secs: u64,
    /// Overall deadline of one scrape lookup.
    pub scrape_lookup_timeout_secs: u64,
    /// In-flight scrape lookups per worker.
    pub scrape_concurrency: usize,
    /// Dedicated outbound packet budget for scrapes.
    pub scrape_packets_per_sec: u32,
    /// Dedicated outbound packet budget for fetch traversals:
    /// fetch runs ~2,000+/s measured, so the 6,000 default gives ~3x
    /// headroom. Zero cannot restore the old shared-budget behavior
    /// (`TokenBucket::new` treats 0 as 1); rollback is revert + rebuild.
    pub fetch_packets_per_sec: u32,
    /// Base admission cooldown of a removed key, in days; repeats escalate
    /// 7 -> 28 -> 90 days (capped, not a knob).
    pub removal_cooldown_days: u64,
    /// Grace before a tombstoned row is hard-purged, in hours.
    pub tombstone_purge_hours: u64,
    /// Age before a gave-up queue row is hard-purged, in hours. Gave-up rows
    /// count against `max_pending` without ever becoming claimable again, so
    /// this must stay short enough that corpses leave faster than failures
    /// arrive; 1 hour holds about an hour of failures.
    pub gave_up_purge_hours: u64,
    /// Interval of the purge sweep, in seconds.
    pub scrape_sweep_secs: u64,
    /// Re-scrape interval of rows whose swarm is still unknown, in seconds.
    pub scrape_unknown_interval_secs: u64,
    /// LRU size of the node-list cache reused as scrape start set; 0 disables.
    pub scrape_node_cache_keys: usize,
    /// Agreeing nonzero responses that end a traversal early (live-only).
    pub scrape_early_exit_quorum: u32,
    /// Pins the BEP 42 `r` value 0-7 for multi-replica deployments, None = random.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bep42_r: Option<u8>,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            dht_port: dc4_dht::DEFAULT_PORT,
            bind_v4: Ipv4Addr::UNSPECIFIED.to_string(),
            bind_v6: Ipv6Addr::UNSPECIFIED.to_string(),
            bootstrap: dc4_dht::DEFAULT_BOOTSTRAP
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            state_dir: PathBuf::from("/var/lib/dhtcrawler4"),
            max_packets_per_sec: dc4_dht::DEFAULT_MAX_PACKETS_PER_SEC,
            sampler_concurrency: dc4_dht::DEFAULT_SAMPLER_CONCURRENCY,
            identities: 1,
            sampler_live_share: 0.10,
            read_only: false,
            fetch_workers: 3072,
            max_connections: 12288,
            max_metadata_bytes: dc4_peer::DEFAULT_MAX_METADATA,
            max_inflight_metadata_bytes: 1024 * 1024 * 1024,
            max_pending: 5_000_000,
            scrape_workers: 1,
            scrape_interval_secs: 7 * 24 * 60 * 60,
            scrape_batch: 64,
            max_scrape_failures: 2,
            scrape_seeder_threshold: 0,
            scrape_query_timeout_secs: 10,
            scrape_lookup_timeout_secs: 60,
            scrape_concurrency: 3,
            scrape_packets_per_sec: dc4_dht::DEFAULT_SCRAPE_PACKETS_PER_SEC,
            fetch_packets_per_sec: dc4_dht::DEFAULT_FETCH_PACKETS_PER_SEC,
            removal_cooldown_days: 7,
            tombstone_purge_hours: 1,
            gave_up_purge_hours: 1,
            scrape_sweep_secs: 3600,
            scrape_unknown_interval_secs: 30 * 24 * 60 * 60,
            scrape_node_cache_keys: 4096,
            scrape_early_exit_quorum: 3,
            bep42_r: None,
        }
    }
}

/// `[index]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IndexConfig {
    pub path: PathBuf,
    pub writer_heap_bytes: usize,
    pub batch_size: i64,
    pub poll_interval_ms: u64,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/dhtcrawler4/index"),
            writer_heap_bytes: dc4_search::DEFAULT_WRITER_HEAP_BYTES,
            batch_size: 1000,
            poll_interval_ms: 1000,
        }
    }
}

/// `[web]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebSettings {
    pub listen: SocketAddr,
    pub site_name: String,
    pub hsts: bool,
    /// CIDR networks (or single addresses) whose `X-Forwarded-For` is trusted.
    pub trusted_proxies: Vec<String>,
    /// How many `(text, sort, page, per_page)` index results to cache.
    /// Zero disables the search query cache.
    pub search_cache_size: usize,
    /// How long a search cache entry lives, in seconds (fixed from insert).
    /// Zero disables the search query cache.
    pub search_cache_ttl_secs: u64,
}

impl Default for WebSettings {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
            site_name: "dhtcrawler4".into(),
            hsts: false,
            trusted_proxies: Vec::new(),
            search_cache_size: dc4_web::DEFAULT_SEARCH_CACHE_ENTRIES,
            search_cache_ttl_secs: dc4_web::DEFAULT_SEARCH_CACHE_TTL_SECS,
        }
    }
}

/// `[metrics]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    pub listen: SocketAddr,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 9100)),
        }
    }
}

/// `[log]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    pub format: LogFormat,
    pub level: LogLevel,
}

/// `log.format`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Json,
    Pretty,
}

/// `log.level`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// Whose database credentials to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbRole {
    /// `[database]` itself: admin commands, and any role without its own
    /// `[database.<role>]` section.
    Main,
    /// `[database.crawler]`, falling back to `[database]`.
    Crawler,
    /// `[database.indexer]`, falling back to `[database]`.
    Indexer,
    /// `[database.web]`, falling back to `[database]`.
    Web,
}

impl DbRole {
    fn section(self) -> &'static str {
        match self {
            DbRole::Main => "database",
            DbRole::Crawler => "database.crawler",
            DbRole::Indexer => "database.indexer",
            DbRole::Web => "database.web",
        }
    }
}

/// Reads the config file (or uses the defaults when `path` is `None` and
/// the default file does not exist), applies the overrides in `env`, and
/// validates the result.
pub fn load<I>(path: Option<&Path>, env: I) -> Result<Config, ConfigError>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let (file, explicit) = match path {
        Some(p) => (p, true),
        None => (Path::new(DEFAULT_CONFIG_PATH), false),
    };
    let text = match read_config_file(file) {
        Ok(text) => Some(text),
        Err(ConfigError::Read { source, .. })
            if !explicit && source.kind() == std::io::ErrorKind::NotFound =>
        {
            None
        }
        Err(e) => return Err(e),
    };
    let table = match text {
        Some(text) => parse_table(file, &text)?,
        None => toml::Table::new(),
    };
    from_table(table, env)
}

/// Parses `text` as a config file, applies `env` and validates the result.
pub fn from_toml_str<I>(text: &str, env: I) -> Result<Config, ConfigError>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    from_table(parse_table(Path::new("<string>"), text)?, env)
}

fn from_table<I>(mut table: toml::Table, env: I) -> Result<Config, ConfigError>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    apply_env_overrides(&mut table, env)?;
    let config: Config = table
        .try_into()
        .map_err(|e: toml::de::Error| ConfigError::Parse(e.message().trim().to_owned()))?;
    config.validate()?;
    Ok(config)
}

fn read_config_file(path: &Path) -> Result<String, ConfigError> {
    let read_err = |source: std::io::Error| ConfigError::Read {
        path: path.to_owned(),
        source,
    };
    let file = File::open(path).map_err(read_err)?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(read_err)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge {
            path: path.to_owned(),
            max: MAX_CONFIG_BYTES,
        });
    }
    String::from_utf8(bytes).map_err(|_| ConfigError::Syntax {
        path: path.to_owned(),
        message: "not valid UTF-8".into(),
    })
}

/// Parses TOML text. The error names the position only: the file's own
/// text is not quoted, in case a line holds something sensitive.
fn parse_table(path: &Path, text: &str) -> Result<toml::Table, ConfigError> {
    toml::from_str::<toml::Table>(text).map_err(|e| {
        let position = e
            .span()
            .map(|span| line_and_column(text, span.start))
            .map(|(line, column)| format!("line {line}, column {column}: "))
            .unwrap_or_default();
        ConfigError::Syntax {
            path: path.to_owned(),
            message: format!("{position}{}", e.message().trim()),
        }
    })
}

/// 1-based line and column of byte offset `at`.
fn line_and_column(text: &str, at: usize) -> (usize, usize) {
    let before = text.get(..at).unwrap_or(text);
    let line = before.matches('\n').count().saturating_add(1);
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |l| l.chars().count())
        .saturating_add(1);
    (line, column)
}

// ---------------------------------------------------------------------------
// Environment overrides
// ---------------------------------------------------------------------------

/// The type of a key, taken from the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    Integer,
    Float,
    Boolean,
    String,
    StringList,
    IntegerList,
}

/// The defaults as a TOML table, with every optional section present, so
/// that every key an override may name has a known type.
fn template() -> Result<toml::Table, ConfigError> {
    let role = RoleCredentials {
        user: Some(String::new()),
        password_file: Some(PathBuf::new()),
    };
    let mut full = Config::default();
    full.database.url = Some(String::new());
    full.crawl.bep42_r = Some(0);
    full.database.crawler = Some(role.clone());
    full.database.indexer = Some(role.clone());
    full.database.web = Some(role);
    toml::Table::try_from(&full)
        .map_err(|e| ConfigError::Invalid(format!("cannot build the override template: {e}")))
}

fn apply_env_overrides<I>(table: &mut toml::Table, env: I) -> Result<(), ConfigError>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut vars: Vec<(String, String, OsString)> = env
        .into_iter()
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            let rest = name.strip_prefix(ENV_PREFIX)?;
            if !rest.contains(ENV_SEPARATOR) {
                return None;
            }
            let rest = rest.to_owned();
            Some((name, rest, value))
        })
        .collect();
    if vars.is_empty() {
        return Ok(());
    }
    vars.sort_by(|a, b| a.0.cmp(&b.0));
    let template = template()?;
    for (name, rest, value) in vars {
        let env_err = |reason: String| ConfigError::Env {
            var: name.clone(),
            reason,
        };
        let path: Vec<String> = rest
            .split(ENV_SEPARATOR)
            .map(str::to_ascii_lowercase)
            .collect();
        let kind = template_kind(&template, &path).map_err(env_err)?;
        let value = value
            .into_string()
            .map_err(|_| env_err("the value is not valid UTF-8".into()))?;
        let value = parse_env_value(kind, &value).map_err(env_err)?;
        set_path(table, &path, value).map_err(env_err)?;
    }
    Ok(())
}

fn template_kind(template: &toml::Table, path: &[String]) -> Result<ValueKind, String> {
    let Some((key, sections)) = path.split_last() else {
        return Err("empty name".into());
    };
    let mut table = template;
    let mut walked: Vec<&str> = Vec::with_capacity(sections.len());
    for section in sections {
        walked.push(section.as_str());
        table = match table.get(section.as_str()) {
            Some(toml::Value::Table(inner)) => inner,
            _ => return Err(format!("unknown section `{}`", walked.join("."))),
        };
    }
    let dotted = path.join(".");
    match table.get(key.as_str()) {
        None => Err(format!("unknown key `{dotted}`")),
        Some(toml::Value::Integer(_)) => Ok(ValueKind::Integer),
        Some(toml::Value::Float(_)) => Ok(ValueKind::Float),
        Some(toml::Value::Boolean(_)) => Ok(ValueKind::Boolean),
        Some(toml::Value::String(_)) => Ok(ValueKind::String),
        Some(toml::Value::Array(items)) => match items.first() {
            None | Some(toml::Value::String(_)) => Ok(ValueKind::StringList),
            Some(toml::Value::Integer(_)) => Ok(ValueKind::IntegerList),
            Some(_) => Err(format!("`{dotted}` cannot be set from the environment")),
        },
        Some(toml::Value::Table(_)) => Err(format!("`{dotted}` is a section, not a key")),
        Some(_) => Err(format!("`{dotted}` cannot be set from the environment")),
    }
}

fn parse_env_value(kind: ValueKind, raw: &str) -> Result<toml::Value, String> {
    let integer = |s: &str| {
        s.trim()
            .parse::<i64>()
            .map(toml::Value::Integer)
            .map_err(|_| "expected an integer".to_owned())
    };
    let items = || {
        raw.split(ENV_LIST_SEPARATOR)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    match kind {
        ValueKind::Integer => integer(raw),
        ValueKind::Float => raw
            .trim()
            .parse::<f64>()
            .map(toml::Value::Float)
            .map_err(|_| "expected a number".to_owned()),
        ValueKind::Boolean => match raw.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(toml::Value::Boolean(true)),
            "false" => Ok(toml::Value::Boolean(false)),
            _ => Err("expected true or false".into()),
        },
        ValueKind::String => Ok(toml::Value::String(raw.to_owned())),
        ValueKind::StringList => Ok(toml::Value::Array(
            items().map(|s| toml::Value::String(s.to_owned())).collect(),
        )),
        ValueKind::IntegerList => items()
            .map(integer)
            .collect::<Result<Vec<_>, _>>()
            .map(toml::Value::Array),
    }
}

fn set_path(table: &mut toml::Table, path: &[String], value: toml::Value) -> Result<(), String> {
    let Some((key, sections)) = path.split_last() else {
        return Err("empty name".into());
    };
    let mut current = table;
    for section in sections {
        let entry = current
            .entry(section.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        current = match entry {
            toml::Value::Table(inner) => inner,
            _ => return Err(format!("`{section}` in the config file is not a section")),
        };
    }
    current.insert(key.clone(), value);
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation and derived values
// ---------------------------------------------------------------------------

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

fn check_range<T: PartialOrd + std::fmt::Display>(
    key: &str,
    value: T,
    min: T,
    max: T,
) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(invalid(format!(
            "{key} must be between {min} and {max}, got {value}"
        )));
    }
    Ok(())
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

/// True when two listen addresses would claim the same socket: same port and
/// equal IPs, a wildcard covering an address of the same family, both
/// wildcards, or a dual-stack `[::]` wildcard against any same-port IPv4
/// address. `0.0.0.0:P` and `[::]:P` overlap: on Linux the default
/// dual-stack `[::]` socket also claims the IPv4 port, so the second bind
/// fails with `EADDRINUSE` at startup. (On platforms with `V6ONLY` forced on
/// that pair could bind disjointly; rejecting it here is still the safe
/// direction — a clear config error instead of a runtime bind failure.)
/// The reverse is not true: an IPv4 wildcard never claims an IPv6 port, so
/// `0.0.0.0:P` and `[::1]:P` bind distinct sockets.
fn listen_addrs_overlap(a: SocketAddr, b: SocketAddr) -> bool {
    if a.port() != b.port() {
        return false;
    }
    if a.ip() == b.ip() {
        return true;
    }
    if a.ip().is_unspecified() && b.ip().is_unspecified() {
        return true;
    }
    if (a.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) && b.ip().is_ipv4())
        || (b.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) && a.ip().is_ipv4())
    {
        return true;
    }
    (a.ip().is_unspecified() || b.ip().is_unspecified()) && a.ip().is_ipv4() == b.ip().is_ipv4()
}

impl Config {
    /// Checks every value the program depends on.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_database()?;
        self.validate_crawl()?;
        self.validate_index()?;
        self.validate_web()?;
        if listen_addrs_overlap(self.metrics.listen, self.web.listen) && self.web.listen.port() != 0
        {
            return Err(invalid("metrics.listen and web.listen must differ"));
        }
        Ok(())
    }

    fn validate_database(&self) -> Result<(), ConfigError> {
        let db = &self.database;
        match db.url.as_deref().filter(|u| !u.is_empty()) {
            Some(url) => {
                parse_db_url(url)?;
            }
            None => {
                if db.host.trim().is_empty() {
                    return Err(invalid("database.host must not be empty"));
                }
                if db.name.trim().is_empty() {
                    return Err(invalid("database.name must not be empty"));
                }
                check_range("database.port", db.port, 1, u16::MAX)?;
            }
        }
        check_range(
            "database.max_connections",
            db.max_connections,
            1,
            MAX_DB_CONNECTIONS,
        )?;
        for role in [DbRole::Main, DbRole::Crawler, DbRole::Indexer, DbRole::Web] {
            let (user, _) = self.credentials(role);
            if user.trim().is_empty() || has_control(user) {
                return Err(invalid(format!(
                    "{}.user must be a non-empty name",
                    role.section()
                )));
            }
        }
        Ok(())
    }

    fn validate_crawl(&self) -> Result<(), ConfigError> {
        let c = &self.crawl;
        check_range("crawl.dht_port", c.dht_port, 1, u16::MAX)?;
        let (v4, v6) = self.dht_binds()?;
        if v4.is_none() && v6.is_none() {
            return Err(invalid(
                "at least one of crawl.bind_v4 and crawl.bind_v6 must be set",
            ));
        }
        if c.bootstrap.len() > MAX_BOOTSTRAP_HOSTS {
            return Err(invalid(format!(
                "crawl.bootstrap has more than {MAX_BOOTSTRAP_HOSTS} entries"
            )));
        }
        for host in &c.bootstrap {
            if !is_host_port(host) {
                return Err(invalid(format!(
                    "crawl.bootstrap entry {host:?} must be host:port"
                )));
            }
        }
        check_range(
            "crawl.max_packets_per_sec",
            c.max_packets_per_sec,
            1,
            u32::MAX,
        )?;
        check_range(
            "crawl.sampler_concurrency",
            c.sampler_concurrency,
            1,
            dc4_dht::MAX_SAMPLER_CONCURRENCY,
        )?;
        check_range(
            "crawl.identities",
            c.identities,
            1,
            dc4_dht::MAX_IDENTITIES,
        )?;
        if u32::from(c.dht_port).saturating_add(c.identities).saturating_sub(1)
            > u32::from(u16::MAX)
        {
            return Err(invalid(
                "crawl.dht_port + crawl.identities - 1 must fit in a port (<= 65535)",
            ));
        }
        // The identity port range must not claim the metrics/web sockets.
        for base in [v4, v6].into_iter().flatten() {
            for i in 0..c.identities {
                let addr =
                    SocketAddr::new(base.ip(), base.port().wrapping_add(i as u16));
                if listen_addrs_overlap(addr, self.metrics.listen) {
                    return Err(invalid(format!(
                        "crawl DHT identity {addr} overlaps metrics.listen"
                    )));
                }
                if self.web.listen.port() != 0 && listen_addrs_overlap(addr, self.web.listen)
                {
                    return Err(invalid(format!(
                        "crawl DHT identity {addr} overlaps web.listen"
                    )));
                }
            }
        };
        // Manual, not `check_range`: NaN slips through `<`/`>` comparisons;
        // `contains` fails NaN (mirrors `DhtTuning::validate`).
        if !(0.0..=1.0).contains(&c.sampler_live_share) {
            return Err(invalid(
                "crawl.sampler_live_share must be between 0.0 and 1.0",
            ));
        };
        check_range("crawl.fetch_workers", c.fetch_workers, 1, MAX_FETCH_WORKERS)?;
        check_range(
            "crawl.max_connections",
            c.max_connections,
            1,
            MAX_PEER_CONNECTIONS,
        )?;
        check_range(
            "crawl.max_metadata_bytes",
            c.max_metadata_bytes,
            MIN_METADATA_BYTES,
            MAX_METADATA_BYTES,
        )?;
        check_range(
            "crawl.max_inflight_metadata_bytes",
            c.max_inflight_metadata_bytes,
            MIN_INFLIGHT_METADATA_BYTES,
            MAX_INFLIGHT_METADATA_BYTES,
        )?;
        check_range("crawl.max_pending", c.max_pending, 0, i64::MAX)?;
        check_range("crawl.scrape_workers", c.scrape_workers, 1, 64)?;
        check_range(
            "crawl.scrape_interval_secs",
            c.scrape_interval_secs,
            3600,
            90 * 24 * 60 * 60,
        )?;
        check_range("crawl.scrape_batch", c.scrape_batch, 1, 1000)?;
        check_range("crawl.max_scrape_failures", c.max_scrape_failures, 1, 10)?;
        check_range(
            "crawl.scrape_seeder_threshold",
            c.scrape_seeder_threshold,
            0,
            1000,
        )?;
        check_range(
            "crawl.scrape_query_timeout_secs",
            c.scrape_query_timeout_secs,
            1,
            60,
        )?;
        check_range(
            "crawl.scrape_lookup_timeout_secs",
            c.scrape_lookup_timeout_secs,
            10,
            300,
        )?;
        if c.scrape_lookup_timeout_secs <= c.scrape_query_timeout_secs {
            return Err(invalid(
                "crawl.scrape_lookup_timeout_secs must exceed crawl.scrape_query_timeout_secs \
                 (overall deadline vs per-RPC timeout)",
            ));
        }
        check_range("crawl.scrape_concurrency", c.scrape_concurrency, 1, 16)?;
        check_range(
            "crawl.scrape_packets_per_sec",
            c.scrape_packets_per_sec,
            1,
            250,
        )?;
        check_range(
            "crawl.fetch_packets_per_sec",
            c.fetch_packets_per_sec,
            1,
            u32::MAX,
        )?;
        check_range(
            "crawl.removal_cooldown_days",
            c.removal_cooldown_days,
            1,
            365,
        )?;
        check_range(
            "crawl.tombstone_purge_hours",
            c.tombstone_purge_hours,
            0,
            168,
        )?;
        check_range("crawl.gave_up_purge_hours", c.gave_up_purge_hours, 0, 168)?;
        check_range("crawl.scrape_sweep_secs", c.scrape_sweep_secs, 60, 86_400)?;
        check_range(
            "crawl.scrape_unknown_interval_secs",
            c.scrape_unknown_interval_secs,
            7 * 24 * 60 * 60,
            90 * 24 * 60 * 60,
        )?;
        if c.scrape_unknown_interval_secs < c.scrape_interval_secs {
            return Err(invalid(
                "crawl.scrape_unknown_interval_secs must be at least crawl.scrape_interval_secs, \
                 else unknown swarms are re-polled faster than live ones",
            ));
        }
        check_range(
            "crawl.scrape_node_cache_keys",
            c.scrape_node_cache_keys,
            0,
            65_536,
        )?;
        check_range(
            "crawl.scrape_early_exit_quorum",
            c.scrape_early_exit_quorum,
            2,
            5,
        )?;
        if c.bep42_r.is_some_and(|r| r > 7) {
            return Err(invalid("crawl.bep42_r must be between 0 and 7"));
        }
        Ok(())
    }

    fn validate_index(&self) -> Result<(), ConfigError> {
        let i = &self.index;
        if i.path.as_os_str().is_empty() {
            return Err(invalid("index.path must not be empty"));
        }
        check_range(
            "index.writer_heap_bytes",
            i.writer_heap_bytes,
            MIN_WRITER_HEAP_BYTES,
            MAX_WRITER_HEAP_BYTES,
        )?;
        check_range("index.batch_size", i.batch_size, 1, MAX_INDEX_BATCH)?;
        check_range(
            "index.poll_interval_ms",
            i.poll_interval_ms,
            1,
            MAX_POLL_INTERVAL_MS,
        )?;
        Ok(())
    }

    fn validate_web(&self) -> Result<(), ConfigError> {
        let w = &self.web;
        let name_chars = w.site_name.chars().count();
        if w.site_name.trim().is_empty()
            || name_chars > MAX_SITE_NAME_CHARS
            || has_control(&w.site_name)
        {
            return Err(invalid(format!(
                "web.site_name must be 1 to {MAX_SITE_NAME_CHARS} printable characters"
            )));
        }
        if w.trusted_proxies.len() > MAX_TRUSTED_PROXIES {
            return Err(invalid(format!(
                "web.trusted_proxies has more than {MAX_TRUSTED_PROXIES} entries"
            )));
        }
        dc4_web::validate_search_cache(w.search_cache_size, w.search_cache_ttl_secs)
            .map_err(invalid)?;
        self.trusted_proxies()?;
        Ok(())
    }

    /// Problems `check-config` reports without refusing the configuration.
    pub fn warnings(&self) -> Vec<String> {
        let w = &self.web;
        let mut out = Vec::new();
        if w.trusted_proxies.is_empty() {
            out.push(
                "web.trusted_proxies is empty: X-Forwarded-For is ignored, so behind a \
                 reverse proxy every visitor shares the proxy's rate limits"
                    .to_owned(),
            );
        }
        if !w.listen.ip().is_loopback() && w.trusted_proxies.is_empty() {
            out.push(
                "web.listen is not a loopback address while web.trusted_proxies is empty: \
                 if a reverse proxy connects from a private network, add that network to \
                 web.trusted_proxies"
                    .to_owned(),
            );
        }
        out
    }

    /// The user and password file for `role`.
    pub fn credentials(&self, role: DbRole) -> (&str, &Path) {
        let db = &self.database;
        let over = match role {
            DbRole::Main => None,
            DbRole::Crawler => db.crawler.as_ref(),
            DbRole::Indexer => db.indexer.as_ref(),
            DbRole::Web => db.web.as_ref(),
        };
        let user = over
            .and_then(|o| o.user.as_deref())
            .filter(|u| !u.is_empty())
            .unwrap_or(&db.user);
        let password_file = over
            .and_then(|o| o.password_file.as_deref())
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(&db.password_file);
        (user, password_file)
    }

    /// Connection options for `role`, with the password read from its file.
    /// The result's `Debug` output includes the password: never log it.
    pub fn connect_options(&self, role: DbRole) -> Result<PgConnectOptions, ConfigError> {
        let db = &self.database;
        let (user, password_file) = self.credentials(role);
        let base = match db.url.as_deref().filter(|u| !u.is_empty()) {
            Some(url) => parse_db_url(url)?,
            None => PgConnectOptions::new_without_pgpass()
                .host(&db.host)
                .port(db.port)
                .database(&db.name),
        };
        let mut options = base.username(user);
        if !password_file.as_os_str().is_empty() {
            let password = read_password_file(password_file)?;
            options = options.password(&password);
        }
        Ok(options)
    }

    /// `web.trusted_proxies` as networks. A bare address is a single host.
    pub fn trusted_proxies(&self) -> Result<Vec<IpNet>, ConfigError> {
        self.web
            .trusted_proxies
            .iter()
            .map(|entry| {
                let text = entry.trim();
                IpNet::from_str(text)
                    .or_else(|_| IpAddr::from_str(text).map(IpNet::from))
                    .map_err(|_| {
                        invalid(format!(
                            "web.trusted_proxies entry {entry:?} is not an address or CIDR network"
                        ))
                    })
            })
            .collect()
    }

    /// The DHT socket addresses; `None` for a disabled family.
    pub fn dht_binds(&self) -> Result<(Option<SocketAddr>, Option<SocketAddr>), ConfigError> {
        let c = &self.crawl;
        let v4 =
            match c.bind_v4.trim() {
                "" => None,
                text => Some(Ipv4Addr::from_str(text).map_err(|_| {
                    invalid(format!("crawl.bind_v4 {text:?} is not an IPv4 address"))
                })?),
            };
        let v6 =
            match c.bind_v6.trim() {
                "" => None,
                text => Some(Ipv6Addr::from_str(text).map_err(|_| {
                    invalid(format!("crawl.bind_v6 {text:?} is not an IPv6 address"))
                })?),
            };
        Ok((
            v4.map(|ip| SocketAddr::from((ip, c.dht_port))),
            v6.map(|ip| SocketAddr::from((ip, c.dht_port))),
        ))
    }

    /// `state_dir/dht-state.json`, or `None` when `state_dir` is empty.
    pub fn dht_state_file(&self) -> Option<PathBuf> {
        let dir = &self.crawl.state_dir;
        (!dir.as_os_str().is_empty()).then(|| dir.join(DHT_STATE_FILE))
    }

    /// The configuration as TOML, with any password in `database.url`
    /// replaced by [`REDACTED`]. Password files are named, never read.
    pub fn to_redacted_toml(&self) -> Result<String, ConfigError> {
        let mut copy = self.clone();
        if let Some(url) = copy.database.url.as_mut() {
            *url = redact_url(url);
        }
        toml::to_string_pretty(&copy)
            .map_err(|e| invalid(format!("cannot print the configuration: {e}")))
    }
}

fn parse_db_url(url: &str) -> Result<PgConnectOptions, ConfigError> {
    if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
        return Err(invalid(
            "database.url must start with postgres:// or postgresql://",
        ));
    }
    if url_has_userinfo_password(url) || url_has_secret_query_key(url) {
        return Err(invalid(
            "database.url must not include a password; put it in database.password_file",
        ));
    }
    // The parser's error could quote parts of the URL, so it is not shown.
    PgConnectOptions::from_str(url)
        .map_err(|_| invalid("database.url is not a valid PostgreSQL URL"))
}

/// True when `url` carries a password in its `user:password@` section.
/// Passwords come from files, never from the URL (which shows up in the
/// environment, process listings and dumps).
fn url_has_userinfo_password(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority_end].rsplit_once('@') {
        Some((userinfo, _)) => userinfo.contains(':'),
        None => false,
    }
}

/// True when `url` carries a secret-looking query parameter (`password`):
/// sqlx reads that key live, so it bypasses file-only passwords exactly
/// like a userinfo password does. Only the exact key sqlx reads is
/// rejected here; substring matches (`bypass`, `compass`) are left to the
/// display-only redaction below so benign parameters keep working.
fn url_has_secret_query_key(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let rest = rest.split_once('#').map(|(t, _)| t).unwrap_or(rest);
    let Some((_, query)) = rest.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        let name = pair.split_once('=').map(|(n, _)| n).unwrap_or(pair);
        name.eq_ignore_ascii_case("password")
    })
}

/// Reads a password file: at most [`MAX_PASSWORD_BYTES`], one line, with
/// one trailing newline removed. An empty password is an error.
pub fn read_password_file(path: &Path) -> Result<String, ConfigError> {
    let fail = |reason: String| ConfigError::Password {
        path: path.to_owned(),
        reason,
    };
    let file = File::open(path).map_err(|e| fail(e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(MAX_PASSWORD_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| fail(e.to_string()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PASSWORD_BYTES {
        return Err(fail(format!("is larger than {MAX_PASSWORD_BYTES} bytes")));
    }
    let text = String::from_utf8(bytes).map_err(|_| fail("is not valid UTF-8".into()))?;
    let password = match text.strip_suffix('\n') {
        Some(rest) => rest.strip_suffix('\r').unwrap_or(rest),
        None => text.as_str(),
    };
    if password.is_empty() {
        return Err(fail("is empty".into()));
    }
    if password.contains(['\n', '\r']) {
        return Err(fail("must hold a single line".into()));
    }
    Ok(password.to_owned())
}

/// `url` with its userinfo password, secret-looking query parameters and
/// fragment dropped. Display only: the result carries no secret and parses
/// back to the same non-secret settings.
pub fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return REDACTED.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let authority = match authority.rsplit_once('@') {
        Some((userinfo, host)) => match userinfo.split_once(':') {
            Some((user, _)) => format!("{user}@{host}"),
            None => authority.to_owned(),
        },
        None => authority.to_owned(),
    };
    // Fragments never reach the server; a `#` can only hide text from the
    // key matching below, so it is dropped, never printed.
    let tail = tail.split_once('#').map(|(t, _)| t).unwrap_or(tail);
    let tail = match tail.split_once('?') {
        Some((path, query)) => {
            let kept: Vec<&str> = query
                .split('&')
                .filter(|pair| {
                    let name = pair.split_once('=').map(|(n, _)| n).unwrap_or(pair);
                    name.is_empty() || !is_password_key(name)
                })
                .collect();
            if kept.is_empty() {
                path.to_owned()
            } else {
                format!("{path}?{}", kept.join("&"))
            }
        }
        None => tail.to_owned(),
    };
    format!("{scheme}://{authority}{tail}")
}

/// True for query keys that may hold a secret (`password` and its common
/// variants). Over-redaction is safe: this is display only, and is
/// deliberately broader than the rejection check above (which only rejects
/// the exact `password` key sqlx reads live).
fn is_password_key(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("pass")
        || lower.contains("pwd")
        || lower.contains("secret")
        || lower.contains("token")
}

/// True for `host:port` with a non-zero port (IPv6 literals in brackets).
fn is_host_port(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    let host_ok = match host.strip_prefix('[') {
        Some(inner) => inner
            .strip_suffix(']')
            .is_some_and(|ip| Ipv6Addr::from_str(ip).is_ok()),
        None => {
            !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        }
    };
    host_ok && port.parse::<u16>().is_ok_and(|p| p != 0)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../deploy/config/dhtcrawler4.toml");
    const COMPOSE: &str = include_str!("../../../deploy/docker-compose.yml");
    const ROLES_SH: &str = include_str!("../../../deploy/postgres/init/10-roles.sh");
    const README: &str = include_str!("../../../README.md");

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(*k), OsString::from(*v)))
            .collect()
    }

    fn with_env(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        from_toml_str(EXAMPLE, env(pairs))
    }

    #[test]
    fn example_file_parses_and_equals_defaults() {
        let parsed = from_toml_str(EXAMPLE, env(&[])).unwrap();
        assert_eq!(parsed, Config::default());
        // The example pins the cache knobs: whole-struct equality alone would
        // also pass if the keys were missing (serde defaults fill them in).
        assert!(EXAMPLE.contains("search_cache_size"));
        assert!(EXAMPLE.contains("search_cache_ttl_secs"));
        assert!(EXAMPLE.contains("sampler_live_share"));
        assert!(EXAMPLE.contains("fetch_packets_per_sec"));
        assert!(EXAMPLE.contains("identities"));
        assert_eq!(
            parsed.web.search_cache_size,
            dc4_web::DEFAULT_SEARCH_CACHE_ENTRIES
        );
        assert_eq!(
            parsed.web.search_cache_ttl_secs,
            dc4_web::DEFAULT_SEARCH_CACHE_TTL_SECS
        );
        // No environment and no file at all gives the same result.
        assert_eq!(from_toml_str("", env(&[])).unwrap(), Config::default());
        // The example's commented role sections parse too.
        let roles = EXAMPLE
            .replace("# [database.", "[database.")
            .replace("# user = ", "user = ")
            .replace("# password_file = ", "password_file = ");
        let parsed = from_toml_str(&roles, env(&[])).unwrap();
        assert_eq!(parsed.credentials(DbRole::Indexer).0, "dc4_indexer");
        assert_eq!(
            parsed.credentials(DbRole::Web).1,
            Path::new("/run/secrets/dc4_web_password")
        );
        assert_eq!(parsed.credentials(DbRole::Main).0, "dc4_crawler");
    }

    #[test]
    fn deploy_queue_tuning_pins() {
        // Part 2 of the db churn plan: bigger checkpoints on the db command,
        // async commits for the crawler role only, and a README pool bullet
        // that matches the compose pool instead of the stale 96.
        for needle in [
            "max_connections=200",
            "checkpoint_timeout=900",
            "max_wal_size=4GB",
            "DC4_DATABASE__MAX_CONNECTIONS: \"128\"",
        ] {
            assert!(COMPOSE.contains(needle), "compose lost {needle}");
        }
        assert!(
            ROLES_SH.contains("ALTER ROLE dc4_crawler SET synchronous_commit = off;"),
            "crawler async-commit setting missing from 10-roles.sh"
        );
        assert!(
            ROLES_SH.contains("ALTER ROLE dc4_crawler CONNECTION LIMIT 200;"),
            "crawler connection limit moved in 10-roles.sh"
        );
        for role in ["dc4_indexer", "dc4_web"] {
            assert!(
                !ROLES_SH.contains(&format!("{role} SET synchronous_commit")),
                "{role} must keep full durability"
            );
        }
        for needle in [
            "compose sets 128",
            "synchronous_commit = off",
            "checkpoint_timeout=900",
            "max_wal_size=4GB",
        ] {
            assert!(README.contains(needle), "readme pool bullet lost {needle}");
        }
        assert!(
            !README.contains("compose sets 96"),
            "stale compose pool size is back in the readme"
        );
    }

    #[test]
    fn unknown_keys_in_the_file_are_errors() {
        for text in [
            "[database]\npassword = \"x\"\n",
            "[nope]\nx = 1\n",
            "[database.crawler]\nhost = \"x\"\n",
            "top = 1\n",
        ] {
            let err = from_toml_str(text, env(&[])).unwrap_err();
            assert!(matches!(err, ConfigError::Parse(_)), "{text}: {err}");
            assert!(!err.to_string().contains("\"x\""), "{err}");
        }
    }

    #[test]
    fn syntax_errors_name_the_position_but_not_the_text() {
        let err =
            from_toml_str("[database]\nurl = \"postgres://u:hunter2@h/db\n", env(&[])).unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, ConfigError::Syntax { .. }), "{text}");
        assert!(text.contains("line 2"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[test]
    fn overlapping_listen_addrs_are_rejected() {
        let mut c = Config::default();
        // Exact equality still rejected.
        c.metrics.listen = "127.0.0.1:9100".parse().unwrap();
        c.web.listen = "127.0.0.1:9100".parse().unwrap();
        assert!(c.validate().is_err());
        // Wildcard vs loopback on the same port overlaps.
        c.metrics.listen = "0.0.0.0:9100".parse().unwrap();
        c.web.listen = "127.0.0.1:9100".parse().unwrap();
        assert!(c.validate().is_err());
        // Distinct loopback IPs on the same port do not overlap.
        c.metrics.listen = "127.0.0.1:9100".parse().unwrap();
        c.web.listen = "127.0.0.2:9100".parse().unwrap();
        assert!(c.validate().is_ok());
        // Different ports are fine.
        c.metrics.listen = "0.0.0.0:9100".parse().unwrap();
        c.web.listen = "127.0.0.1:8080".parse().unwrap();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn cross_family_listen_addrs_overlap() {
        let mut c = Config::default();
        // IPv4 wildcard vs IPv6 loopback on the same port: distinct sockets
        // (an IPv4 wildcard never claims an IPv6 port).
        c.metrics.listen = "0.0.0.0:9100".parse().unwrap();
        c.web.listen = "[::1]:9100".parse().unwrap();
        assert!(c.validate().is_ok());
        // IPv6 wildcard vs IPv4 loopback on the same port: the dual-stack
        // `[::]` claims the IPv4 port on Linux, so this is rejected at
        // validation, not as a runtime `EADDRINUSE`.
        c.metrics.listen = "[::]:9100".parse().unwrap();
        c.web.listen = "127.0.0.1:9100".parse().unwrap();
        assert!(c.validate().is_err());
        // Same in the other order.
        c.metrics.listen = "127.0.0.1:9100".parse().unwrap();
        c.web.listen = "[::]:9100".parse().unwrap();
        assert!(c.validate().is_err());
        // Both wildcards on the same port conflict (dual-stack `[::]`
        // claims the IPv4 port on Linux): rejected at validation, not as a
        // runtime `EADDRINUSE`.
        c.metrics.listen = "0.0.0.0:9100".parse().unwrap();
        c.web.listen = "[::]:9100".parse().unwrap();
        assert!(c.validate().is_err());
        // Same-family wildcard pairs are still rejected.
        c.metrics.listen = "[::]:9100".parse().unwrap();
        c.web.listen = "[::1]:9100".parse().unwrap();
        assert!(c.validate().is_err());
        // Exact IPv6 equality is still rejected.
        c.metrics.listen = "[::1]:9100".parse().unwrap();
        c.web.listen = "[::1]:9100".parse().unwrap();
        assert!(c.validate().is_err());
        // Distinct IPv6 loopbacks on the same port do not overlap.
        c.metrics.listen = "[::1]:9100".parse().unwrap();
        c.web.listen = "[::2]:9100".parse().unwrap();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn env_overrides_of_each_type() {
        let c = with_env(&[
            ("DC4_DATABASE__USER", "dc4_web"),
            ("DC4_DATABASE__MAX_CONNECTIONS", " 4 "),
            ("DC4_CRAWL__READ_ONLY", "TRUE"),
            ("DC4_CRAWL__BOOTSTRAP", "a.example:1, b.example:2,"),
            ("DC4_WEB__TRUSTED_PROXIES", "172.30.80.0/24,10.0.0.1"),
            ("DC4_WEB__LISTEN", "0.0.0.0:8080"),
            ("DC4_LOG__FORMAT", "pretty"),
            ("DC4_LOG__LEVEL", "debug"),
            ("DC4_CRAWL__BIND_V6", ""),
            ("DC4_CRAWL__BEP42_R", "3"),
            ("DC4_DATABASE__CRAWLER__USER", "crawler2"),
            ("DC4_DATABASE__URL", "postgres://h:5433/other"),
            // Ignored: no double underscore.
            ("DC4_TARGET", "x"),
            ("DC4_TEST_DATABASE_URL", "x"),
            ("DC4_E2E_VERBOSE", "1"),
            ("OTHER__THING", "x"),
        ])
        .unwrap();
        assert_eq!(c.database.user, "dc4_web");
        assert_eq!(c.database.max_connections, 4);
        assert!(c.crawl.read_only);
        assert_eq!(c.crawl.bep42_r, Some(3));
        assert_eq!(c.crawl.bootstrap, ["a.example:1", "b.example:2"]);
        assert_eq!(
            c.trusted_proxies().unwrap(),
            vec![
                "172.30.80.0/24".parse::<IpNet>().unwrap(),
                "10.0.0.1/32".parse::<IpNet>().unwrap()
            ]
        );
        assert_eq!(c.web.listen, "0.0.0.0:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(c.log.format, LogFormat::Pretty);
        assert_eq!(c.log.level, LogLevel::Debug);
        assert_eq!(c.dht_binds().unwrap().1, None);
        assert!(c.dht_binds().unwrap().0.is_some());
        assert_eq!(c.credentials(DbRole::Crawler).0, "crawler2");
        assert_eq!(c.credentials(DbRole::Indexer).0, "dc4_web");
        assert_eq!(c.database.url.as_deref(), Some("postgres://h:5433/other"));
        // An empty list override clears the list.
        let c = with_env(&[("DC4_CRAWL__BOOTSTRAP", "")]).unwrap();
        assert!(c.crawl.bootstrap.is_empty());
    }

    #[test]
    fn bad_overrides_are_errors_without_their_values() {
        for (name, value, needle) in [
            (
                "DC4_DATABASE__PASSWORD",
                "hunter2",
                "unknown key `database.password`",
            ),
            ("DC4_NOPE__KEY", "hunter2", "unknown section `nope`"),
            (
                "DC4_DATABASE__OWNER__USER",
                "hunter2",
                "unknown section `database.owner`",
            ),
            ("DC4_DATABASE", "hunter2", ""),
            ("DC4_DATABASE__CRAWLER", "hunter2", "is a section"),
            ("DC4_CRAWL__DHT_PORT", "hunter2", "expected an integer"),
            ("DC4_CRAWL__READ_ONLY", "hunter2", "expected true or false"),
            (
                "DC4_CRAWL__BOOTSTRAP__X",
                "hunter2",
                "unknown section `crawl.bootstrap`",
            ),
            ("DC4___PORT", "hunter2", "unknown section ``"),
        ] {
            let result = with_env(&[(name, value)]);
            if needle.is_empty() {
                // No "__": not an override at all.
                assert!(result.is_ok(), "{name}");
                continue;
            }
            let err = result.unwrap_err();
            let text = err.to_string();
            assert!(matches!(err, ConfigError::Env { .. }), "{name}: {text}");
            assert!(text.contains(name), "{text}");
            assert!(text.contains(needle), "{name}: {text}");
            assert!(!text.contains("hunter2"), "{text}");
        }
        // A value of the right type that fails validation.
        let err = with_env(&[("DC4_CRAWL__DHT_PORT", "70000")]).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err}");
        let err = with_env(&[("DC4_CRAWL__FETCH_WORKERS", "0")]).unwrap_err();
        assert!(err.to_string().contains("crawl.fetch_workers"), "{err}");
    }

    #[test]
    fn non_utf8_override_value_is_an_error() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let vars = vec![(
                OsString::from("DC4_DATABASE__USER"),
                OsString::from_vec(vec![0xff, 0xfe]),
            )];
            let err = from_toml_str(EXAMPLE, vars).unwrap_err();
            assert!(err.to_string().contains("not valid UTF-8"), "{err}");
        }
    }

    #[test]
    fn validation_rules() {
        let bad: &[(&str, &str)] = &[
            ("DC4_CRAWL__DHT_PORT", "0"),
            ("DC4_DATABASE__PORT", "0"),
            ("DC4_DATABASE__MAX_CONNECTIONS", "0"),
            ("DC4_CRAWL__MAX_CONNECTIONS", "0"),
            ("DC4_CRAWL__MAX_INFLIGHT_METADATA_BYTES", "65535"),
            ("DC4_CRAWL__MAX_METADATA_BYTES", "100"),
            ("DC4_CRAWL__BIND_V4", "::"),
            ("DC4_CRAWL__BIND_V6", "0.0.0.0"),
            ("DC4_CRAWL__MAX_PENDING", "-1"),
            ("DC4_CRAWL__SCRAPE_WORKERS", "0"),
            ("DC4_CRAWL__SCRAPE_WORKERS", "65"),
            ("DC4_CRAWL__SCRAPE_BATCH", "0"),
            ("DC4_CRAWL__SCRAPE_BATCH", "1001"),
            ("DC4_CRAWL__MAX_SCRAPE_FAILURES", "0"),
            ("DC4_CRAWL__MAX_SCRAPE_FAILURES", "11"),
            ("DC4_CRAWL__SCRAPE_SEEDER_THRESHOLD", "1001"),
            ("DC4_CRAWL__SCRAPE_QUERY_TIMEOUT_SECS", "0"),
            ("DC4_CRAWL__SCRAPE_QUERY_TIMEOUT_SECS", "61"),
            ("DC4_CRAWL__SCRAPE_LOOKUP_TIMEOUT_SECS", "9"),
            ("DC4_CRAWL__SCRAPE_LOOKUP_TIMEOUT_SECS", "301"),
            ("DC4_CRAWL__SCRAPE_CONCURRENCY", "0"),
            ("DC4_CRAWL__SCRAPE_CONCURRENCY", "17"),
            ("DC4_CRAWL__SCRAPE_PACKETS_PER_SEC", "0"),
            ("DC4_CRAWL__SCRAPE_PACKETS_PER_SEC", "251"),
            ("DC4_CRAWL__REMOVAL_COOLDOWN_DAYS", "0"),
            ("DC4_CRAWL__REMOVAL_COOLDOWN_DAYS", "366"),
            ("DC4_CRAWL__TOMBSTONE_PURGE_HOURS", "169"),
            ("DC4_CRAWL__GAVE_UP_PURGE_HOURS", "169"),
            ("DC4_CRAWL__SCRAPE_SWEEP_SECS", "59"),
            ("DC4_CRAWL__SCRAPE_UNKNOWN_INTERVAL_SECS", "86399"),
            ("DC4_CRAWL__SCRAPE_NODE_CACHE_KEYS", "65537"),
            ("DC4_CRAWL__SCRAPE_EARLY_EXIT_QUORUM", "1"),
            ("DC4_CRAWL__SCRAPE_EARLY_EXIT_QUORUM", "6"),
            ("DC4_CRAWL__BOOTSTRAP", "no-port"),
            ("DC4_CRAWL__SAMPLER_CONCURRENCY", "1025"),
            ("DC4_CRAWL__SAMPLER_CONCURRENCY", "0"),
            ("DC4_CRAWL__IDENTITIES", "0"),
            ("DC4_CRAWL__IDENTITIES", "9"),
            ("DC4_CRAWL__DHT_PORT", "9100"),
            ("DC4_CRAWL__SAMPLER_LIVE_SHARE", "1.5"),
            ("DC4_CRAWL__SAMPLER_LIVE_SHARE", "-0.1"),
            ("DC4_CRAWL__SAMPLER_LIVE_SHARE", "NaN"),
            ("DC4_INDEX__BATCH_SIZE", "1001"),
            ("DC4_INDEX__WRITER_HEAP_BYTES", "1000"),
            ("DC4_INDEX__POLL_INTERVAL_MS", "0"),
            ("DC4_WEB__SITE_NAME", ""),
            ("DC4_WEB__TRUSTED_PROXIES", "not-a-net"),
            ("DC4_WEB__SEARCH_CACHE_SIZE", "10001"),
            ("DC4_WEB__SEARCH_CACHE_TTL_SECS", "604801"),
            ("DC4_METRICS__LISTEN", "127.0.0.1:8080"),
            ("DC4_DATABASE__URL", "mysql://h/db"),
            ("DC4_DATABASE__USER", ""),
            ("DC4_DATABASE__WEB__USER", " "),
        ];
        for (name, value) in bad {
            let err = with_env(&[(name, value)]).unwrap_err();
            assert!(
                matches!(err, ConfigError::Invalid(_) | ConfigError::Parse(_)),
                "{name}={value}: {err}"
            );
        }
        // Out-of-range cache knobs name the limit, never the rejected value.
        for (name, value) in [
            ("DC4_WEB__SEARCH_CACHE_SIZE", "10001"),
            ("DC4_WEB__SEARCH_CACHE_TTL_SECS", "604801"),
        ] {
            let err = with_env(&[(name, value)]).unwrap_err();
            assert!(!err.to_string().contains(value), "{err}");
        }
        let both_off = with_env(&[("DC4_CRAWL__BIND_V4", ""), ("DC4_CRAWL__BIND_V6", "")]);
        assert!(both_off.is_err());
        // The identity port range must fit in 16 bits.
        let overflow = with_env(&[
            ("DC4_CRAWL__DHT_PORT", "65535"),
            ("DC4_CRAWL__IDENTITIES", "2"),
        ]);
        assert!(overflow.is_err());
        // With a URL, host and name may be empty.
        assert!(
            with_env(&[
                ("DC4_DATABASE__URL", "postgresql://h/db"),
                ("DC4_DATABASE__HOST", ""),
                ("DC4_DATABASE__NAME", ""),
            ])
            .is_ok()
        );
    }

    #[test]
    fn scrape_intervals_are_ordered() {
        // Equal is allowed (not faster); only strictly less is refused.
        let ok = with_env(&[
            ("DC4_CRAWL__SCRAPE_INTERVAL_SECS", "604800"),
            ("DC4_CRAWL__SCRAPE_UNKNOWN_INTERVAL_SECS", "604800"),
        ]);
        assert!(ok.is_ok(), "{ok:?}");
        let err = with_env(&[
            ("DC4_CRAWL__SCRAPE_INTERVAL_SECS", "1209600"),
            ("DC4_CRAWL__SCRAPE_UNKNOWN_INTERVAL_SECS", "604800"),
        ])
        .unwrap_err();
        assert!(
            err.to_string().contains("scrape_unknown_interval_secs"),
            "{err}"
        );

        // The overall lookup deadline must exceed the per-RPC timeout.
        let err = with_env(&[
            ("DC4_CRAWL__SCRAPE_QUERY_TIMEOUT_SECS", "10"),
            ("DC4_CRAWL__SCRAPE_LOOKUP_TIMEOUT_SECS", "10"),
        ])
        .unwrap_err();
        assert!(
            err.to_string().contains("scrape_lookup_timeout_secs"),
            "{err}"
        );
    }

    #[test]
    fn search_cache_defaults_and_env_overrides() {
        let w = Config::default().web;
        assert_eq!(w.search_cache_size, 100);
        assert_eq!(w.search_cache_size, dc4_web::DEFAULT_SEARCH_CACHE_ENTRIES);
        assert_eq!(w.search_cache_ttl_secs, 900);
        assert_eq!(
            w.search_cache_ttl_secs,
            dc4_web::DEFAULT_SEARCH_CACHE_TTL_SECS
        );
        let c = with_env(&[
            ("DC4_WEB__SEARCH_CACHE_SIZE", "50"),
            ("DC4_WEB__SEARCH_CACHE_TTL_SECS", "60"),
        ])
        .unwrap();
        assert_eq!(c.web.search_cache_size, 50);
        assert_eq!(c.web.search_cache_ttl_secs, 60);
        // Zero of either knob disables the cache instead of erroring.
        let c = with_env(&[
            ("DC4_WEB__SEARCH_CACHE_SIZE", "0"),
            ("DC4_WEB__SEARCH_CACHE_TTL_SECS", "0"),
        ])
        .unwrap();
        assert_eq!(c.web.search_cache_size, 0);
        assert_eq!(c.web.search_cache_ttl_secs, 0);
    }

    #[test]
    fn scrape_defaults_match_the_spec() {
        let c = Config::default().crawl;
        assert_eq!(c.scrape_workers, 1);
        assert_eq!(c.scrape_interval_secs, 604800);
        assert_eq!(c.scrape_batch, 64);
        assert_eq!(c.max_scrape_failures, 2);
        assert_eq!(c.scrape_seeder_threshold, 0);
        assert_eq!(c.scrape_query_timeout_secs, 10);
        assert_eq!(c.scrape_lookup_timeout_secs, 60);
        assert_eq!(c.scrape_concurrency, 3);
        assert_eq!(c.scrape_packets_per_sec, 100);
        assert_eq!(
            c.fetch_packets_per_sec,
            dc4_dht::DEFAULT_FETCH_PACKETS_PER_SEC
        );
        assert_eq!(c.identities, 1);
        assert_eq!(c.removal_cooldown_days, 7);
        assert_eq!(c.tombstone_purge_hours, 1);
        assert_eq!(c.gave_up_purge_hours, 1);
        assert_eq!(c.scrape_sweep_secs, 3600);
        assert_eq!(c.scrape_unknown_interval_secs, 2592000);
        assert_eq!(c.scrape_node_cache_keys, 4096);
        assert_eq!(c.scrape_early_exit_quorum, 3);
    }

    #[test]
    fn warnings() {
        let c = Config::default();
        let w = c.warnings();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("trusted_proxies"));

        let c = with_env(&[
            ("DC4_WEB__HSTS", "true"),
            ("DC4_WEB__LISTEN", "0.0.0.0:8080"),
        ])
        .unwrap();
        let w = c.warnings();
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("trusted_proxies"));
        assert!(w[1].contains("loopback"));

        let c = with_env(&[
            ("DC4_WEB__HSTS", "true"),
            ("DC4_WEB__TRUSTED_PROXIES", "172.30.80.0/24"),
            ("DC4_WEB__LISTEN", "0.0.0.0:8080"),
        ])
        .unwrap();
        assert!(c.warnings().is_empty(), "{:?}", c.warnings());
    }

    #[test]
    fn password_files() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, content: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, content).unwrap();
            path
        };
        let plain = write("plain", b"s3cret");
        let newline = write("newline", b"s3cret\n");
        let crlf = write("crlf", b"s3cret\r\n");
        let two = write("two", b"s3cret\n\n");
        let empty = write("empty", b"");
        let only_newline = write("only-newline", b"\n");
        let big = write("big", &[b'a'; 5000]);
        let binary = write("binary", &[0xff, 0x00]);
        assert_eq!(read_password_file(&plain).unwrap(), "s3cret");
        assert_eq!(read_password_file(&newline).unwrap(), "s3cret");
        assert_eq!(read_password_file(&crlf).unwrap(), "s3cret");
        for path in [&two, &empty, &only_newline, &big, &binary] {
            let err = read_password_file(path).unwrap_err();
            assert!(matches!(err, ConfigError::Password { .. }), "{err}");
            assert!(!err.to_string().contains("s3cret"), "{err}");
        }
        let missing = dir.path().join("missing");
        assert!(read_password_file(&missing).is_err());

        // connect_options reads the right file per role.
        let crawler_pw = write("crawler", b"crawlerpw\n");
        let c = with_env(&[
            ("DC4_DATABASE__PASSWORD_FILE", plain.to_str().unwrap()),
            (
                "DC4_DATABASE__CRAWLER__PASSWORD_FILE",
                crawler_pw.to_str().unwrap(),
            ),
            ("DC4_DATABASE__CRAWLER__USER", "dc4_crawler2"),
        ])
        .unwrap();
        let main = c.connect_options(DbRole::Main).unwrap();
        assert_eq!(main.get_username(), "dc4_crawler");
        assert_eq!(main.get_host(), "db");
        assert_eq!(main.get_port(), 5432);
        assert_eq!(main.get_database(), Some("dc4"));
        let crawler = c.connect_options(DbRole::Crawler).unwrap();
        assert_eq!(crawler.get_username(), "dc4_crawler2");
        // An empty password file is refused for every role that uses it.
        let c = with_env(&[("DC4_DATABASE__PASSWORD_FILE", empty.to_str().unwrap())]).unwrap();
        assert!(c.connect_options(DbRole::Web).is_err());
        // No password file at all: connect without a password.
        let c = with_env(&[("DC4_DATABASE__PASSWORD_FILE", "")]).unwrap();
        assert!(c.connect_options(DbRole::Main).is_ok());
    }

    #[test]
    fn url_overrides_host_but_not_credentials() {
        let mut c = with_env(&[
            ("DC4_DATABASE__URL", "postgres://pg.internal:6543/other"),
            ("DC4_DATABASE__USER", "dc4_owner"),
            ("DC4_DATABASE__PASSWORD_FILE", ""),
        ])
        .unwrap();
        let o = c.connect_options(DbRole::Main).unwrap();
        assert_eq!(o.get_host(), "pg.internal");
        assert_eq!(o.get_port(), 6543);
        assert_eq!(o.get_database(), Some("other"));
        assert_eq!(o.get_username(), "dc4_owner");
        // A URL password is refused at load: passwords come from files.
        let err = with_env(&[
            (
                "DC4_DATABASE__URL",
                "postgres://someone:urlpw@pg.internal:6543/other",
            ),
            ("DC4_DATABASE__USER", "dc4_owner"),
            ("DC4_DATABASE__PASSWORD_FILE", ""),
        ])
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "{err}");
        assert!(parse_db_url("postgres://u:p@h/db").is_err());
        assert!(parse_db_url("postgres://u@h/db").is_ok());
        assert!(parse_db_url("postgres://h/db?password=x").is_err());
        assert!(parse_db_url("postgres://h/db?sslmode=disable").is_ok());
        // F-12: benign keys containing `pass` are not secret query keys.
        for key in ["bypass", "compass", "passport", "passwordless"] {
            assert!(
                parse_db_url(&format!("postgres://h/db?{key}=x")).is_ok(),
                "{key}"
            );
        }
        // ... but redaction still hides it when such a config is printed.
        c.database.url = Some("postgres://someone:urlpw@pg.internal:6543/other".into());
        let printed = c.to_redacted_toml().unwrap();
        assert!(!printed.contains("urlpw"), "{printed}");
        assert!(
            printed.contains("postgres://someone@pg.internal:6543/other"),
            "{printed}"
        );
    }

    #[test]
    fn url_redaction() {
        for (input, expected) in [
            ("postgres://u:p@h/db", "postgres://u@h/db"),
            ("postgres://u@h/db", "postgres://u@h/db"),
            ("postgres://h:5432/db", "postgres://h:5432/db"),
            (
                "postgres://u:p:q@h/db?sslmode=disable&password=x",
                "postgres://u@h/db?sslmode=disable",
            ),
            // Password variants are dropped, fragments never printed.
            ("postgres://bob:s3cret@h/db?passwd=x", "postgres://bob@h/db"),
            ("postgres://bob:s3cret@h/db?pass=x", "postgres://bob@h/db"),
            (
                "postgres://bob:s3cret@h/db?sslmode=disable&PWD=x&Token=y",
                "postgres://bob@h/db?sslmode=disable",
            ),
            ("postgres://bob:s3cret@h/db#fragpw", "postgres://bob@h/db"),
            (
                "postgres://u:p:q@h/db?sslmode=disable&password=x#f",
                "postgres://u@h/db?sslmode=disable",
            ),
            ("postgres://u:p@h", "postgres://u@h"),
            ("postgres://a:b@c@h/x", "postgres://a@h/x"),
            ("garbage with p@ss", "REDACTED"),
        ] {
            assert_eq!(redact_url(input), expected, "{input}");
        }
    }

    #[test]
    fn derived_values() {
        let c = Config::default();
        assert_eq!(
            c.dht_state_file(),
            Some(PathBuf::from("/var/lib/dhtcrawler4/dht-state.json"))
        );
        let (v4, v6) = c.dht_binds().unwrap();
        assert_eq!(v4, Some("0.0.0.0:6881".parse().unwrap()));
        assert_eq!(v6, Some("[::]:6881".parse().unwrap()));
        let c = with_env(&[("DC4_CRAWL__STATE_DIR", "")]).unwrap();
        assert_eq!(c.dht_state_file(), None);
        assert_eq!(line_and_column("ab\ncd", 4), (2, 2));
        assert!(is_host_port("[::1]:6881"));
        assert!(!is_host_port("[::1]:0"));
        assert!(!is_host_port(":6881"));
    }
}
