//! dhtcrawler4: a BitTorrent DHT search engine (design §13; R19, R20).
//!
//! The binary is a thin wrapper around [`cli::main`]. The library holds
//! everything else, so the end-to-end tests drive the same code:
//!
//! * [`config`]: the configuration file, environment overrides and checks.
//! * [`crawl`]: the crawl role. [`admission`] turns DHT discoveries into
//!   queue entries; [`fetch`] turns queue entries into stored torrents.
//!   [`peers`] is the address chokepoint for peers.
//! * [`index`]: the index role, which projects the database into Tantivy.
//! * [`web`]: the web role, which serves `dc4-web`.
//! * [`admin`]: the admin subcommands; [`healthcheck`]: the container
//!   health check.
//! * [`roles`]: runs one role, or all three, with its metrics listener
//!   ([`metrics_server`]).
//! * [`stores`]: the store operations the pipeline uses, as traits;
//!   [`memstore`] is an in-memory implementation for tests.
//! * [`logging`], [`signals`]: startup helpers.
//!
//! Every role stops gracefully when its `CancellationToken` is cancelled
//! ([`signals`] cancels it on SIGINT and SIGTERM).
#![forbid(unsafe_code)]

pub mod admin;
pub mod admission;
pub mod cli;
pub mod config;
pub mod crawl;
pub mod fetch;
pub mod healthcheck;
pub mod index;
pub mod logging;
pub mod memstore;
pub mod metrics_server;
pub mod peers;
pub mod roles;
pub mod scrape;
pub mod signals;
pub mod stores;
pub mod tracker;
pub mod web;
