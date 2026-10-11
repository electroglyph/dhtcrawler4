//! Rate limiting: a token bucket, the responder budget, per-address inbound
//! buckets and per-address spacing of outbound queries.
//!
//! The bucket is implemented as GCRA (a "virtual scheduling" token bucket):
//! it keeps one instant instead of a token count, and needs no floating point.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use lru::LruCache;
use tokio::time::Instant;

use crate::compact::{AddrKey, AddrPolicy, Family, canonical_addr};
use crate::util::{after, after_skip};

/// Capacity of the per-address maps (design §3).
pub(crate) const RATE_MAP_CAPACITY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(99_999);

/// A token bucket refilling at `rate` per second with capacity `burst`.
#[derive(Clone, Debug)]
pub(crate) struct TokenBucket {
    /// Time one token takes to refill.
    emission: Duration,
    /// Time a full bucket takes to refill (`emission × burst`).
    capacity: Duration,
    /// Theoretical arrival time: the bucket is full when this is not after now.
    tat: Instant,
}

impl TokenBucket {
    /// A full bucket. A rate or burst of zero is treated as one.
    pub(crate) fn new(rate_per_sec: u32, burst: u32, now: Instant) -> Self {
        let second = Duration::from_secs(1);
        let emission = second.checked_div(rate_per_sec.max(1)).unwrap_or(second);
        let capacity = emission.checked_mul(burst.max(1)).unwrap_or(Duration::MAX);
        Self {
            emission,
            capacity,
            tat: now,
        }
    }

    /// The new schedule after taking `n` tokens, if they are available.
    fn take(&self, n: u32, now: Instant) -> Option<Instant> {
        let cost = self.emission.checked_mul(n)?;
        let tat = self.tat.max(now).checked_add(cost)?;
        let fits = now
            .checked_add(self.capacity)
            .is_none_or(|limit| tat <= limit);
        fits.then_some(tat)
    }

    /// Takes one token if available.
    pub(crate) fn try_acquire(&mut self, now: Instant) -> bool {
        self.try_acquire_n(1, now)
    }

    /// Takes `n` tokens if all are available.
    pub(crate) fn try_acquire_n(&mut self, n: u32, now: Instant) -> bool {
        match self.take(n, now) {
            Some(tat) => {
                self.tat = tat;
                true
            }
            None => false,
        }
    }

    /// Gives back `n` tokens taken earlier and not used.
    pub(crate) fn refund(&mut self, n: u32) {
        if let Some(tat) = self
            .emission
            .checked_mul(n)
            .and_then(|d| self.tat.checked_sub(d))
        {
            self.tat = tat;
        }
    }

    /// How long until a token is available (zero if one is available now).
    /// On overflow (only possible with absurd stored state) it returns
    /// `Duration::MAX`, failing closed: callers treat the bucket as
    /// unavailable until their deadline (far in the past relative to the
    /// saturated wake) and give up instead of treating the bucket as
    /// immediately available. The token itself stays gated: `take` returns
    /// `None` when the saturated schedule does not fit the bucket.
    pub(crate) fn wait_time(&self, now: Instant) -> Duration {
        let next = self.tat.max(now).checked_add(self.emission);
        match (next, now.checked_add(self.capacity)) {
            (Some(next), Some(limit)) => next.saturating_duration_since(limit),
            _ => Duration::MAX,
        }
    }
}

/// The global reply budget (design §3): replies and reply bytes per second,
/// each with one second of burst. It is separate from the query budget.
pub(crate) struct ResponderBudget {
    replies: TokenBucket,
    bytes: TokenBucket,
}

impl ResponderBudget {
    pub(crate) fn new(replies_per_sec: u32, bytes_per_sec: u32, now: Instant) -> Self {
        Self {
            replies: TokenBucket::new(replies_per_sec, replies_per_sec, now),
            bytes: TokenBucket::new(bytes_per_sec, bytes_per_sec, now),
        }
    }

    /// Takes one reply and `max_bytes` bytes, or nothing when either is short.
    /// Unused bytes go back with [`refund_bytes`](Self::refund_bytes).
    pub(crate) fn try_reserve(&mut self, max_bytes: u32, now: Instant) -> bool {
        let (Some(replies), Some(bytes)) =
            (self.replies.take(1, now), self.bytes.take(max_bytes, now))
        else {
            return false;
        };
        self.replies.tat = replies;
        self.bytes.tat = bytes;
        true
    }

    /// Returns reserved bytes the reply did not use.
    pub(crate) fn refund_bytes(&mut self, unused: u32) {
        self.bytes.refund(unused);
    }
}

/// Per-host inbound token buckets (an IPv4 address or an IPv6 /48, one
/// external-IP voter), kept in one bounded LRU map per family, so IPv6
/// churn cannot evict IPv4 buckets.
pub(crate) struct InboundLimiter {
    v4: LruCache<AddrKey, TokenBucket>,
    v6: LruCache<AddrKey, TokenBucket>,
    rate: u32,
    burst: u32,
    policy: AddrPolicy,
}

impl InboundLimiter {
    pub(crate) fn new(rate: u32, burst: u32, policy: AddrPolicy) -> Self {
        Self::with_capacity(rate, burst, policy, RATE_MAP_CAPACITY)
    }

    pub(crate) fn with_capacity(
        rate: u32,
        burst: u32,
        policy: AddrPolicy,
        capacity: NonZeroUsize,
    ) -> Self {
        Self {
            v4: LruCache::new(capacity),
            v6: LruCache::new(capacity),
            rate,
            burst,
            policy,
        }
    }

    /// Whether a packet from `from` may be processed.
    pub(crate) fn allow(&mut self, from: &SocketAddr, now: Instant) -> bool {
        let (rate, burst) = (self.rate, self.burst);
        let buckets = match Family::of(&canonical_addr(*from)) {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        };
        buckets
            .get_or_insert_mut(self.policy.inbound_key(from), || {
                TokenBucket::new(rate, burst, now)
            })
            .try_acquire(now)
    }
}

/// Per-key usage counts over fixed windows, in a bounded LRU map. When the
/// map is full of windows still running, new keys get nothing (fail closed).
pub(crate) struct WindowQuota {
    used: LruCache<AddrKey, (Instant, u32)>,
    limit: u32,
    window: Duration,
}

impl WindowQuota {
    pub(crate) fn new(limit: u32, window: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            used: LruCache::new(capacity),
            limit,
            window,
        }
    }

    fn running(&self, start: Instant, now: Instant) -> bool {
        now < after(start, self.window)
    }

    /// Units `key` may still use in its current window.
    pub(crate) fn remaining(&self, key: &AddrKey, now: Instant) -> u32 {
        match self.used.peek(key) {
            Some((start, used)) if self.running(*start, now) => self.limit.saturating_sub(*used),
            Some(_) => self.limit,
            None if self.used.len() < self.used.cap().get() => self.limit,
            None => match self.used.peek_lru() {
                Some((_, (start, _))) if self.running(*start, now) => 0,
                _ => self.limit,
            },
        }
    }

    /// Uses `n` units of `key`; callers check [`remaining`](Self::remaining) first.
    pub(crate) fn charge(&mut self, key: AddrKey, n: u32, now: Instant) {
        if n == 0 || self.remaining(&key, now) == 0 {
            return;
        }
        let window = self.window;
        if let Some(entry) = self.used.get_mut(&key) {
            if now >= after(entry.0, window) {
                *entry = (now, 0);
            }
            entry.1 = entry.1.saturating_add(n);
            return;
        }
        // `remaining` said there is room, or the oldest window has ended.
        self.used.push(key, (now, n));
    }
}

/// Minimum spacing between queries to one address. When the map is full, an
/// entry is evicted only once its spacing has passed.
pub(crate) struct QuerySpacing {
    next_free: LruCache<AddrKey, Instant>,
    spacing: Duration,
    policy: AddrPolicy,
}

impl QuerySpacing {
    pub(crate) fn new(spacing: Duration, policy: AddrPolicy) -> Self {
        Self::with_capacity(spacing, policy, RATE_MAP_CAPACITY)
    }

    pub(crate) fn with_capacity(
        spacing: Duration,
        policy: AddrPolicy,
        capacity: NonZeroUsize,
    ) -> Self {
        Self {
            next_free: LruCache::new(capacity),
            spacing,
            policy,
        }
    }

    /// Reserves a send slot for a query to `to` and returns how long to wait
    /// before sending. Returns `None`, reserving nothing, when the wait would
    /// exceed `max_wait` or the map is full of entries still in force.
    pub(crate) fn reserve(
        &mut self,
        to: &SocketAddr,
        now: Instant,
        max_wait: Duration,
    ) -> Option<Duration> {
        if self.spacing.is_zero() {
            return Some(Duration::ZERO);
        }
        let key = self.policy.host_key(to);
        let known = self.next_free.peek(&key).copied();
        let send_at = known.map_or(now, |t| t.max(now));
        let wait = send_at.saturating_duration_since(now);
        if wait > max_wait {
            return None;
        }
        if known.is_none() && self.next_free.len() >= self.next_free.cap().get() {
            match self.next_free.peek_lru() {
                Some((_, free_at)) if *free_at <= now => {
                    self.next_free.pop_lru();
                }
                _ => return None,
            }
        }
        self.next_free.put(key, after_skip(send_at, self.spacing));
        Some(wait)
    }

    /// Undoes one [`reserve`](Self::reserve): moves the send slot for `to`
    /// earlier by one spacing, dropping it when it is due. Call it when a
    /// reserved query never leaves the socket, so a failed attempt does not
    /// throttle the next query to the same address.
    pub(crate) fn release(&mut self, to: &SocketAddr, now: Instant) {
        if self.spacing.is_zero() {
            return;
        }
        let key = self.policy.host_key(to);
        let Some(free_at) = self.next_free.get(&key).copied() else {
            return;
        };
        match free_at.checked_sub(self.spacing) {
            Some(prev) if prev > now => {
                self.next_free.put(key, prev);
            }
            _ => {
                self.next_free.pop(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);
    const PRODUCTION: AddrPolicy = AddrPolicy {
        allow_private: false,
        by_endpoint: false,
    };
    const TEST: AddrPolicy = AddrPolicy {
        allow_private: true,
        by_endpoint: true,
    };

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn bucket_allows_burst_then_rate() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(10, 20, t0);
        for i in 0..20 {
            assert!(b.try_acquire(t0), "burst packet {i}");
        }
        assert!(!b.try_acquire(t0));
        assert_eq!(b.wait_time(t0), 100 * MS);
        assert!(!b.try_acquire(t0 + 99 * MS));
        assert!(b.try_acquire(t0 + 100 * MS));
        assert!(!b.try_acquire(t0 + 100 * MS));
        // Over a long quiet period the bucket refills only up to the burst.
        let later = t0 + Duration::from_secs(60);
        assert_eq!(b.wait_time(later), Duration::ZERO);
        let mut n = 0;
        while b.try_acquire(later) {
            n += 1;
        }
        assert_eq!(n, 20);
    }

    #[test]
    fn wait_time_overflow_is_fail_closed() {
        let t0 = Instant::now();
        // Absurd stored state (saturated capacity): `now + capacity`
        // overflows, so no wait can be computed. The bucket must report a
        // long wait, not "available now".
        let b = TokenBucket {
            emission: Duration::from_secs(1),
            capacity: Duration::MAX,
            tat: t0,
        };
        assert_eq!(b.wait_time(t0), Duration::MAX);
    }

    #[test]
    fn bucket_sustained_rate() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(250, 1, t0);
        let mut sent = 0;
        for ms in 0..1000u64 {
            if b.try_acquire(t0 + Duration::from_millis(ms)) {
                sent += 1;
            }
        }
        assert_eq!(sent, 250);
        // Degenerate settings do not panic.
        let mut z = TokenBucket::new(0, 0, t0);
        assert!(z.try_acquire(t0));
        assert!(!z.try_acquire(t0));
        let mut fast = TokenBucket::new(u32::MAX, u32::MAX, t0);
        assert!(fast.try_acquire(t0));
        assert!(!z.try_acquire_n(u32::MAX, t0));
    }

    #[test]
    fn scrape_and_crawl_buckets_are_independent() {
        // BEP 33 §2 LB-2/LB-3: scrapes charge a dedicated bucket (25/s),
        // never the crawl bucket (250/s); per-address spacing stays shared
        // (see `query_spacing`). Draining one bucket must not touch the
        // other. Binding: `query_scrape` charges `scrape_budget`
        // (node.rs), `query_gated` charges `budget`.
        let t0 = Instant::now();
        let mut crawl = TokenBucket::new(250, 250, t0);
        let mut scrape = TokenBucket::new(25, 25, t0);
        for _ in 0..25 {
            assert!(scrape.try_acquire(t0));
        }
        assert!(!scrape.try_acquire(t0));
        // The crawl bucket is still full after the scrape bucket drained.
        for i in 0..250 {
            assert!(crawl.try_acquire(t0), "crawl packet {i}");
        }
        assert!(!crawl.try_acquire(t0));
    }

    #[test]
    fn fetch_and_scrape_buckets_are_independent() {
        // WS1: fetch traversals (6 000/s) charge their own bucket, never the
        // 100/s scrape bucket; per-address spacing stays shared (see
        // `query_spacing`). Draining either bucket must not touch the other.
        // Binding: `query_fetch` charges `fetch_budget`, `query_scrape`
        // charges `scrape_budget` (node.rs), routed by `Kind::budget`
        // (lookup.rs).
        let t0 = Instant::now();
        let mut fetch = TokenBucket::new(6000, 6000, t0);
        let mut scrape = TokenBucket::new(100, 100, t0);
        for _ in 0..100 {
            assert!(scrape.try_acquire(t0));
        }
        assert!(!scrape.try_acquire(t0));
        // The fetch bucket is still full after the scrape bucket drained.
        for i in 0..6000 {
            assert!(fetch.try_acquire(t0), "fetch packet {i}");
        }
        assert!(!fetch.try_acquire(t0));
        // And vice versa from fresh buckets: a drained fetch bucket leaves
        // scrapes usable.
        let mut fetch = TokenBucket::new(6000, 6000, t0);
        let mut scrape = TokenBucket::new(100, 100, t0);
        for _ in 0..6000 {
            assert!(fetch.try_acquire(t0));
        }
        assert!(!fetch.try_acquire(t0));
        for i in 0..100 {
            assert!(scrape.try_acquire(t0), "scrape packet {i}");
        }
        assert!(!scrape.try_acquire(t0));
    }

    #[test]
    fn bucket_takes_and_refunds_several_tokens() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(1000, 1000, t0);
        assert!(b.try_acquire_n(600, t0));
        assert!(!b.try_acquire_n(401, t0));
        assert!(b.try_acquire_n(400, t0));
        assert!(!b.try_acquire(t0));
        b.refund(300);
        assert!(b.try_acquire_n(300, t0));
        assert!(!b.try_acquire(t0));
        // 250 ms later, 250 tokens are back.
        let later = t0 + 250 * MS;
        assert!(!b.try_acquire_n(251, later));
        assert!(b.try_acquire_n(250, later));
        // A refund never overfills the bucket.
        b.refund(u32::MAX);
        let much_later = t0 + Duration::from_secs(10);
        assert!(!b.try_acquire_n(1001, much_later));
        assert!(b.try_acquire_n(1000, much_later));
    }

    #[test]
    fn responder_budget_counts_replies() {
        let t0 = Instant::now();
        let mut r = ResponderBudget::new(3, 64_000, t0);
        for _ in 0..3 {
            assert!(r.try_reserve(1024, t0));
            r.refund_bytes(1000);
        }
        assert!(!r.try_reserve(1024, t0));
        // One reply comes back every third of a second.
        assert!(!r.try_reserve(1024, t0 + 300 * MS));
        assert!(r.try_reserve(1024, t0 + 334 * MS));
    }

    #[test]
    fn responder_budget_counts_bytes() {
        let t0 = Instant::now();
        let mut r = ResponderBudget::new(500, 4096, t0);
        // Four full-size replies use up the byte budget.
        for _ in 0..4 {
            assert!(r.try_reserve(1024, t0));
        }
        assert!(!r.try_reserve(1024, t0));
        // Each reservation needs a full datagram's worth of bytes, but only
        // the bytes sent are kept: (4096 - 1024) / 64 + 1 = 49 replies of 64 bytes.
        let later = t0 + Duration::from_secs(1);
        let mut sent = 0;
        while r.try_reserve(1024, later) {
            r.refund_bytes(1024 - 64);
            sent += 1;
        }
        assert_eq!(sent, 49);
        // Small replies are still limited by the reply count.
        let mut r = ResponderBudget::new(500, 64_000, t0);
        let mut sent = 0;
        while r.try_reserve(1024, t0) {
            r.refund_bytes(1024 - 8);
            sent += 1;
        }
        assert_eq!(sent, 500);
    }

    #[test]
    fn failed_reservations_take_nothing() {
        let t0 = Instant::now();
        // Three replies per second and exactly one datagram of bytes.
        let mut r = ResponderBudget::new(3, 1024, t0);
        for _ in 0..3 {
            assert!(r.try_reserve(1024, t0));
            r.refund_bytes(1024);
        }
        // Out of replies: these fail without touching the bytes...
        for _ in 0..10 {
            assert!(!r.try_reserve(1024, t0));
        }
        // ...so the next reply token finds the full datagram's worth still there.
        assert!(r.try_reserve(1024, t0 + 334 * MS));
    }

    #[test]
    fn inbound_limiter_keys_on_ip_in_production() {
        let t0 = Instant::now();
        let mut l = InboundLimiter::new(10, 20, PRODUCTION);
        let a = sa("8.8.8.8:1");
        let a2 = sa("8.8.8.8:2");
        let b = sa("9.9.9.9:1");
        for _ in 0..20 {
            assert!(l.allow(&a, t0));
        }
        assert!(!l.allow(&a, t0));
        // Same IP, other port: same bucket, even for a local address.
        assert!(!l.allow(&a2, t0));
        assert!(l.allow(&b, t0));
        assert!(l.allow(&a, t0 + 100 * MS));
        let lo1 = sa("127.0.0.1:1");
        let lo2 = sa("127.0.0.1:2");
        for _ in 0..20 {
            assert!(l.allow(&lo1, t0));
        }
        assert!(!l.allow(&lo2, t0));
    }

    #[test]
    fn inbound_limiter_keys_on_endpoint_in_tests() {
        let t0 = Instant::now();
        let mut l = InboundLimiter::new(10, 20, TEST);
        let lo1 = sa("127.0.0.1:1");
        let lo2 = sa("127.0.0.1:2");
        for _ in 0..20 {
            assert!(l.allow(&lo1, t0));
        }
        assert!(!l.allow(&lo1, t0));
        assert!(l.allow(&lo2, t0));
    }

    #[test]
    fn inbound_limiter_map_is_bounded() {
        let t0 = Instant::now();
        let cap = NonZeroUsize::new(4).unwrap();
        let mut l = InboundLimiter::with_capacity(1, 1, PRODUCTION, cap);
        for i in 0..10u8 {
            assert!(l.allow(&SocketAddr::from(([8, 8, 8, i], 1)), t0));
        }
        assert_eq!(l.v4.len(), 4);
        for i in 0..10u16 {
            // A distinct /48 each: the third group differs.
            let a = SocketAddr::new(
                std::net::Ipv6Addr::new(0x2a01, 0x4f8, i, 0, 0, 0, 0, 1).into(),
                1,
            );
            assert!(l.allow(&a, t0));
        }
        assert_eq!(l.v6.len(), 4);
    }

    fn v6(net: u16, host: u16) -> SocketAddr {
        SocketAddr::new(
            std::net::Ipv6Addr::new(0x2a01, 0x4f8, 1, net, host, 0, 0, 1).into(),
            6881,
        )
    }

    #[test]
    fn inbound_limiter_keys_ipv6_on_the_48() {
        let t0 = Instant::now();
        let mut l = InboundLimiter::new(10, 20, PRODUCTION);
        let mut allowed = 0;
        // Different /64s of one /48 share a bucket, like one voter.
        for net in 0..50u16 {
            for _ in 0..20 {
                if l.allow(&v6(net, 0), t0) {
                    allowed += 1;
                }
            }
        }
        assert_eq!(allowed, 20);
        // Another /48 has its own bucket.
        let other = SocketAddr::new(
            std::net::Ipv6Addr::new(0x2a01, 0x4f8, 2, 0, 0, 0, 0, 1).into(),
            6881,
        );
        assert!(l.allow(&other, t0));
    }

    #[test]
    fn ipv6_churn_does_not_reset_ipv4_buckets() {
        let t0 = Instant::now();
        let cap = NonZeroUsize::new(4).unwrap();
        let mut l = InboundLimiter::with_capacity(1, 1, PRODUCTION, cap);
        let a = sa("8.8.8.8:1");
        assert!(l.allow(&a, t0));
        assert!(!l.allow(&a, t0));
        for net in 0..100 {
            l.allow(&v6(net, 0), t0);
        }
        assert!(!l.allow(&a, t0));
    }

    #[test]
    fn query_spacing_keys_ipv6_on_the_64() {
        let t0 = Instant::now();
        let second = Duration::from_secs(1);
        let mut s = QuerySpacing::new(second, PRODUCTION);
        assert_eq!(
            s.reserve(&v6(2, 1), t0, Duration::ZERO),
            Some(Duration::ZERO)
        );
        assert_eq!(s.reserve(&v6(2, 2), t0, Duration::ZERO), None);
        assert_eq!(
            s.reserve(&v6(3, 1), t0, Duration::ZERO),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn window_quota_counts_per_window_and_fails_closed() {
        let t0 = Instant::now();
        let minute = Duration::from_secs(60);
        let cap = NonZeroUsize::new(2).unwrap();
        let mut q = WindowQuota::new(5, minute, cap);
        let key = |i: u8| PRODUCTION.host_key(&SocketAddr::from(([8, 8, 8, i], 1)));
        assert_eq!(q.remaining(&key(1), t0), 5);
        q.charge(key(1), 3, t0);
        assert_eq!(q.remaining(&key(1), t0), 2);
        q.charge(key(1), 3, t0);
        assert_eq!(q.remaining(&key(1), t0), 0);
        // A new window starts afresh.
        assert_eq!(q.remaining(&key(1), t0 + minute), 5);
        q.charge(key(2), 1, t0 + MS);
        // Full of running windows: a third key gets nothing and is not stored.
        assert_eq!(q.remaining(&key(3), t0 + MS), 0);
        q.charge(key(3), 1, t0 + MS);
        assert_eq!(q.used.len(), 2);
        assert!(q.used.peek(&key(3)).is_none());
        // Once the oldest window ends, it makes room.
        assert_eq!(q.remaining(&key(3), t0 + minute), 5);
        q.charge(key(3), 1, t0 + minute);
        assert_eq!(q.remaining(&key(3), t0 + minute), 4);
        assert!(q.used.peek(&key(1)).is_none());
    }

    #[test]
    fn query_spacing() {
        let t0 = Instant::now();
        let second = Duration::from_secs(1);
        let mut s = QuerySpacing::new(second, PRODUCTION);
        let a = sa("8.8.8.8:1");
        let a2 = sa("8.8.8.8:2");
        assert_eq!(s.reserve(&a, t0, second * 4), Some(Duration::ZERO));
        assert_eq!(s.reserve(&a2, t0, second * 4), Some(second));
        assert_eq!(s.reserve(&a, t0, second * 4), Some(second * 2));
        // Too long a wait reserves nothing.
        assert_eq!(s.reserve(&a, t0, second), None);
        assert_eq!(s.reserve(&a, t0 + second * 3, second), Some(Duration::ZERO));
        let other = sa("9.9.9.9:1");
        assert_eq!(s.reserve(&other, t0, Duration::ZERO), Some(Duration::ZERO));
        let mut none = QuerySpacing::new(Duration::ZERO, PRODUCTION);
        assert_eq!(none.reserve(&a, t0, Duration::ZERO), Some(Duration::ZERO));
        assert_eq!(none.reserve(&a, t0, Duration::ZERO), Some(Duration::ZERO));
        // Tests space endpoints, not IPs.
        let mut t = QuerySpacing::new(second, TEST);
        assert_eq!(
            t.reserve(&sa("127.0.0.1:1"), t0, Duration::ZERO),
            Some(Duration::ZERO)
        );
        assert_eq!(
            t.reserve(&sa("127.0.0.1:2"), t0, Duration::ZERO),
            Some(Duration::ZERO)
        );
        assert_eq!(t.reserve(&sa("127.0.0.1:1"), t0, Duration::ZERO), None);
    }

    #[test]
    fn spacing_release_undoes_reserve() {
        let t0 = Instant::now();
        let second = Duration::from_secs(1);
        let mut s = QuerySpacing::new(second, PRODUCTION);
        let a = sa("8.8.8.8:1");
        assert_eq!(s.reserve(&a, t0, second * 4), Some(Duration::ZERO));
        // Without a release the next query waits.
        assert_eq!(s.reserve(&a, t0, second * 4), Some(second));
        // Undo one reservation: back to a single wait.
        s.release(&a, t0);
        assert_eq!(s.reserve(&a, t0, second * 4), Some(second));
        s.release(&a, t0);
        s.release(&a, t0);
        // Fully released: no wait again.
        assert_eq!(s.reserve(&a, t0, second * 4), Some(Duration::ZERO));
    }

    #[test]
    fn full_spacing_map_evicts_only_spent_entries() {
        let t0 = Instant::now();
        let second = Duration::from_secs(1);
        let cap = NonZeroUsize::new(2).unwrap();
        let mut s = QuerySpacing::with_capacity(second, PRODUCTION, cap);
        assert!(s.reserve(&sa("8.8.8.1:1"), t0, second).is_some());
        assert!(s.reserve(&sa("8.8.8.2:1"), t0, second).is_some());
        // Both entries are still in force: a third address must wait.
        assert_eq!(s.reserve(&sa("8.8.8.3:1"), t0 + 999 * MS, second), None);
        // Known addresses are unaffected.
        assert_eq!(s.reserve(&sa("8.8.8.1:1"), t0 + 999 * MS, second), Some(MS));
        // Once the least recently used entry (8.8.8.2) is spent, it makes room.
        assert_eq!(
            s.reserve(&sa("8.8.8.3:1"), t0 + second, second),
            Some(Duration::ZERO)
        );
        assert_eq!(s.next_free.len(), 2);
        // 8.8.8.1 and 8.8.8.3 are both in force, so 8.8.8.2 cannot come back yet.
        assert_eq!(s.reserve(&sa("8.8.8.2:1"), t0 + second, second), None);
        assert_eq!(
            s.reserve(&sa("8.8.8.1:1"), t0 + second, second),
            Some(second)
        );
    }
}
