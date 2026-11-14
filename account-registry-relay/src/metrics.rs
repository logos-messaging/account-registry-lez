//! The relay's Prometheus metrics, served as OpenMetrics text on `GET /metrics`.

use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram, info::Info},
    registry::Registry,
};
use tiny_http::{Header, Method, Response, Server};

use crate::relay::Reason;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SubmissionLabels {
    transport: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RefusalLabels {
    reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct WriteLabels {
    kind: &'static str,
    outcome: &'static str,
}

/// Everything the relay reports.
pub struct Metrics {
    registry: Registry,
    submissions: Family<SubmissionLabels, Counter>,
    refusals: Family<RefusalLabels, Counter>,
    writes: Family<WriteLabels, Counter>,
    fees: Counter,
    landing: Histogram,
    /// The payer's balance, in units.
    pub balance: Gauge,
    /// Approved writes waiting to be sent.
    pub queued: Gauge,
    /// Writes sent and not yet landed: 0 or 1.
    pub in_flight: Gauge,
    /// Sponsored writes sent in the past hour.
    pub last_hour: Gauge,
    /// Sponsored writes sent in the past 24 hours.
    pub last_day: Gauge,
    /// Open libp2p connections.
    pub connections: Gauge,
}

impl Metrics {
    /// The relay's metrics, with `info` as the labels of `account_relay_info`.
    #[must_use]
    pub fn new(info: Vec<(String, String)>) -> Self {
        let mut registry = Registry::with_prefix("account_relay");
        let metrics = Self {
            registry: Registry::default(),
            submissions: Family::default(),
            refusals: Family::default(),
            writes: Family::default(),
            fees: Counter::default(),
            landing: Histogram::new([5.0, 10.0, 20.0, 30.0, 45.0, 60.0, 90.0, 120.0, 180.0, 300.0]),
            balance: Gauge::default(),
            queued: Gauge::default(),
            in_flight: Gauge::default(),
            last_hour: Gauge::default(),
            last_day: Gauge::default(),
            connections: Gauge::default(),
        };
        registry.register(
            "build",
            "The relay's version and configuration",
            Info::new(info),
        );
        registry.register(
            "submissions",
            "Submissions received, by transport and whether they were accepted",
            metrics.submissions.clone(),
        );
        registry.register(
            "refusals",
            "Submissions refused, by reason",
            metrics.refusals.clone(),
        );
        registry.register(
            "writes",
            "Sponsored writes sent, by kind (create or append) and outcome",
            metrics.writes.clone(),
        );
        registry.register(
            "fees_spent_units",
            "Units the payer spent on sponsored writes",
            metrics.fees.clone(),
        );
        registry.register(
            "write_landing_seconds",
            "Time from sending a sponsored write to finding it on chain",
            metrics.landing.clone(),
        );
        registry.register(
            "payer_balance_units",
            "The payer's balance, in units",
            metrics.balance.clone(),
        );
        registry.register(
            "queued_writes",
            "Approved writes waiting to be sent",
            metrics.queued.clone(),
        );
        registry.register(
            "writes_in_flight",
            "Sponsored writes sent and not yet landed",
            metrics.in_flight.clone(),
        );
        registry.register(
            "writes_last_hour",
            "Sponsored writes sent in the past hour",
            metrics.last_hour.clone(),
        );
        registry.register(
            "writes_last_day",
            "Sponsored writes sent in the past 24 hours",
            metrics.last_day.clone(),
        );
        registry.register(
            "p2p_connections",
            "Open libp2p connections",
            metrics.connections.clone(),
        );
        Self {
            registry,
            ..metrics
        }
    }

    pub fn accepted(&self, transport: &'static str) {
        self.submissions
            .get_or_create(&SubmissionLabels {
                transport,
                outcome: "accepted",
            })
            .inc();
    }

    pub fn refused(&self, transport: &'static str, reason: Reason) {
        self.submissions
            .get_or_create(&SubmissionLabels {
                transport,
                outcome: "refused",
            })
            .inc();
        self.refusals
            .get_or_create(&RefusalLabels {
                reason: reason.as_str(),
            })
            .inc();
    }

    /// Counts a write that ended, `seconds` after it was sent if it landed.
    pub fn written(&self, append: bool, landed: Option<f64>, cost: u128) {
        let outcome = if landed.is_some() {
            "published"
        } else {
            "failed"
        };
        let kind = if append { "append" } else { "create" };
        self.writes
            .get_or_create(&WriteLabels { kind, outcome })
            .inc();
        self.fees.inc_by(u64::try_from(cost).unwrap_or(u64::MAX));
        if let Some(seconds) = landed {
            self.landing.observe(seconds);
        }
    }

    pub fn set_balance(&self, units: u128) {
        self.balance.set(i64::try_from(units).unwrap_or(i64::MAX));
    }

    /// The metrics as OpenMetrics text.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut text = String::new();
        encode(&mut text, &self.registry).expect("writing to a String cannot fail");
        text
    }
}

/// Serves `GET /metrics` on `server` until it fails.
pub fn serve(server: &Server, metrics: &Metrics) {
    let content_type = Header::from_bytes(
        "content-type",
        "application/openmetrics-text; version=1.0.0; charset=utf-8",
    )
    .expect("a valid header");
    for request in server.incoming_requests() {
        let response = match (request.method(), request.url()) {
            (Method::Get, "/metrics") => {
                Response::from_string(metrics.encode()).with_header(content_type.clone())
            }
            _ => Response::from_string("not found").with_status_code(404),
        };
        let _gone = request.respond(response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_is_reported_under_the_relay_prefix() {
        let metrics = Metrics::new(vec![("version".into(), "0.3.0".into())]);
        metrics.accepted("p2p");
        metrics.refused("p2p", Reason::AccountLimit);
        metrics.written(true, Some(12.0), 26_000_000);
        metrics.set_balance(1_000);
        let text = metrics.encode();
        for line in [
            "account_relay_build_info{version=\"0.3.0\"} 1",
            "account_relay_submissions_total{transport=\"p2p\",outcome=\"accepted\"} 1",
            "account_relay_refusals_total{reason=\"account_limit\"} 1",
            "account_relay_writes_total{kind=\"append\",outcome=\"published\"} 1",
            "account_relay_fees_spent_units_total 26000000",
            "account_relay_payer_balance_units 1000",
            "account_relay_write_landing_seconds_count 1",
        ] {
            assert!(text.contains(line), "missing {line} in\n{text}");
        }
    }
}
