//! `butcherbird.leak.v1`: the event a case tool can ingest later.
//!
//! The shape is documented in `docs/leak-monitoring.md`. Add fields, do not
//! rename or remove them, without a new schema version.

use serde::Serialize;

use super::advice::{recommend, Action};
use super::store::digest;
use super::{Breach, HIBP_ATTRIBUTION};

/// Schema id carried on every event.
pub const LEAK_EVENT_SCHEMA: &str = "butcherbird.leak.v1";

/// Which list a watch entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchKind {
    /// A domain verified on the HIBP account.
    Domain,
    /// A named email address.
    Vip,
}

impl WatchKind {
    /// Stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Vip => "vip",
        }
    }
}

/// One watch entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WatchRef {
    /// Domain or VIP.
    pub kind: WatchKind,
    /// Normalised value.
    pub value: String,
}

impl WatchRef {
    pub(crate) fn new(kind: WatchKind, value: &str) -> Self {
        Self {
            kind,
            value: value.to_string(),
        }
    }

    pub(crate) fn key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.value)
    }
}

/// A recommended step with its id and a sentence for a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionRef {
    /// Stable id, for example `password_reset`.
    pub id: &'static str,
    /// What to do.
    pub summary: &'static str,
}

impl From<Action> for ActionRef {
    fn from(action: Action) -> Self {
        Self {
            id: action.id(),
            summary: action.summary(),
        }
    }
}

/// One identity found in one breach.
#[derive(Debug, Clone, Serialize)]
pub struct LeakEvent {
    /// Always [`LEAK_EVENT_SCHEMA`].
    pub schema: &'static str,
    /// Stable across runs for the same source, identity and breach. Use it to dedupe.
    pub event_id: String,
    /// Data source id, `hibp`.
    pub source: &'static str,
    /// Watch entry that matched.
    pub watch: WatchRef,
    /// Affected address.
    pub identity: String,
    /// Breach metadata. No breach content.
    pub breach: Breach,
    /// When this tool first reported the exposure, RFC 3339 UTC.
    pub first_seen: String,
    /// When this run saw it, RFC 3339 UTC.
    pub observed_at: String,
    /// True when no earlier run reported it.
    pub new: bool,
    /// Generic advice. Nothing has been changed in any tenant.
    pub recommended_actions: Vec<ActionRef>,
    /// Credit line for the source data.
    pub attribution: &'static str,
}

impl LeakEvent {
    pub(crate) fn new(
        source: &'static str,
        watch: WatchRef,
        identity: String,
        breach: Breach,
        first_seen: i64,
        observed_at: i64,
        new: bool,
    ) -> Self {
        let event_id = digest(&format!("{source}\n{identity}\n{}", breach.name))[..32].to_string();
        let recommended_actions = recommend(&breach)
            .into_iter()
            .map(ActionRef::from)
            .collect();
        Self {
            schema: LEAK_EVENT_SCHEMA,
            event_id,
            source,
            watch,
            identity,
            breach,
            first_seen: rfc3339(first_seen),
            observed_at: rfc3339(observed_at),
            new,
            recommended_actions,
            attribution: HIBP_ATTRIBUTION,
        }
    }
}

/// RFC 3339 UTC to the second, for example `2026-11-18T11:06:40Z`.
pub(crate) fn rfc3339(secs: i64) -> String {
    let ts = jiff::Timestamp::from_second(secs).unwrap_or(jiff::Timestamp::UNIX_EPOCH);
    format!("{ts:.0}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_is_whole_seconds_utc() {
        assert_eq!(rfc3339(1_795_000_000), "2026-11-18T11:06:40Z");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn event_fields_match_the_documented_shape() {
        let event = LeakEvent::new(
            "hibp",
            WatchRef::new(WatchKind::Domain, "example.com"),
            "alex@example.com".into(),
            Breach {
                data_classes: vec!["Passwords".into()],
                ..Breach::named("Quokka")
            },
            1_795_000_000,
            1_795_000_100,
            true,
        );
        let value = serde_json::to_value(&event).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "attribution",
                "breach",
                "event_id",
                "first_seen",
                "identity",
                "new",
                "observed_at",
                "recommended_actions",
                "schema",
                "source",
                "watch"
            ]
        );
        let mut breach_keys: Vec<&str> = value["breach"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        breach_keys.sort_unstable();
        assert_eq!(
            breach_keys,
            [
                "added_date",
                "breach_date",
                "data_classes",
                "domain",
                "is_fabricated",
                "is_sensitive",
                "is_spam_list",
                "is_stealer_log",
                "is_verified",
                "name",
                "title"
            ]
        );
        assert_eq!(value["schema"], "butcherbird.leak.v1");
        assert_eq!(value["watch"]["kind"], "domain");
        assert_eq!(value["first_seen"], "2026-11-18T11:06:40Z");
        assert_eq!(value["recommended_actions"][0]["id"], "password_reset");
        // Same id as the example in docs/leak-monitoring.md.
        assert_eq!(value["event_id"], "c243f4fdfb81e66b26d3a2a7ebf2cef8");

        let again = LeakEvent::new(
            "hibp",
            WatchRef::new(WatchKind::Domain, "example.com"),
            "alex@example.com".into(),
            Breach::named("Quokka"),
            0,
            0,
            false,
        );
        assert_eq!(again.event_id, event.event_id);
    }
}
