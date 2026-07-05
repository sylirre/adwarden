//! adblock-rust engine wrapper.
//!
//! Compiles filter lists (ABP/uBO "standard" syntax and hosts files) plus
//! user-authored rules into an `Engine`, with a serialized on-disk cache for
//! fast startup. Only network-rule matching is used (cosmetic rules need a
//! browser DOM), which also keeps the engine's memory footprint down.

use adblock::lists::{FilterFormat, FilterSet, ParseOptions, RuleTypes};
use adblock::request::Request;
use adblock::Engine;

/// Source format of a list, matching the Kotlin `FilterFormat` entity enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    Adblock,
    Hosts,
}

impl ListFormat {
    fn parse_options(self) -> ParseOptions {
        ParseOptions {
            format: match self {
                ListFormat::Adblock => FilterFormat::Standard,
                ListFormat::Hosts => FilterFormat::Hosts,
            },
            // Network rules only — we never do cosmetic filtering.
            rule_types: RuleTypes::NetworkOnly,
            ..ParseOptions::default()
        }
    }
}

pub struct FilterEngine {
    engine: Engine,
}

impl FilterEngine {
    /// Build an engine from a set of `(format, list_text)` sources plus custom
    /// ABP rules (one per element).
    pub fn from_lists(lists: &[(ListFormat, &str)], custom_rules: &[String]) -> Self {
        let mut set = FilterSet::new(false);
        for (format, text) in lists {
            set.add_filter_list(text, format.parse_options());
        }
        if !custom_rules.is_empty() {
            let opts = ListFormat::Adblock.parse_options();
            set.add_filters(custom_rules.iter().map(|s| s.as_str()), opts);
        }
        FilterEngine { engine: Engine::from_filter_set(set, true) }
    }

    /// Restore an engine from its serialized cache.
    pub fn from_serialized(bytes: &[u8]) -> Option<Self> {
        let mut engine = Engine::default();
        engine.deserialize(bytes).ok()?;
        Some(FilterEngine { engine })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.engine.serialize()
    }

    /// DNS-level check: would a request to `domain` be blocked? Synthesizes a
    /// first-party `https://domain/` request; `||domain^` and hosts rules match
    /// regardless of resource type. Exceptions (`@@`) unset `matched`.
    pub fn is_blocked_domain(&self, domain: &str) -> bool {
        let url = format!("https://{}/", domain);
        match Request::new(&url, &url, "document") {
            Ok(req) => self.engine.check_network_request(&req).matched,
            Err(_) => false,
        }
    }

    /// URL-level check for a concrete request (used by later HTTP inspection).
    pub fn is_blocked_url(&self, url: &str, source_url: &str, request_type: &str) -> bool {
        match Request::new(url, source_url, request_type) {
            Ok(req) => self.engine.check_network_request(&req).matched,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_and_allows() {
        let lists = [(ListFormat::Adblock, "||ads.example.com^\n")];
        let engine = FilterEngine::from_lists(&lists, &[]);
        assert!(engine.is_blocked_domain("ads.example.com"));
        assert!(!engine.is_blocked_domain("example.com"));
        assert!(!engine.is_blocked_domain("safe.test"));
    }

    #[test]
    fn honors_exceptions() {
        let lists = [(ListFormat::Adblock, "||ads.example.com^\n@@||ads.example.com/allowed^\n")];
        let engine = FilterEngine::from_lists(&lists, &[]);
        assert!(engine.is_blocked_domain("ads.example.com"));
        assert!(!engine.is_blocked_url(
            "https://ads.example.com/allowed",
            "https://site.test/",
            "script",
        ));
    }

    #[test]
    fn ingests_hosts_format() {
        let hosts = "0.0.0.0 tracker.test\n127.0.0.1 analytics.test\n# comment\n";
        let engine = FilterEngine::from_lists(&[(ListFormat::Hosts, hosts)], &[]);
        assert!(engine.is_blocked_domain("tracker.test"));
        assert!(engine.is_blocked_domain("analytics.test"));
        assert!(!engine.is_blocked_domain("legit.test"));
    }

    #[test]
    fn custom_rules_apply() {
        let engine = FilterEngine::from_lists(&[], &["||custom.block^".to_string()]);
        assert!(engine.is_blocked_domain("custom.block"));
    }

    #[test]
    fn serialize_round_trip_preserves_verdicts() {
        let lists = [(ListFormat::Adblock, "||ads.example.com^\n")];
        let engine = FilterEngine::from_lists(&lists, &[]);
        let bytes = engine.serialize();
        let restored = FilterEngine::from_serialized(&bytes).expect("deserialize");
        assert!(restored.is_blocked_domain("ads.example.com"));
        assert!(!restored.is_blocked_domain("example.com"));
    }
}
