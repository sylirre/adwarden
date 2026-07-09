// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! adblock-rust engine wrapper.
//!
//! Compiles filter lists (ABP/uBO "standard" syntax and hosts files) plus
//! user-authored rules into an `Engine`, with a serialized on-disk cache for
//! fast startup.
//!
//! Both network **and** cosmetic rules are retained (P4). Network matching drives
//! the DNS sinkhole / URL firewall; the cosmetic side feeds the HTTP rewriter,
//! which injects hostname-specific element-hiding CSS ([`FilterEngine::cosmetic_css`])
//! and scriptlet JS ([`FilterEngine::scriptlets_js`]) into `text/html` on
//! inspected flows. Generic hiding that needs the live DOM (simple `##.class`
//! rules) isn't available to a proxy and is left out; `url_cosmetic_resources`
//! still yields hostname-specific and complex-generic selectors, which is what we
//! inject.

use adblock::lists::{FilterFormat, FilterSet, ParseOptions, RuleTypes};
use adblock::request::Request;
use adblock::resources::Resource;
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
            // Retain both network and cosmetic rules (P4): network matching still
            // drives the sinkhole/firewall, and the cosmetic rules feed the HTTP
            // rewriter's element-hiding + scriptlet injection.
            rule_types: RuleTypes::All,
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

    /// Restore an engine from its serialized cache (no scriptlet resources).
    pub fn from_serialized(bytes: &[u8]) -> Option<Self> {
        Self::from_serialized_with_resources(bytes, None)
    }

    /// Restore an engine from its cache and, optionally, load a scriptlet resource
    /// pack so `injected_script` is populated (P4-3).
    ///
    /// The serialized cache carries the cosmetic *rules* (selectors and `##+js()`
    /// scriptlet references round-trip through the flatbuffer), but **not** the
    /// scriptlet JS *implementations* — `Engine::deserialize` leaves the resource
    /// store empty. So the datapath re-applies the runtime-downloaded pack here on
    /// every reload. `resources_json` is a JSON array of `adblock::resources::Resource`
    /// (base64 `content`); a parse failure is logged and treated as "no scriptlets".
    pub fn from_serialized_with_resources(bytes: &[u8], resources_json: Option<&str>) -> Option<Self> {
        let mut engine = Engine::default();
        engine.deserialize(bytes).ok()?;
        if let Some(json) = resources_json {
            match serde_json::from_str::<Vec<Resource>>(json) {
                Ok(resources) => engine.use_resources(resources),
                Err(e) => log::warn!("scriptlet resource pack parse failed: {e}"),
            }
        }
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

    /// Element-hiding CSS for `host`: the hostname-specific (and complex-generic)
    /// hide selectors folded into a single `sel,sel{display:none!important}` rule,
    /// ready to drop inside a `<style>` (P4-2). Empty when nothing matches.
    ///
    /// `#@#` unhide exceptions and `$generichide`/`$elemhide` are already honored by
    /// `url_cosmetic_resources`. Simple `##.class`/`###id` generics need the live
    /// DOM and are intentionally excluded — a proxy can't resolve them.
    pub fn cosmetic_css(&self, host: &str) -> String {
        let url = format!("https://{host}/");
        let res = self.engine.url_cosmetic_resources(&url);
        if res.hide_selectors.is_empty() {
            return String::new();
        }
        // Sort for deterministic output — `hide_selectors` is a HashSet.
        let mut selectors: Vec<&str> = res.hide_selectors.iter().map(String::as_str).collect();
        selectors.sort_unstable();
        format!("{}{{display:none!important;}}", selectors.join(","))
    }

    /// Scriptlet JS for `host`: the `injected_script` assembled from matching
    /// `##+js(...)` rules and the loaded resource pack (P4-3). Empty unless a pack
    /// was supplied to [`Self::from_serialized_with_resources`] and a rule matches.
    pub fn scriptlets_js(&self, host: &str) -> String {
        let url = format!("https://{host}/");
        self.engine.url_cosmetic_resources(&url).injected_script
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

    // --- cosmetic (P4) ---------------------------------------------------

    #[test]
    fn cosmetic_css_hides_hostname_specific_selectors() {
        let lists = [(ListFormat::Adblock, "example.com##.ad-banner\nexample.com##.sponsored\n")];
        let engine = FilterEngine::from_lists(&lists, &[]);
        let css = engine.cosmetic_css("example.com");
        assert!(css.contains(".ad-banner"), "got {css}");
        assert!(css.contains(".sponsored"), "got {css}");
        assert!(css.ends_with("{display:none!important;}"), "got {css}");
        // A host with no rules gets nothing.
        assert!(engine.cosmetic_css("other.test").is_empty());
    }

    #[test]
    fn cosmetic_css_round_trips_through_cache() {
        let lists = [(ListFormat::Adblock, "example.com##.ad-banner\n")];
        let bytes = FilterEngine::from_lists(&lists, &[]).serialize();
        let restored = FilterEngine::from_serialized(&bytes).expect("deserialize");
        assert!(restored.cosmetic_css("example.com").contains(".ad-banner"));
    }

    #[test]
    fn cosmetic_css_honors_unhide_exceptions() {
        // `#@#` removes a selector that another rule would hide on this host.
        let lists = [(ListFormat::Adblock, "example.com##.ad-banner\nexample.com#@#.ad-banner\n")];
        let engine = FilterEngine::from_lists(&lists, &[]);
        assert!(engine.cosmetic_css("example.com").is_empty());
    }

    #[test]
    fn cosmetic_css_excludes_simple_generic_class_rules() {
        // A DOM-only generic (`##.foo`) can't be resolved by a proxy, so it must
        // not leak into the hostname payload.
        let lists = [(ListFormat::Adblock, "##.generic-ad\n")];
        let engine = FilterEngine::from_lists(&lists, &[]);
        assert!(engine.cosmetic_css("example.com").is_empty());
    }

    #[test]
    fn scriptlets_js_is_empty_without_a_resource_pack() {
        let lists = [(ListFormat::Adblock, "example.com##+js(noop)\n")];
        let engine = FilterEngine::from_lists(&lists, &[]);
        assert!(engine.scriptlets_js("example.com").is_empty());
    }

    #[test]
    fn scriptlets_js_populated_after_loading_resources() {
        // A `##+js(noop)` rule references a scriptlet named `noop`; the pack
        // supplies its JS implementation (base64 of `window.ADW_SCRIPTLET_MARKER=1;`).
        let lists = [(ListFormat::Adblock, "example.com##+js(noop)\n")];
        let bytes = FilterEngine::from_lists(&lists, &[]).serialize();
        let pack = r#"[{"name":"noop.js","aliases":["noop"],"kind":{"mime":"application/javascript"},"content":"d2luZG93LkFEV19TQ1JJUFRMRVRfTUFSS0VSPTE7"}]"#;
        let engine = FilterEngine::from_serialized_with_resources(&bytes, Some(pack)).expect("deserialize");
        let js = engine.scriptlets_js("example.com");
        assert!(js.contains("ADW_SCRIPTLET_MARKER"), "expected scriptlet body, got {js:?}");
        // A non-matching host stays clean.
        assert!(engine.scriptlets_js("other.test").is_empty());
    }

    #[test]
    fn from_serialized_with_bad_resource_pack_is_lenient() {
        let bytes = FilterEngine::from_lists(&[], &[]).serialize();
        // Malformed JSON => treated as "no scriptlets", engine still loads.
        let engine = FilterEngine::from_serialized_with_resources(&bytes, Some("not json"));
        assert!(engine.is_some());
    }
}
