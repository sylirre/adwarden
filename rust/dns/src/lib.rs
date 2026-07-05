//! Minimal DNS wire handling for the sinkhole: parse a single-question query,
//! synthesize NXDOMAIN / `A 0.0.0.0` / `AAAA ::` answers.
//!
//! Phase 0 skeleton — parsing and synthesis land with P1-B.
