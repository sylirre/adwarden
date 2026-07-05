//! Userspace TCP/IP datapath support: packet decoding and the per-flow table.
//!
//! The smoltcp-backed TCP proxy and hand-rolled UDP NAT (the actual forwarding
//! stack) land with P1-A; this crate currently provides the pieces the JNI core
//! uses for monitor-mode capture and will grow the stack driver next.

pub mod flow_table;
pub mod packet;

pub use flow_table::{FlowKey, FlowTable};
pub use packet::{decode, Decoded, L4};
