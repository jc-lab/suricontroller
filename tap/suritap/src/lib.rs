//! suritap: low-latency transport between TLS-terminating proxies and the
//! Suricata `suritap` capture plugin.
//!
//! A proxy (client) opens one *session* per Suricata worker thread. A
//! session is a sealed memfd shared by both processes that holds two
//! single-producer/single-consumer rings:
//!
//! * c2s: OPEN/DATA/GAP/EOF/CLOSE/PING records from the proxy,
//! * s2c: VERDICT/BYPASS/PONG/FLOW_ERROR records from Suricata,
//!
//! plus two eventfds used only to wake a sleeping peer. The UNIX
//! `SOCK_SEQPACKET` socket carries the handshake (and the file descriptors)
//! and afterwards only signals liveness.
//!
//! The server side ([`server::Worker`] + [`engine::Engine`]) turns records
//! into synthetic IPv4/IPv6 TCP packets and hands them to an
//! [`engine::Inspector`] — Suricata in the plugin, a stub in tests.
//!
//! See `docs/suritap.md` for the protocol specification.

pub mod client;
pub mod engine;
pub mod pcap;
pub mod proto;
pub mod region;
pub mod ring;
pub mod server;
mod slab;
pub mod sys;

pub use client::{Client, ClientOptions, Conn, OpenParams};
pub use proto::{Action, Alert, Dir, MetaTag, Reason, Verdict};
