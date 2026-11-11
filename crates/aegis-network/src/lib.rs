//! Network sentinel: process-to-connection visibility and domain/IP reputation filtering.

pub mod connections;
pub mod domains;

pub use connections::NetworkSentinel;
pub use domains::DomainShield;

