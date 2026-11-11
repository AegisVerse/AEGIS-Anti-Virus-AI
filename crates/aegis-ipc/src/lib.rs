//! Named pipe IPC communication between desktop client and security service.

pub mod client;
pub mod dispatch;
pub mod framing;
pub mod server;

pub use client::IpcClient;
pub use dispatch::EngineContext;
pub use server::IpcServer;

