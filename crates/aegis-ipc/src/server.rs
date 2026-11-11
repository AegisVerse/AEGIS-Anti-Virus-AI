//! Windows Named Pipe IPC server.

use crate::dispatch::EngineContext;
use crate::framing::{read_frame, write_frame};
use aegis_common::protocol::{Hello, HelloAck, Request, Response, MAX_REQUEST_BYTES};
use std::sync::Arc;

pub struct IpcServer {
    pipe_name: String,
    context: Arc<EngineContext>,
}

impl IpcServer {
    pub fn new(pipe_name: String, context: Arc<EngineContext>) -> Self {
        Self { pipe_name, context }
    }

    /// Run the server loop accepting connections.
    pub async fn run(&self) -> aegis_common::Result<()> {
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ServerOptions;

            let mut server = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&self.pipe_name)
                .map_err(|e| aegis_common::AegisError::Io(e))?;

            tracing::info!("AEGIS IPC server listening on {}", self.pipe_name);

            loop {
                server.connect().await.map_err(|e| aegis_common::AegisError::Io(e))?;
                let connected_pipe = server;

                // Create next instance before handling current client
                server = ServerOptions::new()
                    .create(&self.pipe_name)
                    .map_err(|e| aegis_common::AegisError::Io(e))?;

                let ctx = self.context.clone();
                tokio::spawn(async move {
                    Self::handle_client(connected_pipe, ctx).await;
                });
            }
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    #[cfg(windows)]
    async fn handle_client(
        mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
        context: Arc<EngineContext>,
    ) {
        // 1. Read Hello
        let hello_bytes = match read_frame(&mut stream, MAX_REQUEST_BYTES).await {
            Ok(b) => b,
            Err(_) => return,
        };

        let hello: Hello = match serde_json::from_slice(&hello_bytes) {
            Ok(h) => h,
            Err(_) => return,
        };

        let ack = HelloAck {
            protocol_version: aegis_common::PROTOCOL_VERSION,
            service_version: aegis_common::VERSION.into(),
            service_mode: context.mode.clone(),
            privileged_allowed: context.elevated,
            client_identity: hello.client_name,
        };

        if let Ok(ack_bytes) = serde_json::to_vec(&ack) {
            let _ = write_frame(&mut stream, &ack_bytes).await;
        }

        // 2. Request / Response loop
        loop {
            let req_bytes = match read_frame(&mut stream, MAX_REQUEST_BYTES).await {
                Ok(b) => b,
                Err(_) => break,
            };

            let req: Request = match serde_json::from_slice(&req_bytes) {
                Ok(r) => r,
                Err(e) => {
                    let err_resp = Response::err(aegis_common::error::ErrorCode::Parse, e.to_string());
                    if let Ok(b) = serde_json::to_vec(&err_resp) {
                        let _ = write_frame(&mut stream, &b).await;
                    }
                    continue;
                }
            };

            let resp = context.handle_request(req);
            if let Ok(resp_bytes) = serde_json::to_vec(&resp) {
                if write_frame(&mut stream, &resp_bytes).await.is_err() {
                    break;
                }
            }
        }
    }
}

