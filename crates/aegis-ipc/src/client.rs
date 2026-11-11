//! Windows Named Pipe IPC client used by the Tauri desktop bridge.

use crate::framing::{read_frame, write_frame};
use aegis_common::error::{AegisError, Result};
use aegis_common::paths::{SERVICE_PIPE, user_pipe_name};
use aegis_common::protocol::{Hello, HelloAck, Request, Response, MAX_FRAME_BYTES, MAX_REQUEST_BYTES};

pub struct IpcClient;

impl IpcClient {
    /// Connect to the security service or user engine, send request, and receive response.
    pub async fn call(req: Request) -> Result<Response> {
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ClientOptions;

            // Try service pipe first, then user engine pipe
            let user_pipe = user_pipe_name();
            let mut stream = match ClientOptions::new().open(SERVICE_PIPE) {
                Ok(s) => s,
                Err(_) => match ClientOptions::new().open(&user_pipe) {
                    Ok(s) => s,
                    Err(e) => return Err(AegisError::Unavailable(format!("Could not connect to AEGIS service: {e}"))),
                },
            };

            // Handshake
            let hello = Hello {
                protocol_version: aegis_common::PROTOCOL_VERSION,
                client_name: "aegis-desktop".into(),
                client_version: aegis_common::VERSION.into(),
            };
            let hello_bytes = serde_json::to_vec(&hello)?;
            write_frame(&mut stream, &hello_bytes).await?;

            let ack_bytes = read_frame(&mut stream, MAX_REQUEST_BYTES).await?;
            let _ack: HelloAck = serde_json::from_slice(&ack_bytes)?;

            // Send request
            let req_bytes = serde_json::to_vec(&req)?;
            write_frame(&mut stream, &req_bytes).await?;

            // Read response
            let resp_bytes = read_frame(&mut stream, MAX_FRAME_BYTES).await?;
            let resp: Response = serde_json::from_slice(&resp_bytes)?;
            Ok(resp)
        }

        #[cfg(not(windows))]
        {
            Err(AegisError::Unavailable("Named pipe IPC is only available on Windows".into()))
        }
    }
}

