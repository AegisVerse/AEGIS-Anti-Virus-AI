//! Tauri desktop bridge for AEGIS AI Security.

use aegis_common::paths::{SERVICE_PIPE, user_pipe_name};
use aegis_common::protocol::{Request, Response};
use aegis_ipc::IpcClient;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tauri::Manager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub mode: Option<String>,
    pub pipe: Option<String>,
    pub privileged_allowed: bool,
    pub service_version: Option<String>,
    pub error: Option<String>,
}

#[tauri::command]
async fn aegis_call(request: Request) -> Result<serde_json::Value, serde_json::Value> {
    match IpcClient::call(request).await {
        Ok(resp) => {
            if resp.ok {
                Ok(resp.data.unwrap_or(serde_json::Value::Null))
            } else {
                let err = resp.error.unwrap_or_else(|| aegis_common::protocol::IpcError {
                    code: aegis_common::error::ErrorCode::Internal,
                    message: "Unknown error".into(),
                });
                Err(serde_json::to_value(err).unwrap_or(serde_json::Value::Null))
            }
        }
        Err(e) => {
            let err = aegis_common::protocol::IpcError {
                code: e.code(),
                message: e.to_string(),
            };
            Err(serde_json::to_value(err).unwrap_or(serde_json::Value::Null))
        }
    }
}

#[tauri::command]
async fn aegis_connection() -> Result<ConnectionStatus, String> {
    match IpcClient::call(Request::Ping).await {
        Ok(resp) => {
            if resp.ok {
                Ok(ConnectionStatus {
                    connected: true,
                    mode: Some("service".into()),
                    pipe: Some(SERVICE_PIPE.into()),
                    privileged_allowed: true,
                    service_version: Some(aegis_common::VERSION.into()),
                    error: None,
                })
            } else {
                Ok(ConnectionStatus {
                    connected: false,
                    mode: None,
                    pipe: None,
                    privileged_allowed: false,
                    service_version: None,
                    error: Some("Service responded with error".into()),
                })
            }
        }
        Err(e) => Ok(ConnectionStatus {
            connected: false,
            mode: None,
            pipe: None,
            privileged_allowed: false,
            service_version: None,
            error: Some(e.to_string()),
        }),
    }
}

#[tauri::command]
async fn aegis_start_user_engine() -> Result<ConnectionStatus, String> {
    // Attempt to spawn aegis-service in user mode
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("aegis-service.exe")
            .arg("--run-user")
            .spawn();

        tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
    }

    aegis_connection().await
}

#[tauri::command]
fn aegis_open_path(path: String) -> Result<(), String> {
    let p = Path::new(&path);
    if p.exists() {
        #[cfg(windows)]
        {
            let target = if p.is_dir() { path } else { format!("/select,{}", path) };
            let _ = std::process::Command::new("explorer.exe")
                .arg(target)
                .spawn();
        }
        Ok(())
    } else {
        Err("Path does not exist".into())
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            aegis_call,
            aegis_connection,
            aegis_start_user_engine,
            aegis_open_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AEGIS AI Security desktop application");
}
