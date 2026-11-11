//! Windows Background Security Service binary for AEGIS AI Security.

use aegis_ai::{AiAnalyst, AiClassifier};
use aegis_audit::{StartupGuardian, SystemAuditor, UsbGuardian};
use aegis_behavior::{RansomwareShield, RatHunter};
use aegis_common::paths::{user_pipe_name, DataLayout, EngineMode, SERVICE_NAME, SERVICE_PIPE};
use aegis_common::types::NewEvent;
use aegis_heuristics::HashReputation;
use aegis_ipc::dispatch::EngineContext;
use aegis_ipc::IpcServer;
use aegis_monitor::{ProcessMonitor, RealTimeWatcher};
use aegis_network::DomainShield;
use aegis_quarantine::QuarantineVault;
use aegis_remediation::RemediationEngine;
use aegis_scanner::ScannerEngine;
use aegis_storage::Storage;
use aegis_updater::UpdateManager;
use aegis_yara::YaraEngine;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let is_help = args.iter().any(|a| a == "--help" || a == "-h");
    let is_version = args.iter().any(|a| a == "--version" || a == "-v");
    let is_user_mode = args.iter().any(|a| a == "--run-user");
    let is_install = args.iter().any(|a| a == "--install");
    let is_uninstall = args.iter().any(|a| a == "--uninstall");

    if is_help {
        println!("AEGIS AI Security Service v{}", env!("CARGO_PKG_VERSION"));
        println!("Usage: aegis-service.exe [OPTIONS]\n");
        println!("Options:");
        println!("  --run-user     Run in unprivileged user mode with per-user named pipe");
        println!("  --install      Install and register as a Windows background service");
        println!("  --uninstall    Uninstall and unregister Windows background service");
        println!("  -v, --version  Print version information");
        println!("  -h, --help     Print help information");
        return Ok(());
    }

    if is_version {
        println!("aegis-service {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if is_install {
        install_service()?;
        return Ok(());
    }

    if is_uninstall {
        uninstall_service()?;
        return Ok(());
    }

    let mode = if is_user_mode {
        EngineMode::User
    } else {
        EngineMode::Service
    };

    tracing::info!("Starting AEGIS AI Security engine in {:?} mode", mode);

    let layout = DataLayout::for_mode(mode);
    layout.create_all()?;

    let (storage, _rep) = Storage::open(&layout.db)?;
    let storage = Arc::new(storage);

    let yara = Arc::new(YaraEngine::new(Some(layout.rules.clone()))?);
    let hashes = Arc::new(HashReputation::new(Some(layout.rules.join("hashes.json")))?);
    let scanner = Arc::new(ScannerEngine::new(storage.clone(), yara.clone(), hashes.clone()));
    let vault = Arc::new(QuarantineVault::new(layout.quarantine.clone(), storage.clone())?);
    let ransomware = Arc::new(RansomwareShield::new(storage.clone()));
    let rat_hunter = Arc::new(RatHunter::new(storage.clone()));
    let proc_mon = Arc::new(ProcessMonitor::new(storage.clone(), rat_hunter.clone()));
    let domain_shield = Arc::new(DomainShield::new(storage.clone(), Some(layout.rules.clone())));
    let startup = Arc::new(StartupGuardian::new(storage.clone()));
    let ai_classifier = Arc::new(AiClassifier::new(Some(&layout.models)));
    let ai_analyst = Arc::new(AiAnalyst::new(storage.clone()));
    let remediation = Arc::new(RemediationEngine::new(storage.clone(), vault.clone()));
    let updater = Arc::new(UpdateManager::new(
        storage.clone(),
        yara.clone(),
        hashes.clone(),
        Some(layout.rules.clone()),
    ));

    // Start real-time filesystem watcher
    let mut rt_watcher = RealTimeWatcher::new(storage.clone(), yara.clone(), hashes.clone(), ransomware.clone());
    let _ = rt_watcher.start();
    let watcher_cell = Arc::new(parking_lot::RwLock::new(Some(rt_watcher)));

    let pipe_name = match mode {
        EngineMode::Service => SERVICE_PIPE.to_string(),
        EngineMode::User => user_pipe_name(),
    };

    let ctx = Arc::new(EngineContext {
        storage,
        yara,
        hashes,
        scanner,
        vault,
        ransomware,
        rat_hunter,
        watcher: watcher_cell,
        proc_mon,
        domain_shield,
        startup,
        ai_classifier,
        ai_analyst,
        remediation,
        updater,
        mode: mode.as_str().into(),
        elevated: mode == EngineMode::Service,
    });

    let server = IpcServer::new(pipe_name, ctx);
    server.run().await?;

    Ok(())
}

fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let current_exe = std::env::current_exe()?;
        let bin_path = format!("\"{}\"", current_exe.display());
        let output = std::process::Command::new("sc.exe")
            .args(["create", SERVICE_NAME, &format!("binPath={}", bin_path), "start=auto", "DisplayName=AEGIS AI Security Service"])
            .output()?;
        if !output.status.success() {
            eprintln!("Failed to create service: {}", String::from_utf8_lossy(&output.stderr));
        } else {
            println!("AEGIS AI Security Service registered successfully.");
        }
    }
    Ok(())
}

fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
        let output = std::process::Command::new("sc.exe").args(["delete", SERVICE_NAME]).output()?;
        if !output.status.success() {
            eprintln!("Failed to delete service: {}", String::from_utf8_lossy(&output.stderr));
        } else {
            println!("AEGIS AI Security Service uninstalled successfully.");
        }
    }
    Ok(())
}
