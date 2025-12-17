//! Windows Service support for Ruhop VPN
//!
//! This module provides the ability to install, uninstall, start, and stop
//! Ruhop as a Windows service.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use ruhop_engine::{Config, VpnEngine, VpnRole};

/// Service name used for Windows Service Control Manager
pub const SERVICE_NAME: &str = "ruhop";

/// Display name shown in Windows Services
const SERVICE_DISPLAY_NAME: &str = "Ruhop VPN";

/// Service description
const SERVICE_DESCRIPTION: &str = "Ruhop VPN - A Rust implementation of GoHop protocol with port hopping capabilities";

/// Service type - we run as our own process
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Registry key for storing service configuration
const SERVICE_REGISTRY_KEY: &str = r"SYSTEM\CurrentControlSet\Services\ruhop\Parameters";

/// Standard config directory for the service
const SERVICE_CONFIG_DIR: &str = r"C:\ProgramData\Ruhop";
/// Standard config file path for the service
const SERVICE_CONFIG_PATH: &str = r"C:\ProgramData\Ruhop\ruhop.toml";

/// Install the service
pub fn install_service(config_path: &PathBuf, role: &str) -> Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access).context("Failed to connect to service manager")?;

    // Get the path to our executable
    let service_binary_path = std::env::current_exe().context("Failed to get current executable path")?;

    // Copy config file to standard location
    let dest_config_path = copy_config_to_programdata(config_path)?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec![
            OsString::from("service-run"),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = service_manager
        .create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("Failed to create service")?;

    // Set service description
    service
        .set_description(SERVICE_DESCRIPTION)
        .context("Failed to set service description")?;

    // Store role in registry (config path is now fixed)
    save_service_config(&dest_config_path, role)?;

    println!("Service '{}' installed successfully.", SERVICE_NAME);
    println!("Configuration copied to: {}", dest_config_path);
    println!("Role: {}", role);
    println!();
    println!("To start the service, run: ruhop service start");
    println!("Or use: sc start {}", SERVICE_NAME);

    Ok(())
}

/// Copy config file to C:\ProgramData\Ruhop\ruhop.toml
fn copy_config_to_programdata(source_path: &PathBuf) -> Result<String> {
    use std::fs;

    // Create the directory if it doesn't exist
    let config_dir = std::path::Path::new(SERVICE_CONFIG_DIR);
    fs::create_dir_all(config_dir)
        .with_context(|| format!("Failed to create directory: {}", SERVICE_CONFIG_DIR))?;

    // Read the source config
    let config_content = fs::read_to_string(source_path)
        .with_context(|| format!("Failed to read config file: {:?}", source_path))?;

    // Write to the standard location
    let dest_path = std::path::Path::new(SERVICE_CONFIG_PATH);
    fs::write(dest_path, &config_content)
        .with_context(|| format!("Failed to write config to: {}", SERVICE_CONFIG_PATH))?;

    println!("Copied configuration from {:?} to {}", source_path, SERVICE_CONFIG_PATH);

    Ok(SERVICE_CONFIG_PATH.to_string())
}

/// Save service configuration to registry
fn save_service_config(config_path: &str, role: &str) -> Result<()> {
    use std::process::Command;

    // Create the Parameters subkey and set values using reg.exe
    // This is more reliable than using winreg crate

    // Set ConfigPath
    let output = Command::new("reg")
        .args([
            "add",
            SERVICE_REGISTRY_KEY,
            "/v", "ConfigPath",
            "/t", "REG_SZ",
            "/d", config_path,
            "/f",
        ])
        .output()
        .context("Failed to run reg command")?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to save ConfigPath to registry: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Set Role
    let output = Command::new("reg")
        .args([
            "add",
            SERVICE_REGISTRY_KEY,
            "/v", "Role",
            "/t", "REG_SZ",
            "/d", role,
            "/f",
        ])
        .output()
        .context("Failed to run reg command")?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to save Role to registry: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Load service configuration from registry
fn load_service_config() -> Result<(PathBuf, String)> {
    use std::process::Command;

    // Query ConfigPath
    let output = Command::new("reg")
        .args([
            "query",
            SERVICE_REGISTRY_KEY,
            "/v", "ConfigPath",
        ])
        .output()
        .context("Failed to query registry")?;

    let config_path = if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_reg_value(&stdout, "ConfigPath")
            .unwrap_or_else(|| r"C:\ProgramData\Ruhop\ruhop.toml".to_string())
    } else {
        r"C:\ProgramData\Ruhop\ruhop.toml".to_string()
    };

    // Query Role
    let output = Command::new("reg")
        .args([
            "query",
            SERVICE_REGISTRY_KEY,
            "/v", "Role",
        ])
        .output()
        .context("Failed to query registry")?;

    let role = if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_reg_value(&stdout, "Role")
            .unwrap_or_else(|| "client".to_string())
    } else {
        "client".to_string()
    };

    Ok((PathBuf::from(config_path), role))
}

/// Parse a value from reg query output
fn parse_reg_value(output: &str, value_name: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if line.contains(value_name) && line.contains("REG_SZ") {
            // Format: "    ValueName    REG_SZ    Value"
            let parts: Vec<&str> = line.split("REG_SZ").collect();
            if parts.len() >= 2 {
                return Some(parts[1].trim().to_string());
            }
        }
    }
    None
}

/// Uninstall the service
pub fn uninstall_service() -> Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access).context("Failed to connect to service manager")?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager
        .open_service(SERVICE_NAME, service_access)
        .context("Failed to open service. Is it installed?")?;

    // Stop the service if running
    let status = service.query_status().context("Failed to query service status")?;
    if status.current_state != ServiceState::Stopped {
        println!("Stopping service...");
        service.stop().context("Failed to stop service")?;

        // Wait for service to stop
        let mut attempts = 0;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let status = service.query_status()?;
            if status.current_state == ServiceState::Stopped {
                break;
            }
            attempts += 1;
            if attempts > 20 {
                anyhow::bail!("Timeout waiting for service to stop");
            }
        }
    }

    service.delete().context("Failed to delete service")?;

    println!("Service '{}' uninstalled successfully.", SERVICE_NAME);

    Ok(())
}

/// Start the service
pub fn start_service() -> Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access).context("Failed to connect to service manager")?;

    let service = service_manager
        .open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .context("Failed to open service. Is it installed?")?;

    let status = service.query_status().context("Failed to query service status")?;
    if status.current_state == ServiceState::Running {
        println!("Service is already running.");
        return Ok(());
    }

    service
        .start::<String>(&[])
        .context("Failed to start service")?;

    println!("Service '{}' started.", SERVICE_NAME);

    Ok(())
}

/// Stop the service
pub fn stop_service() -> Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access).context("Failed to connect to service manager")?;

    let service = service_manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)
        .context("Failed to open service. Is it installed?")?;

    let status = service.query_status().context("Failed to query service status")?;
    if status.current_state == ServiceState::Stopped {
        println!("Service is already stopped.");
        return Ok(());
    }

    service.stop().context("Failed to stop service")?;

    println!("Service '{}' stop requested.", SERVICE_NAME);

    Ok(())
}

/// Query service status
pub fn query_service_status() -> Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access).context("Failed to connect to service manager")?;

    let service = service_manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG)
        .context("Failed to open service. Is it installed?")?;

    let status = service.query_status().context("Failed to query service status")?;

    let state_str = match status.current_state {
        ServiceState::Stopped => "Stopped",
        ServiceState::StartPending => "Starting",
        ServiceState::StopPending => "Stopping",
        ServiceState::Running => "Running",
        ServiceState::ContinuePending => "Resuming",
        ServiceState::PausePending => "Pausing",
        ServiceState::Paused => "Paused",
    };

    println!("Service: {}", SERVICE_NAME);
    println!("State:   {}", state_str);

    Ok(())
}

// Define the Windows service entry point
define_windows_service!(ffi_service_main, service_main);

/// Entry point when running as a Windows service
pub fn run_as_service() -> Result<()> {
    // This function is called by the service dispatcher
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("Failed to start service dispatcher")
}

/// Service main function called by Windows SCM
fn service_main(arguments: Vec<OsString>) {
    // Initialize logging for the service - write to Windows Event Log or file
    init_service_logging();

    if let Err(e) = run_service(arguments) {
        error!("Service error: {:?}", e);
    }
}

/// Initialize logging for the service - writes to a log file
fn init_service_logging() {
    use std::fs::OpenOptions;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    // Create log directory
    let log_dir = std::path::PathBuf::from(r"C:\ProgramData\Ruhop");
    let _ = std::fs::create_dir_all(&log_dir);

    // Open log file
    let log_path = log_dir.join("ruhop-service.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path);

    match log_file {
        Ok(file) => {
            // Use file-based logging
            let _ = tracing_subscriber::registry()
                .with(EnvFilter::new("debug"))
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::sync::Mutex::new(file))
                        .with_ansi(false)
                )
                .try_init();
        }
        Err(_) => {
            // Fallback to default (won't be visible but won't crash)
            let _ = tracing_subscriber::registry()
                .with(EnvFilter::new("info"))
                .with(tracing_subscriber::fmt::layer())
                .try_init();
        }
    }
}

/// Actual service implementation
fn run_service(_arguments: Vec<OsString>) -> Result<()> {
    // Create a channel to receive stop events
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    // Register service control handler FIRST - this must happen quickly
    let shutdown_tx_clone = shutdown_tx.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx_clone.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("Failed to register service control handler")?;

    // Report service as starting immediately
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })
        .context("Failed to set service status")?;

    info!("Service starting, loading configuration from registry...");

    // Now load config from registry (after we've registered with SCM)
    let (config_path, role) = match load_service_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load service config from registry: {:?}", e);
            // Report failure and exit
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            return Err(e);
        }
    };

    info!("Config path: {:?}, Role: {}", config_path, role);

    // Update checkpoint to show progress
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 2,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })
        .ok();

    // Load configuration file
    let config = match Config::load(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load config file {:?}: {:?}", config_path, e);
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            anyhow::bail!("Failed to load configuration: {}", e);
        }
    };

    // Determine role
    let vpn_role = match role.as_str() {
        "server" => VpnRole::Server,
        _ => VpnRole::Client,
    };

    // Update checkpoint
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 3,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })
        .ok();

    // Create VPN engine
    let mut engine = match VpnEngine::new(config, vpn_role) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create VPN engine: {:?}", e);
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            anyhow::bail!("Failed to create VPN engine: {}", e);
        }
    };
    let engine_shutdown_tx = engine.create_shutdown_handle();

    // Create tokio runtime for async operations
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create tokio runtime: {:?}", e);
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            anyhow::bail!("Failed to create tokio runtime: {}", e);
        }
    };

    // Start the VPN engine in a background task
    let engine_handle = runtime.spawn(async move {
        if let Err(e) = engine.start().await {
            error!("VPN engine error: {}", e);
        }
    });

    // Report service as running
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .context("Failed to set service status")?;

    info!("Ruhop VPN service started as {}", role);

    // Wait for stop signal
    let _ = shutdown_rx.recv();

    info!("Ruhop VPN service stopping...");

    // Report service as stopping
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
        .ok();

    // Signal VPN engine to stop
    let _ = engine_shutdown_tx.send(());

    // Wait for engine to finish with timeout
    runtime.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(5), engine_handle).await;
    });

    // Report service as stopped
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .ok();

    info!("Ruhop VPN service stopped");

    Ok(())
}
