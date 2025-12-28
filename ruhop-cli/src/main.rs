//! Ruhop VPN CLI
//!
//! A command-line interface for the Ruhop VPN.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use ruhop_engine::{Config, ControlClient, ServerAddress, VpnEngine, VpnRole, DEFAULT_SOCKET_PATH};

#[cfg(windows)]
mod service;

mod share;

/// Ruhop VPN - A Rust implementation of GoHop protocol
#[derive(Parser)]
#[command(name = "ruhop")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, global = true, default_value = "ruhop.toml")]
    config: PathBuf,

    /// Log level (error, warn, info, debug, trace)
    #[arg(short, long, global = true, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as VPN server
    Server,

    /// Run as VPN client
    Client,

    /// Show status of a running VPN instance
    Status {
        /// Path to the control socket
        #[arg(short, long, default_value = DEFAULT_SOCKET_PATH)]
        socket: String,
        /// Output in JSON format
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Generate a sample configuration file
    GenConfig {
        /// Output path for the configuration file
        #[arg(short, long, default_value = "ruhop.toml")]
        output: PathBuf,
    },

    /// Encode configuration as a shareable ruhop:// URL
    Encode,

    /// Decode a ruhop:// URL back to configuration
    Decode {
        /// The ruhop:// URL to decode
        url: String,
    },

    /// Generate a QR code from configuration (displays in terminal)
    Qr,

    /// Windows service management (Windows only)
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Internal: Run as Windows service (called by SCM)
    #[cfg(windows)]
    #[command(hide = true)]
    ServiceRun {
        /// Path to configuration file
        #[arg(long)]
        config: PathBuf,

        /// Role (client or server)
        #[arg(long, default_value = "client")]
        role: String,
    },
}

/// Windows service actions
#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceAction {
    /// Install the service
    Install {
        /// Role to run as (client or server)
        #[arg(short, long, default_value = "client")]
        role: String,
    },

    /// Uninstall the service
    Uninstall,

    /// Start the service
    Start,

    /// Stop the service
    Stop,

    /// Query service status
    Status,
}

fn main() -> Result<()> {
    // On Windows, check if we're being launched as a service BEFORE parsing args
    // The SCM launches us with "service-run" as the first argument
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() > 1 && args[1] == "service-run" {
            // Running as a Windows service - call the service dispatcher directly
            // This must happen before any async runtime is created
            return service::run_as_service();
        }
    }

    // Now we can create the tokio runtime and parse CLI args normally
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime")
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    // For Server and Client commands, load config first to get log file settings
    // These settings are only used when log_file is configured
    let (log_file, log_rotation) = if matches!(cli.command, Commands::Server | Commands::Client) {
        // Try to load config for log file settings (don't fail if config is invalid yet)
        Config::load(&cli.config)
            .ok()
            .map(|c| (c.common.log_file, c.common.log_rotation))
            .unwrap_or((None, "daily".to_string()))
    } else {
        (None, "daily".to_string())
    };

    // Initialize logging - outputs to stdout by default, or to file if log_file is configured
    // The guard must be kept alive to ensure logs are flushed on exit
    let _log_guard = init_logging(&cli.log_level, log_file.as_deref(), &log_rotation);

    // Check for admin privileges on Windows for commands that need it
    #[cfg(windows)]
    {
        let needs_admin = matches!(
            cli.command,
            Commands::Server | Commands::Client | Commands::Service { .. }
        );

        if needs_admin {
            check_windows_admin()?;
        }
    }

    match cli.command {
        Commands::Server => run_server(cli.config).await,
        Commands::Client => run_client(cli.config).await,
        Commands::Status { socket, json } => show_status(socket, json).await,
        Commands::GenConfig { output } => generate_config(output),
        Commands::Encode => encode_config(cli.config),
        Commands::Decode { url } => decode_url(&url),
        Commands::Qr => generate_qr(cli.config),
        #[cfg(windows)]
        Commands::Service { action } => handle_service_action(action, &cli.config),
        #[cfg(windows)]
        Commands::ServiceRun { .. } => {
            // This is handled in main() before tokio runtime is created
            // If we somehow get here, it means something is wrong
            anyhow::bail!("ServiceRun should be handled before async runtime creation");
        }
    }
}

/// Check for Windows administrator privileges and prompt for elevation if needed
#[cfg(windows)]
fn check_windows_admin() -> Result<()> {
    use hop_tun::windows::{is_admin, request_elevation};

    if is_admin() {
        return Ok(());
    }

    eprintln!("This operation requires administrator privileges.");
    eprintln!();
    eprintln!("Would you like to restart with elevated permissions? [Y/n] ");

    // Read user input
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if input.is_empty() || input == "y" || input == "yes" {
        match request_elevation() {
            Ok(true) => {
                // Elevation was requested, new process will start
                eprintln!("Restarting with administrator privileges...");
                std::process::exit(0);
            }
            Ok(false) => {
                // Already elevated (shouldn't happen since we checked above)
                Ok(())
            }
            Err(e) => {
                anyhow::bail!("Failed to elevate privileges: {}", e);
            }
        }
    } else {
        anyhow::bail!("Administrator privileges are required to run the VPN.");
    }
}

#[cfg(windows)]
fn handle_service_action(action: ServiceAction, config_path: &PathBuf) -> Result<()> {
    match action {
        ServiceAction::Install { role } => service::install_service(config_path, &role),
        ServiceAction::Uninstall => service::uninstall_service(),
        ServiceAction::Start => service::start_service(),
        ServiceAction::Stop => service::stop_service(),
        ServiceAction::Status => service::query_service_status(),
    }
}

/// Initialize logging
///
/// By default, logs are written to stdout only.
/// When `log_dir` is set, logs are written to both stdout and files in the specified
/// directory with time-based rolling. File writes are non-blocking to avoid impacting performance.
///
/// Returns an optional guard that must be kept alive for the duration of the program
/// to ensure all logs are flushed before exit.
fn init_logging(
    level: &str,
    log_dir: Option<&str>,
    log_rotation: &str,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_appender::rolling;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    // Only configure file logging if log_dir is specified
    if let Some(dir) = log_dir {
        // Parse rotation period
        let rotation = match log_rotation.to_lowercase().as_str() {
            "hourly" => rolling::Rotation::HOURLY,
            "daily" => rolling::Rotation::DAILY,
            "never" => rolling::Rotation::NEVER,
            _ => {
                eprintln!(
                    "Warning: Invalid log_rotation '{}', using 'daily'",
                    log_rotation
                );
                rolling::Rotation::DAILY
            }
        };

        // Create rolling file appender
        let file_appender = rolling::RollingFileAppender::new(rotation, dir, "ruhop.log");

        // Wrap in non-blocking layer for async writes
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        // Log to both console and file (file writes are non-blocking)
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(non_blocking),
            )
            .init();
        return Some(guard);
    }

    // Default: console-only logging (stdout)
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
    None
}

async fn run_server(config_path: PathBuf) -> Result<()> {
    info!("Starting Ruhop VPN server...");

    let config = load_config(&config_path)?;
    let mut engine =
        VpnEngine::new(config, VpnRole::Server).context("Failed to create VPN engine")?;

    info!("Configuration loaded from {:?}", config_path);

    // Create shutdown handle before moving engine into task
    let shutdown_tx = engine.create_shutdown_handle();

    // Start the engine
    let engine_handle = tokio::spawn(async move {
        if let Err(e) = engine.start().await {
            error!("VPN engine error: {}", e);
        }
    });

    // Wait for shutdown signal
    wait_for_shutdown().await;

    info!("Shutting down server...");

    // Signal graceful shutdown
    let _ = shutdown_tx.send(());

    // Wait for the engine to finish (with timeout)
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), engine_handle).await;

    Ok(())
}

async fn run_client(config_path: PathBuf) -> Result<()> {
    info!("Starting Ruhop VPN client...");

    let config = load_config(&config_path)?;
    let mut engine =
        VpnEngine::new(config, VpnRole::Client).context("Failed to create VPN engine")?;

    info!("Configuration loaded from {:?}", config_path);

    // Create shutdown handle before moving engine into task
    let shutdown_tx = engine.create_shutdown_handle();

    // Start the engine in a task
    let engine_handle = tokio::spawn(async move {
        if let Err(e) = engine.start().await {
            error!("VPN engine error: {}", e);
        }
    });

    // Wait for shutdown signal
    wait_for_shutdown().await;

    info!("Shutting down client...");

    // Signal graceful shutdown
    let _ = shutdown_tx.send(());

    // Wait for the engine to finish (with timeout)
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), engine_handle).await;

    Ok(())
}

fn load_config(path: &PathBuf) -> Result<Config> {
    Config::load(path).with_context(|| format!("Failed to load configuration from {:?}", path))
}

async fn show_status(socket_path: String, json: bool) -> Result<()> {
    let client = ControlClient::new(&socket_path);

    match client.status().await {
        Ok(status) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
                return Ok(());
            }

            println!("Ruhop VPN Status");
            println!("================");
            println!("Role:            {}", status.role);
            println!("State:           {}", status.state);
            println!("Uptime:          {}", format_duration(status.uptime_secs));

            if let Some(ref ip) = status.tunnel_ip {
                println!("Tunnel IP:       {}", ip);
            }
            if let Some(ref ip) = status.peer_ip {
                println!("Peer IP:         {}", ip);
            }
            if let Some(ref name) = status.tun_name {
                println!("TUN Device:      {}", name);
            }

            println!();
            println!("Traffic Statistics");
            println!("------------------");
            println!(
                "Bytes RX:        {} ({})",
                status.bytes_rx,
                format_bytes(status.bytes_rx)
            );
            println!(
                "Bytes TX:        {} ({})",
                status.bytes_tx,
                format_bytes(status.bytes_tx)
            );
            println!("Packets RX:      {}", status.packets_rx);
            println!("Packets TX:      {}", status.packets_tx);

            if status.role == "server" {
                println!();
                println!("Server Info");
                println!("-----------");
                println!("Active Sessions: {}", status.active_sessions);
            }

            if status.role == "client" && !status.blacklisted_endpoints.is_empty() {
                println!();
                println!("Blacklisted Endpoints");
                println!("---------------------");
                for ep in &status.blacklisted_endpoints {
                    println!("  {} (loss: {:.0}%)", ep.addr, ep.loss_rate * 100.0);
                }
            }

            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to get status: {}", e);
            eprintln!("\nMake sure the VPN is running and the socket path is correct.");
            eprintln!("Socket path: {}", socket_path);
            std::process::exit(1);
        }
    }
}

fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn generate_config(output: PathBuf) -> Result<()> {
    let sample = Config::sample();

    std::fs::write(&output, sample)
        .with_context(|| format!("Failed to write configuration to {:?}", output))?;

    info!("Generated sample configuration at {:?}", output);
    println!("Sample configuration written to {:?}", output);
    println!("\nEdit the configuration file and set your pre-shared key before running.");

    Ok(())
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("Failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT");
            }
        }
    }

    #[cfg(windows)]
    {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received Ctrl+C");
    }
}

/// Encode configuration as a shareable ruhop:// URL
fn encode_config(config_path: PathBuf) -> Result<()> {
    let config = load_config(&config_path)?;

    // Extract client configuration
    let client = config
        .client_config()
        .context("encode requires a client configuration section")?;

    // Build ShareConfig from the loaded config
    let server = match &client.server {
        ServerAddress::Single(s) => share::ServerAddr::Single(s.clone()),
        ServerAddress::Multiple(v) => share::ServerAddr::Multiple(v.clone()),
    };

    let share_config = share::ShareConfig {
        key: config.common.key.clone(),
        obfuscation: config.common.obfuscation,
        server,
        port_range: client.port_range,
    };

    let url = share_config.to_url()?;
    println!("{}", url);

    Ok(())
}

/// Decode a ruhop:// URL back to configuration
fn decode_url(url: &str) -> Result<()> {
    let config = share::ShareConfig::from_url(url)?;
    let toml = config.to_toml();
    println!("{}", toml);
    Ok(())
}

/// Generate a QR code from configuration
fn generate_qr(config_path: PathBuf) -> Result<()> {
    use qrcode::QrCode;

    let config = load_config(&config_path)?;

    // Extract client configuration
    let client = config
        .client_config()
        .context("qr requires a client configuration section")?;

    // Build ShareConfig from the loaded config
    let server = match &client.server {
        ServerAddress::Single(s) => share::ServerAddr::Single(s.clone()),
        ServerAddress::Multiple(v) => share::ServerAddr::Multiple(v.clone()),
    };

    let share_config = share::ShareConfig {
        key: config.common.key.clone(),
        obfuscation: config.common.obfuscation,
        server,
        port_range: client.port_range,
    };

    let url = share_config.to_url()?;

    // Generate QR code
    let code = QrCode::new(url.as_bytes()).context("Failed to generate QR code")?;

    // Display in terminal using Unicode block characters
    let string = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .build();

    println!("{}", string);
    println!("\nURL: {}", url);

    Ok(())
}
