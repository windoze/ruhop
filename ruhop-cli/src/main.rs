//! Ruhop VPN CLI
//!
//! A command-line interface for the Ruhop VPN.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use ruhop_engine::{Config, ControlClient, VpnEngine, VpnRole, DEFAULT_SOCKET_PATH};

#[cfg(windows)]
mod service;

/// Ruhop VPN - A Rust implementation of GoHop protocol
#[derive(Parser)]
#[command(name = "ruhop")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "ruhop.toml")]
    config: PathBuf,

    /// Log level (error, warn, info, debug, trace)
    #[arg(short, long, default_value = "info")]
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
    },

    /// Generate a sample configuration file
    GenConfig {
        /// Output path for the configuration file
        #[arg(short, long, default_value = "ruhop.toml")]
        output: PathBuf,
    },

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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle service-run command before initializing logging (service has its own logging)
    #[cfg(windows)]
    if let Commands::ServiceRun { .. } = &cli.command {
        return service::run_as_service();
    }

    // Initialize logging
    init_logging(&cli.log_level);

    match cli.command {
        Commands::Server => run_server(cli.config).await,
        Commands::Client => run_client(cli.config).await,
        Commands::Status { socket } => show_status(socket).await,
        Commands::GenConfig { output } => generate_config(output),
        #[cfg(windows)]
        Commands::Service { action } => handle_service_action(action, &cli.config),
        #[cfg(windows)]
        Commands::ServiceRun { .. } => unreachable!(), // Handled above
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

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn run_server(config_path: PathBuf) -> Result<()> {
    info!("Starting Ruhop VPN server...");

    let config = load_config(&config_path)?;
    let mut engine = VpnEngine::new(config, VpnRole::Server)
        .context("Failed to create VPN engine")?;

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
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        engine_handle
    ).await;

    Ok(())
}

async fn run_client(config_path: PathBuf) -> Result<()> {
    info!("Starting Ruhop VPN client...");

    let config = load_config(&config_path)?;
    let mut engine = VpnEngine::new(config, VpnRole::Client)
        .context("Failed to create VPN engine")?;

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
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        engine_handle
    ).await;

    Ok(())
}

fn load_config(path: &PathBuf) -> Result<Config> {
    Config::load(path)
        .with_context(|| format!("Failed to load configuration from {:?}", path))
}

async fn show_status(socket_path: String) -> Result<()> {
    let client = ControlClient::new(&socket_path);

    match client.status().await {
        Ok(status) => {
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

            println!();
            println!("Traffic Statistics");
            println!("------------------");
            println!("Bytes RX:        {} ({})", status.bytes_rx, format_bytes(status.bytes_rx));
            println!("Bytes TX:        {} ({})", status.bytes_tx, format_bytes(status.bytes_tx));
            println!("Packets RX:      {}", status.packets_rx);
            println!("Packets TX:      {}", status.packets_tx);

            if status.role == "server" {
                println!();
                println!("Server Info");
                println!("-----------");
                println!("Active Sessions: {}", status.active_sessions);
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
