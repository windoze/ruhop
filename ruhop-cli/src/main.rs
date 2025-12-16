//! Ruhop VPN CLI
//!
//! A command-line interface for the Ruhop VPN.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use ruhop_app_interface::{Config, VpnEngine, VpnRole};

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

    /// Generate a sample configuration file
    GenConfig {
        /// Output path for the configuration file
        #[arg(short, long, default_value = "ruhop.toml")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level);

    match cli.command {
        Commands::Server => run_server(cli.config).await,
        Commands::Client => run_client(cli.config).await,
        Commands::GenConfig { output } => generate_config(output),
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
