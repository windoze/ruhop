//! Simple TUN device example
//!
//! This example demonstrates how to create a TUN device and read/write packets.
//!
//! # Requirements
//!
//! - **Linux**: Run with `sudo` or as root
//! - **macOS**: Run with `sudo` or as root
//! - **Windows**: Run as Administrator with WinTun driver installed
//!
//! # Usage
//!
//! ```bash
//! # Linux/macOS
//! sudo cargo run --example simple_tun
//!
//! # Windows (in Admin PowerShell)
//! cargo run --example simple_tun
//! ```

use hop_tun::{TunConfig, TunDevice};
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("Creating TUN device...");

    // Build configuration
    let config = TunConfig::builder()
        .name("hop0") // Interface name (may be auto-assigned on some platforms)
        .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24) // IP address and prefix
        .mtu(1400) // MTU size
        .up(true) // Bring interface up
        .build()?;

    // Create the device
    let device = TunDevice::create(config).await?;

    println!("TUN device created: {}", device.name());
    println!("MTU: {}", device.mtu());

    // Read packets in a loop
    println!("\nWaiting for packets... (Ctrl+C to exit)");
    println!("Try: ping 10.0.0.2 (from another terminal)");

    let mut buf = vec![0u8; 2000];

    loop {
        match device.read(&mut buf).await {
            Ok(n) => {
                println!("Received {} bytes", n);

                // Parse IP header to show basic info
                if n >= 20 {
                    let version = (buf[0] >> 4) & 0x0F;
                    let protocol = buf[9];
                    let src = format!("{}.{}.{}.{}", buf[12], buf[13], buf[14], buf[15]);
                    let dst = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);

                    let proto_name = match protocol {
                        1 => "ICMP",
                        6 => "TCP",
                        17 => "UDP",
                        _ => "Other",
                    };

                    println!(
                        "  IPv{} {} {} -> {}",
                        version, proto_name, src, dst
                    );

                    // For ICMP echo requests, we could send a reply
                    if protocol == 1 && n >= 28 {
                        let icmp_type = buf[20];
                        if icmp_type == 8 {
                            // Echo request
                            println!("  ICMP Echo Request - could send reply");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Read error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
