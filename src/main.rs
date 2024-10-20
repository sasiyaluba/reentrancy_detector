use std::sync::Arc;

use anyhow::Result;
use ethers_providers::{Provider, Ws};
use firewall_reentrancy_detect::front_run::monitor;
#[tokio::main]
async fn main() -> Result<()> {
    let provider = Arc::new(
        Provider::<Ws>::connect(
            "wss://ethereum-mainnet.s.chainbase.online/v1/2hrvFK3P7gk3Bv4orsSf2gxcofG",
        )
        .await?,
    );
    let mut monitor = monitor::Monitor::new(provider);
    monitor.watch().await;
    Ok(())
}
