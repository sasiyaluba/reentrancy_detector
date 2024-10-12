use std::str::FromStr;

use alloy::{
    primitives::TxHash,
    providers::{ProviderBuilder, WsConnect},
};
use firewall_reentrancy_detect::{constants::WHITE_LIST, reentrancyDetector::ReentrancyDetector};

#[tokio::main]
async fn main() {
    // 获得provider
    let builder = ProviderBuilder::new();
    let ws_provider = builder.on_ws(WsConnect::new("wss://lb.drpc.org/ogws?network=ethereum&dkey=AvZwUDJNQ0H-rfHFUNlC228dOWBjNHER76RXhkHL9tz4")).await.expect("error rpc");
    // 实例化检测器
    let detector = ReentrancyDetector::new(ws_provider, WHITE_LIST.clone());
    // 检测
    let _ = detector.detect_block().await;
}
