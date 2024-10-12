use alloy::providers::{ProviderBuilder, WsConnect};
use firewall_reentrancy_detect::reentrancyDetector::ReentrancyDetector;
use lazy_static::lazy_static;
lazy_static! {
    static ref white_item: Vec<String> = vec![
        format!(
            "_,{}",
            "0x7a250d5630b4cf539739df2c5dacb4c659f2488d".to_lowercase()
        ),
        format!(
            "_,{}",
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_lowercase()
        ),
        format!(
            "_,{}",
            "0x2c290d77b277fae723cb0686bcd9e265ec862445".to_lowercase()
        ),
        format!("{},_", "23b872dd".to_lowercase()),
        format!("{},_", "a9059cbb".to_lowercase()),
        format!("{},_", "fa461e33".to_lowercase()),
    ];
}
#[tokio::main]
async fn main() {
    // 获得provider
    let builder = ProviderBuilder::new();
    let ws_provider = builder.on_ws(WsConnect::new("wss://lb.drpc.org/ogws?network=ethereum&dkey=AvZwUDJNQ0H-rfHFUNlC228dOWBjNHER76RXhkHL9tz4")).await.expect("error rpc");
    // 实例化检测器
    let detector = ReentrancyDetector::new(ws_provider, white_item.clone());
    // 检测
    detector.detect().await;
}
