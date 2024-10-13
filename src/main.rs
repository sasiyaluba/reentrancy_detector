use std::{str::FromStr, time};

use alloy::{
    primitives::TxHash,
    providers::{ProviderBuilder, WsConnect},
};
use firewall_reentrancy_detect::{constants::WHITE_LIST, reentrancyDetector::ReentrancyDetector};
/**
 * @description:下面是测试中失败的交易，考虑这些重入漏洞不是单函数重入
 * *测试来源：重入合集=>https://github.com/pcaversaccio/reentrancy-attacks?tab=readme-ov-file
 * *测试数量：该合集中至10 July 2022的所有ethereum重入攻击
// 0xced7ca813081fb594181469001a6aff629c5874bd672cca44075d3ec768db664 lenf.me cannot
// 0x1655592eda3ebbba7c530ab3327daeae95fa95d05c3dec40338471245da10cfe Rari Capital cannot
// 0xd7ec3046ec75efbd04b3eea8752a8a6373a92c0dd813d08b655661054d3239c5 CREAM cannot
// 0xfa97c3476aa8aeac662dae0cc3f0d3da48472ff4e7c55d0e305901ec37a2f704 rpcerror
// 0xadbe5cf9269a001d50990d0c29075b402bcc3a0b0f3258821881621b787b35c6 FeiProtocol-Fuse cannot
 */
#[tokio::main]
async fn main() {
    // 获得provider
    let builder = ProviderBuilder::new();
    let ws_provider = builder
        .on_ws(WsConnect::new(
            "wss://lb.drpc.org/ogws?network=ethereum&dkey=AvZwUDJNQ0H-rfHFUNlC228dOWBjNHER76RXhkHL9tz4",
        ))
        .await
        .expect("error rpc");
    // 实例化检测器
    let detector = ReentrancyDetector::new(ws_provider, WHITE_LIST.clone());
    // 检测
    // let _ = detector.detect_block().await;
    let start = time::Instant::now();

    detector
        .detect_tx(
            TxHash::from_str("0xee5a17a81800a9493e03164673ac0428347d246aa30cdb124b647787faaabbea")
                .unwrap(),
        )
        .await
        .unwrap();
    let end = time::Instant::now();
    println!("time used {:?}", end - start);
}
