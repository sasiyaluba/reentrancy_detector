use std::time;

use alloy::{
    eips::BlockId,
    node_bindings::Anvil,
    primitives::TxHash,
    providers::{ext::AnvilApi, Provider, ProviderBuilder, WsConnect},
};
use anyhow::Result;
use revm::{
    db::{AlloyDB, CacheDB},
    primitives::Address,
    DatabaseRef, Evm,
};
use revm::{
    inspectors::{CustomPrintTracer, GasInspector},
    primitives::U256,
};

#[tokio::main]
async fn main() -> Result<()> {
    let anvil = Anvil::new()
        .fork("https://rpc.mevblocker.io")
        .fork_block_number(21006727)
        .block_time(1)
        .spawn();
    let client: alloy::providers::RootProvider<alloy::pubsub::PubSubFrontend> =
        ProviderBuilder::new()
            .on_ws(WsConnect::new(anvil.ws_endpoint_url()))
            .await?;
    let tx = client
        .get_transaction_by_hash(
            "0x3cb8648d3a66cc7113f52abe09401e054af0e2f04749701e0036e4a564880d43"
                .parse::<TxHash>()
                .unwrap(),
        )
        .await?
        .unwrap();
    let alloydb = AlloyDB::new(client, BlockId::from(21006726)).unwrap();
    let cachedb = CacheDB::new(alloydb);
    let mut evm = Evm::builder()
        .with_db(cachedb)
        .modify_tx_env(|tx_env| {
            tx_env.caller = tx.from;
            tx_env.transact_to = match tx.to {
                Some(address) => revm::primitives::TxKind::Call(address),
                None => revm::primitives::TxKind::Create,
            };
            tx_env.value = tx.value;
            tx_env.data = tx.input;
            tx_env.gas_limit = tx.gas as u64;
        })
        .modify_block_env(|block_env| {
            block_env.number = U256::from(21006726);
        })
        .build();
    let start = time::Instant::now();
    let res = evm.transact_preverified().expect("Transaction Error");
    println!("{:?}", res);
    let end = time::Instant::now();
    println!("用时 {:?}", end - start);
    Ok(())
}
