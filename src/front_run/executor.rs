// 1. 获取交易的数据
// 2. 读取所有地址的状态，设置到evm中
// 3. 模拟执行

use std::{sync::Arc, time};

use alloy::{
    primitives::{Keccak256, TxHash},
    providers::{ext::DebugApi, Provider, RootProvider},
    pubsub::PubSubFrontend,
    rpc::types::trace::geth::{
        GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, PreStateFrame,
    },
};
use anyhow::Result;
use revm::{
    db::{AlloyDB, CacheDB},
    primitives::{AccountInfo, Bytecode, ResultAndState, U256},
    Evm,
};

pub type AlloyCacheDB =
    CacheDB<AlloyDB<PubSubFrontend, alloy::network::Ethereum, Arc<RootProvider<PubSubFrontend>>>>;
pub struct Executor {
    provider: Arc<RootProvider<PubSubFrontend>>,
    fork_block: u64,
}
impl Executor {
    pub fn new(provider: Arc<RootProvider<PubSubFrontend>>, fork_block: u64) -> Self {
        Self {
            fork_block,
            provider,
        }
    }

    pub async fn simulate_tx(
        &mut self,
        db: &mut AlloyCacheDB,
        tx_hash: TxHash,
    ) -> Result<ResultAndState> {
        self.update_db_with_tx_hash(db, tx_hash).await?;
        let tx = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await?
            .unwrap();
        let mut evm = Evm::builder()
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
                block_env.number = U256::from(self.fork_block);
            })
            .with_db(db)
            .build();
        let start = time::Instant::now();
        let res = evm.transact()?;
        let end = time::Instant::now();
        println!("simulate transact use time :{:?}", end - start);
        Ok(res)
    }

    async fn update_db_with_tx_hash(
        &mut self,
        db: &mut AlloyCacheDB,
        tx_hash: TxHash,
    ) -> Result<()> {
        let trace = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::PreStateTracer,
            )),
            ..Default::default()
        };
        let start = time::Instant::now();
        let tx_info = self
            .provider
            .debug_trace_transaction(tx_hash, trace)
            .await?
            .try_into_pre_state_frame()?;
        let end = time::Instant::now();
        println!("debug_trace use time :{:?}", end - start);
        match tx_info {
            PreStateFrame::Default(pre_state_mode) => {
                for (address, state) in pre_state_mode.0.into_iter() {
                    if !db.accounts.contains_key(&address) {
                        let mut _address_info = AccountInfo::default();
                        _address_info.balance = state.balance.unwrap();
                        _address_info.nonce = state.nonce.unwrap();
                        match state.code {
                            Some(code) => {
                                _address_info.code = Some(Bytecode::LegacyRaw(code.clone()));
                                let mut hasher = Keccak256::new();
                                hasher.update(code);
                                _address_info.code_hash = hasher.finalize();
                            }
                            None => {
                                _address_info.code = None;
                                let hasher = Keccak256::new();
                                _address_info.code_hash = hasher.finalize();
                            }
                        };

                        db.insert_account_info(address, _address_info);
                        for (slot, value) in state.storage {
                            db.insert_account_storage(
                                address,
                                U256::from_be_bytes(slot.0),
                                U256::from_be_bytes(value.0),
                            )?;
                        }
                    }
                }
            }
            PreStateFrame::Diff(diff_mode) => todo!(),
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use alloy::{
        node_bindings::Anvil,
        primitives::TxHash,
        providers::{ext::TraceApi, ProviderBuilder, WsConnect},
    };
    use revm::db::{AlloyDB, CacheDB};

    use crate::front_run::executor::Executor;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_executor() {
        let anvil = Anvil::new()
            .fork("https://lb.drpc.org/ogrpc?network=ethereum&dkey=AvZwUDJNQ0H-rfHFUNlC228dOWBjNHER76RXhkHL9tz4")
            .fork_block_number(21006727)
            .block_time(1)
            .spawn();
        let client = Arc::new(
            ProviderBuilder::new()
                .on_ws(WsConnect::new(anvil.ws_endpoint_url()))
                .await
                .unwrap(),
        );
        let mut executor = Executor::new(client.clone(), 21006727);
        let tx_hash: TxHash = "0x3cb8648d3a66cc7113f52abe09401e054af0e2f04749701e0036e4a564880d43"
            .parse()
            .unwrap();
        let alloydb = AlloyDB::new(client, 21006727.into()).unwrap();
        let mut cache = CacheDB::new(alloydb);
        executor.simulate_tx(&mut cache, tx_hash).await;
        let tx_hash2: TxHash = "0x100253222d3103d167d32878d97b867b1417244e357539b4426600206fea2668"
            .parse()
            .unwrap();
        executor.simulate_tx(&mut cache, tx_hash2).await;
    }
}
