use super::{inspector::ReenterDetector, utils::*};
use anyhow::Result;
use ethers_core::types::{Block, BlockId, Transaction, H256, U64};
use ethers_providers::{JsonRpcClient, Middleware, Provider};
use revm::{
    db::EthersDB,
    inspectors::{self, NoOpInspector},
    primitives::{Address, CreateScheme, TransactTo},
    Database, EVM,
};
use std::sync::Arc;
// 执行器
pub async fn process_tx<M: Middleware>(provider: Arc<M>, tx: Transaction) -> Result<bool> {
    let block_number = provider.get_block_number().await.unwrap();
    let provider_clone = Arc::clone(&provider);
    let mut evm = EVM::new();
    let ethersdb = EthersDB::new(provider_clone, Some(BlockId::from(block_number))).unwrap();
    evm.database(ethersdb);
    let block = provider.get_block(block_number).await.unwrap();
    update_evm_with_block(&mut evm, block.unwrap());
    update_evm_with_tx(&mut evm, tx);
    let mut detect = ReenterDetector::default();
    let res = evm.inspect(&mut detect);
    if let Ok(res) = res {
        if res.result.is_success() & detect.is_reenter {
            return Ok(true);
        }
    }
    Ok(false)
}

fn update_evm_with_block<M: Middleware>(evm: &mut EVM<EthersDB<M>>, block: Block<H256>) {
    evm.env.block.timestamp = eu256_to_ru256(&block.timestamp);
    evm.env.block.coinbase = eaddress_to_raddress(&block.author.unwrap());
    evm.env.block.gas_limit = eu256_to_ru256(&block.gas_limit);
    evm.env.block.number = u64_to_ru256(block.number.unwrap().as_u64() + 1);
}

fn update_evm_with_tx<M: Middleware>(evm: &mut EVM<EthersDB<M>>, tx: Transaction) {
    evm.env.tx.caller = eaddress_to_raddress(&tx.from);
    evm.env.tx.gas_limit = tx.gas.as_u64();
    evm.env.tx.gas_price = Default::default();
    evm.env.tx.transact_to = match tx.to {
        Some(to) => TransactTo::Call(eaddress_to_raddress(&to)),
        None => TransactTo::Create(CreateScheme::Create),
    };
    evm.env.tx.value = eu256_to_ru256(&tx.value);
    evm.env.tx.data = tx.input.to_vec().into();
}
