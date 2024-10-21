use alloy::{
    providers::{Provider, RootProvider},
    pubsub::PubSubFrontend,
};
use anyhow::Result;
use futures::StreamExt;
use std::sync::Arc;

use super::executor::{AlloyCacheDB, Executor};

pub struct MempoolMonitor {
    provider: Arc<RootProvider<PubSubFrontend>>,
    exectuor: Executor,
}

impl MempoolMonitor {
    pub fn new(provider: Arc<RootProvider<PubSubFrontend>>, fork_block: u64) -> Self {
        Self {
            provider: provider.clone(),
            exectuor: Executor::new(provider.clone(), fork_block),
        }
    }
    pub async fn front_run(&mut self, db: &mut AlloyCacheDB) -> Result<()> {
        let mut stream = self
            .provider
            .subscribe_pending_transactions()
            .await?
            .into_stream();
        while let Some(tx) = stream.next().await {
            println!("pending tx {:?}", tx.to_string());
            let res = self.exectuor.simulate_tx(db, tx.into()).await?;
            println!("{:?}", res);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy::providers::{ProviderBuilder, WsConnect};
    use revm::db::{AlloyDB, CacheDB};

    use crate::front_run::mempool_monitor::MempoolMonitor;

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_front_run() {
        let client = Arc::new(
            ProviderBuilder::new()
                .on_ws(WsConnect::new(
                    "wss://go.getblock.io/fc9a2ad67c5d44baa0c4ad5d93601b1c",
                ))
                .await
                .unwrap(),
        );

        let mut mempool_monitor = MempoolMonitor::new(client.clone(), 21006727);
        let alloydb = AlloyDB::new(client, 21006727.into()).unwrap();
        let mut cache = CacheDB::new(alloydb);
        mempool_monitor.front_run(&mut cache).await.unwrap();
    }
}
