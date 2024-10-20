use anyhow::Result;
use ethers_providers::{Middleware, PubsubClient};
use futures::StreamExt;
use std::sync::Arc;

use crate::front_run::frontBot::process_tx;

pub struct Monitor<M: Middleware> {
    provider: Arc<M>,
}

impl<M> Monitor<M>
where
    M: Middleware + 'static,
    M::Provider: PubsubClient,
{
    pub fn new(provider: Arc<M>) -> Self {
        Self { provider }
    }
    pub async fn watch(&mut self) -> Result<()> {
        let mut stream = self.provider.subscribe_pending_txs().await?;
        while let Some(pending_tx) = stream.next().await {
            let tx = self.provider.get_transaction(pending_tx).await?;
            println!("{:?}", tx);
            if tx.is_some() {
                let res = process_tx(self.provider.clone(), tx.unwrap())
                    .await
                    .unwrap();
                if res {
                    // 出现重入，抢跑
                    println!("抢跑吧!");
                }
            }
        }
        Ok(())
    }
}
