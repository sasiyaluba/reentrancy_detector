// @description:对网络的封装

use alloy::{
    providers::{Provider, ProviderBuilder, RootProvider, WsConnect},
    pubsub::PubSubFrontend,
    rpc::client::RpcClient,
    transports::{http::Http, Transport},
};
use reqwest::{Client, Url};
use std::{env, str::FromStr};
#[derive(Debug, Clone, Copy)]
pub enum RPCNode {
    EthereumMainnet,
    EthereumSepolia,
    Anvil,
}
impl ToString for RPCNode {
    fn to_string(&self) -> String {
        match &self {
            RPCNode::EthereumMainnet => format!("EthereumMainnet"),
            RPCNode::EthereumSepolia => format!("EthereumSepolia"),
            RPCNode::Anvil => format!("Anvil"),
        }
    }
}

pub struct RPCNetwork {
    pub rpc_node: RPCNode,
    pub rpc_provider: RootProvider<Http<Client>>,
}

impl RPCNetwork {
    pub async fn new_http(rpc_node: RPCNode) -> Result<Self, Box<dyn std::error::Error>> {
        let rpc_url = env::var(format!("{}_HTTP", rpc_node.to_string()))?;
        let rpc_provider_builder = ProviderBuilder::new();
        let rpc_provider = rpc_provider_builder.on_http(Url::from_str(&rpc_url)?);
        Ok(Self {
            rpc_node,
            rpc_provider,
        })
    }
}
