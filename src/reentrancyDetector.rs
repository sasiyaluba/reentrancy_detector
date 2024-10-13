use crate::constants::{CALLTRACE_OPTION, HEADER_MAP, MIN_LOSS, WHITE_LIST};
use alloy::{
    hex::{self, FromHex},
    json_abi::Items,
    primitives::{map::HashSet, Address, BlockHash, Bytes, Selector, TxHash, I256, U256},
    providers::{ext::DebugApi, Provider, ProviderBuilder, RootProvider, WsConnect},
    rpc::types::trace::geth::{
        CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
        GethTrace, TraceResult,
    },
    transports::Transport,
};
use futures::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, str::FromStr};

type Path = Vec<String>;
#[derive(Serialize, Deserialize, Debug, Clone)]
struct BalanceChange {
    account: String,
    assets: Vec<Asset>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Asset {
    address: Address,
    amount: String,
    sign: bool,
    value: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockSecResponse {
    #[serde(rename = "balanceChanges")]
    balance_changes: Vec<BalanceChange>,
}
pub struct ReentrancyDetector<T> {
    provider: RootProvider<T>,
    white_list: Vec<String>,
}
pub type AddressProfit = (Address, I256);
impl<T> ReentrancyDetector<T>
where
    T: Transport + Clone,
{
    /**
     * @description:初始化一个重入检测器
     */
    pub fn new(provider: RootProvider<T>, white_list: Vec<String>) -> Self {
        Self {
            provider,
            white_list,
        }
    }

    /**
     * @description:检测单笔交易是否存在重入可能
     */
    pub async fn detect_tx(
        &self,
        tx_hash: TxHash,
    ) -> Result<Vec<Address>, Box<dyn std::error::Error>> {
        let trace_info = self
            .provider
            .debug_trace_transaction(tx_hash, CALLTRACE_OPTION.clone())
            .await?;
        let call_trace = trace_info.try_into_call_frame()?;
        let address_list = self.get_reenter_address(call_trace);

        // 如果存在重入可能
        if !address_list.is_empty() {
            let address_profit = self.cacl_balance_change(tx_hash).await?;
            // 找出所有盈利的地址，如果盈利超过最小盈利限制，则告警
            let profits = address_profit
                .into_iter()
                .filter(|(_, profit)| profit.lt(&MIN_LOSS))
                .collect::<Vec<AddressProfit>>();
            for profit in profits {
                println!("ALERT!!!");
                println!(
                    "tx_hash:{:?},address:{},asset balance change:{} USD",
                    tx_hash, profit.0, profit.1
                );
            }
        }

        Ok(vec![])
    }

    /**
     * @description:轮询区块，检测所有交易是否存在重入可能
     */
    pub async fn detect_block(&self) -> Result<(), Box<dyn std::error::Error>> {
        // 轮询区块头
        let subscrible_stream = self.provider.watch_blocks().await?;
        let mut stream = subscrible_stream
            .into_stream()
            .flat_map(futures::stream::iter);

        // 有新的区块
        while let Some(block_hash) = stream.next().await {
            println!("new block");
            let trace_info = self
                .provider
                .debug_trace_block_by_hash(block_hash, CALLTRACE_OPTION.clone())
                .await?;
            for trace_response in trace_info {
                match trace_response {
                    TraceResult::Success { result, tx_hash } => {
                        let call_trace = result.try_into_call_frame()?;
                        let address_list = self.get_reenter_address(call_trace);
                        // 如果存在重入可能
                        if !address_list.is_empty() {
                            let address_profit = self.cacl_balance_change(tx_hash.unwrap()).await?;
                            // 找出所有盈利的地址，如果盈利超过最小盈利限制，则告警
                            let profits = address_profit
                                .into_iter()
                                .filter(|(_, profit)| profit.gt(&MIN_LOSS))
                                .collect::<Vec<AddressProfit>>();
                            for profit in profits {
                                println!("ALERT!!!");
                                println!(
                                    "tx_hash:{:?},address:{},asset balance change:{}USD",
                                    tx_hash, profit.0, profit.1
                                );
                            }
                        }
                    }
                    TraceResult::Error { error, tx_hash } => {
                        return Err(error.into());
                    }
                }
            }
        }
        Ok(())
    }

    /**
     * @description:内部函数，根据block_sec接口，获得对应的余额变化
     */
    async fn cacl_balance_change(
        &self,
        tx_hash: TxHash,
    ) -> Result<Vec<AddressProfit>, Box<dyn std::error::Error>> {
        // @description:获取地址余额变化
        let client = reqwest::Client::new();
        let body_data = format!(r#"{{"chainID":1,"txnHash":"{}","blocked":false}}"#, tx_hash);
        let balance_change_json = client
            .post("https://app.blocksec.com/api/v1/onchain/tx/balance-change")
            .headers(HEADER_MAP.clone())
            .body(body_data)
            .send()
            .await?
            .text()
            .await?;
        let balance_change: BlockSecResponse = serde_json::from_str(&balance_change_json).unwrap();
        Ok(self.handle_balance_change(balance_change.clone()))
    }

    /**
     * @description:对余额变化进行处理，得到相关地址的余额变化结构体
     */
    fn handle_balance_change(&self, blocksec_response: BlockSecResponse) -> Vec<AddressProfit> {
        let mut address_profit = Vec::<AddressProfit>::new();
        for balance_change in blocksec_response.balance_changes {
            let mut res = I256::ZERO;
            for asset in balance_change.assets {
                // 处理小数点
                let amount_fragment = if asset.value.contains(".") {
                    asset.value.split_once(".").unwrap().0.to_string()
                } else {
                    asset.value
                };
                // 处理分割符
                let amount_fragment: Vec<&str> = amount_fragment.split(',').collect();
                let value = amount_fragment.join("");
                // 资产变化
                if asset.sign {
                    res += I256::from_str(&value).unwrap();
                } else {
                    res -= I256::from_str(&value).unwrap();
                }
            }
            address_profit.push((balance_change.account.parse::<Address>().unwrap(), res));
        }
        address_profit
    }

    /**
     * @description:获得可重入地址
     * @param:call_trace代表交易的call_trace
     */
    fn get_reenter_address(&self, call_trace: CallFrame) -> Vec<String> {
        //@description:根据路径，获得所有被重入的地址
        let mut reenter_list = Vec::<String>::new();
        // 过滤白名单
        let mut remain_paths = Vec::<Path>::new();
        for path in Self::get_path(call_trace.clone()) {
            let remain_path = self.get_exclude_address(path);
            remain_paths.push(remain_path);
        }
        // 第一次过滤，找到在同一条调用路径上的重入
        for path in remain_paths.clone() {
            // 将调用路径中，白名单项剔除
            let mut set = HashSet::<String>::new();
            // 找出每条路径中存在二次调用的项
            for path_node in path {
                if !set.insert(path_node.clone()) {
                    let (_, address) = path_node.split_once(',').unwrap();
                    reenter_list.push(address.to_string());
                }
            }
        }
        // 第二次过滤：在calltrace中同一子树的同一层找到重入，使用BFS实现
        // !注意，此处可能存在较高误报率
        if reenter_list.is_empty() {
            reenter_list.extend(Self::get_reenter_on_same_depth(call_trace));
        }
        reenter_list
    }

    /**
     * @description:将获得的路径，排除白名单内容
     * @param:path代表路径，路径的形式为"selector,address"
     */
    fn get_exclude_address(&self, path: Vec<String>) -> Vec<String> {
        //@description:将包含在白名单中的项从path中排除
        let mut to_remove = Vec::<usize>::new();
        for white_item in self.white_list.iter() {
            let (white_selector, white_address) = white_item.split_once(',').unwrap();
            if white_selector.eq("_") {
                // 只需要比较地址
                for (idx, path_node) in path.iter().enumerate() {
                    let (_, address) = path_node.split_once(',').unwrap();
                    if address.eq(white_address) {
                        to_remove.push(idx);
                    }
                }
            } else if white_address.eq("_") {
                // 只需要比较函数选择器
                for (idx, path_node) in path.iter().enumerate() {
                    let (selector, _) = path_node.split_once(',').unwrap();
                    if selector.eq(white_selector) {
                        to_remove.push(idx);
                    }
                }
            } else {
                // 正常比较
                for (idx, path_node) in path.iter().enumerate() {
                    if path_node.eq(white_item) {
                        to_remove.push(idx);
                    }
                }
            }
        }
        let mut set = HashSet::<usize>::new();
        set.extend(to_remove);
        let remain_path: Vec<String> = path
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| !set.contains(idx))
            .map(|(_, value)| value.clone())
            .collect();
        remain_path
    }

    /**
     * @description:根据call_trace，得到所有路径
     * @param:call_trace代表交易的call_trace
     */
    fn get_path(call_trace: CallFrame) -> Vec<Path> {
        //@description:使用深度优先遍历，获得calltrace中所有的call调用路径
        let mut paths = Vec::<Path>::new();
        let mut path = Path::new();
        Self::_get_path(call_trace, &mut path, &mut paths);
        paths
    }
    fn _get_path(call_trace: CallFrame, path: &mut Path, paths: &mut Vec<Path>) {
        //@description:使用深度优先遍历，获得calltrace中所有的call调用路径
        // 排除staticcall、inputdata长度小于4字节以及合约创建交易
        if call_trace.to.is_some()
            && call_trace.input.len() >= 4
            && !(call_trace.typ.eq("STATICCALL") || call_trace.typ.eq("SELFDESTRUCT"))
        {
            let selector =
                hex::encode(Self::get_selector(&call_trace.input).unwrap()).to_lowercase();
            let address = call_trace.to.unwrap().to_string().to_lowercase();
            // 插入
            path.push(format!("{selector},{address}"));
        }
        if call_trace.calls.len() > 0 {
            // 有子调用，深度优先遍历
            for sub_call in call_trace.calls {
                if call_trace.to.is_some()
                    && call_trace.input.len() >= 4
                    && !(sub_call.typ.eq("STATICCALL") || sub_call.typ.eq("SELFDESTRUCT"))
                {
                    Self::_get_path(sub_call, path, paths);
                }
            }
        } else {
            // 叶子节点，路径遍历结束，加入paths
            paths.push(path.clone());
        }
        // 将当前节点删除
        path.pop();
    }

    /**
     * @description:根据input_data，获得selector
     * @param:input代表交易的输入
     */
    fn get_selector(input: &Bytes) -> Option<Selector> {
        if input.len() >= 4 {
            let res = input.split_first_chunk::<4>().unwrap().0;
            Some(Selector::from(res.clone()))
        } else {
            None
        }
    }

    /**
     * @description:根据call_trace，获得在不同调用路径的同一层调用中，存在重入的情况
     * @param:call_trace代表交易的call_trace
     * ! 此处还有一个点：需要过滤常见情况
     * todo: 过滤常见情况，否则导致误报率
     */
    fn get_reenter_on_same_depth(call_trace: CallFrame) -> Vec<String> {
        let mut reenter_list = HashSet::<String>::new();
        let mut queue = VecDeque::new();
        queue.push_back(call_trace);
        let mut unique_selector_address = HashSet::<String>::new();
        while let Some(call) = queue.pop_front() {
            unique_selector_address.clear();
            // 有子调用
            if !call.calls.is_empty() {
                // 遍历每个子调用，看是否有相同的函数选择器
                call.calls.iter().for_each(|sub_call| {
                    if sub_call.to.is_some()
                        && sub_call.input.len() >= 4
                        && !(sub_call.typ.eq("STATICCALL") || sub_call.typ.eq("SELFDESTRUCT"))
                    {
                        let selector = hex::encode(Self::get_selector(&sub_call.input).unwrap())
                            .to_lowercase();
                        let address = sub_call.to.unwrap().to_string().to_lowercase();
                        // 无法插入，说明存在重复
                        if !unique_selector_address.insert(format!("{selector},{address}")) {
                            reenter_list.insert(address);
                        }
                    }
                });

                // 继续插入
                for sub_call in call.calls {
                    queue.push_back(sub_call);
                }
            }
        }
        reenter_list.into_iter().collect()
    }

    #[deprecated(since = "0.2.1", note = "High false alarm rate")]
    fn get_reenter_address_loose(&self, call_trace: CallFrame) -> Vec<String> {
        //@description:根据执行过程中的调用情况，获得所有被重入的地址
        let mut visited = Path::new();
        let mut reenter_list = Vec::<String>::new();
        Self::dfs(call_trace, &mut visited, &mut reenter_list);
        let remain_node = self.get_exclude_address(reenter_list);
        remain_node
    }
    fn dfs(call_trace: CallFrame, visited: &mut Path, alerts: &mut Vec<String>) {
        if call_trace.to.is_some()
            && !call_trace.input.is_empty()
            && !(call_trace.typ.eq("STATICCALL") || call_trace.typ.eq("SELFDESTRUCT"))
        {
            let selector =
                hex::encode(Self::get_selector(&call_trace.input).unwrap()).to_lowercase();
            let address = call_trace.to.unwrap().to_string().to_lowercase();
            // 插入
            visited.push(format!("{selector},{address}"));
        }
        if call_trace.calls.len() > 0 {
            // 有子调用，深度优先遍历
            for sub_call in call_trace.calls {
                if call_trace.to.is_some()
                    && !(sub_call.typ.eq("STATICCALL") || sub_call.typ.eq("SELFDESTRUCT"))
                {
                    Self::dfs(sub_call, visited, alerts);
                }
            }
        }
        // 更新告警
        let mut set = HashSet::<&String>::new();
        println!("visited:{:?}", visited);

        for visit in visited.iter() {
            // 有重复项
            if !set.insert(visit) {
                alerts.push(visit.clone());
            }
        }
        // 将当前节点删除
        visited.pop();
    }
}
