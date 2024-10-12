use std::{process::id, str::FromStr, sync::Arc};

use alloy::{
    hex::{self, FromHex},
    json_abi::Items,
    primitives::{map::HashSet, Address, Bytes, Selector},
    providers::{ext::DebugApi, Provider, RootProvider},
    rpc::types::trace::geth::{
        CallFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
        GethTrace, TraceResult,
    },
    transports::Transport,
};
use futures::StreamExt;

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

pub struct ReentrancyDetector<T> {
    provider: RootProvider<T>,
    white_list: Vec<String>,
}
impl<T> ReentrancyDetector<T>
where
    T: Transport + Clone,
{
    pub fn new(provider: RootProvider<T>, white_list: Vec<String>) -> Self {
        Self {
            provider,
            white_list,
        }
    }
    pub async fn detect(&self) {
        // 轮询区块头
        let subscrible_stream = self.provider.watch_blocks().await.unwrap();
        let mut stream = subscrible_stream
            .into_stream()
            .flat_map(futures::stream::iter);
        // debug_traceBlock的参数，用于获得交易的call_tracer
        let mut option = GethDebugTracingOptions::default();
        option.tracer = Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::CallTracer,
        ));
        // 有新的区块
        while let Some(block_hash) = stream.next().await {
            println!("block_hash:{:?}", block_hash);
            match self
                .provider
                .debug_trace_block_by_hash(block_hash, option.clone())
                .await
            {
                // 解构call_tracer
                Ok(trace_info) => {
                    for call_trace in trace_info {
                        match call_trace {
                            TraceResult::Success { result, tx_hash } => match result {
                                GethTrace::CallTracer(call) => {
                                    // 获取可能出现重入的地址
                                    let res = self.get_reentrancy(call);
                                    if !res.is_empty() {
                                        println!("alert!!! => {:?}", tx_hash);
                                        println!("notice address => {:?}", res);
                                    }
                                }
                                _ => {}
                            },
                            TraceResult::Error { error, tx_hash } => {
                                // todo 此处应当再处理
                            }
                        }
                    }
                }
                Err(e) => {}
            }
        }
    }

    fn get_reentrancy(&self, call_trace: CallFrame) -> Vec<String> {
        //@description:获得所有被重入的地址
        let mut reentrances = Vec::<String>::new();
        // 对call_trace进行dfs，得到所有的调用路径
        let paths = Self::dfs(call_trace);
        for path in paths {
            // 将调用路径中，白名单项剔除
            let remain_node = self.get_exclude_address(path);
            let mut set = HashSet::<String>::new();
            // 重入判断所有地址
            for path_node in remain_node {
                if set.contains(&path_node) {
                    let (_, address) = path_node.split_once(',').unwrap();
                    reentrances.push(address.to_string());
                } else {
                    set.insert(path_node);
                }
            }
        }
        reentrances
    }

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
        // println!("to_remove {:?}", set);
        // println!("path {:?}", path);
        let remain_path: Vec<String> = path
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| !set.contains(idx))
            .map(|(_, value)| value.clone())
            .collect();
        // println!("remain path {:?}", remain_path);
        remain_path
    }
    fn dfs(call_trace: CallFrame) -> Vec<Path> {
        //@description:使用深度优先遍历，获得calltrace中所有的call调用路径
        let mut paths = Vec::<Path>::new();
        let mut path = Path::new();
        Self::_dfs(call_trace, &mut path, &mut paths);
        paths
    }
    fn _dfs(call_trace: CallFrame, path: &mut Path, paths: &mut Vec<Path>) {
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
                    Self::_dfs(sub_call, path, paths);
                }
            }
        } else {
            // 叶子节点，路径遍历结束，加入paths
            paths.push(path.clone());
        }
        // 将当前节点删除
        path.pop();
    }
    fn get_selector(input: &Bytes) -> Option<Selector> {
        if input.len() >= 4 {
            let res = input.split_first_chunk::<4>().unwrap().0;
            Some(Selector::from(res.clone()))
        } else {
            None
        }
    }
}
type Path = Vec<String>;
