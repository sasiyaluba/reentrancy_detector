use std::str::FromStr;

use alloy::{
    primitives::{keccak256, I256, U256},
    rpc::types::trace::geth::{
        GethDebugBuiltInTracerType, GethDebugTracerConfig, GethDebugTracerType,
        GethDebugTracingOptions, GethDefaultTracingOptions,
    },
};
use lazy_static::lazy_static;
use reqwest::header::{HeaderMap, HeaderValue};
use revm::primitives::B256;

lazy_static! {
    pub static ref REENTER_EVENT_TOPIC: B256 =
        B256::from_slice(&keccak256("reenter(address)").to_vec());
    pub static ref WHITE_LIST: Vec<String> = vec![
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
    pub static ref CALLTRACE_OPTION: GethDebugTracingOptions = GethDebugTracingOptions {
        config: GethDefaultTracingOptions::default(),
        tracer: Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::CallTracer,
        )),
        tracer_config: GethDebugTracerConfig::default(),
        timeout: None,
    };
    pub static ref MIN_LOSS: I256 = I256::from_str("-100").unwrap();
    pub static ref HEADER_MAP: HeaderMap = {
        let mut header_map = HeaderMap::new();
        header_map.insert("accept", HeaderValue::from_str("application/json").unwrap());
        header_map.insert(
            "accept-language",
            HeaderValue::from_str("zh-CN,zh;q=0.9").unwrap(),
        );
        header_map.insert(
            "content-type",
            HeaderValue::from_str("application/json;charset=utf-8").unwrap(),
        );
        header_map
    };
}
