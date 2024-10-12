use lazy_static::lazy_static;
use reqwest::header::HeaderMap;

lazy_static! {
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
}
