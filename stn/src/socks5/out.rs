use std::{sync::Arc, time::Duration};

pub(crate) struct Out {
    pub(crate) tag: String,
    pub(crate) addr: String,
    pub(crate) tcp_timeout: Duration,
    pub(crate) udp_timeout: Duration,
}

impl Out {
    pub(crate) fn new(root: &serde_json::Value) -> Arc<dyn crate::route::Out + Send + Sync> {
        Arc::new(Self {
            tag: root["tag"].as_str().expect("tag not found").to_string(),
            addr: root["address"]
                .as_str()
                .expect("address not found")
                .to_string(),
            tcp_timeout: Duration::from_nanos(
                (root["tcp_timeout"].as_f64().unwrap_or_else(|| 300f64) * 1000_000_000f64) as u64,
            ),
            udp_timeout: Duration::from_nanos(
                (root["udp_timeout"].as_f64().unwrap_or_else(|| 60f64) * 1000_000_000f64) as u64,
            ),
        })
    }
}
