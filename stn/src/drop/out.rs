use log::*;
use std::sync::Arc;

pub(crate) struct Out {
    pub(crate) tag: String,
}

impl Out {
    pub(crate) fn new(root: &serde_json::Value) -> Arc<dyn crate::route::Out + Send + Sync> {
        Arc::new(Out {
            tag: root["tag"].as_str().expect("tag not found").to_string(),
        })
    }
}

#[async_trait::async_trait]
impl crate::route::OutTcp for Out {
    async fn tcp_connect(
        self: Arc<Self>,
        saddr: String,
        daddr: String,
        _client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        _client_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("{} {} -> {} drop", self.tag, saddr, daddr);
        Err("drop".into())
    }
}

#[async_trait::async_trait]
impl crate::route::OutUdp for Out {
    async fn udp_bind(
        self: Arc<Self>,
        saddr: String,
        _client_tx: tokio::sync::mpsc::Sender<(String, Vec<u8>)>,
        _client_rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("{} {} drop", self.tag, saddr);
        Err("drop".into())
    }
}
