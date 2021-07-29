use std::sync::Arc;

#[async_trait::async_trait]
pub(crate) trait OutTcp {
    async fn tcp_connect(
        self: Arc<Self>,
        saddr: String,
        daddr: String,
        client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        mut client_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

#[async_trait::async_trait]
pub(crate) trait OutUdp {
    async fn udp_bind(
        self: Arc<Self>,
        saddr: String,
        client_tx: tokio::sync::mpsc::Sender<(String, Vec<u8>)>,
        mut client_rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

pub(crate) trait Out: OutTcp + OutUdp {}
impl<T: OutTcp + OutUdp> Out for T {}
