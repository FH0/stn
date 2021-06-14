use std::sync::Arc;
use tokio::sync::mpsc::Sender;

#[async_trait::async_trait]
pub(crate) trait OutTcp {
    async fn tcp_connect(
        self: Arc<Self>,
        saddr: String,
        daddr: String,
        client_tx: Sender<Vec<u8>>,
    ) -> Result<Sender<Vec<u8>>, Box<dyn std::error::Error>>;
}

#[async_trait::async_trait]
pub(crate) trait OutUdp {
    async fn udp_bind(
        self: Arc<Self>,
        saddr: String,
        client_tx: Sender<(String, Vec<u8>)>,
    ) -> Result<Sender<(String, Vec<u8>)>, Box<dyn std::error::Error>>;
}

pub(crate) trait Out: OutTcp + OutUdp {}
impl<T: OutTcp + OutUdp> Out for T {}
