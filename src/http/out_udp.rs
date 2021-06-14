use std::sync::Arc;

#[async_trait::async_trait]
impl crate::route::OutUdp for super::Out {
    async fn udp_bind(
        self: Arc<Self>,
        _saddr: String,
        _client_tx: tokio::sync::mpsc::Sender<(String, Vec<u8>)>,
    ) -> Result<tokio::sync::mpsc::Sender<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
        Err("http unsupport udp")?
    }
}
