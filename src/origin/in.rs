use crate::misc::build_socket_listener;
use std::{sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::mpsc::Sender,
};

pub(crate) struct In {
    pub(crate) tag: String,
    pub(crate) tcp_nodelay: bool,
    pub(crate) tcp_keepalive_inverval: Duration,
    pub(crate) tcp_timeout: Duration,
    pub(crate) udp_timeout: Duration,
    pub(crate) tcp_listener: TcpListener,
    pub(crate) udp_listener: UdpSocket,
    pub(crate) fullcone_map: dashmap::DashMap<String, Sender<Vec<u8>>>,
}

impl In {
    pub(crate) async fn start(root: serde_json::Value) {
        let bind_addr = root["address"].as_str().expect("address not found");

        let r#in = Arc::new(In {
            tag: root["tag"].as_str().expect("tag not found").to_string(),
            tcp_nodelay: root["tcp_nodelay"].as_bool().unwrap_or_else(|| true),
            tcp_keepalive_inverval: Duration::from_nanos(
                (root["tcp_keepalive_inverval"]
                    .as_f64()
                    .unwrap_or_else(|| 30f64)
                    * 1000_000_000f64) as u64,
            ),
            tcp_timeout: Duration::from_nanos(
                (root["tcp_timeout"].as_f64().unwrap_or_else(|| 300f64) * 1000_000_000f64) as u64,
            ),
            udp_timeout: Duration::from_nanos(
                (root["udp_timeout"].as_f64().unwrap_or_else(|| 60f64) * 1000_000_000f64) as u64,
            ),
            tcp_listener: TcpListener::from_std(
                build_socket_listener("tcp", bind_addr).unwrap().into(),
            )
            .unwrap(),
            udp_listener: UdpSocket::from_std(
                build_socket_listener("udp", bind_addr).unwrap().into(),
            )
            .unwrap(),
            fullcone_map: dashmap::DashMap::new(),
        });

        tokio::spawn(r#in.clone().tcp_start());
        tokio::spawn(r#in.clone().udp_start());
    }
}
