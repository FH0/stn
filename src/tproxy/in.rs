use crate::misc::build_socket_listener;
use std::{net::SocketAddr, os::unix::prelude::AsRawFd, sync::Arc, time::Duration};
use stn_tproxy::UdpSocket;
use tokio::{net::TcpListener, sync::mpsc::Sender};

pub(crate) const TCP_LEN: usize = 8192;
pub(crate) const UDP_LEN: usize = 1500;

pub(crate) struct In {
    pub(crate) tag: String,
    pub(crate) tcp_nodelay: bool,
    pub(crate) tcp_keepalive_inverval: Duration,
    pub(crate) tcp_timeout: Duration,
    pub(crate) udp_timeout: Duration,
    pub(crate) tcp_listener: TcpListener,
    pub(crate) udp_listener: UdpSocket,
    pub(crate) fullcone_map: dashmap::DashMap<String, Sender<(String, Vec<u8>)>>,
}

impl In {
    pub(crate) async fn start(root: serde_json::Value) {
        let bind_addr = root["address"].as_str().expect("address not found");
        let ipv6_only = !bind_addr
            .parse::<SocketAddr>()
            .expect("invalid bind_addr")
            .is_ipv6();

        let udp_listener = UdpSocket::bind(bind_addr, ipv6_only).await.unwrap();
        let r#in = In {
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
            udp_listener,
            fullcone_map: dashmap::DashMap::new(),
        };

        stn_tproxy::enable_transparent(r#in.tcp_listener.as_raw_fd(), true, !ipv6_only).unwrap();

        let r#in = Arc::new(r#in);
        tokio::spawn(r#in.clone().listen());
        tokio::spawn(r#in.clone().udp_start());
    }
}
