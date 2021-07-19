use crate::misc::{build_socket_listener, socketaddr_to_string};
use log::*;
use std::{sync::Arc, time::Duration};
use tokio::net::TcpListener;

pub(crate) struct In {
    pub(crate) tag: String,
    pub(crate) tcp_nodelay: bool,
    pub(crate) tcp_keepalive_inverval: Duration,
    pub(crate) tcp_timeout: Duration,
    pub(crate) tcp_listener: TcpListener,
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
            tcp_listener: TcpListener::from_std(
                build_socket_listener("tcp", bind_addr).unwrap().into(),
            )
            .unwrap(),
        });

        tokio::spawn(r#in.clone().listen());
    }

    async fn listen(self: Arc<Self>) {
        loop {
            let (client, saddr) = match self.tcp_listener.accept().await {
                Ok(o) => o,
                Err(e) => {
                    warn!("{}", e);
                    continue;
                }
            };

            if let Err(e) = crate::misc::set_nodelay_keepalive_interval(
                &client,
                self.tcp_nodelay,
                self.tcp_keepalive_inverval,
            ) {
                warn!("{} {} {}", self.tag, saddr, e);
                continue;
            }

            tokio::spawn({
                let self_clone = self.clone();
                async move {
                    let saddr = socketaddr_to_string(&saddr);
                    if let Err(e) = self_clone
                        .clone()
                        .handle_handshake(client, saddr.clone())
                        .await
                    {
                        let e = e.to_string();
                        if e.contains("close") {
                            debug!("{} {} {}", self_clone.tag, saddr, e);
                        } else {
                            warn!("{} {} {}", self_clone.tag, saddr, e);
                        }
                    }
                }
            });
        }
    }
}
