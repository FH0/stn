use super::http::*;
use crate::misc::{build_socket_listener, memmove_buf, socketaddr_to_string};
use log::*;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

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
                        warn!("{} {} {}", self_clone.tag, saddr, e);
                    }
                }
            });
        }
    }

    async fn handle_handshake(
        self: Arc<Self>,
        mut client: TcpStream,
        saddr: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0u8; TCP_LEN];

        // get daddr
        let mut buflen = timeout(self.tcp_timeout, client.read(&mut buf)).await??;
        let daddr = get_http_addr(&buf[..buflen])?;

        // CONNECT
        if String::from_utf8_lossy(&buf[..buflen]).contains("CONNECT ") {
            // response
            timeout(
                self.tcp_timeout,
                client.write_all("HTTP/1.1 200 Connection established\r\n\r\n".as_bytes()),
            )
            .await??;

            let http_end_index = get_http_end_index(&buf[..buflen])?;
            memmove_buf(&mut buf, &mut buflen, http_end_index + 4);
        }

        if let Err(e) = self
            .clone()
            .handle_tcp(client, saddr.clone(), daddr.clone(), buf, buflen)
            .await
        {
            warn!("{} {} -> {} {}", self.tag, saddr, daddr, e);
        }

        Ok(())
    }
}
