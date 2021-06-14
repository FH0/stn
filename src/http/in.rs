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

            let client = match crate::misc::set_nodelay_keepalive_interval(
                client,
                self.tcp_nodelay,
                self.tcp_keepalive_inverval,
            ) {
                Ok(o) => o,
                Err(e) => {
                    warn!("{} {} {}", self.tag, saddr, e);
                    continue;
                }
            };

            tokio::spawn(
                self.clone()
                    .handle_handshake(client, socketaddr_to_string(&saddr)),
            );
        }
    }

    async fn handle_handshake(self: Arc<Self>, mut client: TcpStream, saddr: String) {
        let mut buf = vec![0u8; TCP_LEN];
        let mut buflen = 0usize;

        // recv
        let http_end_index = loop {
            let nread = match timeout(self.tcp_timeout, client.read(&mut buf[buflen..])).await {
                Ok(o) => match o {
                    Ok(o) => o,
                    Err(e) => {
                        warn!("{} {} {}", self.tag, saddr, e);
                        return;
                    }
                },
                Err(e) => {
                    warn!("{} {} {}", self.tag, saddr, e);
                    return;
                }
            };
            buflen += nread;
            match get_http_end_index(&buf[..buflen]) {
                Ok(o) => break o,
                Err(_) => continue,
            };
        };

        // get daddr
        let daddr = match get_http_addr(&buf[..http_end_index]) {
            Ok(o) => o,
            Err(e) => {
                warn!("{} {} {}", self.tag, saddr, e);
                return;
            }
        };

        // CONNECT
        if String::from_utf8_lossy(&buf[..http_end_index]).contains("CONNECT ") {
            // response
            match timeout(
                self.tcp_timeout,
                client.write_all("HTTP/1.1 200 Connection established\r\n\r\n".as_bytes()),
            )
            .await
            {
                Ok(o) => match o {
                    Ok(o) => o,
                    Err(e) => {
                        warn!("{} {} {}", self.tag, saddr, e);
                        return;
                    }
                },
                Err(e) => {
                    warn!("{} {} {}", self.tag, saddr, e);
                    return;
                }
            };

            memmove_buf(&mut buf, &mut buflen, http_end_index + 4);
        }

        self.handle_tcp(client, saddr, daddr, buf, buflen).await;
    }
}
