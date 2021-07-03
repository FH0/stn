use super::*;
use crate::misc::socketaddr_to_string;
use log::*;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

impl super::In {
    pub(crate) async fn tcp_start(self: Arc<Self>) {
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

            tokio::spawn(
                self.clone()
                    .handle_tcp(client, socketaddr_to_string(&saddr)),
            );
        }
    }

    pub(crate) async fn handle_tcp(self: Arc<Self>, client: TcpStream, saddr: String) {
        // daddr = saddr
        let daddr = saddr.clone();

        // connect
        let (mut client_rx, mut client_tx) = client.into_split();
        debug!("{} {} -> {} connect", self.tag, saddr, daddr);
        let (server_tx, mut server_rx) = match timeout(
            self.tcp_timeout,
            crate::route::tcp_connect(self.tag.clone(), saddr.clone(), daddr.clone()),
        )
        .await
        {
            Ok(o) => match o {
                Ok(o) => o,
                Err(e) => {
                    warn!("{} {} -> {} {}", self.tag, saddr, daddr, e);
                    return;
                }
            },
            Err(e) => {
                warn!("{} {} -> {} {}", self.tag, saddr, daddr, e);
                return;
            }
        };

        tokio::spawn(async move {
            let mut buf = vec![0; TCP_LEN];
            match bidirectional_with_timeout!(
                {
                    // read client
                    let nread = client_rx.read(&mut buf).await?;
                    if nread == 0 {
                        Err("close")?
                    }

                    // write server
                    debug!("{} {} -> {} {}", self.tag, saddr, daddr, nread);
                    server_tx
                        .send(buf[..nread].to_vec())
                        .await
                        .or(Err("close"))?;
                },
                {
                    // read server
                    let recv_data = server_rx.recv().await.ok_or("close")?;

                    // write client
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, recv_data.len());
                    client_tx.write_all(&recv_data).await?;
                },
                self.tcp_timeout
            ) {
                // client or timeout error
                (Err(e), _, _) | (_, _, Err(e)) => {
                    let e = e.to_string();
                    if e.as_str() == "close" {
                        debug!("{} {} -> {} {}", self.tag, saddr, daddr, e)
                    } else {
                        warn!("{} {} -> {} {}", self.tag, saddr, daddr, e)
                    }
                }
                // server error
                (_, Err(e), _) => {
                    let e = e.to_string();
                    if e.as_str() == "close" {
                        debug!("{} {} -> {} {}", self.tag, daddr, saddr, e)
                    } else {
                        warn!("{} {} -> {} {}", self.tag, daddr, saddr, e)
                    }
                }
                _ => unreachable!(),
            }
        });
    }
}
