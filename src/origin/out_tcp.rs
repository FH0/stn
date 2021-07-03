use super::*;
use log::*;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::{channel, Sender},
    time::timeout,
};

#[async_trait::async_trait]
impl crate::route::OutTcp for super::Out {
    async fn tcp_connect(
        self: Arc<Self>,
        saddr: String,
        daddr: String,
        client_tx: Sender<Vec<u8>>,
    ) -> Result<Sender<Vec<u8>>, Box<dyn std::error::Error>> {
        // connect
        let daddr_ip = crate::resolve::resolve(&daddr).await?;
        let server = timeout(self.tcp_timeout, TcpStream::connect(daddr_ip)).await??;
        crate::misc::set_nodelay_keepalive_interval(
            &server,
            self.tcp_nodelay,
            self.tcp_keepalive_inverval,
        )?;
        let (mut server_rx, mut server_tx) = server.into_split();
        let (own_tx, mut client_rx) = channel::<Vec<u8>>(1);

        tokio::spawn(async move {
            let mut buf = vec![0; TCP_LEN];
            match bidirectional_with_timeout!(
                {
                    // read client
                    let recv_data = client_rx.recv().await.ok_or("close")?;

                    // write server
                    debug!("{} {} -> {} {}", self.tag, saddr, daddr, recv_data.len());
                    server_tx.write_all(&recv_data).await?;
                },
                {
                    // read server
                    let nread = server_rx.read(&mut buf).await?;
                    if nread == 0 {
                        Err("close")?
                    }

                    // write client
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, nread);
                    client_tx
                        .send(buf[..nread].to_vec())
                        .await
                        .or(Err("close"))?;
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

        Ok(own_tx)
    }
}
