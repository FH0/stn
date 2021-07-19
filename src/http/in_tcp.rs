use super::*;
use log::*;
use std::sync::Arc;
use stn_http_proxy_server::Stream;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

impl super::In {
    pub(crate) async fn handle_handshake<T>(
        self: Arc<Self>,
        client: T,
        saddr: String,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (client, daddr) = Stream::new(client).await?;

        // connect
        let (mut client_rx, mut client_tx) = tokio::io::split(client);
        let (server_tx, mut server_rx) = timeout(
            self.tcp_timeout,
            crate::route::tcp_connect(self.tag.clone(), saddr.clone(), daddr.clone()),
        )
        .await??;

        let mut buf = vec![0; TCP_LEN];
        tokio::spawn(async move {
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

        Ok(())
    }
}
