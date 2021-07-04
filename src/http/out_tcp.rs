use super::*;
use log::*;
use std::sync::Arc;
use tokio::time::timeout;

#[async_trait::async_trait]
impl crate::route::OutTcp for super::Out {
    async fn tcp_connect(
        self: Arc<Self>,
        saddr: String,
        daddr: String,
        client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        mut client_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // connect
        let (server_tx, mut server_rx) = timeout(
            self.tcp_timeout,
            crate::route::tcp_connect(self.tag.clone(), saddr.clone(), self.addr.clone()),
        )
        .await??;

        // send
        let connect_buf = format!(
            "CONNECT {} HTTP/1.1\r\nProxy-Connection: Keep-Alive\r\n\r\n",
            daddr
        )
        .as_bytes()
        .to_vec();
        timeout(self.tcp_timeout, server_tx.send(connect_buf)).await??;

        // recv
        let recv_data = match timeout(self.tcp_timeout, server_rx.recv()).await? {
            Some(s) => s,
            None => Err("channel unexpected close")?,
        };
        let mut buf = recv_data;
        is_http_response_successful(&buf)?;
        let http_end_index = get_http_end_index(&buf)?;
        buf.drain(..http_end_index + 4);

        tokio::spawn(async move {
            let mut buf = vec![0; TCP_LEN];
            match bidirectional_with_timeout!(
                {
                    // write server, buf.len() may not 0, write server first
                    debug!("{} {} -> {} {}", self.tag, saddr, daddr, buf.len());
                    server_tx.send(buf.clone()).await.or(Err("close"))?;
                    buf.resize(0, 0);

                    // read client
                    let recv_data = client_rx.recv().await.ok_or("close")?;
                    buf.extend(recv_data);
                },
                {
                    // read server
                    let recv_data = server_rx.recv().await.ok_or("close")?;

                    // write client
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, recv_data.len());
                    client_tx.send(recv_data).await.or(Err("close"))?;
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
