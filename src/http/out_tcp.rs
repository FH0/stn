use super::*;
use log::*;
use std::sync::Arc;
use tokio::{
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
        let (own_tx, mut server_rx) = channel::<Vec<u8>>(1);
        debug!("{} {} -> {} connect", self.tag, saddr, daddr);
        let server_tx = timeout(
            self.tcp_timeout,
            crate::route::tcp_connect(self.tag.clone(), saddr.clone(), self.addr.clone(), own_tx),
        )
        .await??;
        let (own_tx, mut client_rx) = channel::<Vec<u8>>(1);

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

        let (exit_or_update_timer_tx, mut exit_or_update_timer_rx) = channel::<bool>(1);
        // client
        let task1 = tokio::spawn({
            let exit_or_update_timer_tx = exit_or_update_timer_tx.clone();
            let self_clone = self.clone();
            let saddr = saddr.clone();
            let daddr = daddr.clone();
            async move {
                loop {
                    // write server, buf.len() may not 0, write server first
                    debug!("{} {} -> {} {}", self_clone.tag, saddr, daddr, buf.len());
                    if let Err(_) = server_tx.send(buf.clone()).await {
                        debug!("{} {} -> {} close", self_clone.tag, saddr, daddr);
                        break;
                    }
                    buf.truncate(0);

                    // read client
                    let recv_data = match client_rx.recv().await {
                        Some(s) => s,
                        None => {
                            debug!("{} {} -> {} close", self_clone.tag, saddr, daddr);
                            break;
                        }
                    };
                    buf.extend(recv_data);

                    // update timer
                    exit_or_update_timer_tx.send(false).await.unwrap();
                }

                // exit
                exit_or_update_timer_tx.send(true).await.unwrap();
            }
        });
        // server
        let task2 = tokio::spawn({
            let self_clone = self.clone();
            let saddr = saddr.clone();
            let daddr = daddr.clone();
            async move {
                loop {
                    // read server
                    let recv_data = match server_rx.recv().await {
                        Some(s) => s,
                        None => {
                            debug!("{} {} -> {} close", self_clone.tag, daddr, saddr);
                            break;
                        }
                    };

                    // write client
                    debug!(
                        "{} {} -> {} {}",
                        self_clone.tag,
                        daddr,
                        saddr,
                        recv_data.len()
                    );
                    if let Err(_) = client_tx.send(recv_data).await {
                        debug!("{} {} -> {} close", self_clone.tag, daddr, saddr);
                        break;
                    }

                    // update timer
                    exit_or_update_timer_tx.send(false).await.unwrap();
                }

                // exit
                exit_or_update_timer_tx.send(true).await.unwrap();
            }
        });
        // timeout and others
        tokio::spawn({
            async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(self.tcp_timeout) => {
                            warn!("{} {} -> {} timeout", self.tag, saddr, daddr);
                            break;
                        },
                        exit = exit_or_update_timer_rx.recv() => {
                            if exit.unwrap() {
                                break;
                            } else {
                                continue;
                            }
                        },
                    };
                }

                task1.abort();
                task2.abort();
                let _ = task1.await;
                let _ = task2.await;
            }
        });

        Ok(own_tx)
    }
}
