use crate::origin::TCP_LEN;
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
        debug!("{} {} -> {} connect", self.tag, saddr, daddr);
        let mut server = timeout(self.tcp_timeout, TcpStream::connect(daddr.clone())).await??;
        server = crate::misc::set_nodelay_keepalive_interval(
            server,
            self.tcp_nodelay,
            self.tcp_keepalive_inverval,
        )?;
        let (mut server_rx, mut server_tx) = server.into_split();
        let (own_tx, mut client_rx) = channel::<Vec<u8>>(1);

        let (exit_or_update_timer_tx, mut exit_or_update_timer_rx) = channel::<bool>(1);
        // client
        let task1 = tokio::spawn({
            let exit_or_update_timer_tx = exit_or_update_timer_tx.clone();
            let self_clone = self.clone();
            let saddr = saddr.clone();
            let daddr = daddr.clone();
            async move {
                loop {
                    // read client
                    let recv_data = match client_rx.recv().await {
                        Some(s) => s,
                        None => {
                            debug!("{} {} -> {} close", self_clone.tag, saddr, daddr);
                            break;
                        }
                    };

                    // write server
                    debug!(
                        "{} {} -> {} {}",
                        self_clone.tag,
                        saddr,
                        daddr,
                        recv_data.len()
                    );
                    if let Err(e) = server_tx.write_all(&recv_data).await {
                        warn!("{} {} -> {} {}", self_clone.tag, saddr, daddr, e);
                        break;
                    }

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
                let mut buf = vec![0; TCP_LEN];
                loop {
                    // read server
                    let nread = match server_rx.read(&mut buf).await {
                        Ok(0) => {
                            debug!("{} {} -> {} close", self_clone.tag, daddr, saddr);
                            break;
                        }
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} -> {} {}", self_clone.tag, daddr, saddr, e);
                            break;
                        }
                    };

                    // write client
                    debug!("{} {} -> {} {}", self_clone.tag, daddr, saddr, nread);
                    if let Err(_) = client_tx.send(buf[..nread].to_vec()).await {
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
