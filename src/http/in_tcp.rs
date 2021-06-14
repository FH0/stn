use log::*;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::channel,
    time::timeout,
};

impl super::In {
    pub(crate) async fn handle_tcp(
        self: Arc<Self>,
        client: TcpStream,
        saddr: String,
        daddr: String,
        mut buf: Vec<u8>,
        mut buflen: usize,
    ) {
        // connect
        let (mut client_rx, mut client_tx) = client.into_split();
        let (own_tx, mut server_rx) = channel::<Vec<u8>>(1);
        debug!("{} {} -> {} connect", self.tag, saddr, daddr);
        let server_tx = match timeout(
            self.tcp_timeout,
            crate::route::tcp_connect(self.tag.clone(), saddr.clone(), daddr.clone(), own_tx),
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

        let (exit_or_update_timer_tx, mut exit_or_update_timer_rx) = channel::<bool>(1);
        // client
        let task1 = tokio::spawn({
            let exit_or_update_timer_tx = exit_or_update_timer_tx.clone();
            let self_clone = self.clone();
            let saddr = saddr.clone();
            let daddr = daddr.clone();
            async move {
                loop {
                    // write server, buflen may not 0, so write first
                    if buflen != 0 {
                        debug!("{} {} -> {} {}", self_clone.tag, saddr, daddr, buflen);
                        if let Err(_) = server_tx.send(buf[..buflen].to_vec()).await {
                            debug!("{} {} -> {} close", self_clone.tag, saddr, daddr);
                            break;
                        }
                        buflen = 0;
                    }

                    // read client
                    let nread = match client_rx.read(&mut buf[buflen..]).await {
                        Ok(0) => {
                            debug!("{} {} -> {} close", self_clone.tag, saddr, daddr);
                            break;
                        }
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} {}", self_clone.tag, saddr, e);
                            break;
                        }
                    };
                    buflen += nread;

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
                    if let Err(e) = client_tx.write_all(&recv_data).await {
                        warn!("{} {} -> {} {}", self_clone.tag, daddr, saddr, e);
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
    }
}
