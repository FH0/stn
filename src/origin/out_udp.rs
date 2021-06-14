use crate::{
    misc::{build_socketaddrv6, socketaddr_to_string},
    origin::UDP_LEN,
};
use log::*;
use std::sync::Arc;
use tokio::sync::mpsc::channel;

#[async_trait::async_trait]
impl crate::route::OutUdp for super::Out {
    async fn udp_bind(
        self: Arc<Self>,
        saddr: String,
        client_tx: tokio::sync::mpsc::Sender<(String, Vec<u8>)>,
    ) -> Result<tokio::sync::mpsc::Sender<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
        // bind
        let server = Arc::new(tokio::net::UdpSocket::from_std(
            crate::misc::build_socket_listener("udp", "[::]:0")?.into(),
        )?);
        let (own_tx, mut client_rx) = channel::<(String, Vec<u8>)>(100);

        let (exit_or_update_timer_tx, mut exit_or_update_timer_rx) = channel::<bool>(1);
        // client
        let task1 = tokio::spawn({
            let exit_or_update_timer_tx = exit_or_update_timer_tx.clone();
            let server = server.clone();
            let self_clone = self.clone();
            let saddr = saddr.clone();
            async move {
                loop {
                    // read client
                    let (daddr, recv_data) = match client_rx.recv().await {
                        Some(s) => s,
                        None => {
                            debug!("{} {} close", self_clone.tag, saddr);
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
                    let daddr_v6 = match build_socketaddrv6(daddr.clone()) {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} -> {} {}", self_clone.tag, saddr, daddr, e);
                            break;
                        }
                    };
                    if let Err(e) = server.send_to(&recv_data, daddr_v6).await {
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
            async move {
                let mut buf = vec![0; UDP_LEN];
                loop {
                    // read server
                    let (nrecv, daddr) = match server.recv_from(&mut buf).await {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} {}", self_clone.tag, saddr, e);
                            break;
                        }
                    };
                    let daddr = socketaddr_to_string(&daddr);

                    // write client
                    debug!("{} {} -> {} {}", self_clone.tag, daddr, saddr, nrecv);
                    if let Err(_) = client_tx
                        .send((daddr.to_string(), buf[..nrecv].to_vec()))
                        .await
                    {
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
                        _ = tokio::time::sleep(self.udp_timeout) => {
                            warn!("{} {} timeout", self.tag, saddr);
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
