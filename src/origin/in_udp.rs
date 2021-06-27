use super::*;
use crate::misc::socketaddr_to_string;
use log::*;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver};

impl In {
    pub(crate) async fn udp_start(self: Arc<Self>) {
        let mut buf = vec![0u8; UDP_LEN];

        loop {
            // recv
            let (nrecv, saddr) = match self.udp_listener.recv_from(&mut buf).await {
                Ok(o) => o,
                Err(e) => {
                    info!("{}", e);
                    continue;
                }
            };
            let saddr = socketaddr_to_string(&saddr);

            // get server_tx or new a task
            let server_tx = if let Some(s) = self.fullcone_map.get(&saddr) {
                s.value().clone()
            } else {
                let (own_tx, own_rx) = channel::<Vec<u8>>(100);
                self.fullcone_map.insert(saddr.clone(), own_tx.clone());
                tokio::spawn(self.clone().handle_udp(saddr.clone(), own_rx));
                own_tx
            };

            // send
            if let Err(e) = server_tx.try_send(buf[..nrecv].to_vec()) {
                warn!("{} {} {}", self.tag, saddr, e);
                continue;
            }
        }
    }

    async fn handle_udp(self: Arc<Self>, saddr: String, mut client_rx: Receiver<Vec<u8>>) {
        // daddr = saddr
        let daddr = saddr.clone();

        // bind
        let (own_tx, mut server_rx) = channel::<(String, Vec<u8>)>(100);
        let server_tx = match crate::route::udp_bind(self.tag.clone(), saddr.clone(), own_tx) {
            Ok(o) => o,
            Err(e) => {
                warn!("{} {} {}", self.tag, saddr, e);
                return;
            }
        };

        let (exit_or_update_timer_tx, mut exit_or_update_timer_rx) = channel::<bool>(1);
        // client
        let task1 = tokio::spawn({
            let exit_or_update_timer_tx = exit_or_update_timer_tx.clone();
            let self_clone = self.clone();
            let saddr = saddr.clone();
            async move {
                loop {
                    // read client
                    let recv_data = match client_rx.recv().await {
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
                    if let Err(_) = server_tx.send((daddr.clone(), recv_data)).await {
                        debug!("{} {} -> {} close", self_clone.tag, saddr, daddr);
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
                loop {
                    // read server
                    let (daddr, recv_data) = match server_rx.recv().await {
                        Some(s) => s,
                        None => {
                            warn!("{} {} close", self_clone.tag, saddr);
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
                    if let Err(e) = self_clone
                        .udp_listener
                        .send_to(&recv_data, saddr.clone())
                        .await
                    {
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
                        _ = tokio::time::sleep(self.udp_timeout) => {
                            debug!("{} {} timeout", self.tag, saddr);
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

                // delete from fullcone_map
                self.fullcone_map.remove(&saddr);

                task1.abort();
                task2.abort();
                let _ = task1.await;
                let _ = task2.await;
            }
        });
    }
}
