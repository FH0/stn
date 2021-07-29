use super::*;
use crate::misc::socketaddr_to_string;
use log::*;
use std::sync::Arc;
use stn_tproxy::UdpSocket;
use tokio::sync::mpsc::{self, Receiver};

impl In {
    pub(crate) async fn udp_start(self: Arc<Self>) {
        let mut buf = vec![0u8; UDP_LEN];

        loop {
            let (nrecv, saddr, daddr) = match self.udp_listener.recv_from(&mut buf).await {
                Ok(o) => o,
                Err(e) => {
                    warn!("{}", e);
                    continue;
                }
            };
            let saddr = socketaddr_to_string(&saddr);
            let daddr = socketaddr_to_string(&daddr);

            // get server_tx or new a task
            let server_tx = if let Some(s) = self.fullcone_map.get(&saddr) {
                s.value().clone()
            } else {
                let (own_tx, own_rx) = mpsc::channel(100);
                self.fullcone_map.insert(saddr.clone(), own_tx.clone());
                tokio::spawn(self.clone().handle_udp(saddr.clone(), own_rx));
                own_tx
            };

            // send
            if let Err(e) = server_tx.try_send((daddr.clone(), buf[..nrecv].to_vec())) {
                warn!("{} {} -> {} {}", self.tag, saddr, daddr, e);
                continue;
            }
        }
    }

    async fn handle_udp(
        self: Arc<Self>,
        saddr: String,
        mut client_rx: Receiver<(String, Vec<u8>)>,
    ) {
        // bind
        let (server_tx, mut server_rx) =
            match crate::route::udp_bind(self.tag.clone(), saddr.clone()) {
                Ok(o) => o,
                Err(e) => {
                    warn!("{} {} {}", self.tag, saddr, e);
                    return;
                }
            };

        tokio::spawn(async move {
            match bidirectional_with_timeout!(
                {
                    // read client
                    let (daddr, recv_data) = client_rx.recv().await.ok_or("close")?;

                    // write server
                    debug!("{} {} -> {} {}", self.tag, saddr, daddr, recv_data.len());
                    server_tx
                        .send((daddr.clone(), recv_data))
                        .await
                        .or(Err("close"))?;
                },
                {
                    // read server
                    let (daddr, recv_data) = server_rx.recv().await.ok_or("close")?;

                    // write client
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, recv_data.len());
                    UdpSocket::bind_send_to(daddr, &recv_data, saddr.clone()).await?;
                },
                self.udp_timeout
            ) {
                (Err(e), _, _) | (_, _, Err(e)) | (_, Err(e), _) => {
                    let e = e.to_string();
                    if e.as_str() == "close" || e.as_str() == "timeout" {
                        debug!("{} {} {}", self.tag, saddr, e)
                    } else {
                        warn!("{} {} {}", self.tag, saddr, e)
                    }
                }
                _ => unreachable!(),
            }

            // delete from fullcone_map
            self.fullcone_map.remove(&saddr);
        });
    }
}
