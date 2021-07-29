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
                let (own_tx, own_rx) = channel(100);
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
                    let recv_data = client_rx.recv().await.ok_or("close")?;

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
                    self.udp_listener.send_to(&recv_data, saddr.clone()).await?;
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
