use super::{socks5::*, In};
use crate::misc::socketaddr_to_string;
use log::*;
use std::sync::Arc;
use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, Receiver},
};

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

            // if not contains, add it
            if !self.fullcone_map.contains_key(&saddr) {
                let (own_tx, own_rx) = channel::<Vec<u8>>(100);
                self.fullcone_map.insert(saddr.clone(), own_tx);
                tokio::spawn(self.clone().handle_socks5_udp(saddr.clone(), own_rx));
            }

            // send without blocking, that's why channel has buffer
            let server_tx = match self.fullcone_map.get(&saddr) {
                Some(s) => s,
                None => {
                    warn!("{} {} server_tx is None", self.tag, saddr);
                    continue;
                }
            };
            if let Err(e) = server_tx.try_send(buf[..nrecv].to_vec()) {
                warn!("{} {} {}", self.tag, saddr, e);
                continue;
            }
        }
    }

    async fn handle_socks5_udp(self: Arc<Self>, saddr: String, mut client_rx: Receiver<Vec<u8>>) {
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
                    // +----+------+------+----------+----------+----------+
                    // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
                    // +----+------+------+----------+----------+----------+
                    // | 2  |  1   |  1   | Variable |    2     | Variable |
                    // +----+------+------+----------+----------+----------+
                    // o  RSV  Reserved X'0000'
                    // o  FRAG    Current fragment number
                    // o  ATYP    address type of following addresses:
                    //    o  IP V4 address: X'01'
                    //    o  DOMAINNAME: X'03'
                    //    o  IP V6 address: X'04'
                    // o  DST.ADDR       desired destination address
                    // o  DST.PORT       desired destination port
                    // o  DATA     user data

                    // read client
                    let recv_data = match client_rx.recv().await {
                        Some(s) => s,
                        None => {
                            debug!("{} {} close", self_clone.tag, saddr);
                            break;
                        }
                    };
                    // check length
                    if recv_data.len() < 4
                        || recv_data.len()
                            < 4 + match recv_data[3] {
                                ATYP_IPV4 => 4,
                                ATYP_DOMAIN => {
                                    if recv_data.len() < 5 {
                                        1
                                    } else {
                                        1 + recv_data[4] as usize
                                    }
                                }
                                ATYP_IPV6 => 16,
                                _ => {
                                    warn!(
                                        "{} {} unsupport ATYP:{}",
                                        self_clone.tag, saddr, recv_data[3]
                                    );
                                    continue;
                                }
                            } + 2
                    {
                        warn!("{} {} length not enough", self_clone.tag, saddr);
                        continue;
                    }
                    // not support FRAG
                    if recv_data[2] != 0 {
                        warn!("{} {} not support FRAG", self_clone.tag, saddr);
                        continue;
                    }
                    // get daddr
                    let (daddr, daddr_len) = match get_daddr(&recv_data[3..]) {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} {}", self_clone.tag, saddr, e);
                            continue;
                        }
                    };

                    // write server
                    debug!(
                        "{} {} -> {} {}",
                        self_clone.tag,
                        saddr,
                        daddr,
                        recv_data.len() - (4 + daddr_len + 2)
                    );
                    if let Err(_) = server_tx
                        .send((daddr.clone(), recv_data[4 + daddr_len + 2..].to_vec()))
                        .await
                    {
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

                    // +----+------+------+----------+----------+----------+
                    // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
                    // +----+------+------+----------+----------+----------+
                    // | 2  |  1   |  1   | Variable |    2     | Variable |
                    // +----+------+------+----------+----------+----------+
                    // o  RSV  Reserved X'0000'
                    // o  FRAG    Current fragment number
                    // o  ATYP    address type of following addresses:
                    //    o  IP V4 address: X'01'
                    //    o  DOMAINNAME: X'03'
                    //    o  IP V6 address: X'04'
                    // o  DST.ADDR       desired destination address
                    // o  DST.PORT       desired destination port
                    // o  DATA     user data

                    // write client
                    debug!(
                        "{} {} -> {} {}",
                        self_clone.tag,
                        daddr,
                        saddr,
                        recv_data.len()
                    );
                    let daddr_buf = match generate_daddr_buf(&daddr) {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} -> {} {}", self_clone.tag, daddr, saddr, e);
                            continue;
                        }
                    };
                    let mut buf = vec![0u8, 0, 0];
                    buf.extend(daddr_buf);
                    buf.extend(recv_data);
                    if let Err(e) = self_clone.udp_listener.send_to(&buf, saddr.clone()).await {
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
    }

    #[inline]
    pub(crate) async fn handle_udp(self: Arc<Self>, client: TcpStream) {
        // when readable again, must be closed
        let _ = client.readable().await;
    }
}
