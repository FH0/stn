use super::*;
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
        let (own_tx, mut server_rx) = channel::<(String, Vec<u8>)>(100);
        let server_tx = crate::route::udp_bind(self.tag.clone(), saddr.clone(), own_tx)?;
        let (own_tx, mut client_rx) = channel::<(String, Vec<u8>)>(100);

        let (exit_or_update_timer_tx, mut exit_or_update_timer_rx) = channel::<bool>(1);
        // client
        let task1 = tokio::spawn({
            let exit_or_update_timer_tx = exit_or_update_timer_tx.clone();
            let self_clone = self.clone();
            let saddr = saddr.clone();
            async move {
                loop {
                    // read client
                    let (daddr, mut recv_data) = match client_rx.recv().await {
                        Some(s) => s,
                        None => {
                            debug!("{} {} close", self_clone.tag, saddr);
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

                    // write server
                    debug!(
                        "{} {} -> {} {}",
                        self_clone.tag,
                        saddr,
                        daddr,
                        recv_data.len()
                    );
                    let daddr_buf = match generate_daddr_buf(&daddr) {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} -> {} {}", self_clone.tag, saddr, daddr, e);
                            break;
                        }
                    };
                    recv_data.splice(..0, daddr_buf);
                    recv_data.splice(..0, vec![0, 0, 0]);
                    if let Err(_) = server_tx.send((self_clone.addr.clone(), recv_data)).await {
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

                    // read server
                    let (_, recv_data) = match server_rx.recv().await {
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

                    // write client
                    debug!(
                        "{} {} -> {} {}",
                        self_clone.tag,
                        daddr,
                        saddr,
                        recv_data.len() - (4 + daddr_len + 2)
                    );
                    if let Err(_) = client_tx
                        .send((daddr.clone(), recv_data[4 + daddr_len + 2..].to_vec()))
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
