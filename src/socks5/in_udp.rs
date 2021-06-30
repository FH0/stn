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

            // get server_tx or new a task
            let server_tx = if let Some(s) = self.fullcone_map.get(&saddr) {
                s.value().clone()
            } else {
                let (own_tx, own_rx) = channel::<Vec<u8>>(100);
                self.fullcone_map.insert(saddr.clone(), own_tx.clone());
                tokio::spawn(self.clone().handle_socks5_udp(saddr.clone(), own_rx));
                own_tx
            };

            // send
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

        tokio::spawn(async move {
            match bidirectional_with_timeout!(
                {
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
                    let recv_data = client_rx.recv().await.ok_or("close")?;
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
                                    warn!("{} {} unsupport ATYP:{}", self.tag, saddr, recv_data[3]);
                                    continue;
                                }
                            } + 2
                    {
                        warn!("{} {} length not enough", self.tag, saddr);
                        continue;
                    }
                    // not support FRAG
                    if recv_data[2] != 0 {
                        warn!("{} {} not support FRAG", self.tag, saddr);
                        continue;
                    }
                    // get daddr
                    let (daddr, daddr_len) = get_daddr(&recv_data[3..])?;

                    // write server
                    debug!(
                        "{} {} -> {} {}",
                        self.tag,
                        saddr,
                        daddr,
                        recv_data.len() - (4 + daddr_len + 2)
                    );
                    server_tx
                        .send((daddr.clone(), recv_data[4 + daddr_len + 2..].to_vec()))
                        .await
                        .or(Err("close"))?;
                },
                {
                    // read server
                    let (daddr, recv_data) = server_rx.recv().await.ok_or("close")?;

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
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, recv_data.len());
                    let daddr_buf = generate_daddr_buf(&daddr)?;
                    let mut buf = vec![0u8, 0, 0];
                    buf.extend(daddr_buf);
                    buf.extend(recv_data);
                    self.udp_listener.send_to(&buf, saddr.clone()).await?;
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
        });
    }

    #[inline]
    pub(crate) async fn handle_udp(self: Arc<Self>, client: TcpStream) {
        // when readable again, must be closed
        let _ = client.readable().await;
    }
}
