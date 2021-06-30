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

        tokio::spawn(async move {
            match bidirectional_with_timeout!(
                {
                    // read client
                    let (daddr, mut recv_data) = client_rx.recv().await.ok_or("close")?;

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
                    debug!("{} {} -> {} {}", self.tag, saddr, daddr, recv_data.len());
                    let daddr_buf = generate_daddr_buf(&daddr)?;
                    recv_data.splice(..0, daddr_buf);
                    recv_data.splice(..0, vec![0, 0, 0]);
                    server_tx
                        .send((self.addr.clone(), recv_data))
                        .await
                        .or(Err("close"))?;
                },
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

                    // read server
                    let (_, recv_data) = server_rx.recv().await.ok_or("close")?;
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

                    // write client
                    debug!(
                        "{} {} -> {} {}",
                        self.tag,
                        daddr,
                        saddr,
                        recv_data.len() - (4 + daddr_len + 2)
                    );
                    client_tx
                        .send((daddr.clone(), recv_data[4 + daddr_len + 2..].to_vec()))
                        .await
                        .or(Err("close"))?;
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

        Ok(own_tx)
    }
}
