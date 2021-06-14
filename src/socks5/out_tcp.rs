use super::*;
use log::*;
use std::sync::Arc;
use tokio::{
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
        let (own_tx, mut server_rx) = channel::<Vec<u8>>(1);
        debug!("{} {} -> {} connect", self.tag, saddr, daddr);
        let server_tx = timeout(
            self.tcp_timeout,
            crate::route::tcp_connect(self.tag.clone(), saddr.clone(), self.addr.clone(), own_tx),
        )
        .await??;
        let (own_tx, mut client_rx) = channel::<Vec<u8>>(1);

        // +----+----------+----------+
        // |VER | NMETHODS | METHODS  |
        // +----+----------+----------+
        // | 1  |    1     | 1 to 255 |
        // +----+----------+----------+
        // o  X'00' NO AUTHENTICATION REQUIRED
        // o  X'01' GSSAPI
        // o  X'02' USERNAME/PASSWORD
        // o  X'03' to X'7F' IANA ASSIGNED
        // o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        // o  X'FF' NO ACCEPTABLE METHODS

        // send
        timeout(self.tcp_timeout, server_tx.send(vec![5, 1, 0])).await??;

        // +----+--------+
        // |VER | METHOD |
        // +----+--------+
        // | 1  |   1    |
        // +----+--------+

        // recv
        let recv_data = match timeout(self.tcp_timeout, server_rx.recv()).await? {
            Some(s) => s,
            None => Err("channel unexpected close")?,
        };
        if recv_data.len() != 2 || recv_data != vec![5, 0] {
            Err("recv_data.len() != 2 || recv_data != vec![5, 0]")?
        }

        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        // o  VER    protocol version: X'05'
        // o  CMD
        //    o  CONNECT X'01'
        //    o  BIND X'02'
        //    o  UDP ASSOCIATE X'03'
        // o  RSV    RESERVED
        // o  ATYP   address type of following address
        //    o  IP V4 address: X'01'
        //    o  DOMAINNAME: X'03'
        //    o  IP V6 address: X'04'
        // o  DST.ADDR       desired destination address
        // o  DST.PORT desired destination port in network octet
        //    order

        // send
        let mut daddr_buf = generate_daddr_buf(&daddr)?;
        daddr_buf.splice(..0, vec![5, 1, 0]);
        timeout(self.tcp_timeout, server_tx.send(daddr_buf)).await??;

        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        // o  VER    protocol version: X'05'
        // o  REP    Reply field:
        //    o  X'00' succeeded
        //    o  X'01' general SOCKS server failure
        //    o  X'02' connection not allowed by ruleset
        //    o  X'03' Network unreachable
        //    o  X'04' Host unreachable
        //    o  X'05' Connection refused
        //    o  X'06' TTL expired
        //    o  X'07' Command not supported
        //    o  X'08' Address type not supported
        //    o  X'09' to X'FF' unassigned
        // o  RSV    RESERVED
        // o  ATYP   address type of following address
        //    o  IP V4 address: X'01'
        //    o  DOMAINNAME: X'03'
        //    o  IP V6 address: X'04'
        // o  BND.ADDR       server bound address
        // o  BND.PORT       server bound port in network octet order

        // recv
        let mut buf = Vec::new();
        while buf.len() < 4
            || buf.len()
                < 4 + match buf[3] {
                    ATYP_IPV4 => 4,
                    ATYP_DOMAIN => {
                        if buf.len() < 5 {
                            1
                        } else {
                            1 + buf[4] as usize
                        }
                    }
                    ATYP_IPV6 => 16,
                    _ => Err(format!("{} {} unsupport ATYP:{}", self.tag, saddr, buf[3]))?,
                } + 2
        {
            let recv_data = match timeout(self.tcp_timeout, server_rx.recv()).await? {
                Some(s) => s,
                None => Err("channel unexpected close")?,
            };
            buf.extend(recv_data);
        }
        // check version
        if buf[0] != 5 {
            Err(format!(
                "{} {} unsupport socks version:{}",
                self.tag, saddr, buf[0]
            ))?
        }
        // check reply
        if buf[1] != 0 {
            Err("socks5 reply not succeeded")?
        }
        buf.drain(
            ..4 + match buf[3] {
                ATYP_IPV4 => 4,
                ATYP_DOMAIN => {
                    if buf.len() < 5 {
                        1
                    } else {
                        1 + buf[4] as usize
                    }
                }
                ATYP_IPV6 => 16,
                _ => Err(format!("{} {} unsupport ATYP:{}", self.tag, saddr, buf[3]))?,
            } + 2,
        );

        let (exit_or_update_timer_tx, mut exit_or_update_timer_rx) = channel::<bool>(1);
        // client
        let task1 = tokio::spawn({
            let exit_or_update_timer_tx = exit_or_update_timer_tx.clone();
            let self_clone = self.clone();
            let saddr = saddr.clone();
            let daddr = daddr.clone();
            async move {
                loop {
                    // write server, buf.len() may not 0, write server first
                    debug!("{} {} -> {} {}", self_clone.tag, saddr, daddr, buf.len());
                    if let Err(_) = server_tx.send(buf.clone()).await {
                        debug!("{} {} -> {} close", self_clone.tag, saddr, daddr);
                        break;
                    }
                    buf.truncate(0);

                    // read client
                    let recv_data = match client_rx.recv().await {
                        Some(s) => s,
                        None => {
                            debug!("{} {} -> {} close", self_clone.tag, saddr, daddr);
                            break;
                        }
                    };
                    buf.extend(recv_data);

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
                    if let Err(_) = client_tx.send(recv_data).await {
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
