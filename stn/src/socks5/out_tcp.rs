use super::*;
use log::*;
use std::sync::Arc;
use tokio::time::timeout;

#[async_trait::async_trait]
impl crate::route::OutTcp for super::Out {
    async fn tcp_connect(
        self: Arc<Self>,
        saddr: String,
        daddr: String,
        client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        mut client_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // connect
        let (server_tx, mut server_rx) = timeout(
            self.tcp_timeout,
            crate::route::tcp_connect(self.tag.clone(), saddr.clone(), self.addr.clone()),
        )
        .await??;

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
        let recv_data = timeout(self.tcp_timeout, server_rx.recv())
            .await?
            .ok_or("channel unexpected close")?;
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

        tokio::spawn(async move {
            let mut buf = vec![0; TCP_LEN];
            match bidirectional_with_timeout!(
                {
                    // write server, buf.len() may not 0, write server first
                    debug!("{} {} -> {} {}", self.tag, saddr, daddr, buf.len());
                    server_tx.send(buf.clone()).await.or(Err("close"))?;
                    buf.resize(0, 0);

                    // read client
                    let recv_data = client_rx.recv().await.ok_or("close")?;
                    buf.extend(recv_data);
                },
                {
                    // read server
                    let recv_data = server_rx.recv().await.ok_or("close")?;

                    // write client
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, recv_data.len());
                    client_tx.send(recv_data).await.or(Err("close"))?;
                },
                self.tcp_timeout
            ) {
                // client or timeout error
                (Err(e), _, _) | (_, _, Err(e)) => {
                    let e = e.to_string();
                    if e.as_str() == "close" {
                        debug!("{} {} -> {} {}", self.tag, saddr, daddr, e)
                    } else {
                        warn!("{} {} -> {} {}", self.tag, saddr, daddr, e)
                    }
                }
                // server error
                (_, Err(e), _) => {
                    let e = e.to_string();
                    if e.as_str() == "close" {
                        debug!("{} {} -> {} {}", self.tag, daddr, saddr, e)
                    } else {
                        warn!("{} {} -> {} {}", self.tag, daddr, saddr, e)
                    }
                }
                _ => unreachable!(),
            }
        });

        Ok(())
    }
}
