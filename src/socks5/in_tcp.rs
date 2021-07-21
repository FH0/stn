use super::*;
use log::*;
use std::sync::Arc;
use stn_buf::VecBuf;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

impl super::In {
    pub(crate) async fn handle_tcp(
        self: Arc<Self>,
        client: TcpStream,
        saddr: String,
        mut buf: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

        // get daddr
        let (daddr, daddr_len) = get_daddr(&buf[3..])?;
        buf.drain(..4 + daddr_len + 2);

        // connect
        let (mut client_rx, mut client_tx) = client.into_split();
        let (server_tx, mut server_rx) = timeout(
            self.tcp_timeout,
            crate::route::tcp_connect(self.tag.clone(), saddr.clone(), daddr.clone()),
        )
        .await??;

        tokio::spawn(async move {
            match bidirectional_with_timeout!(
                {
                    // write server, buf.len() may not 0, so write first
                    if buf.len() != 0 {
                        debug!("{} {} -> {} {}", self.tag, saddr, daddr, buf.len());
                        server_tx.send(buf.to_vec()).await.or(Err("close"))?;
                        buf.drain(..);
                    }

                    // read client
                    let nread = client_rx.read(unsafe { buf.remain_mut() }).await?;
                    if nread == 0 {
                        Err("close")?
                    }
                    unsafe { buf.add_len(nread) }
                },
                {
                    // read server
                    let recv_data = server_rx.recv().await.ok_or("close")?;

                    // write client
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, recv_data.len());
                    client_tx.write_all(&recv_data).await?;
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
