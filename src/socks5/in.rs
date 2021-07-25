use super::*;
use crate::misc::{build_socket_listener, socketaddr_to_string};
use bytes::BufMut;
use log::*;
use std::{sync::Arc, time::Duration};
use stn_buf::VecBuf;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc::Sender,
    time::timeout,
};

pub(crate) struct In {
    pub(crate) tag: String,
    pub(crate) tcp_nodelay: bool,
    pub(crate) tcp_keepalive_inverval: Duration,
    pub(crate) tcp_timeout: Duration,
    pub(crate) udp_timeout: Duration,
    pub(crate) tcp_listener: TcpListener,
    pub(crate) udp_listener: UdpSocket,
    pub(crate) fullcone_map: dashmap::DashMap<String, Sender<Vec<u8>>>,
}

impl In {
    pub(crate) async fn start(root: serde_json::Value) {
        let bind_addr = root["address"].as_str().expect("address not found");

        let r#in = Arc::new(In {
            tag: root["tag"].as_str().expect("tag not found").to_string(),
            tcp_nodelay: root["tcp_nodelay"].as_bool().unwrap_or_else(|| true),
            tcp_keepalive_inverval: Duration::from_nanos(
                (root["tcp_keepalive_inverval"]
                    .as_f64()
                    .unwrap_or_else(|| 30f64)
                    * 1000_000_000f64) as u64,
            ),
            tcp_timeout: Duration::from_nanos(
                (root["tcp_timeout"].as_f64().unwrap_or_else(|| 300f64) * 1000_000_000f64) as u64,
            ),
            udp_timeout: Duration::from_nanos(
                (root["udp_timeout"].as_f64().unwrap_or_else(|| 60f64) * 1000_000_000f64) as u64,
            ),
            tcp_listener: TcpListener::from_std(
                build_socket_listener("tcp", bind_addr).unwrap().into(),
            )
            .unwrap(),
            udp_listener: UdpSocket::from_std(
                build_socket_listener("udp", bind_addr).unwrap().into(),
            )
            .unwrap(),
            fullcone_map: dashmap::DashMap::new(),
        });

        tokio::spawn(r#in.clone().listen());
        tokio::spawn(r#in.clone().udp_start());
    }

    async fn listen(self: Arc<Self>) {
        loop {
            let (client, saddr) = match self.tcp_listener.accept().await {
                Ok(o) => o,
                Err(e) => {
                    warn!("{}", e);
                    continue;
                }
            };

            if let Err(e) = crate::misc::set_nodelay_keepalive_interval(
                &client,
                self.tcp_nodelay,
                self.tcp_keepalive_inverval,
            ) {
                warn!("{} {} {}", self.tag, saddr, e);
                continue;
            }

            tokio::spawn({
                let self_clone = self.clone();
                async move {
                    let saddr = socketaddr_to_string(&saddr);
                    if let Err(e) = self_clone
                        .clone()
                        .handle_handshake(client, saddr.clone())
                        .await
                    {
                        warn!("{} {} {}", self_clone.tag, saddr, e);
                    }
                }
            });
        }
    }

    async fn handle_handshake(
        self: Arc<Self>,
        mut client: TcpStream,
        saddr: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = Vec::with_capacity(TCP_LEN);

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

        // recv
        let nread = timeout(self.tcp_timeout, client.read(unsafe { buf.remain_mut() })).await??;
        unsafe { buf.add_len(nread) }
        // check length
        if buf.len() < 2 || buf.len() < 2 + buf[1] as usize {
            Err(format!(
                "{} {} buf.len() < 2 || buf.len() < 2 + buf[1] as usize",
                self.tag, saddr
            ))?
        }
        // check version
        if buf[0] != 5 {
            Err(format!(
                "{} {} unsupport socks version:{}",
                self.tag, saddr, buf[0]
            ))?
        }
        // check methods
        if !&buf[2..2 + buf[1] as usize].contains(&0) {
            Err(format!(
                "{} {} unsupport methods:{:?}",
                self.tag,
                saddr,
                &buf[2..2 + buf[1] as usize]
            ))?
        }
        let header_len = 2 + buf[1] as usize;
        buf.drain(..header_len);

        // +----+--------+
        // |VER | METHOD |
        // +----+--------+
        // | 1  |   1    |
        // +----+--------+
        // o  X'00' NO AUTHENTICATION REQUIRED
        // o  X'01' GSSAPI
        // o  X'02' USERNAME/PASSWORD
        // o  X'03' to X'7F' IANA ASSIGNED
        // o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        // o  X'FF' NO ACCEPTABLE METHODS

        // send
        timeout(self.tcp_timeout, client.write_all(&[5, 0])).await??;

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

        // recv
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
            let nread =
                timeout(self.tcp_timeout, client.read(unsafe { buf.remain_mut() })).await??;
            unsafe { buf.add_len(nread) }
        }
        // check version
        if buf[0] != 5 {
            Err(format!(
                "{} {} unsupport socks version:{}",
                self.tag, saddr, buf[0]
            ))?
        }

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
        //     o  IP V4 address: X'01'
        //     o  DOMAINNAME: X'03'
        //     o  IP V6 address: X'04'
        //  o  BND.ADDR       server bound address
        //  o  BND.PORT       server bound port in network octet order

        // send
        let write_buf = match socketaddr_to_string(&client.local_addr().unwrap())
            .parse()
            .unwrap()
        {
            std::net::SocketAddr::V4(addr) => {
                let mut buf = vec![5, 0, 0, ATYP_IPV4];
                buf.extend(addr.ip().octets());
                buf.put_u16(addr.port());
                buf
            }
            std::net::SocketAddr::V6(addr) => {
                let mut buf = vec![5, 0, 0, ATYP_IPV6];
                buf.extend(addr.ip().octets());
                buf.put_u16(addr.port());
                buf
            }
        };
        timeout(self.tcp_timeout, client.write_all(&write_buf)).await??;

        // read CMD
        match buf[1] {
            CMD_CONNECT => {
                if let Err(e) = self.clone().handle_tcp(client, saddr.clone(), buf).await {
                    warn!("{} {} {}", self.tag, saddr, e);
                }
            }
            CMD_UDP_ASSOCIATE => self.handle_udp(client).await,
            _ => Err(format!("{} {} unsupport CMD:{}", self.tag, saddr, buf[1]))?,
        }

        Ok(())
    }
}
