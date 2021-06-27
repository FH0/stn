use super::socks5::*;
use crate::misc::{build_socket_listener, memmove_buf, socketaddr_to_string};
use log::*;
use std::{sync::Arc, time::Duration};
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

            let client = match crate::misc::set_nodelay_keepalive_interval(
                client,
                self.tcp_nodelay,
                self.tcp_keepalive_inverval,
            ) {
                Ok(o) => o,
                Err(e) => {
                    warn!("{} {} {}", self.tag, saddr, e);
                    continue;
                }
            };

            tokio::spawn(
                self.clone()
                    .handle_handshake(client, socketaddr_to_string(&saddr)),
            );
        }
    }

    async fn handle_handshake(self: Arc<Self>, mut client: TcpStream, saddr: String) {
        let mut buf = vec![0u8; TCP_LEN];
        let mut buflen = 0usize;

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
        let nread = match timeout(self.tcp_timeout, client.read(&mut buf)).await {
            Ok(o) => match o {
                Ok(0) => {
                    warn!("{} {} close", self.tag, saddr);
                    return;
                }
                Ok(o) => o,
                Err(e) => {
                    warn!("{} {} {}", self.tag, saddr, e);
                    return;
                }
            },
            Err(e) => {
                warn!("{} {} {}", self.tag, saddr, e);
                return;
            }
        };
        buflen += nread;
        // check length
        if buflen < 2 || buflen < 2 + buf[1] as usize {
            warn!(
                "{} {} buflen < 2 || buflen < 2 + buf[1] as usize",
                self.tag, saddr
            );
            return;
        }
        // check version
        if buf[0] != 5 {
            warn!("{} {} unsupport socks version:{}", self.tag, saddr, buf[0]);
            return;
        }
        // check methods
        if !&buf[2..2 + buf[1] as usize].contains(&0) {
            warn!(
                "{} {} unsupport methods:{:?}",
                self.tag,
                saddr,
                &buf[2..2 + buf[1] as usize]
            );
            return;
        }
        let header_len = 2 + buf[1] as usize;
        memmove_buf(&mut buf, &mut buflen, header_len);

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
        match timeout(self.tcp_timeout, client.write_all(&[5, 0])).await {
            Ok(o) => {
                if let Err(e) = o {
                    warn!("{} {} {}", self.tag, saddr, e);
                    return;
                }
            }
            Err(e) => {
                warn!("{} {} {}", self.tag, saddr, e);
                return;
            }
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

        // recv
        while buflen < 4
            || buflen
                < 4 + match buf[3] {
                    ATYP_IPV4 => 4,
                    ATYP_DOMAIN => {
                        if buflen < 5 {
                            1
                        } else {
                            1 + buf[4] as usize
                        }
                    }
                    ATYP_IPV6 => 16,
                    _ => {
                        warn!("{} {} unsupport ATYP:{}", self.tag, saddr, buf[3]);
                        return;
                    }
                } + 2
        {
            let nread = match timeout(self.tcp_timeout, client.read(&mut buf[buflen..])).await {
                Ok(o) => match o {
                    Ok(0) => {
                        warn!("{} {} close", self.tag, saddr);
                        return;
                    }
                    Ok(o) => o,
                    Err(e) => {
                        warn!("{} {} {}", self.tag, saddr, e);
                        return;
                    }
                },
                Err(e) => {
                    warn!("{} {} {}", self.tag, saddr, e);
                    return;
                }
            };
            buflen += nread;
        }
        // check version
        if buf[0] != 5 {
            warn!("{} {} unsupport socks version:{}", self.tag, saddr, buf[0]);
            return;
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
        match timeout(
            self.tcp_timeout,
            client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
        )
        .await
        {
            Ok(o) => {
                if let Err(e) = o {
                    warn!("{} {} {}", self.tag, saddr, e);
                    return;
                }
            }
            Err(e) => {
                warn!("{} {} {}", self.tag, saddr, e);
                return;
            }
        }

        // read CMD
        match buf[1] {
            CMD_CONNECT => self.handle_tcp(client, saddr, buf, buflen).await,
            CMD_UDP_ASSOCIATE => self.handle_udp(client).await,
            _ => {
                warn!("{} {} unsupport CMD:{}", self.tag, saddr, buf[1]);
                return;
            }
        }
    }
}
