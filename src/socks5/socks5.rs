use crate::misc::{socketaddr_to_string, split_addr_str};
use bytes::Buf;
use bytes::BufMut;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::net::{SocketAddr, ToSocketAddrs};

pub(crate) const TCP_LEN: usize = 8192;
pub(crate) const UDP_LEN: usize = 1500;

pub(crate) const CMD_CONNECT: u8 = 0x01;
pub(crate) const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub(crate) const ATYP_IPV4: u8 = 0x01;
pub(crate) const ATYP_DOMAIN: u8 = 0x03;
pub(crate) const ATYP_IPV6: u8 = 0x04;

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
#[inline]
pub(crate) fn get_daddr(buf: &[u8]) -> Result<(String, usize), Box<dyn std::error::Error>> {
    match buf[0] {
        ATYP_IPV4 => Ok((
            SocketAddrV4::new(
                Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]),
                (&buf[5..]).get_u16(),
            )
            .to_string(),
            4,
        )),
        ATYP_DOMAIN => {
            let domain_len = buf[1] as usize;

            Ok((
                String::from_utf8_lossy(&buf[2..2 + domain_len]).to_string()
                    + ":"
                    + (&buf[2 + domain_len..]).get_u16().to_string().as_str(),
                1 + domain_len,
            ))
        }
        ATYP_IPV6 => Ok((
            socketaddr_to_string(&SocketAddr::from(SocketAddrV6::new(
                Ipv6Addr::new(
                    (&buf[1..]).get_u16(),
                    (&buf[3..]).get_u16(),
                    (&buf[5..]).get_u16(),
                    (&buf[7..]).get_u16(),
                    (&buf[9..]).get_u16(),
                    (&buf[11..]).get_u16(),
                    (&buf[13..]).get_u16(),
                    (&buf[15..]).get_u16(),
                ),
                (&buf[17..]).get_u16(),
                0,
                0,
            ))),
            16,
        )),
        _ => Err(format!("unsupport ATYP {}", buf[3]))?,
    }
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
#[inline]
pub(crate) fn generate_daddr_buf(daddr: &String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    let (addr, port) = split_addr_str(daddr.as_str())?;
    let port = port as u16;

    match (addr.as_str(), port).to_socket_addrs() {
        Ok(mut iter) => {
            let sockaddr = iter.next().unwrap();

            match sockaddr {
                std::net::SocketAddr::V4(addr) => {
                    buf.put_u8(ATYP_IPV4);
                    buf.put(addr.ip().octets()[..].as_ref());
                    buf.put_u16(addr.port());
                }
                std::net::SocketAddr::V6(addr) => {
                    buf.put_u8(ATYP_IPV6);
                    buf.put(addr.ip().octets()[..].as_ref());
                    buf.put_u16(addr.port());
                }
            }
        }
        Err(_) => {
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(addr.len() as u8);
            buf.put(addr.as_bytes());
            buf.put_u16(port);
        }
    }

    Ok(buf)
}
