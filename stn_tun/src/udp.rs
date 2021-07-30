use etherparse::{IpHeader, PacketBuilder, UdpHeader};
use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
};

const TTL: u8 = 64;

impl super::Tun {
    pub async fn send_to<A: ToSocketAddrs>(
        &self,
        saddr: A,
        buf: &[u8],
        daddr: A,
    ) -> io::Result<usize> {
        let saddr = saddr.to_socket_addrs()?.next().ok_or(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid address",
        ))?;
        let daddr = daddr.to_socket_addrs()?.next().ok_or(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid address",
        ))?;

        let builder = match (saddr, daddr) {
            (SocketAddr::V4(saddr), SocketAddr::V4(daddr)) => {
                PacketBuilder::ipv4(saddr.ip().octets(), daddr.ip().octets(), TTL)
            }
            (SocketAddr::V6(saddr), SocketAddr::V6(daddr)) => {
                PacketBuilder::ipv6(saddr.ip().octets(), daddr.ip().octets(), TTL)
            }
            _ => unreachable!(),
        }
        .udp(saddr.port(), daddr.port());
        let packet = {
            let mut packet = Vec::<u8>::with_capacity(builder.size(buf.len()));
            builder.write(&mut packet, buf).unwrap();
            packet
        };

        self.write(&packet).await
    }

    pub(crate) async fn handle_udp(
        &self,
        ip_header: &IpHeader,
        udp_header: UdpHeader,
        payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (saddr, daddr) = match ip_header {
            etherparse::IpHeader::Version4(ip_header) => {
                (ip_header.source.into(), ip_header.destination.into())
            }
            etherparse::IpHeader::Version6(ip_header) => {
                (ip_header.source.into(), ip_header.destination.into())
            }
        };
        self.udp_tx
            .send((
                SocketAddr::new(saddr, udp_header.source_port),
                payload.to_vec(),
                SocketAddr::new(daddr, udp_header.destination_port),
            ))
            .await?;

        Ok(())
    }
}

// ip tuntap add mode tun tun123
// ifconfig tun123 inet 10.1.2.3 netmask 255.255.255.0 up
//
// cargo test --package stn_tun udp::t1 -- --nocapture
//
// tcpdump -i tun123 -vvnX
#[tokio::test]
async fn t1() {
    use tokio::net::UdpSocket;

    let udp_listener = UdpSocket::bind("10.1.2.3:123").await.unwrap();

    let (tun, _) = crate::Tun::new("tun123", None, None, None, None)
        .await
        .unwrap();
    tun.send_to("8.8.8.8:53", "abcd".as_bytes(), "10.1.2.3:123")
        .await
        .unwrap();

    let mut buf = vec![0; 100];
    let res = udp_listener.recv_from(&mut buf).await.unwrap();
    println!("{:?}", res);
}

// ip tuntap add mode tun tun123
// ifconfig tun123 inet 10.1.2.3 netmask 255.255.255.0 up
//
// cargo test --package stn_tun udp::t2 -- --nocapture
//
// ip route add default dev tun123 table 123
// ip rule add to 1.2.3.4 lookup 123
// dig @1.2.3.4 a.com
#[tokio::test]
async fn t2() {
    let (_tun, mut tun_udp_rx) = crate::Tun::new("tun123", None, None, None, None)
        .await
        .unwrap();
    let recv_data = tun_udp_rx.recv().await.unwrap();
    println!("{:?}", recv_data);
}
