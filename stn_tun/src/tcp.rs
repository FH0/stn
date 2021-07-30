use etherparse::{IpHeader, TcpHeader};
use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
};

impl super::Tun {
    pub fn get_tcp_daddr<A: ToSocketAddrs>(&self, saddr: &A) -> io::Result<SocketAddr> {
        Ok(self
            .tcp_map
            .lock()
            .unwrap()
            .get(
                &saddr
                    .to_socket_addrs()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                    .next()
                    .ok_or(io::Error::new(io::ErrorKind::InvalidData, "invalid saddr"))?,
            )
            .ok_or(io::Error::new(io::ErrorKind::NotFound, "daddr not found"))?
            .clone()
            .0)
    }

    pub(crate) async fn handle_tcp(
        &self,
        ip_header: &mut IpHeader,
        tcp_header: TcpHeader,
        payload: &[u8],
        buf_len: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(buf) = self.handle_buf(ip_header, tcp_header, payload, buf_len)? {
            self.write(&buf).await?;
        }

        Ok(())
    }

    fn handle_buf(
        &self,
        mut ip_header: &mut IpHeader,
        mut tcp_header: TcpHeader,
        payload: &[u8],
        buf_len: usize,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let mut tcp_map_lock = self.tcp_map.lock().unwrap();

        /*
        tun 10.1.2.3/24
        tcp_redirect4 10.1.2.3:1

        raw        10.1.2.3:12345 -> 1.2.3.4:80       SYN
        modified   10.1.2.4:12345 -> 10.1.2.3:1       SYN
        raw        10.1.2.3:1     -> 10.1.2.4:12345   ACK SYN
        modified   1.2.3.4:80     -> 10.1.2.3:12345   ACK SYN
        raw        10.1.2.3:12345 -> 1.2.3.4:80       ACK
        modified   10.1.2.4:12345 -> 10.1.2.3:1       ACK
        */

        // modify
        let (status, saddr) = match (&mut ip_header, self.tcp_redirect4, self.tcp_redirect6) {
            (IpHeader::Version4(ip_header), Some((fake_saddr, fake_daddr)), _) => {
                let saddr = (fake_saddr.octets(), tcp_header.source_port).into();
                let daddr = (ip_header.destination, tcp_header.destination_port).into();

                // syn
                if tcp_header.syn && !tcp_header.ack {
                    tcp_map_lock.insert(saddr, (daddr, TcpStatus::Established));
                }

                if let Some((_, status)) = tcp_map_lock.get_mut(&saddr) {
                    ip_header.source = fake_saddr.octets();
                    ip_header.destination = fake_daddr.ip().octets();
                    ip_header.header_checksum = ip_header.calc_header_checksum()?;

                    tcp_header.source_port = saddr.port();
                    tcp_header.destination_port = fake_daddr.port();
                    tcp_header.checksum = tcp_header.calc_checksum_ipv4(&ip_header, payload)?;

                    (status, saddr)
                } else if let Some((SocketAddr::V4(origin_daddr), status)) =
                    tcp_map_lock.get_mut(&daddr)
                {
                    ip_header.source = origin_daddr.ip().octets();
                    ip_header.destination = fake_daddr.ip().octets();
                    ip_header.header_checksum = ip_header.calc_header_checksum()?;

                    tcp_header.source_port = origin_daddr.port();
                    tcp_header.destination_port = daddr.port();
                    tcp_header.checksum = tcp_header.calc_checksum_ipv4(&ip_header, payload)?;

                    (status, saddr)
                } else {
                    return Ok(None);
                }
            }
            (IpHeader::Version6(ip_header), _, Some((fake_saddr, fake_daddr))) => {
                let saddr = (fake_saddr.octets(), tcp_header.source_port).into();
                let daddr = (ip_header.destination, tcp_header.destination_port).into();

                // syn
                if tcp_header.syn && !tcp_header.ack {
                    tcp_map_lock.insert(saddr, (daddr, TcpStatus::Established));
                }

                if let Some((_, status)) = tcp_map_lock.get_mut(&saddr) {
                    ip_header.source = fake_saddr.octets();
                    ip_header.destination = fake_daddr.ip().octets();

                    tcp_header.source_port = saddr.port();
                    tcp_header.destination_port = fake_daddr.port();
                    tcp_header.checksum = tcp_header.calc_checksum_ipv6(&ip_header, payload)?;

                    (status, saddr)
                } else if let Some((SocketAddr::V6(origin_daddr), status)) =
                    tcp_map_lock.get_mut(&daddr)
                {
                    ip_header.source = origin_daddr.ip().octets();
                    ip_header.destination = fake_daddr.ip().octets();

                    tcp_header.source_port = origin_daddr.port();
                    tcp_header.destination_port = daddr.port();
                    tcp_header.checksum = tcp_header.calc_checksum_ipv6(&ip_header, payload)?;

                    (status, saddr)
                } else {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        };

        // status
        if tcp_header.rst || (tcp_header.ack && *status == TcpStatus::LastAck) {
            tcp_map_lock.remove(&saddr);
        } else if tcp_header.fin {
            if *status == TcpStatus::Established {
                *status = TcpStatus::FinWait;
            } else if *status == TcpStatus::FinWait {
                *status = TcpStatus::LastAck;
            }
        }

        // generate buf
        let mut buf = Vec::with_capacity(buf_len);
        ip_header.write(&mut buf)?;
        tcp_header.write(&mut buf)?;
        buf.extend(payload);

        Ok(Some(buf))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum TcpStatus {
    Established,
    FinWait,
    LastAck,
}

// ip tuntap add mode tun tun123
// ifconfig tun123 inet 10.1.2.3 netmask 255.255.255.0 up
//
// cargo test --package stn_tun tcp::t1 -- --nocapture
//
// curl --interface tun123 1.2.3.4
#[tokio::test]
async fn t1() {
    use tokio::io::AsyncReadExt;

    let (tun, _) = crate::Tun::new(
        "tun123",
        None,
        None,
        Some(("10.1.2.4".parse().unwrap(), "10.1.2.3:1".parse().unwrap())),
        None,
    )
    .await
    .unwrap();

    {
        let tcp_listener = tokio::net::TcpListener::bind("10.1.2.3:1").await.unwrap();
        let (mut tcp_stream, saddr) = tcp_listener.accept().await.unwrap();
        println!("{:?} {:?}", saddr, tun.get_tcp_daddr(&saddr).unwrap(),);

        let mut buf = String::new();
        tcp_stream.read_to_string(&mut buf).await.unwrap();
        println!("{}", buf);
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    println!("{:?}", tun.tcp_map);
}
