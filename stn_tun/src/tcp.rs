use etherparse::{IpHeader, PacketBuilder, TcpHeader};
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
        ip_header: &IpHeader,
        tcp_header: &TcpHeader,
        payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = {
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
            match (ip_header, self.tcp_redirect4, self.tcp_redirect6) {
                (IpHeader::Version4(ip_header), Some((fake_saddr, fake_daddr)), _) => {
                    let saddr = (fake_saddr.octets(), tcp_header.source_port).into();
                    let daddr = (ip_header.destination, tcp_header.destination_port).into();
                    let mut tcp_map_lock = self.tcp_map.lock().unwrap();

                    if tcp_header.syn && !tcp_header.ack {
                        tcp_map_lock.insert(saddr, (daddr, TcpStatus::Established));
                    }

                    if let Some((_, status)) = tcp_map_lock.get_mut(&saddr) {
                        match *status {
                            TcpStatus::Established => {
                                if tcp_header.fin {
                                    *status = TcpStatus::FinWait;
                                }
                            }
                            TcpStatus::FinWait => {
                                if tcp_header.fin {
                                    *status = TcpStatus::LastAck;
                                }
                            }
                            TcpStatus::LastAck => {
                                if tcp_header.ack {
                                    tcp_map_lock.remove(&saddr);
                                }
                            }
                        }
                        if tcp_header.rst {
                            tcp_map_lock.remove(&saddr);
                        }

                        PacketBuilder::ipv4(
                            fake_saddr.octets(),
                            fake_daddr.ip().octets(),
                            ip_header.time_to_live,
                        )
                        .tcp(
                            saddr.port(),
                            fake_daddr.port(),
                            tcp_header.sequence_number,
                            tcp_header.window_size,
                        )
                    } else if let Some((SocketAddr::V4(origin_daddr), status)) =
                        tcp_map_lock.get_mut(&daddr)
                    {
                        let builder = PacketBuilder::ipv4(
                            origin_daddr.ip().octets(),
                            fake_daddr.ip().octets(),
                            ip_header.time_to_live,
                        )
                        .tcp(
                            origin_daddr.port(),
                            daddr.port(),
                            tcp_header.sequence_number,
                            tcp_header.window_size,
                        );

                        match *status {
                            TcpStatus::Established => {
                                if tcp_header.fin {
                                    *status = TcpStatus::FinWait;
                                }
                            }
                            TcpStatus::FinWait => {
                                if tcp_header.fin {
                                    *status = TcpStatus::LastAck;
                                }
                            }
                            TcpStatus::LastAck => {
                                if tcp_header.ack {
                                    tcp_map_lock.remove(&saddr);
                                }
                            }
                        }
                        if tcp_header.rst {
                            tcp_map_lock.remove(&saddr);
                        }

                        builder
                    } else {
                        return Ok(());
                    }
                }
                (IpHeader::Version6(ip_header), _, Some((fake_saddr, fake_daddr))) => {
                    let saddr = (fake_saddr.octets(), tcp_header.source_port).into();
                    let daddr = (ip_header.destination, tcp_header.destination_port).into();
                    let mut tcp_map_lock = self.tcp_map.lock().unwrap();

                    if tcp_header.syn && !tcp_header.ack {
                        tcp_map_lock.insert(saddr, (daddr, TcpStatus::Established));
                    }

                    if let Some((_, status)) = tcp_map_lock.get_mut(&saddr) {
                        match *status {
                            TcpStatus::Established => {
                                if tcp_header.fin {
                                    *status = TcpStatus::FinWait;
                                }
                            }
                            TcpStatus::FinWait => {
                                if tcp_header.fin {
                                    *status = TcpStatus::LastAck;
                                }
                            }
                            TcpStatus::LastAck => {
                                if tcp_header.ack {
                                    tcp_map_lock.remove(&saddr);
                                }
                            }
                        }
                        if tcp_header.rst {
                            tcp_map_lock.remove(&saddr);
                        }

                        PacketBuilder::ipv6(
                            fake_saddr.octets(),
                            fake_daddr.ip().octets(),
                            ip_header.hop_limit,
                        )
                        .tcp(
                            saddr.port(),
                            fake_daddr.port(),
                            tcp_header.sequence_number,
                            tcp_header.window_size,
                        )
                    } else if let Some((SocketAddr::V6(origin_daddr), status)) =
                        tcp_map_lock.get_mut(&daddr)
                    {
                        let builder = PacketBuilder::ipv6(
                            origin_daddr.ip().octets(),
                            fake_daddr.ip().octets(),
                            ip_header.hop_limit,
                        )
                        .tcp(
                            origin_daddr.port(),
                            daddr.port(),
                            tcp_header.sequence_number,
                            tcp_header.window_size,
                        );

                        match *status {
                            TcpStatus::Established => {
                                if tcp_header.fin {
                                    *status = TcpStatus::FinWait;
                                }
                            }
                            TcpStatus::FinWait => {
                                if tcp_header.fin {
                                    *status = TcpStatus::LastAck;
                                }
                            }
                            TcpStatus::LastAck => {
                                if tcp_header.ack {
                                    tcp_map_lock.remove(&saddr);
                                }
                            }
                        }
                        if tcp_header.rst {
                            tcp_map_lock.remove(&saddr);
                        }

                        builder
                    } else {
                        return Ok(());
                    }
                }
                _ => return Ok(()),
            }
        };
        if tcp_header.ns {
            builder = builder.ns();
        }
        if tcp_header.fin {
            builder = builder.fin();
        }
        if tcp_header.syn {
            builder = builder.syn();
        }
        if tcp_header.rst {
            builder = builder.rst();
        }
        if tcp_header.psh {
            builder = builder.psh();
        }
        if tcp_header.ack {
            builder = builder.ack(tcp_header.acknowledgment_number);
        }
        if tcp_header.urg {
            builder = builder.urg(tcp_header.urgent_pointer);
        }
        if tcp_header.ece {
            builder = builder.ece();
        }
        if tcp_header.cwr {
            builder = builder.cwr();
        }
        builder = builder
            .options_raw(tcp_header.options())
            .map_err(|e| format!("{:?}", e))?;

        let mut buf = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut buf, payload)?;

        self.write(&buf).await?;

        Ok(())
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
// cargo test tcp::t1 -- --nocapture
//
// curl --interface tun123 8.8.8.8
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
