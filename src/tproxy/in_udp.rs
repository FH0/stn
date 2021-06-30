use super::r#in::UDP_LEN;
use super::In;
use crate::misc::{sockaddr_to_std, socketaddr_to_string};
use log::*;
use pnet_packet::{
    ip::IpNextHeaderProtocols,
    ipv4, ipv6,
    udp::{self, MutableUdpPacket},
    MutablePacket,
};
use std::{
    io::{self, ErrorKind},
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    os::unix::io::{AsRawFd, RawFd},
    ptr,
    sync::Arc,
};
use tokio::sync::mpsc::{channel, Receiver};

impl In {
    pub(crate) async fn udp_start(self: Arc<Self>) {
        let mut buf = vec![0u8; UDP_LEN];

        loop {
            let mut ready = match self.udp_listener.readable().await {
                Ok(o) => o,
                Err(e) => {
                    warn!("{}", e);
                    continue;
                }
            };

            // recv, until WouldBlock
            loop {
                let (nrecv, saddr, daddr) =
                    match udp_recvmsg(self.udp_listener.as_raw_fd(), &mut buf) {
                        Ok(o) => o,
                        Err(e) => {
                            if e.kind() != ErrorKind::WouldBlock {
                                warn!("{}", e);
                            }

                            break;
                        }
                    };
                let saddr = socketaddr_to_string(&saddr);
                let daddr = socketaddr_to_string(&daddr);

                // get server_tx or new a task
                let server_tx = if let Some(s) = self.fullcone_map.get(&saddr) {
                    s.value().clone()
                } else {
                    let (own_tx, own_rx) = channel::<(String, Vec<u8>)>(100);
                    self.fullcone_map.insert(saddr.clone(), own_tx.clone());
                    tokio::spawn(self.clone().handle_tproxy_udp(saddr.clone(), own_rx));
                    own_tx
                };

                // send
                if let Err(e) = server_tx.try_send((daddr.clone(), buf[..nrecv].to_vec())) {
                    warn!("{} {} -> {} {}", self.tag, saddr, daddr, e);
                    continue;
                }
            }

            ready.clear_ready();
        }
    }

    async fn handle_tproxy_udp(
        self: Arc<Self>,
        saddr: String,
        mut client_rx: Receiver<(String, Vec<u8>)>,
    ) {
        // bind
        let (own_tx, mut server_rx) = channel::<(String, Vec<u8>)>(100);
        let server_tx = match crate::route::udp_bind(self.tag.clone(), saddr.clone(), own_tx) {
            Ok(o) => o,
            Err(e) => {
                warn!("{} {} {}", self.tag, saddr, e);
                return;
            }
        };

        tokio::spawn(async move {
            match bidirectional_with_timeout!(
                {
                    // read client
                    let (daddr, recv_data) = client_rx.recv().await.ok_or("close")?;

                    // write server
                    debug!("{} {} -> {} {}", self.tag, saddr, daddr, recv_data.len());
                    server_tx
                        .send((daddr.clone(), recv_data))
                        .await
                        .or(Err("close"))?;
                },
                {
                    // read server
                    let (daddr, recv_data) = server_rx.recv().await.ok_or("close")?;

                    // write client
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, recv_data.len());
                    self.udp_sendto(daddr.clone(), saddr.clone(), recv_data)?;
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

            // delete from fullcone_map
            self.fullcone_map.remove(&saddr);
        });
    }

    fn udp_sendto(
        &self,
        saddr: String,
        daddr: String,
        buf: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let saddr = saddr.to_socket_addrs()?.next().unwrap();
        let daddr = daddr.to_socket_addrs()?.next().unwrap();

        match (saddr, daddr) {
            (SocketAddr::V4(saddr), SocketAddr::V4(daddr)) => self.clone().udp_sendto4(
                *saddr.ip(),
                saddr.port(),
                *daddr.ip(),
                daddr.port(),
                buf,
            )?,
            (SocketAddr::V6(saddr), SocketAddr::V6(daddr)) => self.clone().udp_sendto6(
                *saddr.ip(),
                saddr.port(),
                *daddr.ip(),
                daddr.port(),
                buf,
            )?,
            _ => Err(format!("unmatch saddr:{} daddr:{}", saddr, daddr))?,
        }

        Ok(())
    }

    fn udp_sendto4(
        &self,
        saddr: Ipv4Addr,
        sport: u16,
        daddr: Ipv4Addr,
        dport: u16,
        data_buf: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut udp_buf = vec![0u8; UDP_LEN];

        let mut ip_header = ipv4::MutableIpv4Packet::new(&mut udp_buf).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(20 + 8 + data_buf.len() as u16);
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(saddr);
        ip_header.set_destination(daddr);
        let checksum = ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);

        let payload = ip_header.payload_mut();
        let mut udp_header = MutableUdpPacket::new(payload).unwrap();
        udp_header.set_source(sport);
        udp_header.set_destination(dport);
        udp_header.set_length((8 + data_buf.len()) as u16);
        udp_header.set_payload(&data_buf);
        let checksum = udp::ipv4_checksum(&udp_header.to_immutable(), &saddr, &daddr);
        udp_header.set_checksum(checksum);

        let daddr_socketaddr = SocketAddrV4::new(daddr, dport);
        if unsafe {
            libc::sendto(
                self.raw4,
                udp_buf.as_mut_ptr() as *mut _,
                20 + 8 + data_buf.len(),
                0,
                &daddr_socketaddr as *const _ as *const _,
                std::mem::size_of_val(&daddr_socketaddr) as _,
            ) == -1
        } {
            Err(io::Error::last_os_error())?;
        }

        Ok(())
    }

    fn udp_sendto6(
        &self,
        saddr: Ipv6Addr,
        sport: u16,
        daddr: Ipv6Addr,
        dport: u16,
        data_buf: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut udp_buf = vec![0u8; UDP_LEN];

        let mut ip_header = ipv6::MutableIpv6Packet::new(&mut udp_buf).unwrap();
        ip_header.set_version(6);
        ip_header.set_payload_length(8 + data_buf.len() as u16);
        ip_header.set_hop_limit(64);
        ip_header.set_next_header(IpNextHeaderProtocols::Udp);
        ip_header.set_source(saddr);
        ip_header.set_destination(daddr);

        let payload = ip_header.payload_mut();
        let mut udp_header = MutableUdpPacket::new(payload).unwrap();
        udp_header.set_source(sport);
        udp_header.set_destination(dport);
        udp_header.set_length(8 + data_buf.len() as u16);
        udp_header.set_payload(&data_buf);
        let checksum = udp::ipv6_checksum(&udp_header.to_immutable(), &saddr, &daddr);
        udp_header.set_checksum(checksum);

        // dport must 0, https://stackoverflow.com/a/47779888/12651220
        let daddr_socketaddr = SocketAddrV6::new(daddr, 0, 0, 0);
        if unsafe {
            libc::sendto(
                self.raw6,
                udp_buf.as_mut_ptr() as *mut _,
                40 + 8 + data_buf.len(),
                0,
                &daddr_socketaddr as *const _ as *const _,
                std::mem::size_of_val(&daddr_socketaddr) as _,
            ) == -1
        } {
            Err(io::Error::last_os_error())?;
        }

        Ok(())
    }
}

fn udp_recvmsg(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut control_buf = [0u8; std::mem::size_of::<libc::sockaddr_storage>()];
    let mut saddr_addr: libc::sockaddr_storage = unsafe { mem::zeroed() };

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = &mut saddr_addr as *mut _ as _;
    msg.msg_namelen = mem::size_of_val(&saddr_addr) as _;

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as _,
        iov_len: buf.len() as _,
    };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    msg.msg_control = control_buf.as_mut_ptr() as _;
    msg.msg_controllen = control_buf.len() as _;

    let buf_len = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if buf_len == -1 {
        return Err(io::Error::last_os_error());
    }

    if let Some(daddr_addr) = parse_udp_msg(&msg) {
        Ok((
            buf_len as usize,
            sockaddr_to_std(&saddr_addr)?,
            sockaddr_to_std(&daddr_addr)?,
        ))
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "daddr_addr not found",
        ))
    }
}

fn parse_udp_msg(msg: &libc::msghdr) -> Option<libc::sockaddr_storage> {
    let mut cmsg: *mut libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let rcmsg = unsafe { &*cmsg };
        match (rcmsg.cmsg_level, rcmsg.cmsg_type) {
            (libc::SOL_IP, libc::IP_RECVORIGDSTADDR) => {
                let mut daddr_addr: libc::sockaddr_storage = unsafe { mem::zeroed() };

                unsafe {
                    ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut daddr_addr as *mut _ as *mut _,
                        mem::size_of::<libc::sockaddr_in>(),
                    );
                }

                return Some(daddr_addr);
            }
            (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR) => {
                let mut daddr_addr: libc::sockaddr_storage = unsafe { mem::zeroed() };

                unsafe {
                    ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut daddr_addr as *mut _ as *mut _,
                        mem::size_of::<libc::sockaddr_in6>(),
                    );
                }

                return Some(daddr_addr);
            }
            _ => {}
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }

    None
}
