use crate::TcpStatus;
use etherparse::PacketHeaders;
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::prelude::AsRawFd,
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::{
    fs::File,
    io::unix::AsyncFd,
    sync::mpsc::{self, Receiver, Sender},
};

pub struct Tun {
    pub(crate) fd: AsyncFd<File>,
    pub(crate) tcp_map: Mutex<HashMap<SocketAddr, (SocketAddr, TcpStatus)>>,
    pub(crate) udp_tx: Sender<(SocketAddr, Vec<u8>, SocketAddr)>,
    pub(crate) tcp_redirect4: Option<(Ipv4Addr, SocketAddrV4)>,
    pub(crate) tcp_redirect6: Option<(Ipv6Addr, SocketAddrV6)>,
}

impl Tun {
    pub async fn new(
        name: &str,
        path: Option<&Path>,
        udp_channel_buffer: Option<usize>,
        tcp_redirect4: Option<(Ipv4Addr, SocketAddrV4)>,
        tcp_redirect6: Option<(Ipv6Addr, SocketAddrV6)>,
    ) -> io::Result<(Arc<Self>, Receiver<(SocketAddr, Vec<u8>, SocketAddr)>)> {
        let (udp_tx, udp_rx) = mpsc::channel(udp_channel_buffer.unwrap_or(100));

        let tun_file = crate::device::tun_alloc(name, path).await?;
        let tun = Tun {
            fd: AsyncFd::new(tun_file)?,
            tcp_map: Mutex::new(HashMap::new()),
            udp_tx,
            tcp_redirect4,
            tcp_redirect6,
        };
        let tun = Arc::new(tun);

        // background
        tokio::spawn(tun.clone().start());

        Ok((tun, udp_rx))
    }

    async fn start(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buf = vec![0u8; u16::MAX as _];

        loop {
            // read
            let nread = self.read(&mut buf).await?;

            // parse
            let mut ph = PacketHeaders::from_ip_slice(&buf[..nread])?;
            let ip_header = match &mut ph.ip {
                Some(s) => s,
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid tun packet",
                ))?,
            };

            // dispatch
            match ph.transport {
                Some(etherparse::TransportHeader::Udp(udp_header)) => {
                    self.handle_udp(ip_header, udp_header, ph.payload).await?;
                }
                Some(etherparse::TransportHeader::Tcp(tcp_header)) => {
                    self.handle_tcp(ip_header, tcp_header, ph.payload, nread)
                        .await?;
                }
                _ => continue,
            }
        }
    }

    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;

            match guard.try_io(|inner| {
                let nread =
                    unsafe { libc::read(inner.as_raw_fd(), buf.as_mut_ptr() as _, buf.len()) };
                if nread == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(nread as _)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;

            match guard.try_io(|inner| {
                let nwrite =
                    unsafe { libc::write(inner.as_raw_fd(), buf.as_ptr() as _, buf.len()) };
                if nwrite == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(nwrite as _)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}
