use crate::misc::build_socket_listener;
use std::{
    io, mem,
    os::unix::io::{AsRawFd, RawFd},
    sync::Arc,
    time::Duration,
};
use tokio::{io::unix::AsyncFd, net::TcpListener, sync::mpsc::Sender};

pub(crate) const TCP_LEN: usize = 8192;
pub(crate) const UDP_LEN: usize = 1500;

pub(crate) struct In {
    pub(crate) tag: String,
    pub(crate) tcp_nodelay: bool,
    pub(crate) tcp_keepalive_inverval: Duration,
    pub(crate) tcp_timeout: Duration,
    pub(crate) udp_timeout: Duration,
    pub(crate) tcp_listener: TcpListener,
    pub(crate) udp_listener: AsyncFd<std::net::UdpSocket>,
    pub(crate) fullcone_map: dashmap::DashMap<String, Sender<(String, Vec<u8>)>>,
    pub(crate) raw4: RawFd, // udp tproxy
    pub(crate) raw6: RawFd, // udp tproxy
}

impl In {
    pub(crate) async fn start(root: serde_json::Value) {
        let bind_addr = root["address"].as_str().expect("address not found");

        let mut r#in = In {
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
            udp_listener: AsyncFd::new(build_socket_listener("udp", bind_addr).unwrap().into())
                .unwrap(),
            fullcone_map: dashmap::DashMap::new(),
            raw4: -1,
            raw6: -1,
        };

        r#in.init_tproxy().unwrap();

        let r#in = Arc::new(r#in);
        tokio::spawn(r#in.clone().listen());
        tokio::spawn(r#in.clone().udp_start());
    }

    fn init_tproxy(&mut self) -> io::Result<()> {
        let enable: libc::c_int = 1;

        // tcp
        if unsafe {
            (
                libc::setsockopt(
                    self.tcp_listener.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                ),
                libc::setsockopt(
                    self.tcp_listener.as_raw_fd(),
                    libc::SOL_IPV6,
                    libc::IPV6_TRANSPARENT,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                ),
            ) == (-1, -1)
        } {
            return Err(io::Error::last_os_error());
        }

        // udp
        if unsafe {
            (
                libc::setsockopt(
                    self.udp_listener.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                ),
                libc::setsockopt(
                    self.udp_listener.as_raw_fd(),
                    libc::SOL_IPV6,
                    libc::IPV6_TRANSPARENT,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                ),
            ) == (-1, -1)
        } {
            return Err(io::Error::last_os_error());
        }
        if unsafe {
            (
                libc::setsockopt(
                    self.udp_listener.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_RECVORIGDSTADDR,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                ),
                libc::setsockopt(
                    self.udp_listener.as_raw_fd(),
                    libc::SOL_IPV6,
                    libc::IPV6_RECVORIGDSTADDR,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                ),
            ) == (-1, -1)
        } {
            return Err(io::Error::last_os_error());
        }

        // raw
        self.raw4 = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                libc::IPPROTO_RAW,
            )
        };
        if self.raw4 == -1 {
            return Err(io::Error::last_os_error());
        }
        self.raw6 = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                libc::IPPROTO_RAW,
            )
        };
        if self.raw6 == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}
