use super::*;
use std::{
    io, mem,
    net::{SocketAddr, ToSocketAddrs},
    os::unix::prelude::AsRawFd,
    ptr,
};
use tokio::io::unix::AsyncFd;

pub struct UdpSocket {
    udp_listener: AsyncFd<i32>,
}

impl UdpSocket {
    pub async fn bind<A: ToSocketAddrs>(addr: A, ipv6_only: bool) -> io::Result<UdpSocket> {
        let addr = parse_std_addr(&addr)?;
        let addr = into_sockaddr_storage(&addr);

        // new socket
        let fd = unsafe {
            libc::socket(
                addr.ss_family as _,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd == -1 {
            Err(io::Error::last_os_error())?
        }

        // set tproxy
        let enable = 1;
        let set_ipv4 = || -> io::Result<()> {
            enable_transparent(fd, true, false)?;
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_RECVORIGDSTADDR,
                    &enable as *const _ as _,
                    mem::size_of_val(&enable) as _,
                ) == -1
            } {
                Err(io::Error::last_os_error())?
            }
            Ok(())
        };
        if addr.ss_family as libc::c_int == libc::AF_INET {
            set_ipv4()?;
        } else {
            enable_transparent(fd, false, true)?;
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_IPV6,
                    libc::IPV6_RECVORIGDSTADDR,
                    &enable as *const _ as _,
                    mem::size_of_val(&enable) as _,
                ) == -1
            } {
                Err(io::Error::last_os_error())?
            }

            // ipv6_only
            if !ipv6_only {
                set_ipv6_only(fd, false)?;
                set_ipv4()?;
            }
        }

        // bind
        if unsafe { libc::bind(fd, &addr as *const _ as _, mem::size_of_val(&addr) as _) == -1 } {
            Err(io::Error::last_os_error())?
        }

        Ok(Self {
            udp_listener: AsyncFd::new(fd)?,
        })
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        loop {
            let mut guard = self.udp_listener.readable().await?;

            match guard.try_io(|udp_listener| tproxy_recv_from(udp_listener.as_raw_fd(), buf)) {
                Ok(o) => return o,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn bind_send_to<A: ToSocketAddrs>(
        saddr: A,
        buf: &[u8],
        daddr: A,
    ) -> io::Result<usize> {
        let saddr = parse_std_addr(&saddr)?;
        let saddr = into_sockaddr_storage(&saddr);
        let daddr = parse_std_addr(&daddr)?;
        let daddr = into_sockaddr_storage(&daddr);

        // new socket
        let fd = unsafe {
            libc::socket(
                saddr.ss_family as _,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd == -1 {
            Err(io::Error::last_os_error())?
        }

        // reuseaddr
        set_reuse_address(fd, true)?;

        // transparent
        match saddr.ss_family as libc::c_int {
            libc::AF_INET => enable_transparent(fd, true, false)?,
            libc::AF_INET6 => enable_transparent(fd, false, true)?,
            _ => unreachable!(),
        }

        // bind
        if unsafe { libc::bind(fd, &saddr as *const _ as _, mem::size_of_val(&saddr) as _) == -1 } {
            Err(io::Error::last_os_error())?
        }

        // async send
        let async_fd = AsyncFd::new(fd)?;
        let r = loop {
            let mut guard = async_fd.writable().await?;

            match guard.try_io(|_| {
                let nsend = unsafe {
                    libc::sendto(
                        fd,
                        buf.as_ptr() as _,
                        buf.len(),
                        0,
                        &daddr as *const _ as _,
                        mem::size_of_val(&daddr) as _,
                    )
                };
                if nsend == -1 {
                    Err(io::Error::last_os_error())?
                }
                Ok(nsend as _)
            }) {
                Ok(o) => break o,
                Err(_would_block) => continue,
            }
        };

        // close
        unsafe {
            libc::close(fd);
        }

        r
    }
}

fn tproxy_recv_from(fd: i32, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut control_buf = [0u8; mem::size_of::<libc::sockaddr_storage>()];
    let mut saddr: libc::sockaddr_storage = unsafe { mem::zeroed() };

    let mut msghdr: libc::msghdr = unsafe { mem::zeroed() };
    msghdr.msg_name = &mut saddr as *mut _ as _;
    msghdr.msg_namelen = mem::size_of_val(&saddr) as _;

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as _,
        iov_len: buf.len() as _,
    };
    msghdr.msg_iov = &mut iov;
    msghdr.msg_iovlen = 1;

    msghdr.msg_control = control_buf.as_mut_ptr() as _;
    msghdr.msg_controllen = control_buf.len() as _;

    let nrecv = unsafe { libc::recvmsg(fd, &mut msghdr, 0) };
    if nrecv == -1 {
        Err(io::Error::last_os_error())?
    }

    let daddr = parse_tproxy_msghdr(&msghdr)?;
    let saddr = parse_sockaddr_storage(&saddr)?;
    let daddr = parse_sockaddr_storage(&daddr)?;
    Ok((nrecv as _, saddr, daddr))
}

fn parse_tproxy_msghdr(msghdr: &libc::msghdr) -> io::Result<libc::sockaddr_storage> {
    let mut cmsghdr = unsafe { &*libc::CMSG_FIRSTHDR(msghdr) };
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };

    while !(cmsghdr as *const libc::cmsghdr).is_null() {
        match (cmsghdr.cmsg_level, cmsghdr.cmsg_type) {
            (libc::SOL_IP, libc::IP_RECVORIGDSTADDR) => unsafe {
                ptr::copy(
                    libc::CMSG_DATA(cmsghdr),
                    &mut addr as *mut _ as _,
                    mem::size_of::<libc::sockaddr_in>(),
                );
            },
            (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR) => unsafe {
                ptr::copy(
                    libc::CMSG_DATA(cmsghdr),
                    &mut addr as *mut _ as _,
                    mem::size_of::<libc::sockaddr_in6>(),
                );
            },
            _ => {
                cmsghdr = unsafe { &*libc::CMSG_NXTHDR(msghdr, cmsghdr) };
                continue;
            }
        }

        return Ok(addr);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid tproxy msghdr",
    ))
}

fn parse_sockaddr_storage(addr: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match addr.ss_family as libc::c_int {
        libc::AF_INET => Ok(SocketAddr::V4(unsafe { mem::transmute_copy(addr) })),
        libc::AF_INET6 => Ok(SocketAddr::V6(unsafe { mem::transmute_copy(addr) })),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ss_family",
        )),
    }
}

fn into_sockaddr_storage(addr: &SocketAddr) -> libc::sockaddr_storage {
    let mut sockaddr_storage = unsafe { mem::zeroed() };

    match addr {
        SocketAddr::V4(addr) => unsafe {
            ptr::copy(
                addr,
                &mut sockaddr_storage as *mut _ as _,
                mem::size_of::<libc::sockaddr_in>(),
            )
        },
        SocketAddr::V6(addr) => unsafe {
            ptr::copy(
                addr,
                &mut sockaddr_storage as *mut _ as _,
                mem::size_of::<libc::sockaddr_in6>(),
            )
        },
    }

    sockaddr_storage
}
