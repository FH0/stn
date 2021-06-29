use regex::Regex;
use socket2::Socket;
use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    time::Duration,
};

// "1.2.3.4:80" -> "1.2.3.4" 80
pub(crate) fn split_addr_str(
    addr_str: &str,
) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let mut index = addr_str.len();

    while index > 0 {
        index -= 1;

        if let Some(b':') = addr_str.as_bytes().get(index) {
            return Ok((
                addr_str[..index]
                    .trim_matches('[')
                    .trim_matches(']')
                    .to_string(),
                addr_str[index + 1..].parse()?,
            ));
        }
    }

    Err(format!("invalid addr_str {}", addr_str).into())
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn sockaddr_to_std(saddr: &libc::sockaddr_storage) -> std::io::Result<SocketAddr> {
    match saddr.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr: SocketAddrV4 = unsafe { std::mem::transmute_copy(saddr) };
            Ok(SocketAddr::V4(addr))
        }
        libc::AF_INET6 => {
            let addr: std::net::SocketAddrV6 = unsafe { std::mem::transmute_copy(saddr) };
            Ok(SocketAddr::V6(addr))
        }
        _ => {
            let err = std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "family must be either AF_INET or AF_INET6",
            );
            Err(err)
        }
    }
}

#[allow(dead_code)]
#[cfg(not(target_os = "windows"))]
pub(crate) fn std_to_sockaddr(saddr: &SocketAddr) -> libc::sockaddr_storage {
    match saddr {
        SocketAddr::V4(saddr) => unsafe { std::mem::transmute_copy(saddr) },
        SocketAddr::V6(saddr) => unsafe { std::mem::transmute_copy(saddr) },
    }
}

pub(crate) fn socketaddr_to_string(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(addr) => addr.to_string(),
        SocketAddr::V6(addr) => {
            if let Some(addr_v4) = addr.ip().to_ipv4() {
                SocketAddrV4::new(addr_v4, addr.port()).to_string()
            } else {
                addr.to_string()
            }
        }
    }
}

#[inline]
pub(crate) fn memmove_buf(buf: &mut [u8], buflen: &mut usize, offset: usize) {
    unsafe {
        let ptr = buf.as_mut_ptr();
        *buflen -= offset;
        std::ptr::copy(ptr.offset(offset as isize), ptr, *buflen);
    }
}

// if addr is ipv6, IPV6_V6ONLY will be disabled
#[inline]
pub(crate) fn build_socket_listener(
    type_str: &str,
    bind_addr: &str,
) -> Result<Socket, Box<dyn std::error::Error>> {
    let bind_addr: std::net::SocketAddr = bind_addr.parse()?;

    let type_ = match type_str {
        "tcp" => socket2::Type::STREAM,
        "udp" => socket2::Type::DGRAM,
        type_ => Err(format!("{} not support", type_))?,
    };

    let listener = if bind_addr.is_ipv4() {
        socket2::Socket::new(socket2::Domain::IPV4, type_, None)?
    } else {
        let listener = socket2::Socket::new(socket2::Domain::IPV6, type_, None)?;
        listener.set_only_v6(false)?; // dual stack
        listener
    };
    listener.set_reuse_address(true)?;
    listener.set_nonblocking(true)?;
    listener.bind(&bind_addr.into())?;
    if type_str == "tcp" {
        listener.listen(512)?;
    }

    Ok(listener)
}

#[inline]
pub(crate) fn build_socketaddrv6(
    target: impl ToSocketAddrs,
) -> Result<SocketAddrV6, Box<dyn std::error::Error>> {
    match target.to_socket_addrs()?.next().ok_or("invalid input")? {
        SocketAddr::V4(addr) => Ok(SocketAddrV6::new(
            addr.ip().to_ipv6_mapped(),
            addr.port(),
            0,
            0,
        )),
        SocketAddr::V6(addr) => Ok(addr),
    }
}

#[inline]
pub(crate) fn set_nodelay_keepalive_interval(
    tokio_socket: tokio::net::TcpStream,
    nodelay: bool,
    keepalive_interval: Duration,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error>> {
    let std_socket = tokio_socket.into_std()?;
    let socket2_socket = socket2::Socket::from(std_socket);

    // nodelay
    let result1 = socket2_socket.set_nodelay(nodelay);

    // keepalive interval
    let result2 = match keepalive_interval == Duration::from_secs(0) {
        true => Ok(()),
        false => {
            let tcp_keepalive = socket2::TcpKeepalive::new().with_time(keepalive_interval);
            #[cfg(any(
                target_os = "freebsd",
                target_os = "fuchsia",
                target_os = "linux",
                target_os = "netbsd",
                target_vendor = "apple",
                windows,
            ))]
            let tcp_keepalive = tcp_keepalive.with_interval(keepalive_interval);
            socket2_socket.set_tcp_keepalive(&tcp_keepalive)
        }
    };

    result1?;
    result2?;

    Ok(tokio::net::TcpStream::from_std(socket2_socket.into())?)
}

#[inline]
pub(crate) fn is_valid_domain(domain: &str) -> bool {
    lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(
            r"^([A-Za-z0-9]{1,63}\.|[A-Za-z0-9][A-Za-z0-9-]{1,61}[A-Za-z0-9]\.)+[A-Za-z]{2,6}(\.|)$"
        ).unwrap();
    }
    RE.is_match(domain)
}

#[test]
fn test_valid_domain() {
    assert_eq!(is_valid_domain("a.com"), true);
    assert_eq!(is_valid_domain("a.com."), true);
    assert_eq!(is_valid_domain("a..com"), false);
    assert_eq!(is_valid_domain(".a.com"), false);
    assert_eq!(is_valid_domain("a.c"), false);
    assert_eq!(is_valid_domain("a"), false);
}
