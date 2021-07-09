use std::{
    io, mem,
    net::{SocketAddr, ToSocketAddrs},
};

pub(crate) fn parse_std_addr<A: ToSocketAddrs>(addr: A) -> io::Result<SocketAddr> {
    addr.to_socket_addrs()?.next().ok_or(io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid address",
    ))
}

pub fn enable_transparent(fd: i32, ipv4: bool, ipv6: bool) -> io::Result<()> {
    let enable = 1;

    // check input
    if ipv4 == false && ipv6 == false {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ipv4 == false && ipv6 == false",
        ))?
    }

    // ipv4
    if unsafe {
        ipv4 && libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &enable as *const _ as _,
            mem::size_of_val(&enable) as _,
        ) == -1
    } {
        Err(io::Error::last_os_error())?
    }

    // ipv6
    if unsafe {
        ipv6 && libc::setsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IPV6_TRANSPARENT,
            &enable as *const _ as _,
            mem::size_of_val(&enable) as _,
        ) == -1
    } {
        Err(io::Error::last_os_error())?
    }

    Ok(())
}

pub fn set_ipv6_only(fd: i32, ipv6_only: bool) -> io::Result<()> {
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IPV6_V6ONLY,
            &ipv6_only as *const _ as *const i32 as _,
            mem::size_of::<i32>() as _,
        ) == -1
    } {
        Err(io::Error::last_os_error()).unwrap()
    }

    Ok(())
}

pub fn set_reuse_address(fd: i32, reuse_address: bool) -> io::Result<()> {
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &reuse_address as *const _ as *const i32 as _,
            mem::size_of::<i32>() as _,
        ) == -1
    } {
        Err(io::Error::last_os_error()).unwrap()
    }

    Ok(())
}
