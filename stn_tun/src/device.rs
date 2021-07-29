use std::{io, os::unix::prelude::AsRawFd, path::Path};
use tokio::fs::{self, File};

const IFNAMSIZ: usize = 16;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_int = 0x400454ca;

#[repr(C)]
pub struct ioctl_flags_data {
    pub ifr_name: [u8; IFNAMSIZ],
    pub ifr_flags: libc::c_short,
}

pub(crate) async fn tun_alloc(name: &str, path: Option<&Path>) -> io::Result<File> {
    // open
    let path = match path {
        Some(s) => Path::new(s),
        None => {
            if Path::new("/dev/net/tun").exists() {
                Path::new("/dev/net/tun")
            } else if Path::new("/dev/tun").exists() {
                Path::new("/dev/tun")
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "tun device path not found",
                ))?
            }
        }
    };
    let tun_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .await?;

    // nonblock
    if unsafe { libc::fcntl(tun_file.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) == -1 } {
        return Err(io::Error::last_os_error());
    }

    // name
    let mut req = ioctl_flags_data {
        ifr_name: {
            let mut buffer = [0u8; IFNAMSIZ];
            buffer[..name.len()].clone_from_slice(name.as_bytes());
            buffer
        },
        ifr_flags: IFF_TUN | IFF_NO_PI,
    };
    if unsafe { libc::ioctl(tun_file.as_raw_fd(), TUNSETIFF, &mut req) == -1 } {
        Err(io::Error::last_os_error())?
    }

    Ok(tun_file)
}

// cargo test device
#[tokio::test]
async fn t1() {
    let _tun_file = tun_alloc("tun123", None).await.unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1000));
}
