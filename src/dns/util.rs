use log::*;
use parking_lot::RwLock;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::sleep;

pub(crate) fn get_server_and_refresh_system(
    root: &serde_json::Value,
) -> Arc<RwLock<Vec<SocketAddr>>> {
    let shared_server = Arc::new(RwLock::new(Vec::new()));

    let mut server: Vec<String> = if let Some(s) = root["server"].as_array() {
        s.iter()
            .map(|x| {
                let x_str = x.as_str().expect("server not string");
                if x_str.parse::<SocketAddr>().is_ok() || x_str == "system" {
                    x_str.to_string()
                } else {
                    format!("{}:53", x_str)
                }
            })
            .collect()
    } else {
        vec!["system".to_string()]
    };

    if server.contains(&"system".to_string()) {
        server.retain(|x| x.as_str() != "system");
        let server = server
            .iter()
            .map(|x| x.parse().unwrap())
            .collect::<Vec<SocketAddr>>();

        // refresh system
        if let Err(e) = refresh_system(server.clone(), shared_server.clone()) {
            warn!("{}", e);
        };
        let interval = Duration::from_nanos(
            (root["refresh_system"].as_f64().unwrap_or_else(|| 3f64) * 1000_000_000f64) as _,
        );
        if interval != Duration::new(0, 0) {
            tokio::spawn({
                let server = server.clone();
                let shared_server = shared_server.clone();
                async move {
                    loop {
                        sleep(interval).await;
                        if let Err(e) = refresh_system(server.clone(), shared_server.clone()) {
                            warn!("{}", e);
                        };
                    }
                }
            });
        }
    } else {
        *shared_server.write() = server
            .iter()
            .map(|x| x.parse().unwrap())
            .collect::<Vec<SocketAddr>>();
    }

    shared_server
}

pub(crate) fn refresh_system(
    mut origin_server: Vec<SocketAddr>,
    shared_server: Arc<RwLock<Vec<SocketAddr>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            for adapter in ipconfig::get_adapters()? {
                for server in adapter.dns_servers() {
                    origin_server.push(SocketAddr::new(server.clone(), 53));
                }
            }
        } else if #[cfg(target_os = "android")] {
            for i in 1..5 {
                let server_string = String::from_utf8_lossy(
                    &std::process::Command::new("/system/bin/getprop")
                        .arg(&format!("net.dns{}", i))
                        .output()?
                        .stdout,
                )
                .trim()
                .to_string();
                if !server_string.is_empty() {
                    origin_server.push(SocketAddr::new(server_string.parse()?, 53));
                }
            }
        } else if #[cfg(target_os = "linux")] {
            let buf = std::fs::read_to_string("/etc/resolv.conf")?;
            let config = resolv_conf::Config::parse(buf)?;
            for elem in config.nameservers {
                origin_server.push(SocketAddr::new(elem.into(), 53));
            }
        } else {
            panic!("unsupport system");
        }
    }

    // dedup
    origin_server.sort_unstable();
    origin_server.dedup();

    // refresh
    *shared_server.write() = origin_server;

    Ok(())
}
