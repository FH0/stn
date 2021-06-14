use lazy_static::lazy_static;
use log::*;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::task::JoinHandle;

use crate::misc::build_socketaddrv6;

pub(crate) struct Resolve {
    pub(crate) timeout: Duration,
    pub(crate) retry: u64,
    pub(crate) min_ttl: u64,
    pub(crate) max_ttl: u64,
    pub(crate) ipv6_first: bool,
}

#[derive(Clone, Debug)]
struct LruResolve {
    addr: String,
    deadline: tokio::time::Instant,
}

const UDP_LEN: usize = 1500;
lazy_static! {
    static ref RESOLVE: RwLock<Resolve> = RwLock::new(unsafe { std::mem::zeroed() });
    static ref SERVER: RwLock<Vec<std::net::SocketAddr>> = RwLock::new(Vec::new());
    static ref LRU: Mutex<lru::LruCache<String, LruResolve>> = Mutex::new(lru::LruCache::new(1));
}

pub(crate) fn init_resolve(root: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    *RESOLVE.write() = Resolve {
        timeout: Duration::from_millis(root["timeout"].as_u64().unwrap_or_else(|| 5000)),
        retry: root["retry"].as_u64().unwrap_or_else(|| 1),
        min_ttl: root["min_ttl"].as_u64().unwrap_or_else(|| 60),
        max_ttl: root["max_ttl"].as_u64().unwrap_or_else(|| 2147483647),
        ipv6_first: root["ipv6_first"].as_bool().unwrap_or_else(|| false),
    };
    *LRU.lock() = lru::LruCache::new(root["cache_size"].as_u64().unwrap_or_else(|| 1024) as usize);

    // refresh_system
    let server = match root["server"].as_array() {
        Some(s) => s.iter().map(|x| x.as_str().unwrap().to_string()).collect(),
        None => vec!["system".to_string()], // default
    };
    let interval = root["refresh_system"].as_u64().unwrap_or_else(|| 3000);
    tokio::spawn(refresh_server(server, Duration::from_millis(interval)));

    // refresh_cache
    if root["refresh_cache"].as_bool().unwrap_or_else(|| false) {
        tokio::spawn(refresh_cache(Duration::from_secs(RESOLVE.read().min_ttl)));
    }

    Ok(())
}

// make sure update in time
async fn refresh_server(server: Vec<String>, interval: Duration) {
    loop {
        SERVER.write().clear();

        for server in &server {
            if server.as_str() == "system" {
                for elem in match badns::get_system_servers() {
                    Ok(o) => o,
                    Err(e) => {
                        info!("{}", e);
                        continue;
                    }
                } {
                    SERVER.write().push(SocketAddr::new(elem, 53));
                }
            } else {
                SERVER.write().push(match server.parse() {
                    Ok(o) => o,
                    Err(e1) => SocketAddr::new(
                        match server.parse() {
                            Ok(o) => o,
                            Err(e2) => {
                                info!("{} {}", e1, e2);
                                continue;
                            }
                        },
                        53,
                    ),
                });
            }
        }
        SERVER.write().sort_unstable();
        SERVER.write().dedup();

        // log
        for elem in &*SERVER.read() {
            debug!("dns server: {}", elem);
        }

        if !server.contains(&"system".to_string()) || interval == Duration::from_millis(0) {
            return;
        }

        tokio::time::sleep(interval).await;
    }
}

// make sure cache is up to date
async fn refresh_cache(interval: Duration) {
    if interval == Duration::from_millis(0) {
        return;
    }

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    loop {
        tokio::time::sleep(interval).await;

        for task in &tasks {
            task.abort();
        }
        tasks.clear();

        for (domain, lru_cache) in &*LRU.lock() {
            let domain = domain.clone();

            if tokio::time::Instant::now() + interval > lru_cache.deadline {
                debug!("refresh name:{}", domain);

                tasks.push(tokio::spawn(async move {
                    if let Err(e) = resolve(&domain).await {
                        info!("refresh cache error: {}", e);
                    }
                }));
            }
        }
    }
}

// ip address will return directly
// unsupport localhost, etc.
pub(crate) async fn resolve(domain: &str) -> Result<String, Box<dyn std::error::Error>> {
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Ok(domain.to_string());
    }

    if let Some(s) = LRU.lock().get(&domain.to_string()) {
        if s.deadline >= tokio::time::Instant::now() {
            return Ok(s.addr.clone());
        }
    }

    let udp_dual_socket = Arc::new(tokio::net::UdpSocket::from_std(
        crate::misc::build_socket_listener("udp", "[::]:0")?.into(),
    )?);
    let mut a_query = badns::generate_query(&domain, badns::QueryType::A);
    a_query.header.id = 4; // XXX fixed dns id 4
    let a_query_buf = a_query.into_buf()?;
    let mut aaaa_query = badns::generate_query(&domain, badns::QueryType::AAAA);
    aaaa_query.header.id = 6; // XXX fixed dns id 6
    let aaaa_query_buf = aaaa_query.into_buf()?;

    let mut tasks = Vec::new();

    // send & recv
    let reply_buf = vec![0u8; UDP_LEN];
    let wrong_first = Arc::new(AtomicBool::new(false));
    let result = tokio::select! {
        _ = async {
            let retry = RESOLVE.read().retry;
            let timeout = RESOLVE.read().timeout;

            send_dns_query(&mut tasks, &udp_dual_socket, &a_query_buf, &aaaa_query_buf);
            tokio::time::sleep(timeout).await;
            for _ in 0..retry {
                send_dns_query(&mut tasks, &udp_dual_socket, &a_query_buf, &aaaa_query_buf);
                tokio::time::sleep(timeout).await;
            }
        } => None,
        r = recv_dns_reply(udp_dual_socket.clone(), reply_buf, wrong_first.clone()) => r,
    };

    for task in tasks {
        task.abort();
    }

    match result {
        Some(s) => Ok(s),
        None => Err("resolve timeout".into()),
    }
}

async fn recv_dns_reply(
    udp_socket: Arc<tokio::net::UdpSocket>,
    mut reply_buf: Vec<u8>,
    wrong_first: Arc<AtomicBool>,
) -> Option<String> {
    loop {
        let (nrecv, _) = match udp_socket.recv_from(&mut reply_buf).await {
            Ok(o) => o,
            Err(e) => {
                info!("{}", e);
                continue;
            }
        };

        let dns = match badns::DNS::from_buf(reply_buf[..nrecv].as_ref()) {
            Ok(o) => o,
            Err(e) => {
                info!("{}", e);
                continue;
            }
        };
        if dns.questions.len() < 1 {
            info!("dns.questions.len() < 1");
            continue;
        }
        if RESOLVE.read().ipv6_first {
            // XXX fixed dns id 6
            if dns.header.id == 6
                && (dns.header.answers == 0
                    || dns.header.response_code != badns::ResponseCode::NoError)
            {
                wrong_first.store(true, Ordering::Relaxed);
            }
        } else {
            // XXX fixed dns id 4
            if dns.header.id == 4
                && (dns.header.answers == 0
                    || dns.header.response_code != badns::ResponseCode::NoError)
            {
                wrong_first.store(true, Ordering::Relaxed);
            }
        }
        for answer in dns.answers {
            match answer.rdata {
                badns::Rdata::A(rdata) => {
                    if !RESOLVE.read().ipv6_first || wrong_first.load(Ordering::Relaxed) {
                        let ttl = if answer.ttl < RESOLVE.read().min_ttl as u32 {
                            RESOLVE.read().min_ttl
                        } else if answer.ttl > RESOLVE.read().max_ttl as u32 {
                            RESOLVE.read().max_ttl
                        } else {
                            answer.ttl as u64
                        };

                        LRU.lock().put(
                            answer.name,
                            LruResolve {
                                addr: rdata.ip.clone(),
                                deadline: tokio::time::Instant::now() + Duration::from_secs(ttl),
                            },
                        );

                        return Some(rdata.ip);
                    }
                }
                badns::Rdata::AAAA(rdata) => {
                    if RESOLVE.read().ipv6_first || wrong_first.load(Ordering::Relaxed) {
                        let ttl = if answer.ttl < RESOLVE.read().min_ttl as u32 {
                            RESOLVE.read().min_ttl
                        } else if answer.ttl > RESOLVE.read().max_ttl as u32 {
                            RESOLVE.read().max_ttl
                        } else {
                            answer.ttl as u64
                        };

                        LRU.lock().put(
                            answer.name,
                            LruResolve {
                                addr: rdata.ip.clone(),
                                deadline: tokio::time::Instant::now() + Duration::from_secs(ttl),
                            },
                        );

                        return Some(rdata.ip);
                    }
                }
                _ => {}
            }
        }
    }
}

fn send_dns_query(
    tasks: &mut Vec<JoinHandle<std::io::Result<usize>>>,
    udp_dual_socket: &Arc<tokio::net::UdpSocket>,
    a_query_buf: &Vec<u8>,
    aaaa_query_buf: &Vec<u8>,
) {
    for server in &*SERVER.read() {
        let server_mapped = build_socketaddrv6(server).unwrap();

        tasks.push(tokio::spawn({
            let udp_dual_socket = udp_dual_socket.clone();
            let a_query_buf = a_query_buf.clone();
            let server_mapped = server_mapped.clone();
            async move { udp_dual_socket.send_to(&a_query_buf, server_mapped).await }
        }));

        tasks.push(tokio::spawn({
            let udp_dual_socket = udp_dual_socket.clone();
            let aaaa_query_buf = aaaa_query_buf.clone();
            let server_mapped = server_mapped.clone();
            async move {
                udp_dual_socket
                    .send_to(&aaaa_query_buf, server_mapped)
                    .await
            }
        }));
    }
}

// cargo test --package stn resolve -- --nocapture
#[tokio::test]
async fn test() {
    SERVER
        .write()
        .push("8.8.8.8:53".parse::<SocketAddr>().unwrap());
    SERVER
        .write()
        .push("[::1]:53".parse::<SocketAddr>().unwrap());
    SERVER
        .write()
        .push("119.29.29.29:53".parse::<SocketAddr>().unwrap());
    *RESOLVE.write() = Resolve {
        timeout: Duration::from_millis(5000),
        retry: 1,
        min_ttl: 60,
        max_ttl: 600,
        ipv6_first: false,
    };

    let addr = resolve(&"qq.com".to_string()).await.unwrap();
    println!("{}", addr);
}
