use log::*;
use parking_lot::{Mutex, RwLock};
use std::{net::IpAddr, str::FromStr, time::Duration};
use tokio::{
    sync::mpsc::channel,
    task::JoinHandle,
    time::{sleep, timeout},
};
use trust_dns_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};

use crate::misc::split_addr_str;

static mut RESOLVE: Option<Resolve> = None;

struct LruCacheValue {
    answer: String,
    deadline: tokio::time::Instant,
}

struct Resolve {
    tag: String,
    server: RwLock<Vec<String>>,
    udp_timeout: Duration,
    min_ttl: u32,
    max_ttl: u32,
    cache: Mutex<lru::LruCache<String, LruCacheValue>>,
    ipv6_first: bool,
}

pub(crate) fn init_resolve(root: &serde_json::Value) {
    let server = root["server"].as_array();
    let mut server = match server {
        Some(s) => s
            .into_iter()
            .map(|x| {
                let x_str = x.as_str().expect("server not string");
                if x_str.contains(":") || x_str == "system" {
                    x_str.to_string()
                } else {
                    format!("{}:53", x_str)
                }
            })
            .collect(),
        None => vec!["system".to_string()],
    };
    let resolve = Resolve {
        tag: root["tag"]
            .as_str()
            .unwrap_or_else(|| "resolve")
            .to_string(),
        server: RwLock::new(server.clone()),
        udp_timeout: Duration::from_nanos(
            (root["udp_timeout"].as_f64().unwrap_or_else(|| 5f64) * 1000_000_000f64) as _,
        ),
        min_ttl: root["min_ttl"].as_u64().unwrap_or_else(|| 60) as _,
        max_ttl: root["max_ttl"].as_u64().unwrap_or_else(|| 2147483647) as _,
        cache: Mutex::new(lru::LruCache::new(
            root["cache_size"].as_u64().unwrap_or_else(|| 1024) as _,
        )),
        ipv6_first: root["ipv6_first"].as_bool().unwrap_or_else(|| false),
    };
    unsafe { RESOLVE = Some(resolve) };

    // refresh system
    #[allow(unreachable_code)]
    for _ in 0..1 {
        if server.contains(&"system".to_string()) {
            // remove system
            server.retain(|x| x.as_str() != "system");

            #[cfg(any(target_os = "windows", target_os = "android", target_os = "linux"))]
            {
                if let Err(e) = refresh_system(server.clone()) {
                    warn!("{}", e);
                };
                let interval = Duration::from_nanos(
                    (root["refresh_system"].as_f64().unwrap_or_else(|| 3f64) * 1000_000_000f64)
                        as _,
                );
                if interval != Duration::new(0, 0) {
                    tokio::spawn(async move {
                        loop {
                            sleep(interval).await;
                            if let Err(e) = refresh_system(server.clone()) {
                                warn!("{}", e);
                            };
                        }
                    });
                }

                break;
            }

            panic!("unsupport system");
        }
    }

    // refresh_cache
    if root["refresh_cache"].as_bool().unwrap_or_else(|| false) {
        tokio::spawn(refresh_cache());
    }
}

pub(crate) async fn resolve(domain: &String) -> Result<String, Box<dyn std::error::Error>> {
    let (domain, port) = split_addr_str(&domain)?;

    // if ip addr
    if domain.parse::<IpAddr>().is_ok() {
        return Ok(format!("{}:{}", domain, port));
    }

    // search cache
    unsafe {
        let mut cache_lock = RESOLVE.as_ref().unwrap().cache.lock();
        if let Some(s) = cache_lock.get(&domain) {
            if tokio::time::Instant::now() > s.deadline {
                cache_lock.pop(&domain);
            } else {
                return Ok(format!("{}:{}", s.answer, port));
            }
        }
    }

    // bind
    let (own_tx, mut server_rx) = channel::<(String, Vec<u8>)>(100);
    let server_tx = crate::route::udp_bind(
        unsafe { RESOLVE.as_ref().unwrap().tag.clone() },
        unsafe {
            format!(
                "{}:{}",
                RESOLVE.as_ref().unwrap().tag,
                domain.as_ptr() as *const usize as usize
            )
        },
        own_tx,
    )?;

    // send
    let mut dns_msg4 = Message::new();
    let mut query4 = Query::new();
    query4.set_name(Name::from_str(&domain)?);
    query4.set_query_class(DNSClass::IN);
    query4.set_query_type(RecordType::A);
    dns_msg4.set_id(4);
    dns_msg4.add_query(query4);
    dns_msg4.set_message_type(MessageType::Query);
    dns_msg4.set_recursion_desired(true);
    let buf4 = dns_msg4.to_vec()?;

    let mut dns_msg6 = Message::new();
    let mut query6 = Query::new();
    query6.set_name(Name::from_str(&domain)?);
    query6.set_query_class(DNSClass::IN);
    query6.set_query_type(RecordType::AAAA);
    dns_msg6.set_id(6);
    dns_msg6.add_query(query6);
    dns_msg6.set_message_type(MessageType::Query);
    dns_msg6.set_recursion_desired(true);
    let buf6 = dns_msg6.to_vec()?;

    let mut tasks = Vec::new();
    for daddr in unsafe { RESOLVE.as_ref().unwrap().server.read().iter() } {
        tasks.push(tokio::spawn({
            let server_tx = server_tx.clone();
            let buf4 = buf4.clone();
            let buf6 = buf6.clone();
            let daddr = daddr.clone();
            async move {
                if let Err(_) = server_tx.send((daddr.clone(), buf4)).await {
                    debug!("channel close");
                }
                if let Err(_) = server_tx.send((daddr, buf6)).await {
                    debug!("channel close");
                }
            }
        }))
    }

    // recv and timeout
    let r = timeout(unsafe { RESOLVE.as_ref().unwrap().udp_timeout }, async {
        // ipv6_first logic
        let mut wrong_first = false;
        let mut cache_second = None;

        while let Some((_, recv_data)) = server_rx.recv().await {
            let dns_msg = match Message::from_vec(&recv_data) {
                Ok(o) => o,
                Err(e) => {
                    warn!("{}", e);
                    continue;
                }
            };

            // wrong_first
            if ((unsafe { RESOLVE.as_ref().unwrap().ipv6_first == false } && dns_msg.id() == 4)
                || (unsafe { RESOLVE.as_ref().unwrap().ipv6_first } && dns_msg.id() == 6))
                && (dns_msg.response_code() != ResponseCode::NoError
                    || dns_msg.answers().len() == 0)
            {
                if let Some(s) = cache_second {
                    return Ok(s);
                } else {
                    wrong_first = true;
                }
            }

            if dns_msg.answers().len() >= 1 {
                match dns_msg.answers()[0].rdata() {
                    RData::A(addr) => {
                        if unsafe { RESOLVE.as_ref().unwrap().ipv6_first == false } || wrong_first {
                            // ttl
                            let ttl = if dns_msg.answers()[0].ttl()
                                < unsafe { RESOLVE.as_ref().unwrap().min_ttl }
                            {
                                unsafe { RESOLVE.as_ref().unwrap().min_ttl }
                            } else if dns_msg.answers()[0].ttl()
                                > unsafe { RESOLVE.as_ref().unwrap().max_ttl }
                            {
                                unsafe { RESOLVE.as_ref().unwrap().max_ttl }
                            } else {
                                dns_msg.answers()[0].ttl()
                            } as u64;

                            // cache
                            unsafe {
                                RESOLVE.as_ref().unwrap().cache.lock().put(
                                    domain.to_string(),
                                    LruCacheValue {
                                        answer: addr.to_string(),
                                        deadline: tokio::time::Instant::now()
                                            + Duration::from_secs(ttl),
                                    },
                                );
                            }

                            return Ok(format!("{}:{}", addr.to_string(), port));
                        } else {
                            cache_second.replace(addr.to_string());
                        }
                    }
                    RData::AAAA(addr) => {
                        if unsafe { RESOLVE.as_ref().unwrap().ipv6_first } || wrong_first {
                            // ttl
                            let ttl = if dns_msg.answers()[0].ttl()
                                < unsafe { RESOLVE.as_ref().unwrap().min_ttl }
                            {
                                unsafe { RESOLVE.as_ref().unwrap().min_ttl }
                            } else if dns_msg.answers()[0].ttl()
                                > unsafe { RESOLVE.as_ref().unwrap().max_ttl }
                            {
                                unsafe { RESOLVE.as_ref().unwrap().max_ttl }
                            } else {
                                dns_msg.answers()[0].ttl()
                            } as u64;

                            // cache
                            unsafe {
                                RESOLVE.as_ref().unwrap().cache.lock().put(
                                    domain.to_string(),
                                    LruCacheValue {
                                        answer: addr.to_string(),
                                        deadline: tokio::time::Instant::now()
                                            + Duration::from_secs(ttl),
                                    },
                                );
                            }

                            return Ok(format!("{}:{}", addr.to_string(), port));
                        } else {
                            cache_second.replace(addr.to_string());
                        }
                    }
                    _ => continue,
                }
            }
        }

        Err::<String, Box<dyn std::error::Error>>("channel close".into())
    })
    .await?;

    if let Ok(o) = &r {
        debug!("{} resolve to {}", domain, o);
    }

    r
}

fn refresh_system(mut origin_server: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    for adapter in ipconfig::get_adapters()? {
        for server in adapter.dns_servers() {
            origin_server.push(format!("{}:53", server));
        }
    }
    #[cfg(target_os = "android")]
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
            origin_server.push(format!("{}:53", server_string));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let buf = std::fs::read_to_string("/etc/resolv.conf")?;
        let config = resolv_conf::Config::parse(buf)?;
        for elem in config.nameservers {
            origin_server.push(format!("{}:53", elem));
        }
    }

    // dedup
    origin_server.sort_unstable();
    origin_server.dedup();

    unsafe {
        RESOLVE
            .as_ref()
            .unwrap()
            .server
            .write()
            .splice(.., origin_server);
    }

    Ok(())
}

async fn refresh_cache() {
    let interval = if unsafe { RESOLVE.as_ref().unwrap().min_ttl } == 0 {
        return;
    } else {
        Duration::from_secs(unsafe { RESOLVE.as_ref().unwrap().min_ttl } as _)
    };

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    loop {
        tokio::time::sleep(interval).await;

        // clear tasks before next refresh cache
        for task in &tasks {
            task.abort();
        }
        tasks.clear();

        // get refresh list
        let mut queries = Vec::new();
        for (k, v) in unsafe { RESOLVE.as_ref().unwrap().cache.lock().iter() } {
            if tokio::time::Instant::now() + interval > v.deadline {
                queries.push(k.clone());
            }
        }

        // delete cache
        {
            let mut cache_lock = unsafe { RESOLVE.as_ref().unwrap().cache.lock() };
            for query in &queries {
                cache_lock.pop(query);
            }
        }

        // refresh cache
        for query in queries {
            debug!("refresh cache: {}", query);

            tasks.push(tokio::spawn(async move {
                if let Err(e) = resolve(&format!("{}:0", query)).await {
                    warn!("{}", e);
                }
            }));
        }
    }
}
