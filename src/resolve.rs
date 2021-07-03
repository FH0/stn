use crate::{
    dns::get_server_and_refresh_system,
    misc::{is_valid_domain, split_addr_str},
};
use log::*;
use parking_lot::{Mutex, RwLock};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{task::JoinHandle, time::timeout};
use trust_dns_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};

lazy_static::lazy_static! {
    static ref RESOLVE :RwLock<Resolve> = RwLock::new(Resolve {
        tag: String::new(),
        server: Arc::new(RwLock::new(Vec::new())),
        udp_timeout: Duration::from_secs(0),
        min_ttl: 0,
        max_ttl: 0,
        cache: Mutex::new(lru::LruCache::new(1)),
        ipv6_first: false,
    });
}

struct Resolve {
    tag: String,
    server: Arc<RwLock<Vec<SocketAddr>>>,
    udp_timeout: Duration,
    min_ttl: u32,
    max_ttl: u32,
    cache: Mutex<lru::LruCache<String, (String, tokio::time::Instant)>>,
    ipv6_first: bool,
}

pub(crate) fn init_resolve(root: &serde_json::Value) {
    let server = get_server_and_refresh_system(&root);

    let mut resolve_write = RESOLVE.write();
    resolve_write.tag = root["tag"]
        .as_str()
        .unwrap_or_else(|| "resolve")
        .to_string();
    resolve_write.server = server;
    resolve_write.udp_timeout = Duration::from_nanos(
        (root["udp_timeout"].as_f64().unwrap_or_else(|| 5f64) * 1000_000_000f64) as _,
    );
    resolve_write.min_ttl = root["min_ttl"].as_u64().unwrap_or_else(|| 60) as _;
    resolve_write.max_ttl = root["max_ttl"].as_u64().unwrap_or_else(|| 2147483647) as _;
    resolve_write.cache = Mutex::new(lru::LruCache::new(
        root["cache_size"].as_u64().unwrap_or_else(|| 1024) as _,
    ));
    resolve_write.ipv6_first = root["ipv6_first"].as_bool().unwrap_or_else(|| false);

    // refresh_cache
    if root["refresh_cache"].as_bool().unwrap_or_else(|| false) {
        tokio::spawn(refresh_cache());
    }
}

pub(crate) async fn resolve(addr_str: &String) -> Result<String, Box<dyn std::error::Error>> {
    let (domain, port) = split_addr_str(&addr_str)?;

    // if ip addr
    if domain.parse::<IpAddr>().is_ok() {
        return Ok(format!("{}:{}", domain, port));
    }

    // if domain
    if !is_valid_domain(&domain) {
        Err(format!("invalid domain: {}", domain))?
    }

    // search cache
    {
        let resolve_read = RESOLVE.read();
        let mut cache_lock = resolve_read.cache.lock();
        if let Some((answer, deadline)) = cache_lock.get(&domain) {
            if tokio::time::Instant::now() > *deadline {
                cache_lock.pop(&domain);
            } else {
                debug!("{}:{} resolve to {}:{}", domain, port, answer, port);
                return Ok(format!("{}:{}", answer, port));
            }
        }
    }

    // bind
    let (server_tx, mut server_rx) = crate::route::udp_bind(
        RESOLVE.read().tag.clone(),
        format!(
            "{}:{}",
            RESOLVE.read().tag,
            domain.as_ptr() as *const usize as usize
        ),
    )?;

    // send
    let mut tasks = Vec::new();
    for (id, query_type) in [(4, RecordType::A), (6, RecordType::AAAA)].iter() {
        let mut dns_msg = Message::new();
        let mut query = Query::new();
        query.set_name(Name::from_str(&domain)?);
        query.set_query_class(DNSClass::IN);
        query.set_query_type(*query_type);
        dns_msg.set_id(*id);
        dns_msg.add_query(query);
        dns_msg.set_message_type(MessageType::Query);
        dns_msg.set_recursion_desired(true);
        let buf = dns_msg.to_vec()?;

        for daddr in RESOLVE.read().server.read().iter() {
            tasks.push(tokio::spawn({
                let server_tx = server_tx.clone();
                let buf = buf.clone();
                let daddr = daddr.clone();
                async move {
                    if let Err(_) = server_tx.send((daddr.to_string(), buf)).await {
                        debug!("channel close");
                    }
                }
            }))
        }
    }

    // recv and timeout
    let udp_timeout = RESOLVE.read().udp_timeout;
    let r = timeout(udp_timeout, async {
        // ipv6_first logic
        let mut wrong_first = false;

        while let Some((_, recv_data)) = server_rx.recv().await {
            let dns_msg = match Message::from_vec(&recv_data) {
                Ok(o) => o,
                Err(e) => {
                    warn!("{}", e);
                    continue;
                }
            };

            // wrong_first
            if ((RESOLVE.read().ipv6_first == false && dns_msg.id() == 4)
                || (RESOLVE.read().ipv6_first && dns_msg.id() == 6))
                && (dns_msg.response_code() != ResponseCode::NoError
                    || !dns_msg.answers().iter().any(|x| match x.rdata() {
                        RData::A(_) | RData::AAAA(_) => true,
                        _ => false,
                    }))
            {
                if let Some((answer, _)) = RESOLVE.read().cache.lock().get(&domain) {
                    return Ok(answer.clone());
                } else {
                    wrong_first = true;
                }
            }

            for answer in dns_msg.answers() {
                // ttl
                let ttl = if answer.ttl() < RESOLVE.read().min_ttl {
                    RESOLVE.read().min_ttl
                } else if answer.ttl() > RESOLVE.read().max_ttl {
                    RESOLVE.read().max_ttl
                } else {
                    answer.ttl()
                } as u64;

                let (addr, is_first) = match answer.rdata() {
                    RData::A(addr) => (addr.to_string(), RESOLVE.read().ipv6_first == false),
                    RData::AAAA(addr) => (addr.to_string(), RESOLVE.read().ipv6_first),
                    _ => continue,
                };

                // cache
                RESOLVE.read().cache.lock().put(
                    domain.to_string(),
                    (
                        addr.clone(),
                        tokio::time::Instant::now() + Duration::from_secs(ttl),
                    ),
                );

                if is_first || wrong_first {
                    return Ok(format!("{}:{}", addr, port));
                }
            }
        }

        Err::<String, Box<dyn std::error::Error>>("channel close".into())
    })
    .await?;

    // abort tasks
    for task in tasks {
        task.abort();
    }

    if let Ok(o) = &r {
        debug!("{}:{} resolve to {}", domain, port, o);
    }

    r
}

async fn refresh_cache() {
    let interval = if RESOLVE.read().min_ttl == 0 {
        return;
    } else {
        Duration::from_secs(RESOLVE.read().min_ttl as _)
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
        for (k, (_, deadline)) in RESOLVE.read().cache.lock().iter() {
            if tokio::time::Instant::now() + interval > *deadline {
                queries.push(k.clone());
            }
        }

        // delete cache
        {
            let resolve_read = RESOLVE.read();
            let mut cache_lock = resolve_read.cache.lock();
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
