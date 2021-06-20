use crate::route::OutUdp;
use log::*;
use parking_lot::{Mutex, RwLock};
use std::{sync::Arc, time::Duration};
use tokio::{sync::mpsc::channel, task::JoinHandle, time::sleep};
use trust_dns_proto::op::{Message, MessageType, Query};

#[derive(Clone, Debug)]
pub(crate) struct LruCacheValue {
    pub(crate) message: Message,
    pub(crate) deadline: tokio::time::Instant,
}

pub(crate) struct Out {
    pub(crate) tag: String,
    pub(crate) server: RwLock<Vec<String>>,
    pub(crate) udp_timeout: Duration,
    pub(crate) min_ttl: u32,
    pub(crate) max_ttl: u32,
    pub(crate) cache: Mutex<lru::LruCache<Vec<Query>, LruCacheValue>>,
}

impl Out {
    pub(crate) fn new(root: &serde_json::Value) -> Arc<dyn crate::route::Out + Send + Sync> {
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

        let out = Arc::new(Self {
            tag: root["tag"].as_str().expect("tag not found").to_string(),
            server: RwLock::new(server.clone()),
            udp_timeout: Duration::from_nanos(
                (root["udp_timeout"].as_f64().unwrap_or_else(|| 60f64) * 1000_000_000f64) as u64,
            ),
            min_ttl: root["min_ttl"].as_u64().unwrap_or_else(|| 60) as _,
            max_ttl: root["max_ttl"].as_u64().unwrap_or_else(|| 2147483647) as _,
            cache: Mutex::new(lru::LruCache::new(
                root["cache_size"].as_u64().unwrap_or_else(|| 1024) as _,
            )),
        });

        // refresh system
        #[allow(unreachable_code)]
        for _ in 0..1 {
            if server.contains(&"system".to_string()) {
                // remove system
                server.retain(|x| x.as_str() != "system");

                #[cfg(any(target_os = "windows", target_os = "android", target_os = "linux"))]
                {
                    if let Err(e) = out.clone().refresh_system(server.clone()) {
                        warn!("{}", e);
                    };
                    let interval = Duration::from_nanos(
                        (root["refresh_system"].as_f64().unwrap_or_else(|| 3f64) * 1000_000_000f64)
                            as _,
                    );
                    if interval != Duration::new(0, 0) {
                        tokio::spawn({
                            let out = out.clone();
                            async move {
                                loop {
                                    sleep(interval).await;
                                    if let Err(e) = out.clone().refresh_system(server.clone()) {
                                        warn!("{}", e);
                                    };
                                }
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
            tokio::spawn(out.clone().refresh_cache());
        }

        out
    }

    fn refresh_system(
        self: Arc<Self>,
        mut origin_server: Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

        self.server.write().splice(.., origin_server);

        Ok(())
    }

    async fn refresh_cache(self: Arc<Self>) {
        let interval = if self.min_ttl == 0 {
            return;
        } else {
            Duration::from_secs(self.min_ttl as _)
        };

        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        let saddr = format!(
            "{}_refresh_cache:{}",
            self.tag,
            self.as_ref() as *const _ as *const usize as usize
        );

        loop {
            tokio::time::sleep(interval).await;

            // clear tasks before next refresh cache
            for task in &tasks {
                task.abort();
            }
            tasks.clear();

            // get refresh list
            let mut queries = Vec::new();
            for (k, v) in &*self.cache.lock() {
                if tokio::time::Instant::now() + interval > v.deadline {
                    queries.push(k.clone());
                }
            }
            if queries.len() == 0 {
                continue;
            }

            // new a udp
            let (own_tx, mut server_rx) = channel(100);
            let server_tx = self.clone().udp_bind(saddr.clone(), own_tx).await.unwrap();

            // ignore server
            tasks.push(tokio::spawn({
                let server_tx = server_tx.clone(); // keep connection
                async move {
                    while let Some(_) = server_rx.recv().await {}
                    debug!("close");
                    let _ = server_tx;
                }
            }));

            // delete cache
            {
                let mut cache_lock = self.cache.lock();
                for query in &queries {
                    cache_lock.pop(query);
                }
            }

            // refresh cache
            for query in queries {
                for i in &query {
                    debug!(
                        "refresh cache: {} {} {} ",
                        i.name().to_utf8(),
                        i.query_type(),
                        i.query_class()
                    );
                }

                // send
                let mut dns_msg = Message::new();
                dns_msg.set_message_type(MessageType::Query);
                dns_msg.set_recursion_desired(true);
                dns_msg.add_queries(query.clone());
                let buf = match dns_msg.to_vec() {
                    Ok(o) => o,
                    Err(e) => {
                        warn!("{}", e);
                        continue;
                    }
                };
                tasks.push(tokio::spawn({
                    let buf = buf.clone();
                    let server_tx = server_tx.clone();
                    async move {
                        if let Err(_) = server_tx
                            .send((
                                "0.0.0.0:0".to_string(), // "0.0.0.0:0" is ok, just refresh cache
                                buf,
                            ))
                            .await
                        {
                            debug!("close");
                        }
                    }
                }));
            }
        }
    }
}

#[async_trait::async_trait]
impl crate::route::OutTcp for Out {
    async fn tcp_connect(
        self: Arc<Self>,
        _saddr: String,
        _daddr: String,
        _client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<tokio::sync::mpsc::Sender<Vec<u8>>, Box<dyn std::error::Error>> {
        Err("dns out unsupport tcp".into())
    }
}
