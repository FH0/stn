use super::*;
use crate::route::OutUdp;
use log::*;
use parking_lot::{Mutex, RwLock};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{sync::mpsc::channel, task::JoinHandle};
use trust_dns_proto::op::{Message, MessageType, Query};

pub(crate) struct Out {
    pub(crate) tag: String,
    pub(crate) server: Arc<RwLock<Vec<SocketAddr>>>,
    pub(crate) udp_timeout: Duration,
    pub(crate) min_ttl: u32,
    pub(crate) max_ttl: u32,
    pub(crate) cache: Mutex<lru::LruCache<Vec<Query>, (Message, tokio::time::Instant)>>,
}

impl Out {
    pub(crate) fn new(root: &serde_json::Value) -> Arc<dyn crate::route::Out + Send + Sync> {
        let server = get_server_and_refresh_system(&root);

        let out = Arc::new(Self {
            tag: root["tag"].as_str().expect("tag not found").to_string(),
            server,
            udp_timeout: Duration::from_nanos(
                (root["udp_timeout"].as_f64().unwrap_or_else(|| 60f64) * 1000_000_000f64) as u64,
            ),
            min_ttl: root["min_ttl"].as_u64().unwrap_or_else(|| 60) as _,
            max_ttl: root["max_ttl"].as_u64().unwrap_or_else(|| 2147483647) as _,
            cache: Mutex::new(lru::LruCache::new(
                root["cache_size"].as_u64().unwrap_or_else(|| 1024) as _,
            )),
        });

        // refresh_cache
        if root["refresh_cache"].as_bool().unwrap_or_else(|| false) {
            tokio::spawn(out.clone().refresh_cache());
        }

        out
    }

    async fn refresh_cache(self: Arc<Self>) {
        let interval = if self.min_ttl == 0 {
            return;
        } else {
            Duration::from_secs(self.min_ttl as _)
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
            for (k, (_, deadline)) in &*self.cache.lock() {
                if tokio::time::Instant::now() + interval > *deadline {
                    queries.push(k.clone());
                }
            }

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

                // generate saddr
                let saddr = format!(
                    "{}_refresh_cache:{}",
                    self.tag,
                    query.as_ptr() as *const usize as usize,
                );

                // new a udp
                let (client_tx, mut server_rx) = channel(100);
                let (server_tx, client_rx) = channel(100);
                self.clone()
                    .udp_bind(saddr.clone(), client_tx, client_rx)
                    .await
                    .unwrap();

                // ignore server
                tasks.push(tokio::spawn({
                    let server_tx = server_tx.clone(); // keep connection
                    async move {
                        while let Some(_) = server_rx.recv().await {}
                        debug!("close");
                        let _ = server_tx;
                    }
                }));

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
        _client_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err("dns out unsupport tcp".into())
    }
}
