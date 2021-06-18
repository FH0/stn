use crate::dns::out::LruCacheValue;
use log::*;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc::{channel, Sender};
use trust_dns_proto::op::{Message, Query};

#[async_trait::async_trait]
impl crate::route::OutUdp for super::Out {
    async fn udp_bind(
        self: Arc<Self>,
        saddr: String,
        client_tx: Sender<(String, Vec<u8>)>,
    ) -> Result<Sender<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
        // bind
        let (own_tx, mut server_rx) = channel::<(String, Vec<u8>)>(100);
        let server_tx = crate::route::udp_bind(self.tag.clone(), saddr.clone(), own_tx)?;
        let (own_tx, mut client_rx) = channel::<(String, Vec<u8>)>(100);

        // send to multi daddr, only the first recv data send to client
        let multi_daddr_map = Arc::new(dashmap::DashMap::<Vec<Query>, String>::new());

        let (exit_or_update_timer_tx, mut exit_or_update_timer_rx) = channel::<bool>(1);
        // client
        let task1 = tokio::spawn({
            let exit_or_update_timer_tx = exit_or_update_timer_tx.clone();
            let self_clone = self.clone();
            let saddr = saddr.clone();
            let client_tx = client_tx.clone();
            let multi_daddr_map = multi_daddr_map.clone();
            async move {
                loop {
                    // read client
                    let (daddr, recv_data) = match client_rx.recv().await {
                        Some(s) => s,
                        None => {
                            debug!("{} {} close", self_clone.tag, saddr);
                            break;
                        }
                    };
                    // if cached
                    let dns_msg = match Message::from_vec(&recv_data) {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} -> {} {}", self_clone.tag, saddr, daddr, e);
                            continue;
                        }
                    };
                    let lru_cache_value_option =
                        match self_clone.cache.lock().get(&dns_msg.queries().to_vec()) {
                            Some(s) => {
                                if tokio::time::Instant::now() <= s.deadline {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            }
                            None => None,
                        };
                    if let Some(mut lru_cache_value) = lru_cache_value_option {
                        // fake id
                        lru_cache_value.message.set_id(dns_msg.id());

                        // write client
                        let buf = match lru_cache_value.message.to_vec() {
                            Ok(o) => o,
                            Err(e) => {
                                warn!("{} {} -> {} {}", self_clone.tag, saddr, daddr, e);
                                continue;
                            }
                        };
                        debug!("{} {} -> {} {}", self_clone.tag, daddr, saddr, buf.len());
                        if let Err(_) = client_tx.send((daddr.clone(), buf)).await {
                            debug!("{} {} -> {} close", self_clone.tag, daddr, saddr);
                            break;
                        }
                    } else {
                        // record
                        multi_daddr_map.insert(dns_msg.queries().to_vec(), daddr.clone());

                        // write server
                        for daddr in &self_clone.server {
                            debug!(
                                "{} {} -> {} {}",
                                self_clone.tag,
                                saddr,
                                daddr,
                                recv_data.len()
                            );
                            if let Err(_) = server_tx.send((daddr.clone(), recv_data.clone())).await
                            {
                                debug!("{} {} -> {} close", self_clone.tag, saddr, daddr);
                                break;
                            }
                        }
                    }

                    // update timer
                    exit_or_update_timer_tx.send(false).await.unwrap();
                }

                // exit
                exit_or_update_timer_tx.send(true).await.unwrap();
            }
        });
        // server
        let task2 = tokio::spawn({
            let self_clone = self.clone();
            let saddr = saddr.clone();
            async move {
                loop {
                    // read server
                    let (daddr, recv_data) = match server_rx.recv().await {
                        Some(s) => s,
                        None => {
                            debug!("{} {} close", self_clone.tag, saddr);
                            break;
                        }
                    };

                    // write client
                    // check cache
                    let mut dns_msg = match Message::from_vec(&recv_data) {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} -> {} {}", self_clone.tag, daddr, saddr, e);
                            continue;
                        }
                    };
                    let daddr = if let Some(s) = multi_daddr_map.remove(&dns_msg.queries().to_vec())
                    {
                        s.1.clone()
                    } else {
                        continue;
                    };
                    // set ttl
                    let mut last_ttl = 0u64;
                    for i in dns_msg.answers_mut() {
                        if i.ttl() < self_clone.min_ttl {
                            i.set_ttl(self_clone.min_ttl);
                        } else if i.ttl() > self_clone.max_ttl {
                            i.set_ttl(self_clone.max_ttl);
                        }

                        last_ttl = i.ttl() as _;
                    }
                    let buf = match dns_msg.to_vec() {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} -> {} {}", self_clone.tag, daddr, saddr, e);
                            continue;
                        }
                    };
                    // cache
                    {
                        let mut cache_lock = self_clone.cache.lock();
                        cache_lock.put(
                            dns_msg.queries().to_vec(),
                            LruCacheValue {
                                message: dns_msg.clone(),
                                deadline: tokio::time::Instant::now()
                                    + Duration::from_secs(last_ttl),
                            },
                        );
                    }
                    debug!("{} {} -> {} {}", self_clone.tag, daddr, saddr, buf.len());
                    if let Err(_) = client_tx.send((daddr.clone(), buf)).await {
                        debug!("{} {} -> {} close", self_clone.tag, daddr, saddr);
                        break;
                    }

                    // update timer
                    exit_or_update_timer_tx.send(false).await.unwrap();
                }

                // exit
                exit_or_update_timer_tx.send(true).await.unwrap();
            }
        });
        // timeout and others
        tokio::spawn({
            async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(self.udp_timeout) => {
                            warn!("{} {} timeout", self.tag, saddr);
                            break;
                        },
                        exit = exit_or_update_timer_rx.recv() => {
                            if exit.unwrap() {
                                break;
                            } else {
                                continue;
                            }
                        },
                    };
                }

                task1.abort();
                task2.abort();
                let _ = task1.await;
                let _ = task2.await;
            }
        });

        Ok(own_tx)
    }
}
