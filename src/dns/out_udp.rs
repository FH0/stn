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

        tokio::spawn(async move {
            match bidirectional_with_timeout!(
                {
                    // read client
                    let (daddr, recv_data) = client_rx.recv().await.ok_or("close")?;
                    // if cached
                    let dns_msg = Message::from_vec(&recv_data)?;
                    let lru_cache_value_option =
                        match self.cache.lock().get(&dns_msg.queries().to_vec()) {
                            Some(s) => {
                                // compare deadline
                                if tokio::time::Instant::now() <= s.1 {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            }
                            None => None,
                        };
                    if let Some((mut message, _)) = lru_cache_value_option {
                        // fake id
                        message.set_id(dns_msg.id());

                        // write client
                        let buf = message.to_vec()?;
                        debug!("{} {} -> {} {}", self.tag, daddr, saddr, buf.len());
                        client_tx
                            .send((daddr.clone(), buf))
                            .await
                            .or(Err("close"))?;
                    } else {
                        // record
                        multi_daddr_map.insert(dns_msg.queries().to_vec(), daddr.clone());

                        // write server
                        let daddrs = self.server.read().clone();
                        for daddr in daddrs {
                            debug!("{} {} -> {} {}", self.tag, saddr, daddr, recv_data.len());

                            server_tx
                                .send((daddr.to_string(), recv_data.clone()))
                                .await
                                .or(Err("close"))?;
                        }
                    }
                },
                {
                    // read server
                    let (_, recv_data) = server_rx.recv().await.ok_or("close")?;

                    // write client
                    // check cache
                    let mut dns_msg = Message::from_vec(&recv_data)?;
                    let daddr = if let Some(s) = multi_daddr_map.remove(&dns_msg.queries().to_vec())
                    {
                        s.1.clone()
                    } else {
                        continue;
                    };
                    // set ttl
                    let mut last_ttl = 0u64;
                    for i in dns_msg.answers_mut() {
                        if i.ttl() < self.min_ttl {
                            i.set_ttl(self.min_ttl);
                        } else if i.ttl() > self.max_ttl {
                            i.set_ttl(self.max_ttl);
                        }

                        last_ttl = i.ttl() as _;
                    }
                    let buf = dns_msg.to_vec()?;
                    // cache
                    {
                        let mut cache_lock = self.cache.lock();
                        cache_lock.put(
                            dns_msg.queries().to_vec(),
                            (
                                dns_msg.clone(),
                                tokio::time::Instant::now() + Duration::from_secs(last_ttl),
                            ),
                        );
                    }
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, buf.len());
                    client_tx
                        .send((daddr.clone(), buf))
                        .await
                        .or(Err("close"))?;
                },
                self.udp_timeout
            ) {
                (Err(e), _, _) | (_, _, Err(e)) | (_, Err(e), _) => {
                    let e = e.to_string();
                    if e.as_str() == "close" || e.as_str() == "timeout" {
                        debug!("{} {} {}", self.tag, saddr, e)
                    } else {
                        warn!("{} {} {}", self.tag, saddr, e)
                    }
                }
                _ => unreachable!(),
            }
        });

        Ok(own_tx)
    }
}
