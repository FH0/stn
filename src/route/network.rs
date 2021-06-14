use crate::route::find_out;
use log::warn;
use std::collections::HashMap;
use tokio::sync::mpsc::{channel, Sender};

// route global entry
#[inline]
pub(crate) async fn tcp_connect(
    tag: String,
    saddr: String,
    daddr: String,
    client_tx: Sender<Vec<u8>>,
) -> Result<Sender<Vec<u8>>, Box<dyn std::error::Error>> {
    // tcp needn't dispatch
    find_out(tag.clone(), "tcp".to_string(), saddr, daddr.clone(), &[])
        .tcp_connect(
            format!(
                "{}:{}",
                tag,
                tag.as_bytes() as *const _ as *const usize as usize
            ),
            daddr,
            client_tx,
        )
        .await
}

// route global entry
#[inline]
pub(crate) fn udp_bind(
    tag: String,
    saddr: String,
    client_tx: Sender<(String, Vec<u8>)>,
) -> Result<Sender<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
    let (own_tx, mut own_rx) = channel::<(String, Vec<u8>)>(100);

    // dispatch, single src may have multi dst out
    tokio::spawn({
        async move {
            let mut out_map: HashMap<usize, Sender<(String, Vec<u8>)>> = HashMap::new();
            let unique_port = Box::new(0u8).as_ref() as *const _ as usize;

            // if None recv, return
            while let Some((daddr, recv_data)) = own_rx.recv().await {
                // out_usize as map key
                let out = find_out(
                    tag.clone(),
                    "udp".to_string(),
                    saddr.clone(),
                    daddr.clone(),
                    &recv_data,
                );
                let out_usize = out.as_ref() as *const _ as *const usize as usize;

                // if not contains, add it
                if !out_map.contains_key(&out_usize) {
                    // give client_tx to server, server send data to client directly
                    let server_tx = match out
                        .udp_bind(format!("{}:{}", tag, unique_port), client_tx.clone())
                        .await
                    {
                        Ok(o) => o,
                        Err(e) => {
                            warn!("{} {} -> {} {}", tag, saddr, daddr, e);
                            continue;
                        }
                    };
                    out_map.insert(out_usize, server_tx);
                }

                // send without blocking, that's why channel has buffer
                let server_tx = match out_map.get(&out_usize) {
                    Some(s) => s,
                    None => {
                        warn!("{} {} -> {} server_tx is None", tag, saddr, daddr);
                        continue;
                    }
                };
                if let Err(e) = server_tx.try_send((daddr.clone(), recv_data)) {
                    warn!("{} {} -> {} {}", tag, saddr, daddr, e);
                    continue;
                }
            }
        }
    });

    Ok(own_tx)
}
