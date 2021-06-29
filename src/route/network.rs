use crate::route::find_out;
use log::*;
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
            let mut fullcone_map: HashMap<usize, Sender<(String, Vec<u8>)>> = HashMap::new();
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

                // get server_tx or new a task
                let server_tx = if let Some(s) = fullcone_map.get(&out_usize) {
                    s.clone()
                } else {
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
                    fullcone_map.insert(out_usize, server_tx.clone());
                    server_tx
                };

                // send
                if let Err(e) = server_tx.try_send((daddr.clone(), recv_data)) {
                    warn!("{} {} -> {} {}", tag, saddr, daddr, e);
                    continue;
                }
            }
        }
    });

    Ok(own_tx)
}

macro_rules! bidirectional_with_timeout {
    ($client_block:block, $server_block:block, $timeout:expr) => {{
        let (timer_tx, mut timer_rx) = tokio::sync::mpsc::channel::<()>(1);
        tokio::select! {
            r = async {
                loop {
                    $client_block

                    // update timer
                    timer_tx.send(()).await.or(Err("close"))?;
                }
                #[allow(unreachable_code)]
                Ok::<(), Box<dyn std::error::Error>>(())
            } => (r, Ok(()), Ok(())),
            r = async {
                loop {
                    $server_block

                    // update timer
                    timer_tx.send(()).await.or(Err("close"))?;
                }
                #[allow(unreachable_code)]
                Ok::<(), Box<dyn std::error::Error>>(())
            } => (Ok(()), r, Ok(())),
            r = async {
                loop {
                    tokio::select! {
                        _ = timer_rx.recv() => continue,
                        _ = tokio::time::sleep($timeout) => Err("timeout")?,
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), Box<dyn std::error::Error>>(())
            } => (
                Ok::<(), Box<dyn std::error::Error>>(()), // client_block
                Ok::<(), Box<dyn std::error::Error>>(()), // server_block
                r,                                        // timeout
            ),
        }
    }};
}
