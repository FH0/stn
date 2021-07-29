use super::*;
use crate::misc::{build_socketaddrv6, socketaddr_to_string};
use log::*;
use std::sync::Arc;

#[async_trait::async_trait]
impl crate::route::OutUdp for super::Out {
    async fn udp_bind(
        self: Arc<Self>,
        saddr: String,
        client_tx: tokio::sync::mpsc::Sender<(String, Vec<u8>)>,
        mut client_rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // bind
        let server = Arc::new(tokio::net::UdpSocket::from_std(
            crate::misc::build_socket_listener("udp", "[::]:0")?.into(),
        )?);

        tokio::spawn(async move {
            let mut buf = vec![0; UDP_LEN];
            match bidirectional_with_timeout!(
                {
                    // read client
                    let (daddr, recv_data) = client_rx.recv().await.ok_or("close")?;

                    // write server
                    debug!("{} {} -> {} {}", self.tag, saddr, daddr, recv_data.len());
                    let daddr_ip = crate::resolve::resolve(&daddr).await?;
                    let daddr_ipv6 = build_socketaddrv6(daddr_ip)?;
                    server.send_to(&recv_data, daddr_ipv6).await?;
                },
                {
                    // read server
                    let (nrecv, daddr) = server.recv_from(&mut buf).await?;
                    let daddr = socketaddr_to_string(&daddr);

                    // write client
                    debug!("{} {} -> {} {}", self.tag, daddr, saddr, nrecv);
                    client_tx
                        .send((daddr.to_string(), buf[..nrecv].to_vec()))
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

        Ok(())
    }
}
