use super::*;
use futures::FutureExt;
use hyper::{
    client::connect::{Connected, Connection},
    service::Service,
    Uri,
};
use log::*;
use std::{future::Future, pin::Pin, sync::Arc, task::Poll::*};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc::{Receiver, Sender},
    time::timeout,
};

#[derive(Clone)]
pub(crate) struct ProxyHttpClient {
    r#in: Arc<In>,
    saddr: String,
}

impl ProxyHttpClient {
    pub(crate) fn new(r#in: Arc<In>, saddr: String) -> Self {
        Self { r#in, saddr }
    }
}

impl Service<Uri> for ProxyHttpClient {
    type Response = ProxyHttpResponse;
    type Error = std::io::Error;
    type Future = ProxyHttpFuture;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let r#in = self.r#in.clone();
        let saddr = self.saddr.clone();

        Self::Future {
            fut: async move {
                let daddr = host_addr(&req).unwrap();
                ProxyHttpResponse::connect(r#in, saddr, daddr).await
            }
            .boxed(),
        }
    }
}

#[pin_project::pin_project]
pub struct ProxyHttpFuture {
    #[pin]
    fut: Pin<Box<dyn Future<Output = Result<ProxyHttpResponse, std::io::Error>> + Send>>,
}

impl Future for ProxyHttpFuture {
    type Output = Result<ProxyHttpResponse, std::io::Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

pub struct ProxyHttpResponse {
    r#in: Arc<In>,
    server_tx: Sender<Vec<u8>>,
    server_rx: Receiver<Vec<u8>>,
    saddr: String,
    daddr: String,
    server_buf: Vec<u8>,
}

impl ProxyHttpResponse {
    async fn connect(r#in: Arc<In>, saddr: String, daddr: String) -> Result<Self, std::io::Error> {
        let (server_tx, server_rx) = match timeout(
            r#in.tcp_timeout,
            crate::route::tcp_connect(r#in.tag.clone(), saddr.clone(), daddr.clone()),
        )
        .await?
        {
            Ok(o) => o,
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                e.to_string(),
            ))?,
        };

        Ok(ProxyHttpResponse {
            r#in,
            server_tx,
            server_rx,
            saddr,
            daddr,
            server_buf: Vec::new(),
        })
    }
}

impl AsyncRead for ProxyHttpResponse {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Box::pin(async {
            if self.server_buf.len() == 0 {
                if let Some(recv_data) = self.server_rx.recv().await {
                    debug!(
                        "{} {} -> {} {}",
                        self.r#in.tag,
                        self.saddr,
                        self.daddr,
                        recv_data.len()
                    );
                    self.server_buf.extend(recv_data);
                } else {
                    // channel closed
                    return Ok(());
                }
            }

            let slice_len = std::cmp::min(buf.remaining(), self.server_buf.len());
            buf.put_slice(&self.server_buf[..slice_len]);
            self.server_buf.drain(..slice_len);

            Ok(())
        })
        .poll_unpin(cx)
    }
}

impl AsyncWrite for ProxyHttpResponse {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Box::pin(async {
            debug!(
                "{} {} -> {} {}",
                self.r#in.tag,
                self.saddr,
                self.daddr,
                buf.len()
            );
            if let Err(_) = self.server_tx.send(buf.to_vec()).await {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "close"))
            } else {
                Ok(buf.len())
            }
        })
        .poll_unpin(cx)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Ready(Ok(()))
    }
}

impl Connection for ProxyHttpResponse {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
