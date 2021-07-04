use super::*;
use crate::misc::{build_socket_listener, socketaddr_to_string};
use futures::FutureExt;
use hyper::{
    http, server::conn::Http, service::service_fn, Body, Client, Method, Request, Response,
};
use log::*;
use std::{sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};

pub(crate) struct In {
    pub(crate) tag: String,
    pub(crate) tcp_nodelay: bool,
    pub(crate) tcp_keepalive_inverval: Duration,
    pub(crate) tcp_timeout: Duration,
    pub(crate) tcp_listener: TcpListener,
}

impl In {
    pub(crate) async fn start(root: serde_json::Value) {
        let bind_addr = root["address"].as_str().expect("address not found");

        let r#in = Arc::new(In {
            tag: root["tag"].as_str().expect("tag not found").to_string(),
            tcp_nodelay: root["tcp_nodelay"].as_bool().unwrap_or_else(|| true),
            tcp_keepalive_inverval: Duration::from_nanos(
                (root["tcp_keepalive_inverval"]
                    .as_f64()
                    .unwrap_or_else(|| 30f64)
                    * 1000_000_000f64) as u64,
            ),
            tcp_timeout: Duration::from_nanos(
                (root["tcp_timeout"].as_f64().unwrap_or_else(|| 300f64) * 1000_000_000f64) as u64,
            ),
            tcp_listener: TcpListener::from_std(
                build_socket_listener("tcp", bind_addr).unwrap().into(),
            )
            .unwrap(),
        });

        tokio::spawn(r#in.clone().listen());
    }

    async fn listen(self: Arc<Self>) {
        loop {
            let (client, saddr) = match self.tcp_listener.accept().await {
                Ok(o) => o,
                Err(e) => {
                    warn!("{}", e);
                    continue;
                }
            };

            if let Err(e) = crate::misc::set_nodelay_keepalive_interval(
                &client,
                self.tcp_nodelay,
                self.tcp_keepalive_inverval,
            ) {
                warn!("{} {} {}", self.tag, saddr, e);
                continue;
            }

            tokio::spawn({
                let self_clone = self.clone();
                async move {
                    let saddr = socketaddr_to_string(&saddr);
                    if let Err(e) = self_clone
                        .clone()
                        .handle_handshake(client, saddr.clone())
                        .await
                    {
                        warn!("{} {} {}", self_clone.tag, saddr, e);
                    }
                }
            });
        }
    }

    #[inline]
    async fn handle_handshake(
        self: Arc<Self>,
        client: TcpStream,
        saddr: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Http::new()
            .http1_only(true)
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve_connection(
                client,
                service_fn(|req| {
                    let self_clone = self.clone();
                    let saddr = saddr.clone();
                    async move { self_clone.dispatch(req, saddr).await }
                }),
            )
            .with_upgrades()
            .await?;

        Ok(())
    }

    async fn dispatch(
        self: Arc<Self>,
        mut req: Request<Body>,
        saddr: String,
    ) -> Result<Response<Body>, hyper::Error> {
        if let Some(daddr) = host_addr(req.uri()) {
            if Method::CONNECT == req.method() {
                tokio::task::spawn({
                    let tag = self.tag.clone();
                    let saddr_ = saddr.clone();
                    let daddr_ = daddr.clone();
                    async move {
                        let upgraded = hyper::upgrade::on(req).await?;
                        self.handle_connect(upgraded, saddr, daddr).await
                    }
                    .map(move |r| {
                        if let Err(e) = r {
                            warn!("{} {} -> {} {}", tag, saddr_, daddr_, e);
                        }
                    })
                });

                Ok(Response::new(Body::empty()))
            } else {
                clear_hop_headers(req.headers_mut());

                let mut res = Client::builder()
                    .http1_title_case_headers(true)
                    .http1_preserve_header_case(true)
                    .build(ProxyHttpClient::new(self.clone(), saddr))
                    .request(req)
                    .await?;

                clear_hop_headers(res.headers_mut());

                Ok(res)
            }
        } else {
            warn!(
                "{} {} CONNECT host is not socket addr: {:?}",
                self.tag,
                saddr,
                req.uri()
            );
            let mut resp = Response::new(Body::from("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    }
}
