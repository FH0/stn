use super::*;
use futures::FutureExt;
use httparse::{parse_chunk_size, Request};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUFLEN: usize = 8192;
const MAX_HEADERS: usize = 100;

pub struct Stream<T> {
    inner: T,
    buf: Vec<u8>,
    readable_len: usize, // chunked
    status: Status,
}

impl<T> Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn new(inner: T) -> io::Result<(Self, String)> {
        let mut me = Self {
            inner,
            buf: Vec::with_capacity(BUFLEN),
            readable_len: 0,
            status: Status::ReadHeaders,
        };

        let daddr = me.read_headers().await?;

        Ok((me, daddr))
    }

    async fn read_headers(&mut self) -> io::Result<String> {
        // read complete headers
        loop {
            // check complete
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut req = Request::new(&mut headers);
            let header_status = req
                .parse(&self.buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            if let httparse::Status::Complete(body_start_index) = header_status {
                // get daddr
                let daddr = get_daddr_from_headers(req.headers)?;

                // check method
                let method = req
                    .method
                    .ok_or(io::Error::new(io::ErrorKind::NotFound, "method not found"))?;
                if method == "CONNECT" {
                    self.status = Status::Connect;
                    let version = req.version.clone();
                    self.response_connect(version).await?;
                    self.buf.drain(..body_start_index);
                } else {
                    // if content length
                    match get_content_length(req.headers) {
                        Ok(content_length) => {
                            self.status = Status::LeftContentLength(content_length);
                        }
                        Err(e) => {
                            if e.kind() != io::ErrorKind::NotFound {
                                Err(e)?
                            }
                        }
                    }

                    // if chunked body
                    if is_chunked_body(req.headers) {
                        self.status = Status::Chunked;
                    }

                    // rebuild req & adjust readable_len
                    let buf = rebuild_proxy_request(req)?;
                    self.readable_len += buf.len();
                    self.buf.splice(..body_start_index, buf);
                }

                return Ok(daddr);
            }

            let nread = self.read_inner().await?;
            if nread == 0 {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ))?
            }
        }
    }

    async fn response_connect(&mut self, version: Option<u8>) -> io::Result<()> {
        // empty body
        match version {
            Some(0) => {
                self.inner.write_all(b"HTTP/1.0 200 OK\r\n\r\n").await?;
            }
            Some(1) => {
                self.inner.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid http version",
            ))?,
        }

        Ok(())
    }

    async fn read_inner(&mut self) -> io::Result<usize> {
        let mut buf = vec![0u8; self.buf.capacity() - self.buf.len()];
        let nread = self.inner.read(&mut buf).await?;
        self.buf.extend(&buf[..nread]);

        Ok(nread)
    }
}

impl<T> AsyncRead for Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Box::pin(async {
            // read from inner if no buf left
            match self.status {
                Status::ReadHeaders => {
                    if self.readable_len == 0 {
                        if let Err(e) = self.read_headers().await {
                            if e.kind() != io::ErrorKind::UnexpectedEof {
                                Err(e)?
                            }
                        }
                    }
                }
                Status::Connect => {
                    if self.buf.len() == 0 {
                        self.read_inner().await?;
                    }

                    self.readable_len = self.buf.len();
                }
                Status::LeftContentLength(content_length) => {
                    if self.buf.len() == 0 {
                        self.read_inner().await?;
                    }

                    if self.buf.len() >= self.readable_len + content_length {
                        self.status = Status::ReadHeaders;
                        self.readable_len += content_length;
                    } else {
                        self.status = Status::LeftContentLength(
                            content_length - (self.buf.len() - self.readable_len),
                        );
                        self.readable_len = self.buf.len();
                    }
                }
                Status::Chunked => loop {
                    if let httparse::Status::Complete(_) =
                        parse_chunk_size(&self.buf[self.readable_len..]).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?
                    {
                        while let Ok(httparse::Status::Complete((start_index, len))) =
                            parse_chunk_size(&self.buf[self.readable_len..]).map_err(|e| {
                                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                            })
                        {
                            if self.buf.len() - self.readable_len >= start_index + len as usize + 2
                            {
                                self.readable_len += start_index + len as usize + 2;

                                // 0\r\n\r\n
                                if len == 0 {
                                    self.status = Status::ReadHeaders;
                                }
                            }
                        }

                        break;
                    }

                    let nread = self.read_inner().await?;
                    if nread == 0 {
                        break;
                    }
                },
            };

            let put_len = buf.remaining().min(self.readable_len);
            buf.put_slice(&self.buf[..put_len]);
            self.buf.drain(..put_len);
            self.readable_len -= put_len;

            Ok(())
        })
        .poll_unpin(cx)
    }
}

impl<T> AsyncWrite for Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).as_mut().poll_shutdown(cx)
    }
}

#[derive(Clone, Debug)]
enum Status {
    ReadHeaders,
    Connect,
    LeftContentLength(usize),
    Chunked,
}
