use hyper::{header::HeaderValue, http, HeaderMap};

pub(crate) const TCP_LEN: usize = 8192;

#[inline]
pub(crate) fn is_http_response_successful(buf: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if !String::from_utf8_lossy(&buf).contains("HTTP/1.1 200")
        && !String::from_utf8_lossy(&buf).contains("HTTP/1.0 200")
    {
        Err("http response not succeeded")?
    }

    Ok(())
}

#[inline]
pub(crate) fn get_http_end_index(buf: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    match String::from_utf8_lossy(buf).find("\r\n\r\n") {
        Some(index) => Ok(index),
        None => return Err("\\r\\n\\r\\n not found")?,
    }
}

#[inline]
pub(super) fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| {
        Some({
            let result = auth.to_string();
            if result.contains(":") {
                result
            } else {
                format!("{}:80", result)
            }
        })
    })
}

// from shadowsocks-rust
pub(super) fn clear_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
    // Clear headers indicated by Connection and Proxy-Connection
    let mut extra_headers = Vec::new();

    for connection in headers.get_all("Connection") {
        if let Ok(conn) = connection.to_str() {
            // close is a command instead of a header
            if conn.eq_ignore_ascii_case("close") {
                continue;
            }

            for header in conn.split(',') {
                let header = header.trim();
                extra_headers.push(header.to_owned());
            }
        }
    }

    for connection in headers.get_all("Proxy-Connection") {
        if let Ok(conn) = connection.to_str() {
            // close is a command instead of a header
            if conn.eq_ignore_ascii_case("close") {
                continue;
            }

            for header in conn.split(',') {
                let header = header.trim();
                extra_headers.push(header.to_owned());
            }
        }
    }

    for header in extra_headers {
        while let Some(..) = headers.remove(&header) {}
    }

    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
    const HOP_BY_HOP_HEADERS: [&str; 9] = [
        "Keep-Alive",
        "Transfer-Encoding",
        "TE",
        "Connection",
        "Trailer",
        "Upgrade",
        "Proxy-Authorization",
        "Proxy-Authenticate",
        "Proxy-Connection", // Not standard, but many implementations do send this header
    ];

    for header in &HOP_BY_HOP_HEADERS {
        while let Some(..) = headers.remove(*header) {}
    }
}
