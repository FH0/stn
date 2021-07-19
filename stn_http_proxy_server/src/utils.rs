use httparse::{Header, Request};
use std::io;

pub(crate) fn get_daddr_from_headers(headers: &[Header]) -> io::Result<String> {
    for i in headers {
        if i.name == "Host" {
            let value = String::from_utf8_lossy(i.value).to_string();
            if value.contains(":") {
                return Ok(value);
            } else {
                return Ok(value + ":80");
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Host field not found",
    ))
}

pub(crate) fn get_content_length(headers: &[Header]) -> io::Result<usize> {
    for i in headers {
        if i.name == "Content-Length" {
            return Ok(String::from_utf8_lossy(i.value)
                .parse()
                .or(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid Content-Length value",
                )))?);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Content-Length field not found",
    ))
}

pub(crate) fn is_chunked_body(headers: &[Header]) -> bool {
    for i in headers {
        if i.name == "Transfer-Encoding" && i.value == b"chunked" {
            return true;
        }
    }

    false
}

pub(crate) fn rebuild_proxy_request(req: Request) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();

    // method
    result.extend(
        req.method
            .ok_or(io::Error::new(
                io::ErrorKind::NotFound,
                "http method not found",
            ))?
            .as_bytes(),
    );
    result.extend([b' ']);

    // path
    let path = req.path.ok_or(io::Error::new(
        io::ErrorKind::NotFound,
        "http path not found",
    ))?;
    let split_vec = path
        .split("/")
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    if split_vec.len() < 4 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid http path",
        ))?
    }
    result.extend([b'/']);
    result.extend(split_vec[3..].join("/").as_bytes());
    result.extend([b' ']);

    // version
    result.extend(b"HTTP/1.");
    match req.version {
        Some(0) => result.extend(b"0\r\n"),
        Some(1) => result.extend(b"1\r\n"),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid http version",
        ))?,
    }

    // headers
    for i in req.headers {
        result.extend(i.name.as_bytes());
        result.extend([b':', b' ']);
        result.extend(i.value);
        result.extend([b'\r', b'\n']);
    }

    // end
    result.extend([b'\r', b'\n']);

    Ok(result)
}
