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
pub(crate) fn get_http_addr(buf: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let buf_string = String::from_utf8_lossy(buf);
    let buf_string_split = buf_string.split(" ").collect::<Vec<&str>>();
    let raw_addr = buf_string_split.get(1).ok_or("invalid http header")?;

    let result = if raw_addr.contains("http://") {
        raw_addr
            .split("/")
            .collect::<Vec<&str>>()
            .get(2)
            .ok_or("invalid http header")?
            .to_string()
    } else {
        raw_addr.to_string()
    };

    Ok(if result.contains(":") {
        result
    } else {
        format!("{}:80", result)
    })
}

#[test]
fn test() {
    assert_eq!(
        get_http_addr("CONNECT a.com:443 HTTP/1.1\r\n\r\n".as_bytes())
            .unwrap()
            .as_str(),
        "a.com:443"
    );
    assert_eq!(
        get_http_addr("GET http://a.com/a.txt HTTP/1.1\r\n\r\n".as_bytes())
            .unwrap()
            .as_str(),
        "a.com:80"
    );
    assert_eq!(
        get_http_addr("GET http://a.com:232/a.txt HTTP/1.1\r\n\r\n".as_bytes())
            .unwrap()
            .as_str(),
        "a.com:232"
    );
}
