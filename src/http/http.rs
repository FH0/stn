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
