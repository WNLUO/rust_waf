use super::*;

#[derive(Debug, Clone)]
pub(crate) struct UpstreamHttpResponse {
    pub(crate) status_code: u16,
    pub(crate) status_text: Option<String>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

pub(crate) fn parse_http1_response(response: &[u8]) -> Result<UpstreamHttpResponse> {
    let headers_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            anyhow::anyhow!("Invalid upstream HTTP/1 response: missing header terminator")
        })?;
    let header_block = &response[..headers_end];
    let body_offset = headers_end + 4;
    let header_text = String::from_utf8_lossy(header_block);
    let mut lines = header_text.lines();

    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid upstream HTTP/1 response: missing status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let _version = status_parts.next();
    let status_code = status_parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid upstream HTTP/1 response: missing status code"))?
        .parse::<u16>()?;
    let status_text = status_parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let mut headers = Vec::new();
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
                continue;
            }
            headers.push((name, value));
        }
    }

    let body = if chunked {
        decode_chunked_body(&response[body_offset..])?
    } else {
        response[body_offset..].to_vec()
    };

    Ok(UpstreamHttpResponse {
        status_code,
        status_text,
        headers,
        body,
    })
}

pub(crate) async fn write_http1_upstream_response<W>(
    context: &WafContext,
    client_stream: &mut W,
    response: &UpstreamHttpResponse,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut headers = response.headers.clone();
    apply_response_policies(context, &mut headers, response.status_code);
    Http1Handler::new()
        .write_response_with_headers(
            client_stream,
            response.status_code,
            response
                .status_text
                .as_deref()
                .unwrap_or(http_status_text(response.status_code)),
            &headers,
            &response.body,
        )
        .await?;
    Ok(())
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();

    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                anyhow::anyhow!("Invalid chunked response: missing chunk size terminator")
            })?
            + cursor;
        let size_line = std::str::from_utf8(&body[cursor..line_end])?;
        let size_hex = size_line.split(';').next().unwrap_or(size_line).trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)?;
        cursor = line_end + 2;

        if chunk_size == 0 {
            break;
        }

        let chunk_end = cursor + chunk_size;
        if chunk_end > body.len() {
            anyhow::bail!("Invalid chunked response: chunk exceeds body length");
        }
        decoded.extend_from_slice(&body[cursor..chunk_end]);
        cursor = chunk_end;

        if body.get(cursor..cursor + 2) != Some(b"\r\n") {
            anyhow::bail!("Invalid chunked response: missing CRLF after chunk");
        }
        cursor += 2;
    }

    Ok(decoded)
}
