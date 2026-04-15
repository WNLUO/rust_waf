use super::{HttpVersion, ProtocolError, UnifiedHttpRequest};
use anyhow::Result;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Duration};

/// HTTP/1.1处理器
///
/// 处理HTTP/1.1协议的请求和响应
pub struct Http1Handler;

impl Http1Handler {
    /// 创建新的HTTP/1.1处理器
    pub fn new() -> Self {
        Self
    }

    /// 读取HTTP/1.1请求
    ///
    /// 读取HTTP/1.1格式的请求并转换为统一请求结构
    pub async fn read_request<R>(
        &self,
        reader: &mut R,
        max_size: usize,
        first_byte_timeout_ms: u64,
        read_idle_timeout_ms: u64,
    ) -> Result<UnifiedHttpRequest, ProtocolError>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut buffer = Vec::with_capacity(max_size.min(4096));
        let mut temp_buffer = vec![0u8; 1024];
        let mut headers_complete = false;
        let mut content_length: Option<usize> = None;
        let mut body_bytes_read = 0;

        // 读取HTTP头
        while !headers_complete && buffer.len() < max_size {
            let timeout_ms = if buffer.is_empty() {
                first_byte_timeout_ms
            } else {
                read_idle_timeout_ms
            };
            let bytes_read = tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                reader.read(&mut temp_buffer),
            )
            .await
            .map_err(|_| ProtocolError::Timeout)??;
            if bytes_read == 0 {
                break;
            }

            let remaining = max_size.saturating_sub(buffer.len());
            let to_copy = remaining.min(bytes_read);
            buffer.extend_from_slice(&temp_buffer[..to_copy]);

            // 检查是否到达头部结束标记
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                headers_complete = true;

                // 解析Content-Length
                let request_str = String::from_utf8_lossy(&buffer);
                for line in request_str.lines() {
                    if line.to_lowercase().starts_with("content-length:") {
                        if let Some(len_str) = line.split(':').nth(1) {
                            if let Ok(len) = len_str.trim().parse::<usize>() {
                                content_length = Some(len);
                            }
                        }
                    }
                }

                break;
            }
        }

        if !headers_complete {
            return Ok(UnifiedHttpRequest::default());
        }

        // 读取请求体（如果有Content-Length）
        if let Some(expected_length) = content_length {
            let headers_end = buffer
                .iter()
                .position(|_b| {
                    buffer.get(buffer.len().saturating_sub(3)) == Some(&b'\r')
                        && buffer.get(buffer.len().saturating_sub(2)) == Some(&b'\n')
                        && buffer.get(buffer.len().saturating_sub(1)) == Some(&b'\r')
                        && buffer.last() == Some(&b'\n')
                })
                .unwrap_or(0);

            if let Some(headers_end_pos) = headers_end.checked_add(4) {
                let current_body_size = buffer.len().saturating_sub(headers_end_pos);

                // 继续读取请求体直到达到Content-Length
                while body_bytes_read + current_body_size < expected_length
                    && buffer.len() < max_size
                {
                    let bytes_to_read = (expected_length - body_bytes_read - current_body_size)
                        .min(temp_buffer.len());

                    let bytes_read = tokio::time::timeout(
                        std::time::Duration::from_millis(read_idle_timeout_ms),
                        reader.read(&mut temp_buffer[..bytes_to_read]),
                    )
                    .await
                    .map_err(|_| ProtocolError::Timeout)??;
                    if bytes_read == 0 {
                        break;
                    }

                    let remaining = max_size.saturating_sub(buffer.len());
                    let to_copy = remaining.min(bytes_read);
                    buffer.extend_from_slice(&temp_buffer[..to_copy]);
                    body_bytes_read += to_copy;
                }
            }
        }

        // 解析HTTP请求
        self.parse_request(&buffer)
    }

    /// 解析HTTP/1.1请求
    fn parse_request(&self, buffer: &[u8]) -> Result<UnifiedHttpRequest, ProtocolError> {
        let request_str = String::from_utf8_lossy(buffer).to_string();
        let mut lines = request_str.lines();

        // 解析请求行
        let request_line = lines
            .next()
            .ok_or_else(|| ProtocolError::ParseError("Missing request line".to_string()))?;

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("GET").to_string();
        let uri = parts.next().unwrap_or("/").to_string();
        let version = match parts.next().unwrap_or("HTTP/1.1") {
            "HTTP/1.0" => HttpVersion::Http1_0,
            _ => HttpVersion::Http1_1,
        };

        let mut unified_request = UnifiedHttpRequest::new(version, method, uri);

        // 解析头部
        let mut headers_complete = false;
        let mut content_length_count = 0usize;
        let mut has_transfer_encoding = false;
        let mut has_expect_100_continue = false;
        for line in lines {
            if line.is_empty() {
                headers_complete = true;
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                let normalized_key = key.trim().to_ascii_lowercase();
                let trimmed_value = value.trim().to_string();
                if normalized_key == "content-length" {
                    content_length_count += 1;
                }
                if normalized_key == "transfer-encoding" {
                    has_transfer_encoding = true;
                }
                if normalized_key == "expect"
                    && trimmed_value.eq_ignore_ascii_case("100-continue")
                {
                    has_expect_100_continue = true;
                }
                unified_request.add_header(normalized_key, trimmed_value);
            }
        }

        unified_request.add_metadata(
            "http1.content_length_count".to_string(),
            content_length_count.to_string(),
        );
        unified_request.add_metadata(
            "http1.has_transfer_encoding".to_string(),
            has_transfer_encoding.to_string(),
        );
        unified_request.add_metadata(
            "http1.has_expect_100_continue".to_string(),
            has_expect_100_continue.to_string(),
        );

        // 提取请求体
        if headers_complete {
            let body_start = request_str.find("\r\n\r\n").map(|pos| pos + 4).unwrap_or(0);

            if body_start < request_str.len() {
                unified_request.body = request_str.as_bytes()[body_start..].to_vec();
            }
        }

        debug!(
            "Parsed HTTP/1.1 request: {} {}",
            unified_request.method, unified_request.uri
        );
        Ok(unified_request)
    }

    /// 写入HTTP/1.1响应
    pub async fn write_response<W>(
        &self,
        writer: &mut W,
        status_code: u16,
        status_text: &str,
        body: &[u8],
    ) -> Result<(), ProtocolError>
    where
        W: AsyncWriteExt + Unpin,
    {
        self.write_response_with_headers(
            writer,
            status_code,
            status_text,
            &[("Content-Type".to_string(), "text/plain".to_string())],
            body,
        )
        .await
    }

    pub async fn write_response_with_headers<W>(
        &self,
        writer: &mut W,
        status_code: u16,
        status_text: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(), ProtocolError>
    where
        W: AsyncWriteExt + Unpin,
    {
        let mut response = format!("HTTP/1.1 {} {}\r\n", status_code, status_text).into_bytes();
        let mut has_content_type = false;
        let mut has_connection = false;
        let mut has_content_length = false;

        for (key, value) in headers {
            if key.eq_ignore_ascii_case("content-type") {
                has_content_type = true;
            } else if key.eq_ignore_ascii_case("connection") {
                has_connection = true;
            } else if key.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
            response.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
        }

        if !has_content_type {
            response.extend_from_slice(b"Content-Type: text/plain\r\n");
        }
        if !has_content_length {
            response.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        if !has_connection {
            response.extend_from_slice(b"Connection: close\r\n");
        }

        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(body);

        writer.write_all(&response).await?;
        writer.flush().await?;

        debug!("Wrote HTTP/1.1 response: {} {}", status_code, status_text);
        Ok(())
    }

    pub async fn write_response_with_headers_tarpit<W>(
        &self,
        writer: &mut W,
        status_code: u16,
        status_text: &str,
        headers: &[(String, String)],
        body: &[u8],
        tarpit: &crate::core::TarpitConfig,
    ) -> Result<(), ProtocolError>
    where
        W: AsyncWriteExt + Unpin,
    {
        let mut response = format!("HTTP/1.1 {} {}\r\n", status_code, status_text).into_bytes();
        let mut has_content_type = false;
        let mut has_connection = false;
        let mut has_content_length = false;

        for (key, value) in headers {
            if key.eq_ignore_ascii_case("content-type") {
                has_content_type = true;
            } else if key.eq_ignore_ascii_case("connection") {
                has_connection = true;
            } else if key.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
            response.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
        }

        if !has_content_type {
            response.extend_from_slice(b"Content-Type: text/plain\r\n");
        }
        if !has_content_length {
            response.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        if !has_connection {
            response.extend_from_slice(b"Connection: close\r\n");
        }

        response.extend_from_slice(b"\r\n");
        writer.write_all(&response).await?;
        writer.flush().await?;

        for chunk in body.chunks(tarpit.bytes_per_chunk) {
            writer.write_all(chunk).await?;
            writer.flush().await?;
            if chunk.len() == tarpit.bytes_per_chunk {
                sleep(Duration::from_millis(tarpit.chunk_interval_ms)).await;
            }
        }

        debug!(
            "Wrote HTTP/1.1 tarpit response: {} {}",
            status_code, status_text
        );
        Ok(())
    }
}

impl Default for Http1Handler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_simple_get_request() {
        let handler = Http1Handler::new();
        let request_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut cursor = Cursor::new(request_data);

        let request = handler
            .read_request(&mut cursor, 1024, 100, 100)
            .await
            .unwrap();

        assert_eq!(request.version, HttpVersion::Http1_1);
        assert_eq!(request.method, "GET");
        assert_eq!(request.uri, "/");
        assert_eq!(request.get_header("host"), Some(&"example.com".to_string()));
    }

    #[tokio::test]
    async fn test_post_request_with_body() {
        let handler = Http1Handler::new();
        let request_data = b"POST /api/data HTTP/1.1\r\n\
            Host: example.com\r\n\
            Content-Type: application/json\r\n\
            Content-Length: 13\r\n\
            \r\n\
            {\"test\": true}";
        let mut cursor = Cursor::new(request_data);

        let request = handler
            .read_request(&mut cursor, 1024, 100, 100)
            .await
            .unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.uri, "/api/data");
        assert_eq!(request.content_length(), Some(13));
        assert_eq!(request.get_body_as_string(), "{\"test\": true}");
    }

    #[tokio::test]
    async fn test_response_writing() {
        let handler = Http1Handler::new();
        let mut buffer = Vec::new();

        handler
            .write_response(&mut buffer, 200, "OK", b"Test response")
            .await
            .unwrap();

        let response_str = String::from_utf8_lossy(&buffer);
        assert!(response_str.contains("HTTP/1.1 200 OK"));
        assert!(response_str.contains("Content-Length: 13"));
        assert!(response_str.contains("Test response"));
    }

    #[tokio::test]
    async fn test_read_request_times_out_when_client_stalls() {
        let handler = Http1Handler::new();
        let (_client, mut server) = duplex(64);

        let result = handler.read_request(&mut server, 1024, 10, 10).await;
        assert!(matches!(result, Err(ProtocolError::Timeout)));
    }
}
