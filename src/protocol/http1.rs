use super::{HttpVersion, ProtocolError, UnifiedHttpRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::debug;
use anyhow::Result;

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
    pub async fn read_request<R>(&self, reader: &mut R, max_size: usize) -> Result<UnifiedHttpRequest, ProtocolError>
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
            let bytes_read = reader.read(&mut temp_buffer).await?;
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
            let headers_end = buffer.iter()
                .position(|_b| {
                    buffer.get(buffer.len().saturating_sub(3)) == Some(&b'\r') &&
                    buffer.get(buffer.len().saturating_sub(2)) == Some(&b'\n') &&
                    buffer.get(buffer.len().saturating_sub(1)) == Some(&b'\r') &&
                    buffer.last() == Some(&b'\n')
                })
                .unwrap_or(0);

            if let Some(headers_end_pos) = headers_end.checked_add(4) {
                let current_body_size = buffer.len().saturating_sub(headers_end_pos);

                // 继续读取请求体直到达到Content-Length
                while body_bytes_read + current_body_size < expected_length && buffer.len() < max_size {
                    let bytes_to_read = (expected_length - body_bytes_read - current_body_size)
                        .min(temp_buffer.len());

                    let bytes_read = reader.read(&mut temp_buffer[..bytes_to_read]).await?;
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
        let request_line = lines.next()
            .ok_or_else(|| ProtocolError::ParseError("Missing request line".to_string()))?;

        let mut parts = request_line.split_whitespace();
        let method = parts.next()
            .unwrap_or("GET")
            .to_string();
        let uri = parts.next()
            .unwrap_or("/")
            .to_string();

        let mut unified_request = UnifiedHttpRequest::new(HttpVersion::Http1_1, method, uri);

        // 解析头部
        let mut headers_complete = false;
        for line in lines {
            if line.is_empty() {
                headers_complete = true;
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                unified_request.add_header(key.trim().to_string(), value.trim().to_string());
            }
        }

        // 提取请求体
        if headers_complete {
            let body_start = request_str.find("\r\n\r\n")
                .map(|pos| pos + 4)
                .unwrap_or(0);

            if body_start < request_str.len() {
                unified_request.body = request_str[body_start..].as_bytes().to_vec();
            }
        }

        debug!("Parsed HTTP/1.1 request: {} {}", unified_request.method, unified_request.uri);
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
        let response = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            status_code, status_text,
            body.len(),
            String::from_utf8_lossy(body)
        );

        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;

        debug!("Wrote HTTP/1.1 response: {} {}", status_code, status_text);
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

    #[tokio::test]
    async fn test_simple_get_request() {
        let handler = Http1Handler::new();
        let request_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut cursor = Cursor::new(request_data);

        let request = handler.read_request(&mut cursor, 1024).await.unwrap();

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

        let request = handler.read_request(&mut cursor, 1024).await.unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.uri, "/api/data");
        assert_eq!(request.content_length(), Some(13));
        assert_eq!(request.get_body_as_string(), "{\"test\": true}");
    }

    #[tokio::test]
    async fn test_response_writing() {
        let handler = Http1Handler::new();
        let mut buffer = Vec::new();

        handler.write_response(&mut buffer, 200, "OK", b"Test response").await.unwrap();

        let response_str = String::from_utf8_lossy(&buffer);
        assert!(response_str.contains("HTTP/1.1 200 OK"));
        assert!(response_str.contains("Content-Length: 13"));
        assert!(response_str.contains("Test response"));
    }
}