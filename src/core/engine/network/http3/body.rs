use super::*;

pub(super) async fn read_http3_request_body(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    max_size: usize,
    read_idle_timeout_ms: u64,
    body_min_bytes_per_sec: u32,
) -> Result<Vec<u8>, crate::protocol::ProtocolError> {
    let mut body = Vec::new();
    let started_at = std::time::Instant::now();

    while let Some(mut chunk) = tokio::time::timeout(
        std::time::Duration::from_millis(read_idle_timeout_ms),
        stream.recv_data(),
    )
    .await
    .map_err(|_| crate::protocol::ProtocolError::SlowBody {
        bytes_read: body.len(),
        expected_bytes: body.len().max(1),
        elapsed_ms: started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    })?
    .map_err(|err| {
        crate::protocol::ProtocolError::ParseError(format!("HTTP/3 body read failed: {err}"))
    })? {
        let remaining = chunk.remaining();
        if body.len() + remaining > max_size {
            return Err(crate::protocol::ProtocolError::ParseError(
                "HTTP/3 request body exceeded limit".to_string(),
            ));
        }
        body.extend_from_slice(chunk.copy_to_bytes(remaining).as_ref());
        if body_min_bytes_per_sec > 0
            && started_at.elapsed() >= std::time::Duration::from_secs(1)
            && (body.len() as f64 / started_at.elapsed().as_secs_f64())
                < body_min_bytes_per_sec as f64
        {
            return Err(crate::protocol::ProtocolError::SlowBody {
                bytes_read: body.len(),
                expected_bytes: body.len().max(1),
                elapsed_ms: started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            });
        }
    }

    Ok(body)
}
