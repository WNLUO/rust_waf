use super::*;

pub(super) async fn send_http3_response(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status_code: u16,
    headers: &[(String, String)],
    body: Vec<u8>,
    tarpit: Option<&crate::core::TarpitConfig>,
) -> Result<()> {
    let mut builder = http::Response::builder().status(status_code);
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("transfer-encoding")
            || key.eq_ignore_ascii_case("connection")
            || key.starts_with(':')
        {
            continue;
        }
        builder = builder.header(key, value);
    }

    stream.send_response(builder.body(())?).await?;
    if !body.is_empty() {
        if let Some(tarpit) = tarpit {
            for chunk in body.chunks(tarpit.bytes_per_chunk) {
                stream.send_data(Bytes::copy_from_slice(chunk)).await?;
                if chunk.len() == tarpit.bytes_per_chunk {
                    tokio::time::sleep(std::time::Duration::from_millis(tarpit.chunk_interval_ms))
                        .await;
                }
            }
        } else {
            stream.send_data(Bytes::from(body)).await?;
        }
    }
    stream.finish().await?;
    Ok(())
}
