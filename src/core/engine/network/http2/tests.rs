use super::decision::{drop_http2_result, result_should_drop_http2};
use super::*;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use tokio::io::duplex;
use tokio::sync::Semaphore;

#[tokio::test]
async fn request_level_permit_exhaustion_returns_503() {
    let context = Arc::new(
        WafContext::new(crate::config::Config::default())
            .await
            .unwrap(),
    );
    let peer_addr: std::net::SocketAddr = "127.0.0.1:54322".parse().unwrap();
    let local_addr: std::net::SocketAddr = "127.0.0.1:660".parse().unwrap();
    let request_semaphore = Arc::new(Semaphore::new(0));
    let connection_permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
    let (client, server) = duplex(16 * 1024);

    let server_task = tokio::spawn({
        let context = Arc::clone(&context);
        let request_semaphore = Arc::clone(&request_semaphore);
        async move {
            let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::TCP);
            handle_http2_connection(
                context,
                server,
                peer_addr,
                &packet,
                Vec::new(),
                connection_permit,
                request_semaphore,
            )
            .await
        }
    });

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(client))
        .await
        .unwrap();
    let client_task = tokio::spawn(async move { conn.await });

    let request = http::Request::builder()
        .method("GET")
        .uri("https://wnluo.com/")
        .header("host", "wnluo.com")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    assert_eq!(status, http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        headers
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    assert_eq!(body.as_ref(), b"gateway overloaded, retry later");

    drop(sender);
    client_task.abort();
    let _ = client_task.await;
    server_task.await.unwrap().unwrap();
}

#[test]
fn drop_decision_resets_http2_request_path() {
    let request = UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
    let drop = crate::core::InspectionResult::drop(InspectionLayer::L7, "drop it");
    assert!(result_should_drop_http2(&drop, &request));

    let block = crate::core::InspectionResult::block(InspectionLayer::L7, "block");
    assert!(!result_should_drop_http2(&block, &request));

    let mut metadata_drop =
        UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
    metadata_drop.add_metadata("l7.enforcement".to_string(), "drop".to_string());
    let alert = crate::core::InspectionResult::alert(InspectionLayer::L7, "alert");
    assert!(result_should_drop_http2(&alert, &metadata_drop));

    let err = drop_http2_result("unit-test drop");
    assert!(err.to_string().contains("HTTP/2 request dropped"));
    assert!(err.to_string().contains("unit-test drop"));
}
