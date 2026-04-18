use super::decision::result_should_drop_http1;
use super::*;
use std::sync::Arc;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

#[tokio::test]
async fn request_level_permit_exhaustion_returns_503() {
    let context = Arc::new(
        WafContext::new(crate::config::Config::default())
            .await
            .unwrap(),
    );
    let peer_addr: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let local_addr: std::net::SocketAddr = "127.0.0.1:660".parse().unwrap();
    let request_semaphore = Arc::new(Semaphore::new(0));
    let connection_permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
    let (mut client, server) = duplex(4096);

    let task = tokio::spawn({
        let context = Arc::clone(&context);
        async move {
            let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::TCP);
            handle_http1_connection(
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

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: wnluo.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    client.shutdown().await.unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    task.await.unwrap().unwrap();

    let response = String::from_utf8_lossy(&response);
    assert!(response.contains("HTTP/1.1 503 Service Unavailable"));
    assert!(response.contains("gateway overloaded, retry later"));
    assert!(response.contains("Retry-After: 5"));
}

#[test]
fn drop_decision_closes_http1_without_response_path() {
    let request = UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    let drop = crate::core::InspectionResult::drop(InspectionLayer::L7, "drop it");
    assert!(result_should_drop_http1(&drop, &request));

    let respond = crate::core::InspectionResult::respond(
        InspectionLayer::L7,
        "challenge",
        crate::core::CustomHttpResponse {
            status_code: 403,
            headers: Vec::new(),
            body: b"challenge".to_vec(),
            tarpit: None,
            random_status: None,
        },
    );
    assert!(!result_should_drop_http1(&respond, &request));

    let mut metadata_drop =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    metadata_drop.add_metadata("l7.enforcement".to_string(), "drop".to_string());
    let alert = crate::core::InspectionResult::alert(InspectionLayer::L7, "alert");
    assert!(result_should_drop_http1(&alert, &metadata_drop));
}
