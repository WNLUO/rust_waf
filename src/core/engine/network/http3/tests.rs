use super::decision::result_should_drop_http3;
use super::*;

#[test]
fn drop_decision_resets_http3_request_path() {
    let request = UnifiedHttpRequest::new(HttpVersion::Http3_0, "GET".to_string(), "/".to_string());
    let drop = crate::core::InspectionResult::drop(InspectionLayer::L7, "drop it");
    assert!(result_should_drop_http3(&drop, &request));

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
    assert!(!result_should_drop_http3(&respond, &request));

    let mut metadata_drop =
        UnifiedHttpRequest::new(HttpVersion::Http3_0, "GET".to_string(), "/".to_string());
    metadata_drop.add_metadata("l7.enforcement".to_string(), "drop".to_string());
    let alert = crate::core::InspectionResult::alert(InspectionLayer::L7, "alert");
    assert!(result_should_drop_http3(&alert, &metadata_drop));
}
