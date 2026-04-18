use super::*;

pub(super) fn build_custom_http2_response(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    response: &crate::core::CustomHttpResponse,
    apply_policies_to_headers: bool,
) -> Http2Response {
    let response = resolve_runtime_custom_response(response);
    let body = body_for_request(request, &response.body);
    let mut headers = response.headers.clone();
    if apply_policies_to_headers {
        apply_response_policies(context, &mut headers, response.status_code);
    }

    Http2Response {
        status_code: response.status_code,
        headers,
        body,
    }
}

pub(super) fn build_plain_http2_response(
    status_code: u16,
    body: impl Into<Vec<u8>>,
) -> Http2Response {
    Http2Response {
        status_code,
        headers: vec![],
        body: body.into(),
    }
}
