use super::*;
use tokio::io::AsyncWrite;

pub(super) async fn write_custom_http1_response<S>(
    context: &WafContext,
    http1_handler: &Http1Handler,
    stream: &mut S,
    request: &UnifiedHttpRequest,
    response: &crate::core::CustomHttpResponse,
    soften_for_runtime: bool,
    apply_policies_to_headers: bool,
) -> Result<u16>
where
    S: AsyncWrite + Unpin,
{
    let response = resolve_runtime_custom_response(response);
    let response = if soften_for_runtime {
        crate::core::engine::network::helpers::soften_explicit_response_for_runtime(
            context, &response,
        )
    } else {
        response
    };
    let body = body_for_request(request, &response.body);
    let mut headers = response.headers.clone();
    if apply_policies_to_headers {
        apply_response_policies(context, &mut headers, response.status_code);
    }

    if let Some(tarpit) = response.tarpit.as_ref() {
        http1_handler
            .write_response_with_headers_tarpit(
                stream,
                response.status_code,
                http_status_text(response.status_code),
                &headers,
                &body,
                tarpit,
            )
            .await?;
    } else {
        http1_handler
            .write_response_with_headers(
                stream,
                response.status_code,
                http_status_text(response.status_code),
                &headers,
                &body,
            )
            .await?;
    }

    Ok(response.status_code)
}
