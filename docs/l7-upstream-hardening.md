# L7 Upstream Hardening Guide

This project now supports protocol-aware upstream forwarding and stricter HTTP/1.1 safety controls.

## Recommended Defaults

For most deployments:

- Set upstream protocol policy to `http2_preferred`
- Keep `upstream_http1_strict_mode = true`
- Keep `upstream_http1_allow_connection_reuse = false`
- Keep all HTTP/1.1 rejection toggles enabled

This gives the safest default path:

- HTTPS upstreams prefer HTTP/2
- Plain HTTP upstreams fall back to HTTP/1.1
- Risky HTTP/1.1 request shapes are rejected before proxying

## Policy Choices

Use `http2_preferred` when:

- The upstream is HTTPS
- You want the best balance between compatibility and security
- Some legacy upstreams may still require HTTP/1.1 fallback

Use `http2_only` when:

- The upstream definitely supports HTTP/2
- You want to avoid accidental fallback to HTTP/1.1
- Security matters more than legacy compatibility

Use `auto` when:

- You are still evaluating mixed upstream behavior
- You want a softer transition than `http2_only`

Use `http1_only` only when:

- The upstream cannot support HTTP/2
- You are handling a legacy application that breaks on HTTP/2

If `http1_only` is required, keep strict mode enabled.

## HTTP/1.1 Strict Mode

When strict mode is enabled, the gateway rejects high-risk request patterns before sending them upstream.

Recommended settings:

- `reject_ambiguous_http1_requests = true`
- `reject_http1_transfer_encoding_requests = true`
- `reject_body_on_safe_http_methods = true`
- `reject_expect_100_continue = true`

These settings reduce the desync/smuggling attack surface when upstream HTTP/1.1 cannot be avoided.

## Deployment Suggestions

For production:

1. Prefer HTTPS upstreams.
2. Set upstream protocol policy to `http2_preferred` or `http2_only`.
3. Leave HTTP/1.1 strict mode enabled.
4. Only enable HTTP/1.1 connection reuse after confirming the upstream absolutely requires it.

For temporary legacy compatibility:

1. Start with `http2_preferred`.
2. If the upstream fails, temporarily switch to `http1_only`.
3. Keep strict mode enabled while troubleshooting.
4. Move back to HTTP/2 as soon as possible.

## Practical Profiles

Modern HTTPS upstream:

- `upstream_protocol_policy = http2_preferred`
- `upstream_http1_strict_mode = true`
- `upstream_http1_allow_connection_reuse = false`

High-security upstream:

- `upstream_protocol_policy = http2_only`
- `upstream_http1_strict_mode = true`
- `upstream_http1_allow_connection_reuse = false`

Legacy HTTP-only upstream:

- `upstream_protocol_policy = http1_only`
- `upstream_http1_strict_mode = true`
- `upstream_http1_allow_connection_reuse = false`

NTLM-like legacy exception:

- `upstream_protocol_policy = http1_only`
- `upstream_http1_strict_mode = false`
- `upstream_http1_allow_connection_reuse = true`

Only use the NTLM-like exception profile when compatibility testing proves it is necessary.
