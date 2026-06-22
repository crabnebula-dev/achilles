//! Per-source adapters. Each module exposes one or more `lookup*` functions
//! that take a shared `reqwest::Client` + package identifier and return a
//! `Vec<Advisory>` normalised into the shared [`crate::Advisory`] shape.
//!
//! Every lookup is cached on disk by key; see [`crate::cache`].

pub mod euvd;
pub mod ghsa;
pub mod nvd;
pub mod osv;

/// Build the [`crate::Error`] for a failed HTTP response. A `5xx` / `429`
/// classifies as [`crate::Error::Unavailable`] (transient, kept out of the
/// user-facing report); anything else (`4xx`, malformed responses) is a
/// [`crate::Error::BadPayload`] worth surfacing. `label` identifies the lookup
/// (e.g. `"nvd cpe:..."`); `body` is the raw response text, truncated to `max`
/// bytes for the message via [`err_body`].
pub(crate) fn http_error(
    label: impl std::fmt::Display,
    status: reqwest::StatusCode,
    body: &str,
    max: usize,
) -> crate::Error {
    let msg = format!("{label} {status}{}", err_body(status, body, max));
    if status.is_server_error() || status.as_u16() == 429 {
        crate::Error::Unavailable(msg)
    } else {
        crate::Error::BadPayload(msg)
    }
}

/// Format the trailing `: <body>` snippet for a failed HTTP request's error
/// message. Server-error (5xx) responses are almost always HTML error pages
/// from a CDN/proxy (e.g. a `503 Service Unavailable` splash) and carry no
/// useful detail, so we drop the body and let the status speak for itself.
/// Other bodies (typically 4xx API errors) are kept but truncated to `max`
/// bytes. Returns an empty string when there's nothing worth showing, so call
/// sites can interpolate it directly after the status.
fn err_body(status: reqwest::StatusCode, body: &str, max: usize) -> String {
    let body = body.trim();
    if status.is_server_error() || body.is_empty() {
        return String::new();
    }
    let mut end = max.min(body.len());
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    if end < body.len() {
        format!(": {}…", &body[..end])
    } else {
        format!(": {body}")
    }
}
