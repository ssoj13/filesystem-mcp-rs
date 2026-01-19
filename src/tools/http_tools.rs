use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::{engine::general_purpose, Engine as _};
use futures::StreamExt;
use reqwest::{Client, Method, Url};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, COOKIE, CONTENT_TYPE};

use crate::tools::fs_ops::decode_bytes;

#[derive(Debug, Clone)]
pub struct HttpRequestParams {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub query: BTreeMap<String, String>,
    pub body: Option<String>,
    pub body_base64: bool,
    pub body_bytes: Option<Vec<u8>>,
    pub timeout_ms: u64,
    pub max_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct HttpRequestItem {
    pub id: Option<String>,
    pub params: HttpRequestParams,
}

#[derive(Debug, Clone)]
pub struct HttpBatchResult {
    pub id: Option<String>,
    pub ok: bool,
    pub response: Option<HttpResponse>,
    pub error: Option<String>,
}

pub fn parse_method(method: &str) -> Result<Method> {
    Method::from_bytes(method.as_bytes())
        .with_context(|| format!("Invalid HTTP method '{method}'"))
}

pub fn parse_url(raw: &str) -> Result<Url> {
    Url::parse(raw).with_context(|| format!("Invalid URL '{raw}'"))
}

pub fn is_domain_allowed(host: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    for entry in allowlist {
        if entry == "*" {
            return true;
        }
        if entry.starts_with("*.") {
            let suffix = &entry[1..];
            if host.ends_with(suffix) {
                return true;
            }
        } else if entry.starts_with('.') {
            if host.ends_with(entry) {
                return true;
            }
        } else if host == entry {
            return true;
        }
    }
    false
}

fn build_headers(
    headers: &BTreeMap<String, String>,
    cookies: &BTreeMap<String, String>,
) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for (k, v) in headers {
        let name = HeaderName::from_bytes(k.as_bytes())
            .with_context(|| format!("Invalid header name '{k}'"))?;
        let value = HeaderValue::from_str(v)
            .with_context(|| format!("Invalid header value for '{k}'"))?;
        map.insert(name, value);
    }

    if !cookies.is_empty() {
        let cookie_str = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        if let Some(existing) = map.get(COOKIE) {
            let merged = format!("{}; {}", existing.to_str().unwrap_or(""), cookie_str);
            map.insert(COOKIE, HeaderValue::from_str(&merged)?);
        } else {
            map.insert(COOKIE, HeaderValue::from_str(&cookie_str)?);
        }
    }

    Ok(map)
}

fn decode_body(
    body: &Option<String>,
    body_base64: bool,
    body_bytes: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    if let Some(bytes) = body_bytes {
        return Ok(Some(bytes));
    }
    let Some(body) = body else { return Ok(None) };
    if body_base64 {
        let bytes = general_purpose::STANDARD
            .decode(body.as_bytes())
            .context("Invalid base64 body")?;
        Ok(Some(bytes))
    } else {
        Ok(Some(body.as_bytes().to_vec()))
    }
}

pub async fn http_request(client: &Client, params: HttpRequestParams) -> Result<HttpResponse> {
    let method = parse_method(&params.method)?;
    let mut url = parse_url(&params.url)?;

    if !params.query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (k, v) in params.query {
            pairs.append_pair(&k, &v);
        }
    }

    if url.scheme() != "http" && url.scheme() != "https" {
        bail!("Only http/https URLs are supported");
    }

    let mut request = client.request(method, url);
    request = request.headers(build_headers(&params.headers, &params.cookies)?);
    request = request.timeout(Duration::from_millis(params.timeout_ms));

    if let Some(body) = decode_body(&params.body, params.body_base64, params.body_bytes)? {
        request = request.body(body);
    }

    let response = request.send().await.context("HTTP request failed")?;
    let status = response.status().as_u16();
    let final_url = response.url().to_string();

    let mut headers = BTreeMap::new();
    let mut content_type = None;
    let mut content_length = None;
    for (k, v) in response.headers().iter() {
        let value = v.to_str().unwrap_or("").to_string();
        if k == CONTENT_TYPE {
            content_type = Some(value.clone());
        }
        if k.as_str().eq_ignore_ascii_case("content-length") {
            if let Ok(len) = value.parse::<u64>() {
                content_length = Some(len);
            }
        }
        headers.insert(k.as_str().to_string(), value);
    }

    let mut body_bytes = Vec::new();
    let mut truncated = false;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read response body")?;
        if params.max_bytes > 0 && body_bytes.len() + chunk.len() > params.max_bytes {
            let remaining = params.max_bytes.saturating_sub(body_bytes.len());
            body_bytes.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body_bytes.extend_from_slice(&chunk);
    }

    Ok(HttpResponse {
        status,
        url: final_url,
        headers,
        content_type,
        content_length,
        body: body_bytes,
        truncated,
    })
}

pub async fn http_request_batch(
    client: &Client,
    items: Vec<HttpRequestItem>,
) -> Vec<HttpBatchResult> {
    let mut results = Vec::with_capacity(items.len());
    for item in items {
        match http_request(client, item.params).await {
            Ok(response) => results.push(HttpBatchResult {
                id: item.id,
                ok: true,
                response: Some(response),
                error: None,
            }),
            Err(err) => results.push(HttpBatchResult {
                id: item.id,
                ok: false,
                response: None,
                error: Some(err.to_string()),
            }),
        }
    }
    results
}

pub fn decode_body_text(bytes: &[u8]) -> String {
    decode_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::is_domain_allowed;

    #[test]
    fn test_domain_allowlist_exact() {
        let allow = vec!["example.com".to_string()];
        assert!(is_domain_allowed("example.com", &allow));
        assert!(!is_domain_allowed("sub.example.com", &allow));
    }

    #[test]
    fn test_domain_allowlist_wildcard() {
        let allow = vec!["*.example.com".to_string()];
        assert!(is_domain_allowed("sub.example.com", &allow));
        assert!(!is_domain_allowed("example.com", &allow));
    }

    #[test]
    fn test_domain_allowlist_star() {
        let allow = vec!["*".to_string()];
        assert!(is_domain_allowed("example.com", &allow));
    }
}
