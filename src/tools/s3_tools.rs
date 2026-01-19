use std::collections::BTreeMap;
use anyhow::{Context, Result, bail};
use aws_sdk_s3::{Client, types::ObjectIdentifier};
use aws_sdk_s3::presigning::PresigningConfig;
use base64::{engine::general_purpose, Engine as _};
use tokio::fs;

use crate::tools::fs_ops::decode_bytes;

#[derive(Debug, Clone)]
pub struct S3ListParams {
    pub bucket: String,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: Option<i32>,
    pub continuation_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct S3ObjectInfo {
    pub key: String,
    pub size: Option<i64>,
    pub e_tag: Option<String>,
    pub last_modified: Option<String>,
    pub storage_class: Option<String>,
}

#[derive(Debug, Clone)]
pub struct S3ListResult {
    pub objects: Vec<S3ObjectInfo>,
    pub prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct S3StatResult {
    pub bucket: String,
    pub key: String,
    pub size: i64,
    pub e_tag: Option<String>,
    pub content_type: Option<String>,
    pub last_modified: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct S3GetParams {
    pub bucket: String,
    pub key: String,
    pub range: Option<String>,
    pub output_path: Option<String>,
    pub max_bytes: Option<usize>,
    pub accept_text: bool,
}

#[derive(Debug, Clone)]
pub struct S3GetResult {
    pub bucket: String,
    pub key: String,
    pub size: Option<i64>,
    pub content_type: Option<String>,
    pub body: Option<Vec<u8>>,
    pub text: Option<String>,
    pub output_path: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct S3PutParams {
    pub bucket: String,
    pub key: String,
    pub path: Option<String>,
    pub body: Option<String>,
    pub body_base64: bool,
    pub content_type: Option<String>,
    pub cache_control: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct S3CopyParams {
    pub source_bucket: String,
    pub source_key: String,
    pub dest_bucket: String,
    pub dest_key: String,
}

#[derive(Debug, Clone)]
pub struct S3DeleteParams {
    pub bucket: String,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct S3PresignParams {
    pub bucket: String,
    pub key: String,
    pub method: String,
    pub expires_in_seconds: u64,
}

pub fn is_bucket_allowed(bucket: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    allowlist.iter().any(|b| b == "*" || b == bucket)
}

pub async fn build_s3_client() -> Result<Client> {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    Ok(Client::new(&config))
}

pub async fn list_objects(client: &Client, params: S3ListParams) -> Result<S3ListResult> {
    let mut req = client.list_objects_v2().bucket(&params.bucket);
    if let Some(prefix) = &params.prefix {
        req = req.prefix(prefix);
    }
    if let Some(delimiter) = &params.delimiter {
        req = req.delimiter(delimiter);
    }
    if let Some(max_keys) = params.max_keys {
        req = req.max_keys(max_keys);
    }
    if let Some(token) = &params.continuation_token {
        req = req.continuation_token(token);
    }

    let resp = req.send().await.context("S3 list_objects_v2 failed")?;
    let mut objects = Vec::new();
    if let Some(items) = resp.contents {
        for obj in items {
            if let Some(key) = obj.key {
                objects.push(S3ObjectInfo {
                    key,
                    size: obj.size,
                    e_tag: obj.e_tag,
                    last_modified: obj.last_modified.map(|d| d.to_string()),
                    storage_class: obj.storage_class.map(|s| s.as_str().to_string()),
                });
            }
        }
    }
    let prefixes = resp
        .common_prefixes
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| p.prefix)
        .collect();

    Ok(S3ListResult {
        objects,
        prefixes,
        is_truncated: resp.is_truncated.unwrap_or(false),
        next_token: resp.next_continuation_token,
    })
}

pub async fn stat_object(client: &Client, bucket: &str, key: &str) -> Result<S3StatResult> {
    let resp = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context("S3 head_object failed")?;

    let mut metadata = BTreeMap::new();
    if let Some(map) = resp.metadata {
        for (k, v) in map {
            metadata.insert(k, v);
        }
    }

    Ok(S3StatResult {
        bucket: bucket.to_string(),
        key: key.to_string(),
        size: resp.content_length.unwrap_or(0),
        e_tag: resp.e_tag,
        content_type: resp.content_type,
        last_modified: resp.last_modified.map(|d| d.to_string()),
        metadata,
    })
}

pub async fn get_object(client: &Client, params: S3GetParams) -> Result<S3GetResult> {
    let mut req = client.get_object().bucket(&params.bucket).key(&params.key);
    if let Some(range) = &params.range {
        req = req.range(range);
    }
    let resp = req.send().await.context("S3 get_object failed")?;
    let content_type = resp.content_type.clone();
    let size = resp.content_length;

    let mut body = resp.body.collect().await.context("Read S3 body failed")?.into_bytes().to_vec();
    let mut truncated = false;
    if let Some(max) = params.max_bytes {
        if body.len() > max {
            body.truncate(max);
            truncated = true;
        }
    }

    if let Some(path) = &params.output_path {
        fs::write(path, &body).await.context("Failed to write output file")?;
        return Ok(S3GetResult {
            bucket: params.bucket,
            key: params.key,
            size,
            content_type,
            body: None,
            text: None,
            output_path: Some(path.clone()),
            truncated,
        });
    }

    let (body_bytes, text) = if params.accept_text {
        let text = decode_bytes(&body);
        (None, Some(text))
    } else {
        (Some(body), None)
    };

    Ok(S3GetResult {
        bucket: params.bucket,
        key: params.key,
        size,
        content_type,
        body: body_bytes,
        text,
        output_path: None,
        truncated,
    })
}

fn decode_body(body: &Option<String>, body_base64: bool) -> Result<Option<Vec<u8>>> {
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

pub async fn put_object(client: &Client, params: S3PutParams) -> Result<()> {
    let bytes = if let Some(path) = &params.path {
        fs::read(path).await.context("Failed to read input file")?
    } else if let Some(bytes) = decode_body(&params.body, params.body_base64)? {
        bytes
    } else {
        bail!("Provide either path or body for s3_put");
    };

    let mut req = client
        .put_object()
        .bucket(&params.bucket)
        .key(&params.key)
        .body(bytes.into());

    if let Some(ct) = &params.content_type {
        req = req.content_type(ct);
    }
    if let Some(cc) = &params.cache_control {
        req = req.cache_control(cc);
    }
    if !params.metadata.is_empty() {
        for (k, v) in params.metadata {
            req = req.metadata(k, v);
        }
    }

    req.send().await.context("S3 put_object failed")?;
    Ok(())
}

pub async fn copy_object(client: &Client, params: S3CopyParams) -> Result<()> {
    let source = format!("{}/{}", params.source_bucket, params.source_key);
    client
        .copy_object()
        .bucket(&params.dest_bucket)
        .key(&params.dest_key)
        .copy_source(source)
        .send()
        .await
        .context("S3 copy_object failed")?;
    Ok(())
}

pub async fn delete_object(client: &Client, params: S3DeleteParams) -> Result<()> {
    client
        .delete_object()
        .bucket(&params.bucket)
        .key(&params.key)
        .send()
        .await
        .context("S3 delete_object failed")?;
    Ok(())
}

pub async fn delete_objects(client: &Client, bucket: &str, keys: Vec<String>) -> Result<()> {
    let mut objects = Vec::new();
    for key in keys {
        objects.push(ObjectIdentifier::builder().key(key).build()?);
    }
    let delete = aws_sdk_s3::types::Delete::builder()
        .set_objects(Some(objects))
        .build()?;
    client
        .delete_objects()
        .bucket(bucket)
        .delete(delete)
        .send()
        .await
        .context("S3 delete_objects failed")?;
    Ok(())
}

pub async fn presign(client: &Client, params: S3PresignParams) -> Result<String> {
    let expires = PresigningConfig::expires_in(std::time::Duration::from_secs(params.expires_in_seconds))
        .context("Invalid presign duration")?;
    match params.method.as_str() {
        "GET" => {
            let req = client.get_object().bucket(&params.bucket).key(&params.key);
            let presigned = req.presigned(expires).await?;
            Ok(presigned.uri().to_string())
        }
        "PUT" => {
            let req = client.put_object().bucket(&params.bucket).key(&params.key);
            let presigned = req.presigned(expires).await?;
            Ok(presigned.uri().to_string())
        }
        _ => bail!("Unsupported presign method '{}'", params.method),
    }
}
