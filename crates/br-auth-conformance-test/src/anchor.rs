use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use br_auth_contract::SealedBearer;
use br_test_harness::run_once;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::error::{ConformanceError, Result};

pub fn anchor_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("anchor")
        .canonicalize()
        .expect("anchor source directory must exist")
}

pub async fn ensure_go_available() -> Result<()> {
    match run_once("go", &["version"], &[], Duration::from_secs(30)).await {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(ConformanceError::GoUnavailable(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )),
        Err(e) => Err(ConformanceError::GoUnavailable(e)),
    }
}

pub async fn build_anchor() -> Result<PathBuf> {
    ensure_go_available().await?;
    let dir = anchor_dir();
    let dir_str = dir.to_string_lossy().into_owned();
    let binary =
        std::env::temp_dir().join(format!("br-auth-anchor-{}", uuid::Uuid::now_v7().simple()));
    let binary_str = binary.to_string_lossy().into_owned();
    let output = run_once(
        "go",
        &["build", "-C", &dir_str, "-o", &binary_str, "."],
        &[],
        Duration::from_secs(300),
    )
    .await
    .map_err(ConformanceError::Build)?;

    if !output.status.success() {
        return Err(ConformanceError::Build(format!(
            "go build failed (status {}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    if !binary.exists() {
        return Err(ConformanceError::Build(format!(
            "go build reported success but {} is missing",
            binary.display()
        )));
    }
    Ok(binary)
}

#[derive(Debug, Serialize)]
struct AnchorRequest<'a> {
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_b64: Option<String>,
    token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed: Option<SealedBearer>,
}

#[derive(Debug, Deserialize)]
struct AnchorResponse {
    #[serde(default)]
    kv_key: Option<String>,
    #[serde(default)]
    token_hash: Option<String>,
    #[serde(default)]
    sealed: Option<SealedBearer>,
    #[serde(default)]
    plaintext_b64: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

pub struct Anchor {
    binary: PathBuf,
}

impl Anchor {
    pub async fn build() -> Result<Self> {
        Ok(Self {
            binary: build_anchor().await?,
        })
    }

    pub async fn kv_key(&self, token: &str) -> Result<(String, String)> {
        let resp = self
            .invoke(AnchorRequest {
                op: "key",
                key_b64: None,
                token,
                plaintext_b64: None,
                sealed: None,
            })
            .await?;
        let kv_key = resp
            .kv_key
            .ok_or_else(|| ConformanceError::AnchorResponse("key op returned no kv_key".into()))?;
        let token_hash = resp.token_hash.ok_or_else(|| {
            ConformanceError::AnchorResponse("key op returned no token_hash".into())
        })?;
        Ok((kv_key, token_hash))
    }

    pub async fn seal(&self, key: &[u8], token: &str, plaintext: &[u8]) -> Result<SealedBearer> {
        let resp = self
            .invoke(AnchorRequest {
                op: "seal",
                key_b64: Some(STANDARD.encode(key)),
                token,
                plaintext_b64: Some(STANDARD.encode(plaintext)),
                sealed: None,
            })
            .await?;
        resp.sealed
            .ok_or_else(|| ConformanceError::AnchorResponse("seal op returned no sealed".into()))
    }

    pub async fn open(
        &self,
        key: &[u8],
        token: &str,
        sealed: &SealedBearer,
    ) -> Result<std::result::Result<Vec<u8>, String>> {
        let resp = self
            .invoke(AnchorRequest {
                op: "open",
                key_b64: Some(STANDARD.encode(key)),
                token,
                plaintext_b64: None,
                sealed: Some(sealed.clone()),
            })
            .await?;
        if let Some(err) = resp.error {
            return Ok(Err(err));
        }
        let plaintext_b64 = resp.plaintext_b64.ok_or_else(|| {
            ConformanceError::AnchorResponse("open op returned neither plaintext nor error".into())
        })?;
        let plaintext = STANDARD
            .decode(plaintext_b64)
            .map_err(|e| ConformanceError::AnchorResponse(format!("plaintext not base64: {e}")))?;
        Ok(Ok(plaintext))
    }

    async fn invoke(&self, request: AnchorRequest<'_>) -> Result<AnchorResponse> {
        let body = serde_json::to_vec(&request)
            .map_err(|e| ConformanceError::Run(format!("encode anchor request: {e}")))?;

        let mut child = tokio::process::Command::new(&self.binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ConformanceError::Run(format!("spawn anchor: {e}")))?;

        child
            .stdin
            .take()
            .expect("anchor stdin was piped")
            .write_all(&body)
            .await
            .map_err(|e| ConformanceError::Run(format!("write anchor stdin: {e}")))?;

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| ConformanceError::Run(format!("await anchor: {e}")))?;

        if !output.status.success() {
            return Err(ConformanceError::Run(format!(
                "anchor exited {} ; stderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let resp: AnchorResponse = serde_json::from_slice(&output.stdout).map_err(|e| {
            ConformanceError::AnchorResponse(format!(
                "{e}\nstdout: {}",
                String::from_utf8_lossy(&output.stdout)
            ))
        })?;
        if let Some(err) = &resp.error
            && request.op != "open"
        {
            return Err(ConformanceError::AnchorError(err.clone()));
        }
        Ok(resp)
    }
}
