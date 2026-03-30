use crate::error::{LoreError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter};
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_PROJECT_NAME_LEN: usize = 64;
const MAX_INLINE_CONTENT_LEN: usize = 16 * 1024;
const MAX_CONTENT_LEN: usize = 512 * 1024;
const MAX_IMAGE_BYTES_LEN: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockType {
    Markdown,
    Html,
    Svg,
    Image,
}

impl BlockType {
    pub fn default_extension(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Html => "html",
            Self::Svg => "svg",
            Self::Image => "bin",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct ProjectName(String);

impl ProjectName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PROJECT_NAME_LEN {
            return Err(LoreError::Validation(format!(
                "project name must be 1..={MAX_PROJECT_NAME_LEN} characters"
            )));
        }
        if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
            return Err(LoreError::Validation(
                "project name contains unsafe dot usage".into(),
            ));
        }
        if !value.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.')
        }) {
            return Err(LoreError::Validation(
                "project name must contain only lowercase ascii letters, digits, '.', '_' or '-'"
                    .into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ProjectName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct BlockId(String);

impl BlockId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_string(value: String) -> Result<Self> {
        Uuid::parse_str(&value)
            .map_err(|_| LoreError::Validation("block id must be a valid uuid".into()))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for BlockId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct KeyFingerprint(String);

impl KeyFingerprint {
    pub fn from_api_key(api_key: &str) -> Result<Self> {
        Self::from_scoped_value("agent", api_key, "api key must not be empty")
    }

    pub fn from_user_name(username: &str) -> Result<Self> {
        Self::from_scoped_value("user", username, "username must not be empty")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_scoped_value(scope: &str, value: &str, empty_message: &str) -> Result<Self> {
        if value.trim().is_empty() {
            return Err(LoreError::Validation(empty_message.into()));
        }

        let mut hasher = Sha256::new();
        hasher.update(scope.as_bytes());
        hasher.update(b":");
        hasher.update(value.as_bytes());
        let digest = hasher.finalize();
        Ok(Self(format!("{digest:x}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct OrderKey(String);

impl OrderKey {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty() {
            return Err(LoreError::Validation("order key must not be empty".into()));
        }
        if !value
            .split('.')
            .all(|segment| segment.len() == 8 && segment.chars().all(|ch| ch.is_ascii_hexdigit()))
        {
            return Err(LoreError::Validation(
                "order key must contain dot-separated 8-char hex segments".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for OrderKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContentRef {
    Inline(String),
    External { relative_path: String },
}

impl ContentRef {
    pub fn inline_limit() -> usize {
        MAX_INLINE_CONTENT_LEN
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaRef {
    pub relative_path: String,
    pub media_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageUpload {
    pub media_type: String,
    pub bytes: Vec<u8>,
}

impl ImageUpload {
    pub fn validate(&self) -> Result<()> {
        if self.bytes.is_empty() {
            return Err(LoreError::Validation(
                "uploaded image must not be empty".into(),
            ));
        }
        if self.bytes.len() > MAX_IMAGE_BYTES_LEN {
            return Err(LoreError::Validation(format!(
                "uploaded image exceeds maximum size of {MAX_IMAGE_BYTES_LEN} bytes"
            )));
        }
        if !self.media_type.starts_with("image/") {
            return Err(LoreError::Validation(
                "uploaded file must use an image/* media type".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredBlock {
    pub id: BlockId,
    pub project: ProjectName,
    pub block_type: BlockType,
    pub order: OrderKey,
    pub author: KeyFingerprint,
    pub content: ContentRef,
    pub media: Option<MediaRef>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewBlock {
    pub project: ProjectName,
    pub block_type: BlockType,
    pub content: String,
    pub author_key: String,
    pub left: Option<OrderKey>,
    pub right: Option<OrderKey>,
    pub image_upload: Option<ImageUpload>,
}

impl NewBlock {
    pub fn validate(&self) -> Result<()> {
        if self.content.is_empty() && self.image_upload.is_none() {
            return Err(LoreError::Validation("content must not be empty".into()));
        }
        if self.content.len() > MAX_CONTENT_LEN {
            return Err(LoreError::Validation(format!(
                "content exceeds maximum size of {MAX_CONTENT_LEN} bytes"
            )));
        }
        if let (Some(left), Some(right)) = (&self.left, &self.right) {
            if left >= right {
                return Err(LoreError::InvalidOrderRange);
            }
        }
        if let Some(upload) = &self.image_upload {
            if self.block_type != BlockType::Image {
                return Err(LoreError::Validation(
                    "uploaded files are only supported for image blocks".into(),
                ));
            }
            upload.validate()?;
        }
        KeyFingerprint::from_api_key(&self.author_key)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UpdateBlock {
    pub project: ProjectName,
    pub block_id: BlockId,
    pub block_type: BlockType,
    pub content: String,
    pub author_key: String,
    pub left: Option<OrderKey>,
    pub right: Option<OrderKey>,
    pub image_upload: Option<ImageUpload>,
}

impl UpdateBlock {
    pub fn validate(&self) -> Result<()> {
        if self.content.is_empty() && self.image_upload.is_none() {
            return Err(LoreError::Validation("content must not be empty".into()));
        }
        if self.content.len() > MAX_CONTENT_LEN {
            return Err(LoreError::Validation(format!(
                "content exceeds maximum size of {MAX_CONTENT_LEN} bytes"
            )));
        }
        if let (Some(left), Some(right)) = (&self.left, &self.right) {
            if left >= right {
                return Err(LoreError::InvalidOrderRange);
            }
        }
        if let Some(upload) = &self.image_upload {
            if self.block_type != BlockType::Image {
                return Err(LoreError::Validation(
                    "uploaded files are only supported for image blocks".into(),
                ));
            }
            upload.validate()?;
        }
        KeyFingerprint::from_api_key(&self.author_key)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub id: BlockId,
    pub project: ProjectName,
    pub block_type: BlockType,
    pub order: OrderKey,
    pub author: KeyFingerprint,
    pub content: String,
    pub media_type: Option<String>,
    pub created_at: OffsetDateTime,
}
