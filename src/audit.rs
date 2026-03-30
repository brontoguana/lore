use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_AUDIT_EVENTS: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditActorKind {
    User,
    ExternalAuth,
    Oidc,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditActor {
    pub kind: AuditActorKind,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAuditEvent {
    pub id: String,
    pub actor: AuditActor,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct AuditStore {
    root: PathBuf,
}

impl AuditStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn append(&self, event: StoredAuditEvent) -> Result<()> {
        self.ensure_layout()?;
        let path = self.audit_path();
        let mut events: Vec<StoredAuditEvent> = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            Vec::new()
        };
        events.push(event);
        events.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        events.truncate(MAX_AUDIT_EVENTS);
        write_json_atomic(path, &events)
    }

    pub fn list_recent(&self, limit: usize) -> Result<Vec<StoredAuditEvent>> {
        let path = self.audit_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut events: Vec<StoredAuditEvent> = serde_json::from_slice(&fs::read(path)?)?;
        events.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        events.truncate(limit);
        Ok(events)
    }

    fn audit_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    fn audit_path(&self) -> PathBuf {
        self.audit_dir().join("auth-audit.json")
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(self.audit_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.audit_dir(), fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

fn write_json_atomic<T>(path: PathBuf, value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp_path, &path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
