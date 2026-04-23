use crate::error::{LoreError, Result};
use crate::model::{
    Block, BlockId, BlockType, ContentRef, DocumentId, KeyFingerprint, MediaRef, NewBlock,
    OrderKey, ProjectName, RESERVED_BLOCK_IDS, StoredBlock, UpdateBlock, slugify,
};
use crate::order::generate_order_key;
use crate::versioning::{
    StoredBlockSnapshot, block_matches_snapshot, media_bytes, snapshot_from_stored_block,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default)]
    pub sort_order: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_context: Option<String>,
    #[serde(default)]
    pub storage_version: u32,
}

#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub slug: ProjectName,
    pub display_name: String,
    pub parent: Option<String>,
    pub sort_order: u64,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMeta {
    pub id: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct DocumentInfo {
    pub id: DocumentId,
    pub display_name: String,
    pub children: Vec<DocumentInfo>,
}

/// Result of resolving a lore:// link UUID.
#[derive(Debug, Clone)]
pub enum LoreLinkTarget {
    /// Links to a project. Contains (slug, display_name).
    Project(ProjectName, String),
    /// Links to a block. Contains (project_slug, block_id, block_type, content_preview).
    Block(ProjectName, BlockId, BlockType, String),
}

enum UpdateMode {
    AgentOwner(KeyFingerprint),
    ProjectWriter(KeyFingerprint),
}

#[derive(Debug)]
pub struct FileBlockStore {
    root: PathBuf,
    /// Per-project write locks to prevent concurrent file corruption.
    project_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Cache of (project_slug, doc_id) -> directory path to avoid recursive fs walks.
    doc_dir_cache: Mutex<HashMap<(String, String), PathBuf>>,
}

impl Clone for FileBlockStore {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            project_locks: Mutex::new(HashMap::new()),
            doc_dir_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl FileBlockStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            project_locks: Mutex::new(HashMap::new()),
            doc_dir_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get a per-project lock for write operations.
    fn project_lock(&self, project: &ProjectName) -> Arc<Mutex<()>> {
        let mut locks = self.project_locks.lock().unwrap();
        locks
            .entry(project.as_str().to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn list_projects(&self) -> Result<Vec<ProjectName>> {
        self.list_project_infos()
            .map(|infos| infos.into_iter().map(|info| info.slug).collect())
    }

    pub fn list_project_infos(&self) -> Result<Vec<ProjectInfo>> {
        let projects_dir = self.root.join("projects");
        if !projects_dir.exists() {
            return Ok(Vec::new());
        }

        let mut infos = Vec::new();
        for entry in fs::read_dir(projects_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();
            if let Ok(project) = ProjectName::new(&name) {
                let meta = self.read_project_meta(&project);
                infos.push(ProjectInfo {
                    display_name: meta.display_name,
                    parent: meta.parent,
                    sort_order: meta.sort_order,
                    id: meta.id.unwrap_or_default(),
                    slug: project,
                });
            }
        }

        infos.sort_by(|a, b| a.sort_order.cmp(&b.sort_order).then(a.slug.cmp(&b.slug)));
        Ok(infos)
    }

    /// Resolve a project identifier that may be a slug or a display name.
    pub fn resolve_project(&self, input: &str) -> Result<ProjectName> {
        // Try as a direct slug
        if let Ok(name) = ProjectName::new(input) {
            if self.project_dir(&name).exists() {
                return Ok(name);
            }
        }
        // Try slugifying (handles display names like "My Project" -> "my-project")
        let slug = slugify(input);
        if !slug.is_empty() {
            if let Ok(name) = ProjectName::new(&slug) {
                if self.project_dir(&name).exists() {
                    return Ok(name);
                }
            }
        }
        Err(LoreError::Validation(format!(
            "project '{}' not found",
            input
        )))
    }

    /// On startup, rename project directories whose slug doesn't match
    /// `slugify(display_name)`. Returns the list of (old_slug, new_slug) renames.
    pub fn sync_project_slugs(&self) -> Vec<(ProjectName, ProjectName)> {
        let infos = match self.list_project_infos() {
            Ok(infos) => infos,
            Err(_) => return Vec::new(),
        };
        let mut renames = Vec::new();
        for info in &infos {
            let expected = slugify(&info.display_name);
            if expected.is_empty() || expected == info.slug.as_str() {
                continue;
            }
            let new_slug = match ProjectName::new(&expected) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("warning: cannot sync slug for '{}': {e}", info.display_name);
                    continue;
                }
            };
            if self.project_dir(&new_slug).exists() {
                eprintln!(
                    "warning: cannot rename '{}' -> '{}': target already exists",
                    info.slug.as_str(),
                    expected
                );
                continue;
            }
            let old_dir = self.project_dir(&info.slug);
            if let Err(e) = fs::rename(&old_dir, &self.project_dir(&new_slug)) {
                eprintln!(
                    "warning: failed to rename '{}' -> '{}': {e}",
                    info.slug.as_str(),
                    expected
                );
                continue;
            }
            self.invalidate_doc_cache_for_project(&info.slug);
            renames.push((info.slug.clone(), new_slug));
        }
        // Update parent references that pointed to old slugs
        if !renames.is_empty() {
            if let Ok(infos) = self.list_project_infos() {
                for info in &infos {
                    if let Some(parent) = &info.parent {
                        if let Some((_, new_slug)) =
                            renames.iter().find(|(old, _)| old.as_str() == parent)
                        {
                            let mut meta = self.read_project_meta(&info.slug);
                            meta.parent = Some(new_slug.as_str().to_string());
                            let _ = self.write_project_meta_unlocked(&info.slug, &meta);
                        }
                    }
                }
            }
        }
        renames
    }

    pub fn read_project_meta(&self, project: &ProjectName) -> ProjectMeta {
        let meta_path = self.project_dir(project).join("project.json");
        if let Ok(bytes) = fs::read(&meta_path) {
            if let Ok(mut meta) = serde_json::from_slice::<ProjectMeta>(&bytes) {
                // Lazy backfill: assign a UUID if the project doesn't have one yet
                if meta.id.is_none() {
                    meta.id = Some(Uuid::new_v4().to_string());
                    if let Ok(bytes) = serde_json::to_vec_pretty(&meta) {
                        let _ = fs::write(&meta_path, bytes);
                    }
                }
                return meta;
            }
        }
        // Fallback: use the slug as the display name
        ProjectMeta {
            display_name: project.as_str().to_string(),
            parent: None,
            sort_order: 0,
            id: Some(Uuid::new_v4().to_string()),
            agent_context: None,
            storage_version: 0,
        }
    }

    pub fn write_project_meta(&self, project: &ProjectName, meta: &ProjectMeta) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        self.write_project_meta_unlocked(project, meta)
    }

    fn write_project_meta_unlocked(&self, project: &ProjectName, meta: &ProjectMeta) -> Result<()> {
        self.ensure_layout(project)?;
        let meta_path = self.project_dir(project).join("project.json");
        let bytes = serde_json::to_vec_pretty(meta)?;
        fs::write(meta_path, bytes)?;
        Ok(())
    }

    /// Rename a project's display name and sync the directory slug to match.
    /// Returns `Some((old_slug, new_slug))` if the directory was renamed, `None` if only
    /// the display name changed without affecting the slug.
    pub fn rename_project(
        &self,
        project: &ProjectName,
        new_display_name: &str,
    ) -> Result<Option<(ProjectName, ProjectName)>> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let trimmed = new_display_name.trim();
        if trimmed.is_empty() {
            return Err(LoreError::Validation(
                "display name must not be empty".into(),
            ));
        }
        let mut meta = self.read_project_meta(project);
        meta.display_name = trimmed.to_string();
        let new_slug_str = slugify(trimmed);
        if new_slug_str.is_empty() {
            return Err(LoreError::Validation(
                "project name must contain at least one letter or digit".into(),
            ));
        }
        if new_slug_str != project.as_str() {
            let new_slug = ProjectName::new(&new_slug_str)?;
            let new_dir = self.project_dir(&new_slug);
            if new_dir.exists() {
                return Err(LoreError::Validation(format!(
                    "a project with slug '{}' already exists",
                    new_slug_str
                )));
            }
            let old_dir = self.project_dir(project);
            fs::rename(&old_dir, &new_dir)?;
            // Update parent references in other projects
            if let Ok(infos) = self.list_project_infos() {
                for info in &infos {
                    if info.parent.as_deref() == Some(project.as_str()) {
                        let mut child_meta = self.read_project_meta(&info.slug);
                        child_meta.parent = Some(new_slug_str.clone());
                        let _ = self.write_project_meta_unlocked(&info.slug, &child_meta);
                    }
                }
            }
            self.invalidate_doc_cache_for_project(project);
            self.write_project_meta_unlocked(&new_slug, &meta)?;
            Ok(Some((project.clone(), new_slug)))
        } else {
            self.write_project_meta_unlocked(project, &meta)?;
            Ok(None)
        }
    }

    pub fn write_agent_context(&self, project: &ProjectName, context: &str) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let mut meta = self.read_project_meta(project);
        let trimmed = context.trim();
        meta.agent_context = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        self.write_project_meta_unlocked(project, &meta)
    }

    pub fn delete_project(&self, project: &ProjectName) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let dir = self.project_dir(project);
        if !dir.exists() {
            return Err(LoreError::Validation("project does not exist".into()));
        }
        // Re-parent any children to have no parent (promote to root)
        let infos = self.list_project_infos()?;
        for info in &infos {
            if info.parent.as_deref() == Some(project.as_str()) {
                // Use the child's own lock for its meta write
                self.write_project_meta(&info.slug, &{
                    let mut meta = self.read_project_meta(&info.slug);
                    meta.parent = None;
                    meta
                })?;
            }
        }
        self.invalidate_doc_cache_for_project(project);
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// Move a project: change its parent and/or reorder it among siblings.
    /// `new_parent` is the new parent slug (None = root level).
    /// `after_slug` is the sibling it should be placed after (None = first among siblings).
    pub fn move_project(
        &self,
        project: &ProjectName,
        new_parent: Option<&str>,
        after_slug: Option<&str>,
    ) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let dir = self.project_dir(project);
        if !dir.exists() {
            return Err(LoreError::Validation("project does not exist".into()));
        }
        // Prevent making a project its own descendant
        if let Some(parent_slug) = new_parent {
            if parent_slug == project.as_str() {
                return Err(LoreError::Validation(
                    "cannot move a project under itself".into(),
                ));
            }
            // Walk up the tree to check for cycles
            let infos = self.list_project_infos()?;
            let mut current = Some(parent_slug.to_string());
            while let Some(ref slug) = current {
                if slug == project.as_str() {
                    return Err(LoreError::Validation(
                        "cannot move a project under one of its own descendants".into(),
                    ));
                }
                current = infos
                    .iter()
                    .find(|i| i.slug.as_str() == slug)
                    .and_then(|i| i.parent.clone());
            }
        }

        // Get all siblings in the target parent, sorted by sort_order
        let infos = self.list_project_infos()?;
        let siblings: Vec<&ProjectInfo> = infos
            .iter()
            .filter(|i| i.parent.as_deref() == new_parent && i.slug != *project)
            .collect();

        // Calculate new sort_order based on position
        let new_order = if let Some(after) = after_slug {
            // Place after a specific sibling
            if let Some(pos) = siblings.iter().position(|s| s.slug.as_str() == after) {
                let after_order = siblings[pos].sort_order;
                let before_order = siblings.get(pos + 1).map(|s| s.sort_order);
                match before_order {
                    Some(before) if before > after_order + 1 => {
                        // Slot in between
                        after_order + (before - after_order) / 2
                    }
                    Some(_) | None => {
                        // No gap; rewrite all sibling orders
                        after_order + 1000
                    }
                }
            } else {
                // after_slug not found among siblings, place at end
                siblings.last().map(|s| s.sort_order + 1000).unwrap_or(1000)
            }
        } else {
            // Place first: before all siblings
            if let Some(first) = siblings.first() {
                if first.sort_order > 1 {
                    first.sort_order / 2
                } else {
                    // Need to rewrite; set to 0 and bump others
                    0
                }
            } else {
                1000
            }
        };

        let mut meta = self.read_project_meta(project);
        meta.parent = new_parent.map(|s| s.to_string());
        meta.sort_order = new_order;
        self.write_project_meta_unlocked(project, &meta)
    }

    /// Resolve a lore:// link UUID to either a project or a block.
    /// Checks projects first (by their UUID), then blocks across all projects.
    pub fn resolve_lore_link(&self, uuid: &str) -> Option<LoreLinkTarget> {
        // Check projects first
        let infos = self.list_project_infos().ok()?;
        for info in &infos {
            if info.id == uuid {
                return Some(LoreLinkTarget::Project(
                    info.slug.clone(),
                    info.display_name.clone(),
                ));
            }
        }
        // Check blocks across all projects (project-level and document-level)
        for info in &infos {
            if let Ok(blocks) = self.list_blocks(&info.slug) {
                for block in &blocks {
                    if block.id.as_str() == uuid {
                        let preview = truncate_single_line(&block.content, 48);
                        return Some(LoreLinkTarget::Block(
                            info.slug.clone(),
                            block.id.clone(),
                            block.block_type,
                            preview,
                        ));
                    }
                }
            }
            if let Ok(doc_blocks) = self.list_all_blocks_across_docs(&info.slug) {
                for (_doc_id, block) in &doc_blocks {
                    if block.id.as_str() == uuid {
                        let preview = truncate_single_line(&block.content, 48);
                        return Some(LoreLinkTarget::Block(
                            info.slug.clone(),
                            block.id.clone(),
                            block.block_type,
                            preview,
                        ));
                    }
                }
            }
        }
        None
    }

    pub fn create_project(&self, display_name: &str, parent: Option<&str>) -> Result<ProjectInfo> {
        let (slug, display) = ProjectName::from_display_name(display_name)?;
        // Check if project already exists
        if self.project_dir(&slug).exists() {
            return Err(LoreError::Validation(format!(
                "a project with slug '{}' already exists",
                slug.as_str()
            )));
        }
        // Verify parent exists if specified
        if let Some(parent_slug) = parent {
            let parent_project = ProjectName::new(parent_slug)?;
            let parent_dir = self.project_dir(&parent_project);
            if !parent_dir.exists() {
                return Err(LoreError::Validation(
                    "parent project does not exist".into(),
                ));
            }
        }
        self.ensure_layout(&slug)?;
        let sort_order = OffsetDateTime::now_utc().unix_timestamp() as u64;
        let project_id = Uuid::new_v4().to_string();
        let meta = ProjectMeta {
            display_name: display.clone(),
            parent: parent.map(|s| s.to_string()),
            sort_order,
            id: Some(project_id.clone()),
            agent_context: None,
            storage_version: 1,
        };
        self.write_project_meta(&slug, &meta)?;
        self.ensure_reserved_blocks(&slug)?;
        Ok(ProjectInfo {
            display_name: display,
            parent: parent.map(|s| s.to_string()),
            sort_order,
            id: project_id,
            slug,
        })
    }

    pub fn create_block(&self, new_block: NewBlock) -> Result<Block> {
        let author = KeyFingerprint::from_api_key(&new_block.author_key)?;
        self.create_block_internal(new_block, author)
    }

    pub fn create_block_as_project_writer(&self, new_block: NewBlock) -> Result<Block> {
        let author = KeyFingerprint::from_user_name(&new_block.author_key)?;
        self.create_block_internal(new_block, author)
    }

    fn create_block_internal(&self, new_block: NewBlock, author: KeyFingerprint) -> Result<Block> {
        let _lock = self.project_lock(&new_block.project);
        let _guard = _lock.lock().unwrap();
        new_block.validate()?;

        let order = generate_order_key(new_block.left.as_ref(), new_block.right.as_ref())?;
        let id = BlockId::new();
        let created_at = OffsetDateTime::now_utc();

        self.ensure_layout(&new_block.project)?;

        let content_ref = self.persist_text_content(
            &new_block.project,
            &id,
            new_block.block_type,
            &new_block.content,
        )?;
        let media_ref =
            self.persist_uploaded_media(&new_block.project, &id, new_block.image_upload)?;

        let stored = StoredBlock {
            id: id.clone(),
            project: new_block.project.clone(),
            block_type: new_block.block_type,
            order: order.clone(),
            author: author.clone(),
            content: content_ref,
            media: media_ref,
            created_at,
            pinned: false,
        };

        let metadata_path = self.block_metadata_path(&new_block.project, &id);
        let bytes = serde_json::to_vec_pretty(&stored)?;
        fs::write(metadata_path, bytes)?;

        self.inflate_block(stored)
    }

    pub fn list_blocks(&self, project: &ProjectName) -> Result<Vec<Block>> {
        let blocks_dir = self.project_dir(project).join("blocks");
        if !blocks_dir.exists() {
            return Ok(Vec::new());
        }

        let mut blocks = Vec::new();
        for entry in fs::read_dir(blocks_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let stored: StoredBlock = serde_json::from_slice(&fs::read(&path)?)?;
            blocks.push(self.inflate_block(stored)?);
        }

        blocks.sort_by(|a, b| {
            a.order
                .cmp(&b.order)
                .then_with(|| a.created_at.cmp(&b.created_at))
        });
        Ok(blocks)
    }

    pub fn search_blocks(&self, project: &ProjectName, query: &str) -> Result<Vec<Block>> {
        let needle = query.trim();
        if needle.is_empty() {
            return self.list_blocks(project);
        }

        let needle = needle.to_lowercase();
        let mut blocks = self.list_blocks(project)?;
        blocks.retain(|block| {
            block.content.to_lowercase().contains(&needle)
                || block.order.as_str().to_lowercase().contains(&needle)
                || format!("{:?}", block.block_type)
                    .to_lowercase()
                    .contains(&needle)
                || block.author.as_str().to_lowercase().contains(&needle)
        });
        Ok(blocks)
    }

    pub fn get_block(&self, project: &ProjectName, block_id: &BlockId) -> Result<Block> {
        let metadata_path = self.block_metadata_path(project, block_id);
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
        }

        let stored: StoredBlock = serde_json::from_slice(&fs::read(metadata_path)?)?;
        self.inflate_block(stored)
    }

    pub fn snapshot_block(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
    ) -> Result<StoredBlockSnapshot> {
        let metadata_path = self.block_metadata_path(project, block_id);
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
        }

        let stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        let content = match &stored.content {
            ContentRef::Inline(content) => content.clone(),
            ContentRef::External { relative_path } => {
                let blob_path = self.project_dir(project).join(relative_path);
                read_utf8(&blob_path)?
            }
        };
        let media: Result<Option<(String, Vec<u8>)>> = match stored.media.as_ref() {
            Some(media) => {
                let blob_path = self.project_dir(project).join(&media.relative_path);
                Ok(Some((media.media_type.clone(), fs::read(blob_path)?)))
            }
            None => Ok(None),
        };
        Ok(snapshot_from_stored_block(stored, content, media?))
    }

    pub fn read_blocks_around(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        before: usize,
        after: usize,
    ) -> Result<Vec<Block>> {
        let blocks = self.list_blocks(project)?;
        let index = blocks
            .iter()
            .position(|block| &block.id == block_id)
            .ok_or_else(|| LoreError::BlockNotFound(block_id.as_str().to_string()))?;
        let start = index.saturating_sub(before);
        let end = (index + after + 1).min(blocks.len());
        Ok(blocks[start..end].to_vec())
    }

    pub fn delete_block(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        requesting_key: &str,
    ) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let fingerprint = KeyFingerprint::from_api_key(requesting_key)?;
        self.delete_block_unlocked(project, block_id, Some(&fingerprint))
    }

    pub fn delete_block_as_project_writer(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
    ) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        self.delete_block_unlocked(project, block_id, None)
    }

    pub fn set_block_pinned(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        pinned: bool,
    ) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let metadata_path = self.block_metadata_path(project, block_id);
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
        }
        let mut stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        stored.pinned = pinned;
        let bytes = serde_json::to_vec_pretty(&stored)?;
        fs::write(metadata_path, bytes)?;
        Ok(())
    }

    /// Merge consecutive markdown blocks into single blocks, joining content
    /// with a newline. Pinned blocks break a run (they are never merged).
    /// Returns the number of blocks removed.
    pub fn compact_markdown_blocks(&self, project: &ProjectName) -> Result<usize> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let blocks = self.list_blocks(project)?;
        let mut removed = 0usize;

        // Collect runs of consecutive markdown blocks (pinned blocks break a run)
        let mut runs: Vec<Vec<&Block>> = Vec::new();
        let mut current_run: Vec<&Block> = Vec::new();
        for block in &blocks {
            if block.block_type == BlockType::Markdown && !block.pinned {
                current_run.push(block);
            } else {
                if current_run.len() > 1 {
                    runs.push(std::mem::take(&mut current_run));
                } else {
                    current_run.clear();
                }
            }
        }
        if current_run.len() > 1 {
            runs.push(current_run);
        }

        for run in &runs {
            // Merge all content into the first block
            let merged_content = run
                .iter()
                .map(|b| b.content.as_str())
                .collect::<Vec<_>>()
                .join("\n");

            // Update the first block with merged content
            let first = &run[0];
            let metadata_path = self.block_metadata_path(project, &first.id);
            let mut stored: StoredBlock = serde_json::from_slice(&std::fs::read(&metadata_path)?)?;
            self.remove_external_blob_if_present(project, &stored.content)?;
            stored.content = self.persist_text_content(
                project,
                &first.id,
                BlockType::Markdown,
                &merged_content,
            )?;
            let bytes = serde_json::to_vec_pretty(&stored)?;
            std::fs::write(&metadata_path, bytes)?;

            // Delete the remaining blocks in the run
            for block in &run[1..] {
                self.delete_block_unlocked(project, &block.id, None)?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    fn delete_block_unlocked(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        owner_fingerprint: Option<&KeyFingerprint>,
    ) -> Result<()> {
        let metadata_path = self.block_metadata_path(project, block_id);
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
        }

        let stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        if let Some(owner_fingerprint) = owner_fingerprint {
            if stored.pinned {
                return Err(LoreError::BlockPinned);
            }
            if &stored.author != owner_fingerprint {
                return Err(LoreError::PermissionDenied);
            }
        }

        if let ContentRef::External { relative_path } = &stored.content {
            let blob_path = self.project_dir(project).join(relative_path);
            if blob_path.exists() {
                fs::remove_file(blob_path)?;
            }
        }
        self.remove_media_if_present(project, stored.media.as_ref())?;

        fs::remove_file(metadata_path)?;
        Ok(())
    }

    pub fn update_block(&self, update: UpdateBlock) -> Result<Block> {
        let fingerprint = KeyFingerprint::from_api_key(&update.author_key)?;
        self.update_block_internal(update, UpdateMode::AgentOwner(fingerprint))
    }

    pub fn update_block_as_project_writer(&self, update: UpdateBlock) -> Result<Block> {
        let fingerprint = KeyFingerprint::from_user_name(&update.author_key)?;
        self.update_block_internal(update, UpdateMode::ProjectWriter(fingerprint))
    }

    fn update_block_internal(&self, update: UpdateBlock, mode: UpdateMode) -> Result<Block> {
        let _lock = self.project_lock(&update.project);
        let _guard = _lock.lock().unwrap();
        update.validate()?;

        let metadata_path = self.block_metadata_path(&update.project, &update.block_id);
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(
                update.block_id.as_str().to_string(),
            ));
        }

        let mut stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        match &mode {
            UpdateMode::AgentOwner(fingerprint) => {
                if stored.pinned {
                    return Err(LoreError::BlockPinned);
                }
                if &stored.author != fingerprint {
                    return Err(LoreError::PermissionDenied);
                }
            }
            UpdateMode::ProjectWriter(_) => {}
        }

        self.ensure_layout(&update.project)?;
        self.remove_external_blob_if_present(&update.project, &stored.content)?;
        self.remove_media_if_present(&update.project, stored.media.as_ref())?;

        stored.block_type = update.block_type;
        stored.author = match mode {
            UpdateMode::AgentOwner(fingerprint) | UpdateMode::ProjectWriter(fingerprint) => {
                fingerprint
            }
        };
        if update.left.is_some() || update.right.is_some() {
            stored.order = generate_order_key(update.left.as_ref(), update.right.as_ref())?;
        }
        stored.content = self.persist_text_content(
            &update.project,
            &update.block_id,
            update.block_type,
            &update.content,
        )?;
        stored.media =
            self.persist_uploaded_media(&update.project, &update.block_id, update.image_upload)?;

        let bytes = serde_json::to_vec_pretty(&stored)?;
        fs::write(metadata_path, bytes)?;
        self.inflate_block(stored)
    }

    pub fn resolve_after_block(
        &self,
        project: &ProjectName,
        after_block_id: Option<&BlockId>,
        exclude_block_id: Option<&BlockId>,
    ) -> Result<(Option<OrderKey>, Option<OrderKey>)> {
        let mut blocks = self.list_blocks(project)?;
        if let Some(exclude_block_id) = exclude_block_id {
            blocks.retain(|block| &block.id != exclude_block_id);
        }

        match after_block_id {
            None => Ok((None, blocks.first().map(|block| block.order.clone()))),
            Some(after_block_id) => {
                let index = blocks
                    .iter()
                    .position(|block| &block.id == after_block_id)
                    .ok_or_else(|| {
                        LoreError::Validation("selected placement block was not found".into())
                    })?;
                let left = Some(blocks[index].order.clone());
                let right = blocks.get(index + 1).map(|block| block.order.clone());
                Ok((left, right))
            }
        }
    }

    pub fn move_block_after(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        after_block_id: Option<&BlockId>,
        requesting_key: &str,
    ) -> Result<Block> {
        let existing = self.get_block(project, block_id)?;
        let (left, right) = self.resolve_after_block(project, after_block_id, Some(block_id))?;
        self.update_block(UpdateBlock {
            project: project.clone(),
            block_id: block_id.clone(),
            block_type: existing.block_type,
            content: existing.content,
            author_key: requesting_key.to_string(),
            left,
            right,
            image_upload: None,
        })
    }

    pub fn move_block_after_as_project_writer(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        after_block_id: Option<&BlockId>,
        username: &str,
    ) -> Result<Block> {
        let existing = self.get_block(project, block_id)?;
        let (left, right) = self.resolve_after_block(project, after_block_id, Some(block_id))?;
        self.update_block_as_project_writer(UpdateBlock {
            project: project.clone(),
            block_id: block_id.clone(),
            block_type: existing.block_type,
            content: existing.content,
            author_key: username.to_string(),
            left,
            right,
            image_upload: None,
        })
    }

    pub fn read_block_media(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
    ) -> Result<(String, Vec<u8>)> {
        let metadata_path = self.block_metadata_path(project, block_id);
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
        }

        let stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        let media = stored
            .media
            .ok_or_else(|| LoreError::Validation("block does not have uploaded media".into()))?;
        let media_path = self.project_dir(project).join(media.relative_path);
        let bytes = fs::read(media_path)?;
        Ok((media.media_type, bytes))
    }

    pub fn restore_block_snapshot(&self, snapshot: &StoredBlockSnapshot) -> Result<Block> {
        self.ensure_layout(&snapshot.project)?;
        let metadata_path = self.block_metadata_path(&snapshot.project, &snapshot.id);
        if metadata_path.exists() {
            let existing: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
            self.remove_external_blob_if_present(&snapshot.project, &existing.content)?;
            self.remove_media_if_present(&snapshot.project, existing.media.as_ref())?;
        }

        let content_ref = self.persist_text_content(
            &snapshot.project,
            &snapshot.id,
            snapshot.block_type,
            &snapshot.content,
        )?;
        let media_ref = if let Some(media) = &snapshot.media {
            let extension = media_extension(&media.media_type);
            let blob_name = format!("{}.{}", snapshot.id.as_str(), extension);
            let relative_path = format!("blobs/{blob_name}");
            let blob_path = self.project_dir(&snapshot.project).join(&relative_path);
            fs::write(blob_path, media_bytes(media)?)?;
            Some(MediaRef {
                relative_path,
                media_type: media.media_type.clone(),
            })
        } else {
            None
        };

        let stored = StoredBlock {
            id: snapshot.id.clone(),
            project: snapshot.project.clone(),
            block_type: snapshot.block_type,
            order: snapshot.order.clone(),
            author: snapshot.author.clone(),
            content: content_ref,
            media: media_ref,
            created_at: snapshot.created_at,
            pinned: false,
        };
        let bytes = serde_json::to_vec_pretty(&stored)?;
        fs::write(metadata_path, bytes)?;
        self.inflate_block(stored)
    }

    pub fn block_matches_snapshot(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        snapshot: &StoredBlockSnapshot,
    ) -> Result<bool> {
        match self.get_block(project, block_id) {
            Ok(block) => Ok(block_matches_snapshot(&block, snapshot)),
            Err(LoreError::BlockNotFound(_)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub fn doc_block_matches_snapshot(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
        snapshot: &StoredBlockSnapshot,
    ) -> Result<bool> {
        match self.get_doc_block(project, doc_id, block_id) {
            Ok(block) => Ok(block_matches_snapshot(&block, snapshot)),
            Err(LoreError::BlockNotFound(_)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub fn restore_doc_block_snapshot(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        snapshot: &StoredBlockSnapshot,
    ) -> Result<Block> {
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        let metadata_path = doc_dir
            .join("blocks")
            .join(format!("{}.json", snapshot.id.as_str()));
        if metadata_path.exists() {
            let existing: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
            self.remove_external_blob_if_present(&snapshot.project, &existing.content)?;
            self.remove_media_if_present(&snapshot.project, existing.media.as_ref())?;
        }

        let content_ref = self.persist_text_content(
            &snapshot.project,
            &snapshot.id,
            snapshot.block_type,
            &snapshot.content,
        )?;
        let media_ref = if let Some(media) = &snapshot.media {
            let extension = media_extension(&media.media_type);
            let blob_name = format!("{}.{}", snapshot.id.as_str(), extension);
            let relative_path = format!("blobs/{blob_name}");
            let blob_path = self.project_dir(&snapshot.project).join(&relative_path);
            fs::write(blob_path, media_bytes(media)?)?;
            Some(MediaRef {
                relative_path,
                media_type: media.media_type.clone(),
            })
        } else {
            None
        };

        let stored = StoredBlock {
            id: snapshot.id.clone(),
            project: snapshot.project.clone(),
            block_type: snapshot.block_type,
            order: snapshot.order.clone(),
            author: snapshot.author.clone(),
            content: content_ref,
            media: media_ref,
            created_at: snapshot.created_at,
            pinned: false,
        };
        let bytes = serde_json::to_vec_pretty(&stored)?;
        fs::write(metadata_path, bytes)?;
        self.inflate_block(stored)
    }

    // ---- Document CRUD ----

    pub fn create_document(
        &self,
        project: &ProjectName,
        parent_doc: Option<&DocumentId>,
        display_name: &str,
    ) -> Result<DocumentInfo> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let trimmed = display_name.trim();
        if trimmed.is_empty() {
            return Err(LoreError::Validation(
                "document name must not be empty".into(),
            ));
        }
        let doc_id = DocumentId::new();
        let parent_docs_dir = match parent_doc {
            None => self.project_dir(project).join("docs"),
            Some(pid) => self.find_doc_dir(project, pid)?.join("docs"),
        };
        let doc_dir = parent_docs_dir.join(doc_id.as_str());
        fs::create_dir_all(doc_dir.join("blocks"))?;
        fs::create_dir_all(doc_dir.join("blobs"))?;
        fs::create_dir_all(doc_dir.join("docs"))?;
        let meta = DocumentMeta {
            id: doc_id.as_str().to_string(),
            display_name: trimmed.to_string(),
            created_at: Some(OffsetDateTime::now_utc()),
        };
        fs::write(doc_dir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
        Ok(DocumentInfo {
            id: doc_id,
            display_name: trimmed.to_string(),
            children: Vec::new(),
        })
    }

    pub fn list_documents(&self, project: &ProjectName) -> Result<Vec<DocumentInfo>> {
        let docs_dir = self.project_dir(project).join("docs");
        self.list_documents_recursive(&docs_dir)
    }

    pub fn rename_document(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        new_name: &str,
    ) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            return Err(LoreError::Validation(
                "document name must not be empty".into(),
            ));
        }
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        let meta_path = doc_dir.join("meta.json");
        let mut meta: DocumentMeta = serde_json::from_slice(&fs::read(&meta_path)?)?;
        meta.display_name = trimmed.to_string();
        fs::write(meta_path, serde_json::to_vec_pretty(&meta)?)?;
        Ok(())
    }

    pub fn delete_document(&self, project: &ProjectName, doc_id: &DocumentId) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        self.invalidate_doc_cache_for_project(project);
        fs::remove_dir_all(doc_dir)?;
        Ok(())
    }

    // ---- Document-scoped block operations ----

    pub fn list_doc_blocks(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
    ) -> Result<Vec<Block>> {
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        let blocks_dir = doc_dir.join("blocks");
        if !blocks_dir.exists() {
            return Ok(Vec::new());
        }
        let mut blocks = Vec::new();
        for entry in fs::read_dir(blocks_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let stored: StoredBlock = serde_json::from_slice(&fs::read(&path)?)?;
            blocks.push(self.inflate_block(stored)?);
        }
        blocks.sort_by(|a, b| {
            a.order
                .cmp(&b.order)
                .then_with(|| a.created_at.cmp(&b.created_at))
        });
        Ok(blocks)
    }

    pub fn get_doc_block(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
    ) -> Result<Block> {
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        let path = doc_dir
            .join("blocks")
            .join(format!("{}.json", block_id.as_str()));
        if !path.exists() {
            return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
        }
        let stored: StoredBlock = serde_json::from_slice(&fs::read(path)?)?;
        self.inflate_block(stored)
    }

    pub fn create_doc_block(&self, doc_id: &DocumentId, new_block: NewBlock) -> Result<Block> {
        let _lock = self.project_lock(&new_block.project);
        let _guard = _lock.lock().unwrap();
        let author = KeyFingerprint::from_api_key(&new_block.author_key)?;
        let doc_dir = self.find_doc_dir(&new_block.project, doc_id)?;
        self.create_block_in_doc_dir(&doc_dir, new_block, author)
    }

    pub fn create_doc_block_as_project_writer(
        &self,
        doc_id: &DocumentId,
        new_block: NewBlock,
    ) -> Result<Block> {
        let _lock = self.project_lock(&new_block.project);
        let _guard = _lock.lock().unwrap();
        let author = KeyFingerprint::from_user_name(&new_block.author_key)?;
        let doc_dir = self.find_doc_dir(&new_block.project, doc_id)?;
        self.create_block_in_doc_dir(&doc_dir, new_block, author)
    }

    pub fn update_doc_block(&self, doc_id: &DocumentId, update: UpdateBlock) -> Result<Block> {
        let _lock = self.project_lock(&update.project);
        let _guard = _lock.lock().unwrap();
        let fingerprint = KeyFingerprint::from_api_key(&update.author_key)?;
        let doc_dir = self.find_doc_dir(&update.project, doc_id)?;
        self.update_block_in_doc_dir(&doc_dir, update, UpdateMode::AgentOwner(fingerprint))
    }

    pub fn update_doc_block_as_project_writer(
        &self,
        doc_id: &DocumentId,
        update: UpdateBlock,
    ) -> Result<Block> {
        let _lock = self.project_lock(&update.project);
        let _guard = _lock.lock().unwrap();
        let fingerprint = KeyFingerprint::from_user_name(&update.author_key)?;
        let doc_dir = self.find_doc_dir(&update.project, doc_id)?;
        self.update_block_in_doc_dir(&doc_dir, update, UpdateMode::ProjectWriter(fingerprint))
    }

    pub fn delete_doc_block(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
        requesting_key: &str,
    ) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let fingerprint = KeyFingerprint::from_api_key(requesting_key)?;
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        self.delete_block_in_doc_dir(&doc_dir, project, block_id, Some(&fingerprint))
    }

    pub fn delete_doc_block_as_project_writer(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
    ) -> Result<()> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        self.delete_block_in_doc_dir(&doc_dir, project, block_id, None)
    }

    /// Split a document block at a character offset. Updates the original block
    /// with content before the split point and creates a new block immediately
    /// after it with the remaining content. Returns (updated_original, new_block).
    pub fn split_doc_block(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
        position: usize,
        author: KeyFingerprint,
    ) -> Result<(Block, Block)> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        let existing = {
            let path = doc_dir
                .join("blocks")
                .join(format!("{}.json", block_id.as_str()));
            if !path.exists() {
                return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
            }
            let stored: StoredBlock = serde_json::from_slice(&fs::read(&path)?)?;
            self.inflate_block(stored)?
        };
        if existing.block_type != BlockType::Markdown {
            return Err(LoreError::Validation(
                "only markdown blocks can be split".into(),
            ));
        }
        if position == 0 || position >= existing.content.len() {
            return Err(LoreError::Validation(
                "split position must be between 1 and content length - 1".into(),
            ));
        }
        let before_content = existing.content[..position].to_string();
        let after_content = existing.content[position..].to_string();

        // Find the next block's order key for insertion
        let blocks = self.list_doc_blocks_in_dir(&doc_dir)?;
        let idx = blocks
            .iter()
            .position(|b| &b.id == block_id)
            .ok_or_else(|| LoreError::BlockNotFound(block_id.as_str().to_string()))?;
        let right_order = blocks.get(idx + 1).map(|b| b.order.clone());

        // Update original block with first half
        let updated = self.update_block_in_doc_dir(
            &doc_dir,
            UpdateBlock {
                project: project.clone(),
                block_id: block_id.clone(),
                block_type: BlockType::Markdown,
                content: before_content,
                author_key: "internal".into(),
                left: None,
                right: None,
                image_upload: None,
            },
            UpdateMode::ProjectWriter(author.clone()),
        )?;

        // Create new block after the original with second half
        let new_order = generate_order_key(Some(&existing.order), right_order.as_ref())?;
        let new_id = BlockId::new();
        let project_dir = self.project_dir(project);
        let content_ref = self.persist_text_content_in(
            &doc_dir,
            &project_dir,
            &new_id,
            BlockType::Markdown,
            &after_content,
        )?;
        let stored = StoredBlock {
            id: new_id.clone(),
            project: project.clone(),
            block_type: BlockType::Markdown,
            order: new_order,
            author,
            content: content_ref,
            media: None,
            created_at: OffsetDateTime::now_utc(),
            pinned: false,
        };
        let path = doc_dir
            .join("blocks")
            .join(format!("{}.json", new_id.as_str()));
        fs::write(path, serde_json::to_vec_pretty(&stored)?)?;
        let new_block = self.inflate_block(stored)?;

        Ok((updated, new_block))
    }

    /// Combine consecutive markdown blocks in a document into a single block.
    /// All block_ids must be markdown, consecutive in order, and non-pinned.
    /// Content is joined with newlines. The first block is kept; the rest are deleted.
    /// Returns the merged block.
    pub fn combine_doc_blocks(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_ids: &[BlockId],
        author: KeyFingerprint,
    ) -> Result<Block> {
        if block_ids.len() < 2 {
            return Err(LoreError::Validation(
                "combine requires at least 2 block IDs".into(),
            ));
        }
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        let all_blocks = self.list_doc_blocks_in_dir(&doc_dir)?;

        // Find the indices of the requested blocks and verify they are consecutive markdown
        let mut indices = Vec::with_capacity(block_ids.len());
        for bid in block_ids {
            let idx = all_blocks
                .iter()
                .position(|b| &b.id == bid)
                .ok_or_else(|| LoreError::BlockNotFound(bid.as_str().to_string()))?;
            indices.push(idx);
        }
        indices.sort();
        for i in 1..indices.len() {
            if indices[i] != indices[i - 1] + 1 {
                return Err(LoreError::Validation(
                    "blocks must be consecutive in document order".into(),
                ));
            }
        }
        for &idx in &indices {
            let b = &all_blocks[idx];
            if b.block_type != BlockType::Markdown {
                return Err(LoreError::Validation(format!(
                    "block {} is not markdown — only markdown blocks can be combined",
                    b.id
                )));
            }
            if b.pinned {
                return Err(LoreError::Validation(format!(
                    "block {} is pinned — unpin before combining",
                    b.id
                )));
            }
        }

        // Merge content in order
        let merged_content: String = indices
            .iter()
            .map(|&idx| all_blocks[idx].content.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        // Update first block with merged content
        let first_id = &all_blocks[indices[0]].id;
        let updated = self.update_block_in_doc_dir(
            &doc_dir,
            UpdateBlock {
                project: project.clone(),
                block_id: first_id.clone(),
                block_type: BlockType::Markdown,
                content: merged_content,
                author_key: "internal".into(),
                left: None,
                right: None,
                image_upload: None,
            },
            UpdateMode::ProjectWriter(author),
        )?;

        // Delete the remaining blocks
        for &idx in &indices[1..] {
            let bid = &all_blocks[idx].id;
            self.delete_block_in_doc_dir(&doc_dir, project, bid, None)?;
        }

        Ok(updated)
    }

    /// Read a document (or a range of blocks within it) as a single text with
    /// block boundary markers.  The marker format is:
    ///
    /// ```text
    /// @@block id=<ID> type=<TYPE>
    /// content
    /// @@end
    /// ```
    ///
    /// Image blocks have empty content between the markers.
    pub fn read_document_text(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        start_block_id: Option<&BlockId>,
        end_block_id: Option<&BlockId>,
    ) -> Result<String> {
        let blocks = self.list_doc_blocks(project, doc_id)?;
        let range = filter_block_range(&blocks, start_block_id, end_block_id)?;
        Ok(serialize_blocks_to_text(range))
    }

    /// Apply a full document write expressed in the marker text format.
    ///
    /// The caller supplies parsed `DocumentWriteEntry` items (use
    /// `parse_document_text` to obtain them).  The method diffs against the
    /// current blocks and applies creates, updates, deletes and reordering
    /// under a single project lock.
    ///
    /// * Existing blocks are matched by UUID.
    /// * Image blocks are validated but their content is never changed.
    /// * Non-UUID ids are treated as new-block placeholders and replaced with
    ///   real UUIDs.
    /// * Any current block **not** present in `entries` is deleted.
    /// * Block order is set to match the input sequence.
    pub fn write_document_text(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        entries: Vec<DocumentWriteEntry>,
        author: KeyFingerprint,
    ) -> Result<DocumentWriteResult> {
        let _lock = self.project_lock(project);
        let _guard = _lock.lock().unwrap();
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        let current_blocks = self.list_doc_blocks_in_dir(&doc_dir)?;

        let mut existing_map: HashMap<String, &Block> = HashMap::new();
        for block in &current_blocks {
            existing_map.insert(block.id.as_str().to_string(), block);
        }

        let mut result = DocumentWriteResult {
            created: Vec::new(),
            updated: Vec::new(),
            deleted: Vec::new(),
        };

        let mut referenced_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut final_block_ids: Vec<BlockId> = Vec::new();

        for entry in &entries {
            let is_existing_uuid =
                Uuid::parse_str(&entry.id).is_ok() && existing_map.contains_key(&entry.id);
            let is_unknown_uuid =
                Uuid::parse_str(&entry.id).is_ok() && !existing_map.contains_key(&entry.id);

            if is_unknown_uuid {
                return Err(LoreError::Validation(format!(
                    "block {} not found in document",
                    entry.id
                )));
            }

            if is_existing_uuid {
                let existing = existing_map[&entry.id];
                referenced_ids.insert(entry.id.clone());

                if existing.block_type == BlockType::Image {
                    // Image: validate only, never modify content
                    final_block_ids.push(existing.id.clone());
                    continue;
                }

                if existing.content != entry.content || existing.block_type != entry.block_type {
                    let updated = self.update_block_in_doc_dir(
                        &doc_dir,
                        UpdateBlock {
                            project: project.clone(),
                            block_id: existing.id.clone(),
                            block_type: entry.block_type,
                            content: entry.content.clone(),
                            author_key: "internal".into(),
                            left: None,
                            right: None,
                            image_upload: None,
                        },
                        UpdateMode::ProjectWriter(author.clone()),
                    )?;
                    result.updated.push(updated);
                }
                final_block_ids.push(BlockId::from_string(entry.id.clone())?);
            } else {
                // Non-UUID id → new block placeholder
                let new_block = self.create_block_in_doc_dir(
                    &doc_dir,
                    NewBlock {
                        project: project.clone(),
                        block_type: entry.block_type,
                        content: entry.content.clone(),
                        author_key: "internal".into(),
                        left: None,
                        right: None,
                        image_upload: None,
                    },
                    author.clone(),
                )?;
                final_block_ids.push(new_block.id.clone());
                result.created.push((entry.id.clone(), new_block));
            }
        }

        // Delete blocks not referenced in the input
        for block in &current_blocks {
            if !referenced_ids.contains(block.id.as_str()) {
                self.delete_block_in_doc_dir(&doc_dir, project, &block.id, None)?;
                result.deleted.push(block.id.clone());
            }
        }

        // Reorder blocks to match input sequence
        let mut prev_order: Option<OrderKey> = None;
        for block_id in &final_block_ids {
            let new_order = generate_order_key(prev_order.as_ref(), None)?;
            let path = doc_dir
                .join("blocks")
                .join(format!("{}.json", block_id.as_str()));
            if path.exists() {
                let mut stored: StoredBlock = serde_json::from_slice(&fs::read(&path)?)?;
                if stored.order != new_order {
                    stored.order = new_order.clone();
                    fs::write(&path, serde_json::to_vec_pretty(&stored)?)?;
                }
            }
            prev_order = Some(new_order);
        }

        Ok(result)
    }

    fn list_doc_blocks_in_dir(&self, doc_dir: &std::path::Path) -> Result<Vec<Block>> {
        let blocks_dir = doc_dir.join("blocks");
        if !blocks_dir.exists() {
            return Ok(Vec::new());
        }
        let mut blocks = Vec::new();
        for entry in fs::read_dir(blocks_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let stored: StoredBlock = serde_json::from_slice(&fs::read(&path)?)?;
            blocks.push(self.inflate_block(stored)?);
        }
        blocks.sort_by(|a, b| {
            a.order
                .cmp(&b.order)
                .then_with(|| a.created_at.cmp(&b.created_at))
        });
        Ok(blocks)
    }

    pub fn resolve_after_doc_block(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        after_block_id: Option<&BlockId>,
        exclude_block_id: Option<&BlockId>,
    ) -> Result<(Option<OrderKey>, Option<OrderKey>)> {
        let mut blocks = self.list_doc_blocks(project, doc_id)?;
        if let Some(exclude) = exclude_block_id {
            blocks.retain(|b| &b.id != exclude);
        }
        match after_block_id {
            None => Ok((None, blocks.first().map(|b| b.order.clone()))),
            Some(after_id) => {
                let index = blocks
                    .iter()
                    .position(|b| &b.id == after_id)
                    .ok_or_else(|| {
                        LoreError::Validation("selected placement block was not found".into())
                    })?;
                let left = Some(blocks[index].order.clone());
                let right = blocks.get(index + 1).map(|b| b.order.clone());
                Ok((left, right))
            }
        }
    }

    pub fn move_doc_block_after(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
        after_block_id: Option<&BlockId>,
        requesting_key: &str,
    ) -> Result<Block> {
        let existing = self.get_doc_block(project, doc_id, block_id)?;
        let (left, right) =
            self.resolve_after_doc_block(project, doc_id, after_block_id, Some(block_id))?;
        self.update_doc_block(
            doc_id,
            UpdateBlock {
                project: project.clone(),
                block_id: block_id.clone(),
                block_type: existing.block_type,
                content: existing.content,
                author_key: requesting_key.to_string(),
                left,
                right,
                image_upload: None,
            },
        )
    }

    pub fn move_doc_block_after_as_project_writer(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
        after_block_id: Option<&BlockId>,
        username: &str,
    ) -> Result<Block> {
        let existing = self.get_doc_block(project, doc_id, block_id)?;
        let (left, right) =
            self.resolve_after_doc_block(project, doc_id, after_block_id, Some(block_id))?;
        self.update_doc_block_as_project_writer(
            doc_id,
            UpdateBlock {
                project: project.clone(),
                block_id: block_id.clone(),
                block_type: existing.block_type,
                content: existing.content,
                author_key: username.to_string(),
                left,
                right,
                image_upload: None,
            },
        )
    }

    pub fn snapshot_doc_block(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
    ) -> Result<StoredBlockSnapshot> {
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        let metadata_path = doc_dir
            .join("blocks")
            .join(format!("{}.json", block_id.as_str()));
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
        }
        let stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        let content = match &stored.content {
            ContentRef::Inline(content) => content.clone(),
            ContentRef::External { relative_path } => {
                let blob_path = self.project_dir(project).join(relative_path);
                read_utf8(&blob_path)?
            }
        };
        let media: Result<Option<(String, Vec<u8>)>> = match stored.media.as_ref() {
            Some(media) => {
                let blob_path = self.project_dir(project).join(&media.relative_path);
                Ok(Some((media.media_type.clone(), fs::read(blob_path)?)))
            }
            None => Ok(None),
        };
        Ok(snapshot_from_stored_block(stored, content, media?))
    }

    pub fn list_all_blocks_across_docs(
        &self,
        project: &ProjectName,
    ) -> Result<Vec<(DocumentId, Block)>> {
        let docs = self.list_documents(project)?;
        let mut result = Vec::new();
        fn walk(
            store: &FileBlockStore,
            project: &ProjectName,
            docs: &[DocumentInfo],
            result: &mut Vec<(DocumentId, Block)>,
        ) -> Result<()> {
            for doc in docs {
                let blocks = store.list_doc_blocks(project, &doc.id)?;
                for block in blocks {
                    result.push((doc.id.clone(), block));
                }
                walk(store, project, &doc.children, result)?;
            }
            Ok(())
        }
        walk(self, project, &docs, &mut result)?;
        Ok(result)
    }

    pub fn find_block_document(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
    ) -> Result<DocumentId> {
        let docs = self.list_documents(project)?;
        fn search(
            store: &FileBlockStore,
            project: &ProjectName,
            docs: &[DocumentInfo],
            block_id: &BlockId,
        ) -> Result<Option<DocumentId>> {
            for doc in docs {
                let doc_dir = store.find_doc_dir(project, &doc.id)?;
                let block_path = doc_dir
                    .join("blocks")
                    .join(format!("{}.json", block_id.as_str()));
                if block_path.exists() {
                    return Ok(Some(doc.id.clone()));
                }
                if let Some(found) = search(store, project, &doc.children, block_id)? {
                    return Ok(Some(found));
                }
            }
            Ok(None)
        }
        search(self, project, &docs, block_id)?
            .ok_or_else(|| LoreError::BlockNotFound(block_id.as_str().to_string()))
    }

    pub fn find_document_project(&self, doc_id: &DocumentId) -> Result<ProjectName> {
        for project in self.list_projects()? {
            if self.find_doc_dir(&project, doc_id).is_ok() {
                return Ok(project);
            }
        }
        Err(LoreError::Validation(format!(
            "document '{}' not found",
            doc_id
        )))
    }

    pub fn find_block_project_and_document(
        &self,
        block_id: &BlockId,
    ) -> Result<(ProjectName, DocumentId)> {
        for project in self.list_projects()? {
            if let Ok(doc_id) = self.find_block_document(&project, block_id) {
                return Ok((project, doc_id));
            }
        }
        Err(LoreError::BlockNotFound(block_id.as_str().to_string()))
    }

    pub fn read_doc_blocks_around(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
        before: usize,
        after: usize,
    ) -> Result<Vec<Block>> {
        let blocks = self.list_doc_blocks(project, doc_id)?;
        let index = blocks
            .iter()
            .position(|block| &block.id == block_id)
            .ok_or_else(|| LoreError::BlockNotFound(block_id.as_str().to_string()))?;
        let start = index.saturating_sub(before);
        let end = (index + after + 1).min(blocks.len());
        Ok(blocks[start..end].to_vec())
    }

    pub fn first_document_id(&self, project: &ProjectName) -> Result<Option<DocumentId>> {
        let docs = self.list_documents(project)?;
        Ok(docs.into_iter().next().map(|d| d.id))
    }

    pub fn read_doc_block_media(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
        block_id: &BlockId,
    ) -> Result<(String, Vec<u8>)> {
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        let metadata_path = doc_dir
            .join("blocks")
            .join(format!("{}.json", block_id.as_str()));
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
        }
        let stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        let media = stored
            .media
            .ok_or_else(|| LoreError::Validation("block does not have uploaded media".into()))?;
        let media_path = self.project_dir(project).join(media.relative_path);
        let bytes = fs::read(media_path)?;
        Ok((media.media_type, bytes))
    }

    // ---- Reserved blocks ----

    pub fn ensure_reserved_blocks(&self, project: &ProjectName) -> Result<()> {
        self.ensure_layout(project)?;
        for &reserved_id in RESERVED_BLOCK_IDS {
            let block_id = BlockId::reserved(reserved_id);
            let path = self.block_metadata_path(project, &block_id);
            if path.exists() {
                continue;
            }
            let stored = StoredBlock {
                id: block_id,
                project: project.clone(),
                block_type: BlockType::Markdown,
                order: OrderKey::new("80000000".into())?,
                author: KeyFingerprint::from_user_name("system")?,
                content: ContentRef::Inline(String::new()),
                media: None,
                created_at: OffsetDateTime::now_utc(),
                pinned: true,
            };
            fs::write(path, serde_json::to_vec_pretty(&stored)?)?;
        }
        Ok(())
    }

    pub fn get_reserved_block(&self, project: &ProjectName, reserved_id: &str) -> Result<Block> {
        let block_id = BlockId::from_string(reserved_id.to_string())?;
        if !block_id.is_reserved() {
            return Err(LoreError::Validation("not a reserved block id".into()));
        }
        self.get_block(project, &block_id)
    }

    pub fn update_reserved_block(
        &self,
        project: &ProjectName,
        reserved_id: &str,
        content: &str,
        is_agent: bool,
    ) -> Result<Block> {
        let block_id = BlockId::from_string(reserved_id.to_string())?;
        if !block_id.is_reserved() {
            return Err(LoreError::Validation("not a reserved block id".into()));
        }
        if is_agent && reserved_id != "_map" {
            return Err(LoreError::PermissionDenied);
        }
        match reserved_id {
            "_overview" if content.len() > 2000 => {
                return Err(LoreError::Validation(
                    "overview exceeds 2000 character limit".into(),
                ));
            }
            "_map" if content.len() > 4000 => {
                return Err(LoreError::Validation(
                    "file map exceeds 4000 character limit".into(),
                ));
            }
            _ => {}
        }
        let metadata_path = self.block_metadata_path(project, &block_id);
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(reserved_id.to_string()));
        }
        let mut stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        self.remove_external_blob_if_present(project, &stored.content)?;
        stored.content =
            self.persist_text_content(project, &block_id, BlockType::Markdown, content)?;
        fs::write(&metadata_path, serde_json::to_vec_pretty(&stored)?)?;
        self.inflate_block(stored)
    }

    // ---- Migration ----

    pub fn migrate_project_to_documents(&self, project: &ProjectName) -> Result<bool> {
        let meta = self.read_project_meta(project);
        if meta.storage_version >= 1 {
            return Ok(false);
        }

        let project_dir = self.project_dir(project);
        let blocks_dir = project_dir.join("blocks");

        self.ensure_layout(project)?;
        self.ensure_reserved_blocks(project)?;

        // Collect non-reserved block files
        let mut block_files = Vec::new();
        if blocks_dir.exists() {
            for entry in fs::read_dir(&blocks_dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.ends_with(".json") || name.starts_with('_') {
                    continue;
                }
                block_files.push(entry.path());
            }
        }

        if !block_files.is_empty() {
            // Create root document for migrated content
            let doc_id = DocumentId::new();
            let docs_dir = project_dir.join("docs");
            let doc_dir = docs_dir.join(doc_id.as_str());
            let doc_blocks_dir = doc_dir.join("blocks");
            let doc_blobs_dir = doc_dir.join("blobs");
            fs::create_dir_all(&doc_blocks_dir)?;
            fs::create_dir_all(&doc_blobs_dir)?;
            fs::create_dir_all(doc_dir.join("docs"))?;

            let doc_meta = DocumentMeta {
                id: doc_id.as_str().to_string(),
                display_name: meta.display_name.clone(),
                created_at: Some(OffsetDateTime::now_utc()),
            };
            fs::write(
                doc_dir.join("meta.json"),
                serde_json::to_vec_pretty(&doc_meta)?,
            )?;

            for block_path in &block_files {
                let mut stored: StoredBlock = serde_json::from_slice(&fs::read(block_path)?)?;

                if let ContentRef::External { ref relative_path } = stored.content {
                    let old_blob = project_dir.join(relative_path);
                    if old_blob.exists() {
                        let blob_name = old_blob.file_name().unwrap();
                        let new_blob = doc_blobs_dir.join(blob_name);
                        fs::rename(&old_blob, &new_blob)?;
                        stored.content = ContentRef::External {
                            relative_path: new_blob
                                .strip_prefix(&project_dir)
                                .unwrap()
                                .to_string_lossy()
                                .into_owned(),
                        };
                    }
                }

                if let Some(ref media_ref) = stored.media {
                    let old_media = project_dir.join(&media_ref.relative_path);
                    if old_media.exists() {
                        let media_name = old_media.file_name().unwrap();
                        let new_media = doc_blobs_dir.join(media_name);
                        fs::rename(&old_media, &new_media)?;
                        stored.media = Some(MediaRef {
                            relative_path: new_media
                                .strip_prefix(&project_dir)
                                .unwrap()
                                .to_string_lossy()
                                .into_owned(),
                            media_type: media_ref.media_type.clone(),
                        });
                    }
                }

                let dest = doc_blocks_dir.join(block_path.file_name().unwrap());
                fs::write(dest, serde_json::to_vec_pretty(&stored)?)?;
                fs::remove_file(block_path)?;
            }
        }

        // Populate _agent-context from project meta
        if let Some(ctx) = &meta.agent_context {
            if !ctx.trim().is_empty() {
                let _ = self.update_reserved_block(project, "_agent-context", ctx, false);
            }
        }

        // Mark as migrated
        let mut meta = self.read_project_meta(project);
        meta.storage_version = 1;
        self.write_project_meta(project, &meta)?;

        Ok(true)
    }

    pub fn ensure_layout(&self, project: &ProjectName) -> Result<()> {
        fs::create_dir_all(self.project_dir(project).join("blocks"))?;
        fs::create_dir_all(self.project_dir(project).join("blobs"))?;
        fs::create_dir_all(self.project_dir(project).join("docs"))?;
        Ok(())
    }

    fn find_doc_dir(&self, project: &ProjectName, doc_id: &DocumentId) -> Result<PathBuf> {
        let cache_key = (project.as_str().to_string(), doc_id.as_str().to_string());
        if let Some(cached) = self.doc_dir_cache.lock().unwrap().get(&cache_key) {
            if cached.exists() {
                return Ok(cached.clone());
            }
        }
        let docs_root = self.project_dir(project).join("docs");
        let result = self
            .find_doc_dir_recursive(&docs_root, doc_id)
            .ok_or_else(|| LoreError::Validation(format!("document '{}' not found", doc_id)))?;
        self.doc_dir_cache
            .lock()
            .unwrap()
            .insert(cache_key, result.clone());
        Ok(result)
    }

    fn invalidate_doc_cache_for_project(&self, project: &ProjectName) {
        let prefix = project.as_str().to_string();
        self.doc_dir_cache
            .lock()
            .unwrap()
            .retain(|k, _| k.0 != prefix);
    }

    fn find_doc_dir_recursive(
        &self,
        parent_docs_dir: &Path,
        doc_id: &DocumentId,
    ) -> Option<PathBuf> {
        if !parent_docs_dir.exists() {
            return None;
        }
        for entry in fs::read_dir(parent_docs_dir).ok()? {
            let entry = entry.ok()?;
            if !entry.file_type().ok()?.is_dir() {
                continue;
            }
            let dir_name = entry.file_name().to_string_lossy().into_owned();
            if dir_name == doc_id.as_str() {
                return Some(entry.path());
            }
            let child_docs = entry.path().join("docs");
            if let Some(found) = self.find_doc_dir_recursive(&child_docs, doc_id) {
                return Some(found);
            }
        }
        None
    }

    fn list_documents_recursive(&self, docs_dir: &Path) -> Result<Vec<DocumentInfo>> {
        if !docs_dir.exists() {
            return Ok(Vec::new());
        }
        let mut docs = Vec::new();
        for entry in fs::read_dir(docs_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let meta_path = entry.path().join("meta.json");
            if !meta_path.exists() {
                continue;
            }
            let meta: DocumentMeta = serde_json::from_slice(&fs::read(&meta_path)?)?;
            let doc_id = DocumentId::from_string(meta.id)?;
            let children = self.list_documents_recursive(&entry.path().join("docs"))?;
            docs.push(DocumentInfo {
                id: doc_id,
                display_name: meta.display_name,
                children,
            });
        }
        docs.sort_by(|a, b| {
            a.display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase())
        });
        Ok(docs)
    }

    fn create_block_in_doc_dir(
        &self,
        doc_dir: &Path,
        new_block: NewBlock,
        author: KeyFingerprint,
    ) -> Result<Block> {
        new_block.validate()?;
        let order = generate_order_key(new_block.left.as_ref(), new_block.right.as_ref())?;
        let id = BlockId::new();
        let created_at = OffsetDateTime::now_utc();
        let project_dir = self.project_dir(&new_block.project);
        let content_ref = self.persist_text_content_in(
            doc_dir,
            &project_dir,
            &id,
            new_block.block_type,
            &new_block.content,
        )?;
        let media_ref =
            self.persist_uploaded_media_in(doc_dir, &project_dir, &id, new_block.image_upload)?;
        let stored = StoredBlock {
            id: id.clone(),
            project: new_block.project.clone(),
            block_type: new_block.block_type,
            order,
            author,
            content: content_ref,
            media: media_ref,
            created_at,
            pinned: false,
        };
        let metadata_path = doc_dir.join("blocks").join(format!("{}.json", id.as_str()));
        fs::write(metadata_path, serde_json::to_vec_pretty(&stored)?)?;
        self.inflate_block(stored)
    }

    fn update_block_in_doc_dir(
        &self,
        doc_dir: &Path,
        update: UpdateBlock,
        mode: UpdateMode,
    ) -> Result<Block> {
        update.validate()?;
        let metadata_path = doc_dir
            .join("blocks")
            .join(format!("{}.json", update.block_id.as_str()));
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(
                update.block_id.as_str().to_string(),
            ));
        }
        let mut stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        match &mode {
            UpdateMode::AgentOwner(fingerprint) => {
                if stored.pinned {
                    return Err(LoreError::BlockPinned);
                }
                if &stored.author != fingerprint {
                    return Err(LoreError::PermissionDenied);
                }
            }
            UpdateMode::ProjectWriter(_) => {}
        }
        self.remove_external_blob_if_present(&update.project, &stored.content)?;
        self.remove_media_if_present(&update.project, stored.media.as_ref())?;
        let project_dir = self.project_dir(&update.project);
        stored.block_type = update.block_type;
        stored.author = match mode {
            UpdateMode::AgentOwner(fp) | UpdateMode::ProjectWriter(fp) => fp,
        };
        if update.left.is_some() || update.right.is_some() {
            stored.order = generate_order_key(update.left.as_ref(), update.right.as_ref())?;
        }
        stored.content = self.persist_text_content_in(
            doc_dir,
            &project_dir,
            &update.block_id,
            update.block_type,
            &update.content,
        )?;
        stored.media = self.persist_uploaded_media_in(
            doc_dir,
            &project_dir,
            &update.block_id,
            update.image_upload,
        )?;
        fs::write(&metadata_path, serde_json::to_vec_pretty(&stored)?)?;
        self.inflate_block(stored)
    }

    fn delete_block_in_doc_dir(
        &self,
        doc_dir: &Path,
        project: &ProjectName,
        block_id: &BlockId,
        owner_fingerprint: Option<&KeyFingerprint>,
    ) -> Result<()> {
        let metadata_path = doc_dir
            .join("blocks")
            .join(format!("{}.json", block_id.as_str()));
        if !metadata_path.exists() {
            return Err(LoreError::BlockNotFound(block_id.as_str().to_string()));
        }
        let stored: StoredBlock = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        if let Some(fp) = owner_fingerprint {
            if stored.pinned {
                return Err(LoreError::BlockPinned);
            }
            if &stored.author != fp {
                return Err(LoreError::PermissionDenied);
            }
        }
        if let ContentRef::External { relative_path } = &stored.content {
            let blob_path = self.project_dir(project).join(relative_path);
            if blob_path.exists() {
                fs::remove_file(blob_path)?;
            }
        }
        self.remove_media_if_present(project, stored.media.as_ref())?;
        fs::remove_file(metadata_path)?;
        Ok(())
    }

    fn persist_text_content_in(
        &self,
        container_dir: &Path,
        project_dir: &Path,
        block_id: &BlockId,
        block_type: BlockType,
        content: &str,
    ) -> Result<ContentRef> {
        if content.len() <= ContentRef::inline_limit() {
            return Ok(ContentRef::Inline(content.to_string()));
        }
        let blob_name = format!("{}.{}", block_id.as_str(), block_type.default_extension());
        let blob_path = container_dir.join("blobs").join(&blob_name);
        let relative_path = blob_path
            .strip_prefix(project_dir)
            .map_err(|_| LoreError::Validation("internal: blob path not under project dir".into()))?
            .to_string_lossy()
            .into_owned();
        fs::write(&blob_path, content.as_bytes())?;
        Ok(ContentRef::External { relative_path })
    }

    fn persist_uploaded_media_in(
        &self,
        container_dir: &Path,
        project_dir: &Path,
        block_id: &BlockId,
        image_upload: Option<crate::model::ImageUpload>,
    ) -> Result<Option<MediaRef>> {
        let Some(image_upload) = image_upload else {
            return Ok(None);
        };
        let extension = media_extension(&image_upload.media_type);
        let blob_name = format!("{}.{}", block_id.as_str(), extension);
        let blob_path = container_dir.join("blobs").join(&blob_name);
        let relative_path = blob_path
            .strip_prefix(project_dir)
            .map_err(|_| LoreError::Validation("internal: blob path not under project dir".into()))?
            .to_string_lossy()
            .into_owned();
        fs::write(&blob_path, image_upload.bytes)?;
        Ok(Some(MediaRef {
            relative_path,
            media_type: image_upload.media_type,
        }))
    }

    fn project_dir(&self, project: &ProjectName) -> PathBuf {
        self.root.join("projects").join(project.as_str())
    }

    fn block_metadata_path(&self, project: &ProjectName, block_id: &BlockId) -> PathBuf {
        self.project_dir(project)
            .join("blocks")
            .join(format!("{}.json", block_id.as_str()))
    }

    fn inflate_block(&self, stored: StoredBlock) -> Result<Block> {
        let content = match &stored.content {
            ContentRef::Inline(content) => content.clone(),
            ContentRef::External { relative_path } => {
                let blob_path = self.project_dir(&stored.project).join(relative_path);
                read_utf8(&blob_path)?
            }
        };

        Ok(Block {
            id: stored.id,
            project: stored.project,
            block_type: stored.block_type,
            order: stored.order,
            author: stored.author,
            content,
            media_type: stored.media.as_ref().map(|media| media.media_type.clone()),
            created_at: stored.created_at,
            pinned: stored.pinned,
        })
    }

    fn persist_text_content(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        block_type: BlockType,
        content: &str,
    ) -> Result<ContentRef> {
        if content.len() <= ContentRef::inline_limit() {
            return Ok(ContentRef::Inline(content.to_string()));
        }

        let blob_name = format!("{}.{}", block_id.as_str(), block_type.default_extension());
        let relative_path = format!("blobs/{blob_name}");
        let blob_path = self.project_dir(project).join(&relative_path);
        fs::write(blob_path, content.as_bytes())?;
        Ok(ContentRef::External { relative_path })
    }

    fn persist_uploaded_media(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        image_upload: Option<crate::model::ImageUpload>,
    ) -> Result<Option<MediaRef>> {
        let Some(image_upload) = image_upload else {
            return Ok(None);
        };

        let extension = media_extension(&image_upload.media_type);
        let blob_name = format!("{}.{}", block_id.as_str(), extension);
        let relative_path = format!("blobs/{blob_name}");
        let blob_path = self.project_dir(project).join(&relative_path);
        fs::write(blob_path, image_upload.bytes)?;
        Ok(Some(MediaRef {
            relative_path,
            media_type: image_upload.media_type,
        }))
    }

    fn remove_external_blob_if_present(
        &self,
        project: &ProjectName,
        content_ref: &ContentRef,
    ) -> Result<()> {
        if let ContentRef::External { relative_path } = content_ref {
            let blob_path = self.project_dir(project).join(relative_path);
            if blob_path.exists() {
                fs::remove_file(blob_path)?;
            }
        }
        Ok(())
    }

    fn remove_media_if_present(
        &self,
        project: &ProjectName,
        media_ref: Option<&MediaRef>,
    ) -> Result<()> {
        if let Some(media_ref) = media_ref {
            let blob_path = self.project_dir(project).join(&media_ref.relative_path);
            if blob_path.exists() {
                fs::remove_file(blob_path)?;
            }
        }
        Ok(())
    }
}

fn truncate_single_line(content: &str, max_chars: usize) -> String {
    let line = content.lines().next().unwrap_or("");
    if line.len() <= max_chars {
        line.to_string()
    } else {
        format!("{}...", &line[..max_chars])
    }
}

fn read_utf8(path: &Path) -> Result<String> {
    String::from_utf8(fs::read(path)?)
        .map_err(|_| LoreError::Validation("stored blob content is not valid utf-8".into()))
}

fn media_extension(media_type: &str) -> &'static str {
    match media_type {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        _ => "bin",
    }
}

// ---------------------------------------------------------------------------
// Document text format: serialize / parse / types
// ---------------------------------------------------------------------------

/// A single entry parsed from the document text write format.
#[derive(Debug, Clone)]
pub struct DocumentWriteEntry {
    pub id: String,
    pub block_type: BlockType,
    pub content: String,
}

/// Result returned by `write_document_text`.
#[derive(Debug)]
pub struct DocumentWriteResult {
    /// `(placeholder_id, created_block)` for every new block.
    pub created: Vec<(String, Block)>,
    /// Blocks whose content or type was changed.
    pub updated: Vec<Block>,
    /// Block IDs that were removed because they were absent from the input.
    pub deleted: Vec<BlockId>,
}

/// Serialize a slice of blocks into the marker text format.
pub fn serialize_blocks_to_text(blocks: &[Block]) -> String {
    let mut out = String::new();
    for (i, block) in blocks.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let type_label = match block.block_type {
            BlockType::Markdown => "markdown",
            BlockType::Html => "html",
            BlockType::Svg => "svg",
            BlockType::Image => "image",
        };
        out.push_str(&format!("@@block id={} type={}\n", block.id, type_label));
        if block.block_type != BlockType::Image {
            if !block.content.is_empty() {
                out.push_str(&block.content);
                if !block.content.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
        out.push_str("@@end");
        if i + 1 < blocks.len() {
            out.push('\n');
        }
    }
    out
}

fn parse_document_block_type(type_str: &str, line_num: usize) -> crate::error::Result<BlockType> {
    use crate::error::LoreError;

    match type_str {
        "markdown" => Ok(BlockType::Markdown),
        "html" => Ok(BlockType::Html),
        "svg" => Ok(BlockType::Svg),
        "image" => Ok(BlockType::Image),
        other => Err(LoreError::Validation(format!(
            "line {}: unknown block type '{}'",
            line_num, other
        ))),
    }
}

fn parse_document_start_marker(
    line: &str,
    line_num: usize,
) -> crate::error::Result<Option<(String, BlockType)>> {
    use crate::error::LoreError;

    if let Some(rest) = line.strip_prefix("@@block ") {
        let mut id = None;
        let mut block_type = None;
        for field in rest.split_whitespace() {
            if let Some(value) = field.strip_prefix("id=") {
                id = Some(value.to_string());
            } else if let Some(value) = field.strip_prefix("type=") {
                block_type = Some(parse_document_block_type(value, line_num)?);
            } else {
                return Err(LoreError::Validation(format!(
                    "line {}: malformed block start marker",
                    line_num
                )));
            }
        }
        let id = id
            .ok_or_else(|| LoreError::Validation(format!("line {}: missing block id", line_num)))?;
        let block_type = block_type.ok_or_else(|| {
            LoreError::Validation(format!("line {}: missing type in block marker", line_num))
        })?;
        return Ok(Some((id, block_type)));
    }

    if let Some(rest) = line.strip_prefix("<<<< block:") {
        let rest = rest.strip_suffix(" >>>>").ok_or_else(|| {
            LoreError::Validation(format!("line {}: malformed block start marker", line_num))
        })?;
        let mut parts = rest.splitn(2, " type:");
        let id = parts
            .next()
            .ok_or_else(|| LoreError::Validation(format!("line {}: missing block id", line_num)))?
            .to_string();
        let type_str = parts.next().ok_or_else(|| {
            LoreError::Validation(format!("line {}: missing type in block marker", line_num))
        })?;
        return Ok(Some((id, parse_document_block_type(type_str, line_num)?)));
    }

    Ok(None)
}

enum DocumentEndMarker {
    Any,
    Id(String),
}

fn parse_document_end_marker(
    line: &str,
    line_num: usize,
) -> crate::error::Result<Option<DocumentEndMarker>> {
    use crate::error::LoreError;

    if let Some(rest) = line.strip_prefix("@@end") {
        let rest = rest.trim();
        if rest.is_empty() {
            return Ok(Some(DocumentEndMarker::Any));
        }
        if let Some(value) = rest.strip_prefix("id=") {
            if value.is_empty() {
                return Err(LoreError::Validation(format!(
                    "line {}: missing block id in end marker",
                    line_num
                )));
            }
            return Ok(Some(DocumentEndMarker::Id(value.to_string())));
        }
        return Err(LoreError::Validation(format!(
            "line {}: malformed end marker",
            line_num
        )));
    }

    if let Some(rest) = line.strip_prefix("<<<< end:") {
        let end_id = rest.strip_suffix(" >>>>").ok_or_else(|| {
            LoreError::Validation(format!("line {}: malformed end marker", line_num))
        })?;
        return Ok(Some(DocumentEndMarker::Id(end_id.to_string())));
    }

    Ok(None)
}

/// Parse the marker text format into a vec of write entries.
///
/// Returns an error on malformed markers (mismatched start/end, nested blocks,
/// unrecognised block type, content outside markers, etc).
pub fn parse_document_text(text: &str) -> crate::error::Result<Vec<DocumentWriteEntry>> {
    use crate::error::LoreError;

    let mut entries = Vec::new();
    let mut current_id: Option<String> = None;
    let mut current_type: Option<BlockType> = None;
    let mut content_lines: Vec<&str> = Vec::new();

    for (line_num, line) in text.lines().enumerate() {
        if let Some((id, block_type)) = parse_document_start_marker(line, line_num + 1)? {
            if current_id.is_some() {
                return Err(LoreError::Validation(format!(
                    "line {}: nested block marker (previous block not closed)",
                    line_num + 1
                )));
            }
            current_id = Some(id);
            current_type = Some(block_type);
            content_lines.clear();
        } else if let Some(end_marker) = parse_document_end_marker(line, line_num + 1)? {
            match &current_id {
                Some(id)
                    if matches!(&end_marker, DocumentEndMarker::Any)
                        || matches!(&end_marker, DocumentEndMarker::Id(end_id) if id == end_id) =>
                {
                    let content = if content_lines.is_empty() {
                        String::new()
                    } else {
                        let joined = content_lines.join("\n");
                        // Strip single trailing newline that serialization added
                        if joined.ends_with('\n') {
                            joined[..joined.len() - 1].to_string()
                        } else {
                            joined
                        }
                    };
                    entries.push(DocumentWriteEntry {
                        id: id.clone(),
                        block_type: current_type.unwrap(),
                        content,
                    });
                    current_id = None;
                    current_type = None;
                    content_lines.clear();
                }
                Some(id) => {
                    let end_id = match &end_marker {
                        DocumentEndMarker::Any => "@@end".to_string(),
                        DocumentEndMarker::Id(end_id) => end_id.clone(),
                    };
                    return Err(LoreError::Validation(format!(
                        "line {}: end marker id '{}' does not match open block '{}'",
                        line_num + 1,
                        end_id,
                        id
                    )));
                }
                None => {
                    return Err(LoreError::Validation(format!(
                        "line {}: end marker without matching block start",
                        line_num + 1
                    )));
                }
            }
        } else if current_id.is_some() {
            content_lines.push(line);
        } else if !line.trim().is_empty() {
            return Err(LoreError::Validation(format!(
                "line {}: content outside of block markers",
                line_num + 1
            )));
        }
    }

    if current_id.is_some() {
        return Err(LoreError::Validation(
            "unexpected end of input: block not closed".into(),
        ));
    }

    Ok(entries)
}

/// Filter a block slice to a start..=end range (both inclusive, both optional).
fn filter_block_range<'a>(
    blocks: &'a [Block],
    start: Option<&BlockId>,
    end: Option<&BlockId>,
) -> crate::error::Result<&'a [Block]> {
    use crate::error::LoreError;

    let start_idx = match start {
        Some(id) => blocks
            .iter()
            .position(|b| &b.id == id)
            .ok_or_else(|| LoreError::BlockNotFound(id.as_str().to_string()))?,
        None => 0,
    };
    let end_idx = match end {
        Some(id) => blocks
            .iter()
            .position(|b| &b.id == id)
            .ok_or_else(|| LoreError::BlockNotFound(id.as_str().to_string()))?,
        None => {
            if blocks.is_empty() {
                return Ok(&[]);
            }
            blocks.len() - 1
        }
    };
    if start_idx > end_idx {
        return Err(LoreError::Validation(
            "start_block_id must come before end_block_id".into(),
        ));
    }
    Ok(&blocks[start_idx..=end_idx])
}

#[cfg(test)]
mod tests {
    use super::{FileBlockStore, parse_document_text, serialize_blocks_to_text};
    use crate::error::LoreError;
    use crate::model::{BlockType, KeyFingerprint, NewBlock, OrderKey, ProjectName, UpdateBlock};
    use tempfile::tempdir;

    #[test]
    fn stores_and_lists_blocks_in_order() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = ProjectName::new("alpha.docs").unwrap();

        let first = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "first".into(),
                author_key: "key-a".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "second".into(),
                author_key: "key-b".into(),
                left: Some(first.order.clone()),
                right: None,
                image_upload: None,
            })
            .unwrap();

        let blocks = store.list_blocks(&project).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].content, "first");
        assert_eq!(blocks[1].content, "second");
    }

    #[test]
    fn stores_large_payloads_as_blobs() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = ProjectName::new("alpha.docs").unwrap();
        let content = "x".repeat(20_000);

        let block = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Svg,
                content: content.clone(),
                author_key: "key-a".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        assert_eq!(block.content.len(), content.len());
        let blob_dir = dir.path().join("projects/alpha.docs/blobs");
        assert!(blob_dir.exists());
        assert_eq!(store.list_blocks(&project).unwrap()[0].content, content);
    }

    #[test]
    fn only_owner_can_delete_block() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = ProjectName::new("alpha.docs").unwrap();
        let block = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Html,
                content: "<p>owned</p>".into(),
                author_key: "owner-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        let err = store
            .delete_block(&project, &block.id, "intruder-key")
            .unwrap_err();
        assert!(matches!(err, LoreError::PermissionDenied));

        store
            .delete_block(&project, &block.id, "owner-key")
            .unwrap();
        assert!(store.list_blocks(&project).unwrap().is_empty());
    }

    #[test]
    fn only_owner_can_update_block() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = ProjectName::new("alpha.docs").unwrap();
        let block = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "first".into(),
                author_key: "owner-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        let err = store
            .update_block(UpdateBlock {
                project: project.clone(),
                block_id: block.id.clone(),
                block_type: BlockType::Html,
                content: "<p>edited</p>".into(),
                author_key: "intruder-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap_err();
        assert!(matches!(err, LoreError::PermissionDenied));

        let updated = store
            .update_block(UpdateBlock {
                project: project.clone(),
                block_id: block.id.clone(),
                block_type: BlockType::Html,
                content: "<p>edited</p>".into(),
                author_key: "owner-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        assert_eq!(updated.block_type, BlockType::Html);
        assert_eq!(updated.content, "<p>edited</p>");
        assert_eq!(updated.order, block.order);
    }

    #[test]
    fn searches_blocks_by_content() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = ProjectName::new("alpha.docs").unwrap();

        store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "Architecture decision record".into(),
                author_key: "owner-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "Release checklist".into(),
                author_key: "owner-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        let results = store.search_blocks(&project, "decision").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "Architecture decision record");
    }

    #[test]
    fn lists_projects_in_sorted_order() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let alpha = ProjectName::new("alpha.docs").unwrap();
        let beta = ProjectName::new("beta.docs").unwrap();

        store
            .create_block(NewBlock {
                project: beta.clone(),
                block_type: BlockType::Markdown,
                content: "beta".into(),
                author_key: "owner-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        store
            .create_block(NewBlock {
                project: alpha.clone(),
                block_type: BlockType::Markdown,
                content: "alpha".into(),
                author_key: "owner-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        assert_eq!(store.list_projects().unwrap(), vec![alpha, beta]);
    }

    #[test]
    fn reads_blocks_around_anchor() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = ProjectName::new("alpha.docs").unwrap();

        let first = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "first".into(),
                author_key: "owner-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        let second = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "second".into(),
                author_key: "owner-key".into(),
                left: Some(first.order.clone()),
                right: None,
                image_upload: None,
            })
            .unwrap();

        let third = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "third".into(),
                author_key: "owner-key".into(),
                left: Some(second.order.clone()),
                right: None,
                image_upload: None,
            })
            .unwrap();

        let window = store
            .read_blocks_around(&project, &second.id, 1, 1)
            .unwrap();
        assert_eq!(window.len(), 3);
        assert_eq!(window[0].id, first.id);
        assert_eq!(window[1].id, second.id);
        assert_eq!(window[2].id, third.id);
    }

    #[test]
    fn moves_block_after_target() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = ProjectName::new("alpha.docs").unwrap();

        let first = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "first".into(),
                author_key: "owner-key".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        let second = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "second".into(),
                author_key: "owner-key".into(),
                left: Some(first.order.clone()),
                right: None,
                image_upload: None,
            })
            .unwrap();

        let third = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "third".into(),
                author_key: "owner-key".into(),
                left: Some(second.order.clone()),
                right: None,
                image_upload: None,
            })
            .unwrap();

        store
            .move_block_after(&project, &first.id, Some(&third.id), "owner-key")
            .unwrap();

        let blocks = store.list_blocks(&project).unwrap();
        assert_eq!(
            blocks
                .into_iter()
                .map(|block| block.content)
                .collect::<Vec<_>>(),
            vec!["second", "third", "first"]
        );
    }

    #[test]
    fn rejects_project_path_traversal() {
        let err = ProjectName::new("../escape").unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn validates_order_ranges() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = ProjectName::new("alpha.docs").unwrap();
        let left = OrderKey::new("80000000".into()).unwrap();
        let right = OrderKey::new("40000000".into()).unwrap();

        let err = store
            .create_block(NewBlock {
                project,
                block_type: BlockType::Markdown,
                content: "oops".into(),
                author_key: "key-a".into(),
                left: Some(left),
                right: Some(right),
                image_upload: None,
            })
            .unwrap_err();

        assert!(matches!(err, LoreError::InvalidOrderRange));
    }

    #[test]
    fn slugify_free_form_names() {
        use crate::model::slugify;
        assert_eq!(slugify("My Cool Project"), "my-cool-project");
        assert_eq!(slugify("API Docs v2"), "api-docs-v2");
        assert_eq!(slugify("  Hello  World  "), "hello-world");
        assert_eq!(slugify("Engineering"), "engineering");
        assert_eq!(slugify("alpha.docs"), "alpha-docs");
        assert_eq!(slugify("a--b"), "a-b");
        assert_eq!(slugify("---"), "");
    }

    #[test]
    fn from_display_name_roundtrip() {
        let (slug, display) = ProjectName::from_display_name("My Test Project").unwrap();
        assert_eq!(slug.as_str(), "my-test-project");
        assert_eq!(display, "My Test Project");
    }

    #[test]
    fn create_project_writes_metadata() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let info = store.create_project("My Project", None).unwrap();
        assert_eq!(info.slug.as_str(), "my-project");
        assert_eq!(info.display_name, "My Project");
        assert!(info.parent.is_none());

        let meta = store.read_project_meta(&info.slug);
        assert_eq!(meta.display_name, "My Project");

        // list_project_infos should return it with the display name
        let infos = store.list_project_infos().unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].display_name, "My Project");
    }

    #[test]
    fn create_child_project() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let parent = store.create_project("Engineering", None).unwrap();
        let child = store
            .create_project("API Docs", Some(parent.slug.as_str()))
            .unwrap();
        assert_eq!(child.slug.as_str(), "api-docs");
        assert_eq!(child.parent.as_deref(), Some("engineering"));
    }

    #[test]
    fn rename_project_updates_display_name() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let info = store.create_project("Old Name", None).unwrap();
        assert_eq!(info.display_name, "Old Name");
        assert_eq!(info.slug.as_str(), "old-name");

        let result = store.rename_project(&info.slug, "New Name").unwrap();
        // Slug changed: old-name -> new-name
        let (old_slug, new_slug) = result.expect("slug should have changed");
        assert_eq!(old_slug.as_str(), "old-name");
        assert_eq!(new_slug.as_str(), "new-name");
        let meta = store.read_project_meta(&new_slug);
        assert_eq!(meta.display_name, "New Name");
        // Old slug dir should no longer exist
        assert!(!dir.path().join("projects").join(old_slug.as_str()).exists());

        // Rename without slug change (just capitalization tweak keeping same slug)
        let result = store.rename_project(&new_slug, "new name").unwrap();
        assert!(
            result.is_none(),
            "slug should not change for same slugified value"
        );
        let meta = store.read_project_meta(&new_slug);
        assert_eq!(meta.display_name, "new name");

        // empty name should fail
        assert!(store.rename_project(&new_slug, "  ").is_err());
    }

    #[test]
    fn rename_project_updates_child_parent_refs() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let parent = store.create_project("Old Parent", None).unwrap();
        let _child = store
            .create_project("Child", Some(parent.slug.as_str()))
            .unwrap();
        // Rename parent -> slug changes
        let result = store.rename_project(&parent.slug, "New Parent").unwrap();
        let (_, new_slug) = result.expect("slug should change");
        assert_eq!(new_slug.as_str(), "new-parent");
        // Child's parent should now point to new slug
        let child_slug = ProjectName::new("child").unwrap();
        let child_meta = store.read_project_meta(&child_slug);
        assert_eq!(child_meta.parent.as_deref(), Some("new-parent"));
    }

    #[test]
    fn sync_project_slugs_renames_mismatched_dirs() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        // Create a project, then manually change its display name without renaming dir
        let info = store.create_project("Original", None).unwrap();
        assert_eq!(info.slug.as_str(), "original");
        let mut meta = store.read_project_meta(&info.slug);
        meta.display_name = "Renamed Project".to_string();
        store.write_project_meta(&info.slug, &meta).unwrap();
        // Directory is still "original" but display name is "Renamed Project"
        let renames = store.sync_project_slugs();
        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].0.as_str(), "original");
        assert_eq!(renames[0].1.as_str(), "renamed-project");
        // Old dir gone, new dir exists
        assert!(!dir.path().join("projects/original").exists());
        assert!(dir.path().join("projects/renamed-project").exists());
        // Meta is readable at new location
        let new_slug = ProjectName::new("renamed-project").unwrap();
        let meta = store.read_project_meta(&new_slug);
        assert_eq!(meta.display_name, "Renamed Project");
    }

    #[test]
    fn resolve_project_by_display_name() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        store.create_project("My Project", None).unwrap();
        // Resolve by slug
        let p = store.resolve_project("my-project").unwrap();
        assert_eq!(p.as_str(), "my-project");
        // Resolve by display name
        let p = store.resolve_project("My Project").unwrap();
        assert_eq!(p.as_str(), "my-project");
        // Non-existent
        assert!(store.resolve_project("does-not-exist").is_err());
    }

    #[test]
    fn delete_project_removes_dir_and_reparents_children() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let parent = store.create_project("Parent", None).unwrap();
        let child = store
            .create_project("Child", Some(parent.slug.as_str()))
            .unwrap();
        assert_eq!(child.parent.as_deref(), Some("parent"));

        store.delete_project(&parent.slug).unwrap();

        // Parent gone
        let infos = store.list_project_infos().unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].slug.as_str(), "child");
        // Child promoted to root
        assert!(infos[0].parent.is_none());
    }

    #[test]
    fn move_project_changes_parent() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let a = store.create_project("Alpha", None).unwrap();
        let b = store.create_project("Beta", None).unwrap();

        // Move Beta under Alpha
        store
            .move_project(&b.slug, Some(a.slug.as_str()), None)
            .unwrap();

        let infos = store.list_project_infos().unwrap();
        let beta = infos.iter().find(|i| i.slug.as_str() == "beta").unwrap();
        assert_eq!(beta.parent.as_deref(), Some("alpha"));
    }

    #[test]
    fn move_project_prevents_cycle() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let a = store.create_project("Alpha", None).unwrap();
        let b = store.create_project("Beta", Some(a.slug.as_str())).unwrap();

        // Moving Alpha under Beta should fail (cycle)
        let result = store.move_project(&a.slug, Some(b.slug.as_str()), None);
        assert!(result.is_err());
    }

    #[test]
    fn projects_sorted_by_creation_order() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        // Create with specific sort orders by writing meta directly
        let (slug_c, _) = ProjectName::from_display_name("Charlie").unwrap();
        let (slug_a, _) = ProjectName::from_display_name("Alpha").unwrap();
        let (slug_b, _) = ProjectName::from_display_name("Beta").unwrap();
        store.create_project("Charlie", None).unwrap();
        // Manually set sort orders to test ordering
        let mut meta_c = store.read_project_meta(&slug_c);
        meta_c.sort_order = 100;
        store.write_project_meta(&slug_c, &meta_c).unwrap();

        store.create_project("Alpha", None).unwrap();
        let mut meta_a = store.read_project_meta(&slug_a);
        meta_a.sort_order = 200;
        store.write_project_meta(&slug_a, &meta_a).unwrap();

        store.create_project("Beta", None).unwrap();
        let mut meta_b = store.read_project_meta(&slug_b);
        meta_b.sort_order = 300;
        store.write_project_meta(&slug_b, &meta_b).unwrap();

        let infos = store.list_project_infos().unwrap();
        assert_eq!(infos[0].slug.as_str(), "charlie");
        assert_eq!(infos[1].slug.as_str(), "alpha");
        assert_eq!(infos[2].slug.as_str(), "beta");
    }

    #[test]
    fn resolve_lore_link_finds_project_and_block() {
        use super::LoreLinkTarget;
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let info = store.create_project("My Docs", None).unwrap();
        let block = store
            .create_block(NewBlock {
                project: info.slug.clone(),
                block_type: BlockType::Markdown,
                content: "Hello world".into(),
                author_key: "key-a".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        // Resolve project by its UUID
        let result = store.resolve_lore_link(&info.id);
        assert!(matches!(result, Some(LoreLinkTarget::Project(_, _))));

        // Resolve block by its UUID
        let result = store.resolve_lore_link(block.id.as_str());
        assert!(matches!(result, Some(LoreLinkTarget::Block(_, _, _, _))));

        // Unknown UUID returns None
        assert!(
            store
                .resolve_lore_link("00000000-0000-0000-0000-000000000000")
                .is_none()
        );
    }

    #[test]
    fn project_meta_gets_uuid_on_read() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let info = store.create_project("Test", None).unwrap();
        assert!(!info.id.is_empty());

        // Reading meta should return same UUID
        let meta = store.read_project_meta(&info.slug);
        assert!(meta.id.is_some());
        assert_eq!(meta.id.unwrap(), info.id);
    }

    #[test]
    fn creates_and_lists_documents() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        store.create_document(&project.slug, None, "Doc A").unwrap();
        store.create_document(&project.slug, None, "Doc B").unwrap();

        let docs = store.list_documents(&project.slug).unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].display_name, "Doc A");
        assert_eq!(docs[1].display_name, "Doc B");
    }

    #[test]
    fn creates_nested_documents() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        let parent = store
            .create_document(&project.slug, None, "Parent")
            .unwrap();
        let child = store
            .create_document(&project.slug, Some(&parent.id), "Child")
            .unwrap();

        let docs = store.list_documents(&project.slug).unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].display_name, "Parent");
        assert_eq!(docs[0].children.len(), 1);
        assert_eq!(docs[0].children[0].display_name, "Child");
        assert_eq!(docs[0].children[0].id, child.id);
    }

    #[test]
    fn renames_document() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store
            .create_document(&project.slug, None, "Old Name")
            .unwrap();

        store
            .rename_document(&project.slug, &doc.id, "New Name")
            .unwrap();

        let docs = store.list_documents(&project.slug).unwrap();
        assert_eq!(docs[0].display_name, "New Name");
    }

    #[test]
    fn deletes_document_recursively() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        let parent = store
            .create_document(&project.slug, None, "Parent")
            .unwrap();
        store
            .create_document(&project.slug, Some(&parent.id), "Child")
            .unwrap();

        store
            .create_doc_block(
                &parent.id,
                NewBlock {
                    project: project.slug.clone(),
                    block_type: BlockType::Markdown,
                    content: "content".into(),
                    author_key: "key-a".into(),
                    left: None,
                    right: None,
                    image_upload: None,
                },
            )
            .unwrap();

        store.delete_document(&project.slug, &parent.id).unwrap();
        assert!(store.list_documents(&project.slug).unwrap().is_empty());
    }

    #[test]
    fn doc_block_crud() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store
            .create_document(&project.slug, None, "My Doc")
            .unwrap();

        let block = store
            .create_doc_block(
                &doc.id,
                NewBlock {
                    project: project.slug.clone(),
                    block_type: BlockType::Markdown,
                    content: "hello".into(),
                    author_key: "key-a".into(),
                    left: None,
                    right: None,
                    image_upload: None,
                },
            )
            .unwrap();
        assert_eq!(block.content, "hello");

        let blocks = store.list_doc_blocks(&project.slug, &doc.id).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].content, "hello");

        let fetched = store
            .get_doc_block(&project.slug, &doc.id, &block.id)
            .unwrap();
        assert_eq!(fetched.content, "hello");

        let updated = store
            .update_doc_block(
                &doc.id,
                UpdateBlock {
                    project: project.slug.clone(),
                    block_id: block.id.clone(),
                    block_type: BlockType::Markdown,
                    content: "updated".into(),
                    author_key: "key-a".into(),
                    left: None,
                    right: None,
                    image_upload: None,
                },
            )
            .unwrap();
        assert_eq!(updated.content, "updated");

        store
            .delete_doc_block(&project.slug, &doc.id, &block.id, "key-a")
            .unwrap();
        assert!(
            store
                .list_doc_blocks(&project.slug, &doc.id)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn reserved_blocks_created_with_project() {
        use crate::model::{RESERVED_AGENT_CONTEXT, RESERVED_MAP, RESERVED_OVERVIEW};
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        for id in [RESERVED_AGENT_CONTEXT, RESERVED_OVERVIEW, RESERVED_MAP] {
            let block = store.get_reserved_block(&project.slug, id).unwrap();
            assert_eq!(block.content, "");
            assert!(block.id.is_reserved());
        }
    }

    #[test]
    fn reserved_block_size_limits() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        let big = "x".repeat(2001);
        let err = store
            .update_reserved_block(&project.slug, "_overview", &big, false)
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));

        let big = "x".repeat(4001);
        let err = store
            .update_reserved_block(&project.slug, "_map", &big, false)
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));

        store
            .update_reserved_block(&project.slug, "_map", "files here", true)
            .unwrap();
        let err = store
            .update_reserved_block(&project.slug, "_overview", "nope", true)
            .unwrap_err();
        assert!(matches!(err, LoreError::PermissionDenied));
    }

    #[test]
    fn migrates_project_blocks_to_document() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = ProjectName::new("legacy").unwrap();

        let b1 = store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "first block".into(),
                author_key: "key-a".into(),
                left: None,
                right: None,
                image_upload: None,
            })
            .unwrap();

        store
            .create_block(NewBlock {
                project: project.clone(),
                block_type: BlockType::Markdown,
                content: "second block".into(),
                author_key: "key-a".into(),
                left: Some(b1.order.clone()),
                right: None,
                image_upload: None,
            })
            .unwrap();

        store.write_agent_context(&project, "be helpful").unwrap();

        let migrated = store.migrate_project_to_documents(&project).unwrap();
        assert!(migrated);

        let project_blocks = store.list_blocks(&project).unwrap();
        assert!(project_blocks.iter().all(|b| b.id.is_reserved()));
        assert_eq!(project_blocks.len(), 3);

        let docs = store.list_documents(&project).unwrap();
        assert_eq!(docs.len(), 1);

        let doc_blocks = store.list_doc_blocks(&project, &docs[0].id).unwrap();
        assert_eq!(doc_blocks.len(), 2);
        assert_eq!(doc_blocks[0].content, "first block");
        assert_eq!(doc_blocks[1].content, "second block");

        let ctx = store
            .get_reserved_block(&project, "_agent-context")
            .unwrap();
        assert_eq!(ctx.content, "be helpful");

        let migrated_again = store.migrate_project_to_documents(&project).unwrap();
        assert!(!migrated_again);
    }

    #[test]
    fn doc_blocks_with_large_content() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store
            .create_document(&project.slug, None, "Big Doc")
            .unwrap();

        let big_content = "x".repeat(20_000);
        let block = store
            .create_doc_block(
                &doc.id,
                NewBlock {
                    project: project.slug.clone(),
                    block_type: BlockType::Markdown,
                    content: big_content.clone(),
                    author_key: "key-a".into(),
                    left: None,
                    right: None,
                    image_upload: None,
                },
            )
            .unwrap();

        assert_eq!(block.content.len(), 20_000);

        let fetched = store
            .get_doc_block(&project.slug, &doc.id, &block.id)
            .unwrap();
        assert_eq!(fetched.content, big_content);
    }

    // -----------------------------------------------------------------------
    // Helpers for document text tests
    // -----------------------------------------------------------------------

    /// Create a project + doc + N markdown blocks, return (project_slug, doc_id, block_ids)
    fn setup_doc_with_blocks(
        store: &FileBlockStore,
        contents: &[&str],
    ) -> (ProjectName, super::DocumentId, Vec<crate::model::BlockId>) {
        let project = store.create_project("Test", None).unwrap();
        let doc = store
            .create_document(&project.slug, None, "My Doc")
            .unwrap();
        let mut ids = Vec::new();
        let mut prev_order: Option<OrderKey> = None;
        for &text in contents {
            let block = store
                .create_doc_block_as_project_writer(
                    &doc.id,
                    NewBlock {
                        project: project.slug.clone(),
                        block_type: BlockType::Markdown,
                        content: text.into(),
                        author_key: "testuser".into(),
                        left: prev_order.clone(),
                        right: None,
                        image_upload: None,
                    },
                )
                .unwrap();
            prev_order = Some(block.order.clone());
            ids.push(block.id);
        }
        (project.slug, doc.id, ids)
    }

    fn author() -> KeyFingerprint {
        KeyFingerprint::from_user_name("testuser").unwrap()
    }

    // -----------------------------------------------------------------------
    // serialize_blocks_to_text / parse_document_text round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_parse_roundtrip_single_block() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, _ids) = setup_doc_with_blocks(&store, &["Hello world"]);

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        let text = serialize_blocks_to_text(&blocks);
        assert!(text.contains("@@block id="));
        assert!(text.contains("@@end"));
        let parsed = parse_document_text(&text).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, blocks[0].id.as_str());
        assert_eq!(parsed[0].block_type, BlockType::Markdown);
        assert_eq!(parsed[0].content, "Hello world");
    }

    #[test]
    fn serialize_parse_roundtrip_multiple_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, _ids) = setup_doc_with_blocks(&store, &["First", "Second", "Third"]);

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        let text = serialize_blocks_to_text(&blocks);
        let parsed = parse_document_text(&text).unwrap();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].content, "First");
        assert_eq!(parsed[1].content, "Second");
        assert_eq!(parsed[2].content, "Third");
    }

    #[test]
    fn serialize_parse_roundtrip_multiline_content() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let content = "Line one\nLine two\nLine three";
        let (project, doc_id, _ids) = setup_doc_with_blocks(&store, &[content]);

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        let text = serialize_blocks_to_text(&blocks);
        let parsed = parse_document_text(&text).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].content, content);
    }

    #[test]
    fn serialize_parse_roundtrip_empty_content() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, _ids) = setup_doc_with_blocks(&store, &[""]);

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        let text = serialize_blocks_to_text(&blocks);
        let parsed = parse_document_text(&text).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].content, "");
    }

    #[test]
    fn serialize_parse_roundtrip_svg_block() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store
            .create_document(&project.slug, None, "SVG Doc")
            .unwrap();
        let svg = "<svg><circle r=\"10\"/></svg>";
        store
            .create_doc_block_as_project_writer(
                &doc.id,
                NewBlock {
                    project: project.slug.clone(),
                    block_type: BlockType::Svg,
                    content: svg.into(),
                    author_key: "testuser".into(),
                    left: None,
                    right: None,
                    image_upload: None,
                },
            )
            .unwrap();

        let blocks = store.list_doc_blocks(&project.slug, &doc.id).unwrap();
        let text = serialize_blocks_to_text(&blocks);
        assert!(text.contains("type=svg"));
        let parsed = parse_document_text(&text).unwrap();
        assert_eq!(parsed[0].block_type, BlockType::Svg);
        assert_eq!(parsed[0].content, svg);
    }

    // -----------------------------------------------------------------------
    // parse_document_text error cases
    // -----------------------------------------------------------------------

    #[test]
    fn parse_rejects_nested_block_markers() {
        let text = "<<<< block:abc type:markdown >>>>\n<<<< block:def type:markdown >>>>\ncontent\n<<<< end:def >>>>\n<<<< end:abc >>>>";
        let err = parse_document_text(text).unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn parse_accepts_new_marker_format() {
        let text =
            "@@block id=abc type=markdown\nhello\n@@end\n\n@@block id=def type=svg\n<svg/>\n@@end";
        let parsed = parse_document_text(text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "abc");
        assert_eq!(parsed[0].content, "hello");
        assert_eq!(parsed[1].block_type, BlockType::Svg);
    }

    #[test]
    fn parse_accepts_legacy_marker_format() {
        let text = "<<<< block:abc type:markdown >>>>\nhello\n<<<< end:abc >>>>";
        let parsed = parse_document_text(text).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "abc");
        assert_eq!(parsed[0].content, "hello");
    }

    #[test]
    fn parse_rejects_mismatched_end_id() {
        let text = "<<<< block:abc type:markdown >>>>\ncontent\n<<<< end:xyz >>>>";
        let err = parse_document_text(text).unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn parse_rejects_unclosed_block() {
        let text = "<<<< block:abc type:markdown >>>>\ncontent";
        let err = parse_document_text(text).unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn parse_rejects_content_outside_markers() {
        let text = "stray content\n<<<< block:abc type:markdown >>>>\ncontent\n<<<< end:abc >>>>";
        let err = parse_document_text(text).unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn parse_rejects_unknown_block_type() {
        let text = "<<<< block:abc type:javascript >>>>\ncontent\n<<<< end:abc >>>>";
        let err = parse_document_text(text).unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn parse_rejects_end_without_start() {
        let text = "<<<< end:abc >>>>";
        let err = parse_document_text(text).unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn parse_allows_blank_lines_between_blocks() {
        let text = "<<<< block:a type:markdown >>>>\nfirst\n<<<< end:a >>>>\n\n<<<< block:b type:markdown >>>>\nsecond\n<<<< end:b >>>>";
        let parsed = parse_document_text(text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].content, "first");
        assert_eq!(parsed[1].content, "second");
    }

    // -----------------------------------------------------------------------
    // read_document_text
    // -----------------------------------------------------------------------

    #[test]
    fn read_document_text_full() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Alpha", "Beta", "Gamma"]);

        let text = store
            .read_document_text(&project, &doc_id, None, None)
            .unwrap();
        assert!(text.contains("@@block id="));
        assert!(text.contains("@@end"));
        let parsed = parse_document_text(&text).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].id, ids[0].as_str());
        assert_eq!(parsed[1].id, ids[1].as_str());
        assert_eq!(parsed[2].id, ids[2].as_str());
        assert_eq!(parsed[0].content, "Alpha");
        assert_eq!(parsed[1].content, "Beta");
        assert_eq!(parsed[2].content, "Gamma");
    }

    #[test]
    fn read_document_text_partial_range() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["A", "B", "C", "D", "E"]);

        // Read blocks B..D (indices 1..3 inclusive)
        let text = store
            .read_document_text(&project, &doc_id, Some(&ids[1]), Some(&ids[3]))
            .unwrap();
        let parsed = parse_document_text(&text).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].content, "B");
        assert_eq!(parsed[1].content, "C");
        assert_eq!(parsed[2].content, "D");
    }

    #[test]
    fn read_document_text_start_only() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["A", "B", "C"]);

        // From B to end
        let text = store
            .read_document_text(&project, &doc_id, Some(&ids[1]), None)
            .unwrap();
        let parsed = parse_document_text(&text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].content, "B");
        assert_eq!(parsed[1].content, "C");
    }

    #[test]
    fn read_document_text_end_only() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["A", "B", "C"]);

        // From start to B
        let text = store
            .read_document_text(&project, &doc_id, None, Some(&ids[1]))
            .unwrap();
        let parsed = parse_document_text(&text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].content, "A");
        assert_eq!(parsed[1].content, "B");
    }

    #[test]
    fn read_document_text_single_block_range() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["A", "B", "C"]);

        // Just block B
        let text = store
            .read_document_text(&project, &doc_id, Some(&ids[1]), Some(&ids[1]))
            .unwrap();
        let parsed = parse_document_text(&text).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].content, "B");
    }

    #[test]
    fn read_document_text_reversed_range_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["A", "B", "C"]);

        // Start after end
        let err = store
            .read_document_text(&project, &doc_id, Some(&ids[2]), Some(&ids[0]))
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn read_document_text_nonexistent_block_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, _ids) = setup_doc_with_blocks(&store, &["A"]);

        let fake_id = crate::model::BlockId::new();
        let err = store
            .read_document_text(&project, &doc_id, Some(&fake_id), None)
            .unwrap_err();
        assert!(matches!(err, LoreError::BlockNotFound(_)));
    }

    #[test]
    fn read_document_text_empty_doc() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store.create_document(&project.slug, None, "Empty").unwrap();

        let text = store
            .read_document_text(&project.slug, &doc.id, None, None)
            .unwrap();
        assert_eq!(text, "");
    }

    // -----------------------------------------------------------------------
    // write_document_text
    // -----------------------------------------------------------------------

    #[test]
    fn write_document_text_updates_content() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Original A", "Original B"]);

        // Read, modify, write back
        let mut text = store
            .read_document_text(&project, &doc_id, None, None)
            .unwrap();
        text = text.replace("Original A", "Modified A");
        text = text.replace("Original B", "Modified B");

        let entries = parse_document_text(&text).unwrap();
        let result = store
            .write_document_text(&project, &doc_id, entries, author())
            .unwrap();

        assert_eq!(result.updated.len(), 2);
        assert!(result.created.is_empty());
        assert!(result.deleted.is_empty());

        // Verify
        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].content, "Modified A");
        assert_eq!(blocks[1].content, "Modified B");
        assert_eq!(blocks[0].id, ids[0]);
        assert_eq!(blocks[1].id, ids[1]);
    }

    #[test]
    fn write_document_text_deletes_missing_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) =
            setup_doc_with_blocks(&store, &["Keep", "Delete me", "Also keep"]);

        // Read and remove the middle block from the text
        let text = store
            .read_document_text(&project, &doc_id, None, None)
            .unwrap();
        let entries = parse_document_text(&text).unwrap();
        let filtered: Vec<_> = entries
            .into_iter()
            .filter(|e| e.id != ids[1].as_str())
            .collect();

        let result = store
            .write_document_text(&project, &doc_id, filtered, author())
            .unwrap();

        assert_eq!(result.deleted.len(), 1);
        assert_eq!(result.deleted[0], ids[1]);

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].content, "Keep");
        assert_eq!(blocks[1].content, "Also keep");
    }

    #[test]
    fn write_document_text_creates_new_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Existing"]);

        // Build text with existing block + a new placeholder block
        let text = format!(
            "<<<< block:{} type:markdown >>>>\nExisting\n<<<< end:{} >>>>\n\n<<<< block:new_block_1 type:markdown >>>>\nBrand new content\n<<<< end:new_block_1 >>>>",
            ids[0], ids[0]
        );
        let entries = parse_document_text(&text).unwrap();
        let result = store
            .write_document_text(&project, &doc_id, entries, author())
            .unwrap();

        assert_eq!(result.created.len(), 1);
        assert_eq!(result.created[0].0, "new_block_1");
        assert_eq!(result.created[0].1.content, "Brand new content");
        assert!(result.updated.is_empty());

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].content, "Existing");
        assert_eq!(blocks[1].content, "Brand new content");
    }

    #[test]
    fn write_document_text_reorders_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["First", "Second", "Third"]);

        // Reverse the order
        let text = format!(
            "<<<< block:{id2} type:markdown >>>>\nThird\n<<<< end:{id2} >>>>\n\n<<<< block:{id1} type:markdown >>>>\nSecond\n<<<< end:{id1} >>>>\n\n<<<< block:{id0} type:markdown >>>>\nFirst\n<<<< end:{id0} >>>>",
            id0 = ids[0],
            id1 = ids[1],
            id2 = ids[2]
        );
        let entries = parse_document_text(&text).unwrap();
        store
            .write_document_text(&project, &doc_id, entries, author())
            .unwrap();

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks[0].content, "Third");
        assert_eq!(blocks[1].content, "Second");
        assert_eq!(blocks[2].content, "First");
    }

    #[test]
    fn write_document_text_rejects_unknown_uuid() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, _ids) = setup_doc_with_blocks(&store, &["A"]);

        let fake_uuid = uuid::Uuid::new_v4().to_string();
        let text = format!(
            "<<<< block:{fake_uuid} type:markdown >>>>\ncontent\n<<<< end:{fake_uuid} >>>>"
        );
        let entries = parse_document_text(&text).unwrap();
        let err = store
            .write_document_text(&project, &doc_id, entries, author())
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn write_document_text_image_block_not_modified() {
        use crate::model::{BlockId, ContentRef, StoredBlock};
        use time::OffsetDateTime;

        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store.create_document(&project.slug, None, "Doc").unwrap();

        // Create image block directly on disk (bypasses validate which rejects
        // empty content for non-markdown blocks — in production, images always
        // come with an upload)
        let img_id = BlockId::new();
        let doc_dir = store.find_doc_dir(&project.slug, &doc.id).unwrap();
        let img_order = OrderKey::new("40000000".into()).unwrap();
        let img_stored = StoredBlock {
            id: img_id.clone(),
            project: project.slug.clone(),
            block_type: BlockType::Image,
            order: img_order.clone(),
            author: author(),
            content: ContentRef::Inline(String::new()),
            media: None,
            created_at: OffsetDateTime::now_utc(),
            pinned: false,
        };
        std::fs::write(
            doc_dir
                .join("blocks")
                .join(format!("{}.json", img_id.as_str())),
            serde_json::to_vec_pretty(&img_stored).unwrap(),
        )
        .unwrap();

        // Create a markdown block after
        let md_block = store
            .create_doc_block_as_project_writer(
                &doc.id,
                NewBlock {
                    project: project.slug.clone(),
                    block_type: BlockType::Markdown,
                    content: "text".into(),
                    author_key: "testuser".into(),
                    left: Some(img_order),
                    right: None,
                    image_upload: None,
                },
            )
            .unwrap();

        // Write back with image block present and markdown updated
        let text = format!(
            "<<<< block:{img} type:image >>>>\n<<<< end:{img} >>>>\n\n<<<< block:{md} type:markdown >>>>\nupdated text\n<<<< end:{md} >>>>",
            img = img_id,
            md = md_block.id
        );
        let entries = parse_document_text(&text).unwrap();
        let result = store
            .write_document_text(&project.slug, &doc.id, entries, author())
            .unwrap();

        // Image should not appear in updated list
        assert!(!result.updated.iter().any(|b| b.id == img_id));
        assert_eq!(result.updated.len(), 1);
        assert_eq!(result.updated[0].content, "updated text");

        let blocks = store.list_doc_blocks(&project.slug, &doc.id).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].block_type, BlockType::Image);
        assert_eq!(blocks[1].content, "updated text");
    }

    #[test]
    fn write_document_text_combined_create_update_delete_reorder() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["A", "B", "C", "D"]);

        // Keep C (unchanged), update A, delete B and D, add new block
        // Order: new_block, C, A-updated
        let text = format!(
            "<<<< block:new1 type:markdown >>>>\nFresh\n<<<< end:new1 >>>>\n\n<<<< block:{c} type:markdown >>>>\nC\n<<<< end:{c} >>>>\n\n<<<< block:{a} type:markdown >>>>\nA-updated\n<<<< end:{a} >>>>",
            a = ids[0],
            c = ids[2]
        );
        let entries = parse_document_text(&text).unwrap();
        let result = store
            .write_document_text(&project, &doc_id, entries, author())
            .unwrap();

        assert_eq!(result.created.len(), 1);
        assert_eq!(result.created[0].0, "new1");
        assert_eq!(result.updated.len(), 1); // A content changed
        assert_eq!(result.deleted.len(), 2); // B and D

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].content, "Fresh");
        assert_eq!(blocks[1].content, "C");
        assert_eq!(blocks[2].content, "A-updated");
    }

    #[test]
    fn write_document_text_no_changes() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, _ids) = setup_doc_with_blocks(&store, &["Unchanged"]);

        let text = store
            .read_document_text(&project, &doc_id, None, None)
            .unwrap();
        let entries = parse_document_text(&text).unwrap();
        let result = store
            .write_document_text(&project, &doc_id, entries, author())
            .unwrap();

        assert!(result.created.is_empty());
        assert!(result.updated.is_empty());
        assert!(result.deleted.is_empty());
    }

    #[test]
    fn write_document_text_delete_all_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["A", "B"]);

        // Empty entries = delete everything
        let result = store
            .write_document_text(&project, &doc_id, Vec::new(), author())
            .unwrap();

        assert_eq!(result.deleted.len(), 2);
        assert!(result.deleted.contains(&ids[0]));
        assert!(result.deleted.contains(&ids[1]));

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn write_document_text_multiple_new_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store.create_document(&project.slug, None, "Doc").unwrap();

        let text = "<<<< block:a type:markdown >>>>\nFirst\n<<<< end:a >>>>\n\n<<<< block:b type:markdown >>>>\nSecond\n<<<< end:b >>>>\n\n<<<< block:c type:svg >>>>\n<svg/>\n<<<< end:c >>>>";
        let entries = parse_document_text(text).unwrap();
        let result = store
            .write_document_text(&project.slug, &doc.id, entries, author())
            .unwrap();

        assert_eq!(result.created.len(), 3);
        let blocks = store.list_doc_blocks(&project.slug, &doc.id).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].content, "First");
        assert_eq!(blocks[0].block_type, BlockType::Markdown);
        assert_eq!(blocks[1].content, "Second");
        assert_eq!(blocks[2].content, "<svg/>");
        assert_eq!(blocks[2].block_type, BlockType::Svg);
    }

    // -----------------------------------------------------------------------
    // split_doc_block
    // -----------------------------------------------------------------------

    #[test]
    fn split_doc_block_at_midpoint() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["HelloWorld"]);

        let (left, right) = store
            .split_doc_block(&project, &doc_id, &ids[0], 5, author())
            .unwrap();

        assert_eq!(left.content, "Hello");
        assert_eq!(right.content, "World");
        assert_eq!(left.id, ids[0]); // original keeps its ID

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].content, "Hello");
        assert_eq!(blocks[1].content, "World");
    }

    #[test]
    fn split_doc_block_at_position_1() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["ABCDE"]);

        let (left, right) = store
            .split_doc_block(&project, &doc_id, &ids[0], 1, author())
            .unwrap();

        assert_eq!(left.content, "A");
        assert_eq!(right.content, "BCDE");
    }

    #[test]
    fn split_doc_block_at_last_position() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["ABCDE"]);

        let (left, right) = store
            .split_doc_block(&project, &doc_id, &ids[0], 4, author())
            .unwrap();

        assert_eq!(left.content, "ABCD");
        assert_eq!(right.content, "E");
    }

    #[test]
    fn split_doc_block_preserves_surrounding_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Before", "SplitMe", "After"]);

        store
            .split_doc_block(&project, &doc_id, &ids[1], 5, author())
            .unwrap();

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 4);
        assert_eq!(blocks[0].content, "Before");
        assert_eq!(blocks[1].content, "Split");
        assert_eq!(blocks[2].content, "Me");
        assert_eq!(blocks[3].content, "After");
    }

    #[test]
    fn split_doc_block_position_0_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Hello"]);

        let err = store
            .split_doc_block(&project, &doc_id, &ids[0], 0, author())
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn split_doc_block_position_at_length_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Hello"]);

        let err = store
            .split_doc_block(&project, &doc_id, &ids[0], 5, author())
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn split_doc_block_position_past_length_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Hello"]);

        let err = store
            .split_doc_block(&project, &doc_id, &ids[0], 100, author())
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn split_doc_block_non_markdown_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store.create_document(&project.slug, None, "Doc").unwrap();
        let svg_block = store
            .create_doc_block_as_project_writer(
                &doc.id,
                NewBlock {
                    project: project.slug.clone(),
                    block_type: BlockType::Svg,
                    content: "<svg/>".into(),
                    author_key: "testuser".into(),
                    left: None,
                    right: None,
                    image_upload: None,
                },
            )
            .unwrap();

        let err = store
            .split_doc_block(&project.slug, &doc.id, &svg_block.id, 3, author())
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn split_doc_block_multiline_at_newline() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let content = "Line one\nLine two\nLine three";
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &[content]);

        // Split right at the first newline boundary (after "Line one\n")
        let (left, right) = store
            .split_doc_block(&project, &doc_id, &ids[0], 9, author())
            .unwrap();

        assert_eq!(left.content, "Line one\n");
        assert_eq!(right.content, "Line two\nLine three");
    }

    // -----------------------------------------------------------------------
    // combine_doc_blocks
    // -----------------------------------------------------------------------

    #[test]
    fn combine_two_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Hello", "World"]);

        let merged = store
            .combine_doc_blocks(
                &project,
                &doc_id,
                &[ids[0].clone(), ids[1].clone()],
                author(),
            )
            .unwrap();

        assert_eq!(merged.content, "Hello\nWorld");
        assert_eq!(merged.id, ids[0]); // first block survives

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].content, "Hello\nWorld");
    }

    #[test]
    fn combine_three_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["A", "B", "C"]);

        let merged = store
            .combine_doc_blocks(
                &project,
                &doc_id,
                &[ids[0].clone(), ids[1].clone(), ids[2].clone()],
                author(),
            )
            .unwrap();

        assert_eq!(merged.content, "A\nB\nC");
        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn combine_preserves_surrounding_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) =
            setup_doc_with_blocks(&store, &["Before", "Merge A", "Merge B", "After"]);

        store
            .combine_doc_blocks(
                &project,
                &doc_id,
                &[ids[1].clone(), ids[2].clone()],
                author(),
            )
            .unwrap();

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].content, "Before");
        assert_eq!(blocks[1].content, "Merge A\nMerge B");
        assert_eq!(blocks[2].content, "After");
    }

    #[test]
    fn combine_single_block_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Alone"]);

        let err = store
            .combine_doc_blocks(&project, &doc_id, &[ids[0].clone()], author())
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn combine_non_consecutive_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["A", "B", "C"]);

        // Skip the middle block
        let err = store
            .combine_doc_blocks(
                &project,
                &doc_id,
                &[ids[0].clone(), ids[2].clone()],
                author(),
            )
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn combine_non_markdown_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store.create_document(&project.slug, None, "Doc").unwrap();
        let md_block = store
            .create_doc_block_as_project_writer(
                &doc.id,
                NewBlock {
                    project: project.slug.clone(),
                    block_type: BlockType::Markdown,
                    content: "text".into(),
                    author_key: "testuser".into(),
                    left: None,
                    right: None,
                    image_upload: None,
                },
            )
            .unwrap();
        let svg_block = store
            .create_doc_block_as_project_writer(
                &doc.id,
                NewBlock {
                    project: project.slug.clone(),
                    block_type: BlockType::Svg,
                    content: "<svg/>".into(),
                    author_key: "testuser".into(),
                    left: Some(md_block.order.clone()),
                    right: None,
                    image_upload: None,
                },
            )
            .unwrap();

        let err = store
            .combine_doc_blocks(
                &project.slug,
                &doc.id,
                &[md_block.id, svg_block.id],
                author(),
            )
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    // -----------------------------------------------------------------------
    // split + combine round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn split_then_combine_restores_original() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["HelloWorld"]);

        let (left, right) = store
            .split_doc_block(&project, &doc_id, &ids[0], 5, author())
            .unwrap();

        let merged = store
            .combine_doc_blocks(
                &project,
                &doc_id,
                &[left.id.clone(), right.id.clone()],
                author(),
            )
            .unwrap();

        // Content is joined with \n, not perfectly restored, but blocks are back to one
        assert_eq!(merged.content, "Hello\nWorld");
        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 1);
    }

    // -----------------------------------------------------------------------
    // read_document_text + write_document_text full round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn read_write_roundtrip_preserves_content() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(
            &store,
            &[
                "# Heading\n\nParagraph one.",
                "## Subheading\n\nParagraph two with `code`.",
                "Final block with **bold** text.",
            ],
        );

        let text = store
            .read_document_text(&project, &doc_id, None, None)
            .unwrap();
        let entries = parse_document_text(&text).unwrap();
        let result = store
            .write_document_text(&project, &doc_id, entries, author())
            .unwrap();

        // No changes expected
        assert!(result.created.is_empty());
        assert!(result.updated.is_empty());
        assert!(result.deleted.is_empty());

        // Content intact
        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].content, "# Heading\n\nParagraph one.");
        assert_eq!(blocks[0].id, ids[0]);
    }

    #[test]
    fn write_then_read_reflects_changes() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["Original"]);

        // Build new text with updated content and a new block
        let text = format!(
            "<<<< block:{id} type:markdown >>>>\nEdited\n<<<< end:{id} >>>>\n\n<<<< block:new1 type:markdown >>>>\nAppended\n<<<< end:new1 >>>>",
            id = ids[0]
        );
        let entries = parse_document_text(&text).unwrap();
        store
            .write_document_text(&project, &doc_id, entries, author())
            .unwrap();

        // Read back and verify
        let text2 = store
            .read_document_text(&project, &doc_id, None, None)
            .unwrap();
        let parsed = parse_document_text(&text2).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].content, "Edited");
        assert_eq!(parsed[0].id, ids[0].as_str());
        assert_eq!(parsed[1].content, "Appended");
        // New block should have a real UUID, not "new1"
        assert!(uuid::Uuid::parse_str(&parsed[1].id).is_ok());
    }

    // -----------------------------------------------------------------------
    // Reserved blocks (project-level data)
    // -----------------------------------------------------------------------

    #[test]
    fn read_write_project_overview() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        let overview = store
            .get_reserved_block(&project.slug, "_overview")
            .unwrap();
        assert_eq!(overview.content, "");

        store
            .update_reserved_block(&project.slug, "_overview", "Project description", false)
            .unwrap();
        let updated = store
            .get_reserved_block(&project.slug, "_overview")
            .unwrap();
        assert_eq!(updated.content, "Project description");
    }

    #[test]
    fn read_write_file_map() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        // Agents CAN write file map
        store
            .update_reserved_block(&project.slug, "_map", "src/\n  main.rs", true)
            .unwrap();
        let block = store.get_reserved_block(&project.slug, "_map").unwrap();
        assert_eq!(block.content, "src/\n  main.rs");
    }

    #[test]
    fn agents_cannot_write_overview() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        let err = store
            .update_reserved_block(&project.slug, "_overview", "nope", true)
            .unwrap_err();
        assert!(matches!(err, LoreError::PermissionDenied));
    }

    #[test]
    fn agents_cannot_write_agent_context() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        let err = store
            .update_reserved_block(&project.slug, "_agent-context", "nope", true)
            .unwrap_err();
        assert!(matches!(err, LoreError::PermissionDenied));
    }

    // -----------------------------------------------------------------------
    // Document management
    // -----------------------------------------------------------------------

    #[test]
    fn create_document_empty_name_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();

        let err = store
            .create_document(&project.slug, None, "  ")
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn rename_document_empty_name_errors() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let project = store.create_project("Test", None).unwrap();
        let doc = store.create_document(&project.slug, None, "Valid").unwrap();

        let err = store
            .rename_document(&project.slug, &doc.id, "  ")
            .unwrap_err();
        assert!(matches!(err, LoreError::Validation(_)));
    }

    #[test]
    fn doc_block_ordering_with_many_blocks() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let contents: Vec<String> = (0..20).map(|i| format!("Block {i}")).collect();
        let content_refs: Vec<&str> = contents.iter().map(|s| s.as_str()).collect();
        let (project, doc_id, _ids) = setup_doc_with_blocks(&store, &content_refs);

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks.len(), 20);
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(block.content, format!("Block {i}"));
        }

        // Read as document text and verify order
        let text = store
            .read_document_text(&project, &doc_id, None, None)
            .unwrap();
        let parsed = parse_document_text(&text).unwrap();
        for (i, entry) in parsed.iter().enumerate() {
            assert_eq!(entry.content, format!("Block {i}"));
        }
    }

    #[test]
    fn write_document_text_type_change() {
        let dir = tempdir().unwrap();
        let store = FileBlockStore::new(dir.path());
        let (project, doc_id, ids) = setup_doc_with_blocks(&store, &["some content"]);

        // Change block type from markdown to svg
        let text = format!(
            "<<<< block:{id} type:svg >>>>\n<svg><text>hello</text></svg>\n<<<< end:{id} >>>>",
            id = ids[0]
        );
        let entries = parse_document_text(&text).unwrap();
        let result = store
            .write_document_text(&project, &doc_id, entries, author())
            .unwrap();

        assert_eq!(result.updated.len(), 1);
        assert_eq!(result.updated[0].block_type, BlockType::Svg);

        let blocks = store.list_doc_blocks(&project, &doc_id).unwrap();
        assert_eq!(blocks[0].block_type, BlockType::Svg);
        assert_eq!(blocks[0].content, "<svg><text>hello</text></svg>");
    }
}
