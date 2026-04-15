use crate::error::{LoreError, Result};
use crate::model::{
    Block, BlockId, BlockType, ContentRef, DocumentId, KeyFingerprint, MediaRef, NewBlock,
    OrderKey, ProjectName, StoredBlock, UpdateBlock, RESERVED_BLOCK_IDS,
};
use crate::order::generate_order_key;
use crate::versioning::{
    StoredBlockSnapshot, block_matches_snapshot, media_bytes, snapshot_from_stored_block,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
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

#[derive(Debug, Clone)]
pub struct FileBlockStore {
    root: PathBuf,
}

impl FileBlockStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
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
        self.ensure_layout(project)?;
        let meta_path = self.project_dir(project).join("project.json");
        let bytes = serde_json::to_vec_pretty(meta)?;
        fs::write(meta_path, bytes)?;
        Ok(())
    }

    pub fn rename_project(&self, project: &ProjectName, new_display_name: &str) -> Result<()> {
        let trimmed = new_display_name.trim();
        if trimmed.is_empty() {
            return Err(LoreError::Validation(
                "display name must not be empty".into(),
            ));
        }
        let mut meta = self.read_project_meta(project);
        meta.display_name = trimmed.to_string();
        self.write_project_meta(project, &meta)
    }

    pub fn write_agent_context(&self, project: &ProjectName, context: &str) -> Result<()> {
        let mut meta = self.read_project_meta(project);
        let trimmed = context.trim();
        meta.agent_context = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        self.write_project_meta(project, &meta)
    }

    pub fn delete_project(&self, project: &ProjectName) -> Result<()> {
        let dir = self.project_dir(project);
        if !dir.exists() {
            return Err(LoreError::Validation("project does not exist".into()));
        }
        // Re-parent any children to have no parent (promote to root)
        let infos = self.list_project_infos()?;
        for info in &infos {
            if info.parent.as_deref() == Some(project.as_str()) {
                let mut meta = self.read_project_meta(&info.slug);
                meta.parent = None;
                self.write_project_meta(&info.slug, &meta)?;
            }
        }
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
        self.write_project_meta(project, &meta)
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
        let fingerprint = KeyFingerprint::from_api_key(requesting_key)?;
        self.delete_block_internal(project, block_id, Some(&fingerprint))
    }

    pub fn delete_block_as_project_writer(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
    ) -> Result<()> {
        self.delete_block_internal(project, block_id, None)
    }

    pub fn set_block_pinned(
        &self,
        project: &ProjectName,
        block_id: &BlockId,
        pinned: bool,
    ) -> Result<()> {
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
                self.delete_block_internal(project, &block.id, None)?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    fn delete_block_internal(
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

    pub fn delete_document(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
    ) -> Result<()> {
        let doc_dir = self.find_doc_dir(project, doc_id)?;
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
        let author = KeyFingerprint::from_api_key(&new_block.author_key)?;
        let doc_dir = self.find_doc_dir(&new_block.project, doc_id)?;
        self.create_block_in_doc_dir(&doc_dir, new_block, author)
    }

    pub fn create_doc_block_as_project_writer(
        &self,
        doc_id: &DocumentId,
        new_block: NewBlock,
    ) -> Result<Block> {
        let author = KeyFingerprint::from_user_name(&new_block.author_key)?;
        let doc_dir = self.find_doc_dir(&new_block.project, doc_id)?;
        self.create_block_in_doc_dir(&doc_dir, new_block, author)
    }

    pub fn update_doc_block(&self, doc_id: &DocumentId, update: UpdateBlock) -> Result<Block> {
        let fingerprint = KeyFingerprint::from_api_key(&update.author_key)?;
        let doc_dir = self.find_doc_dir(&update.project, doc_id)?;
        self.update_block_in_doc_dir(&doc_dir, update, UpdateMode::AgentOwner(fingerprint))
    }

    pub fn update_doc_block_as_project_writer(
        &self,
        doc_id: &DocumentId,
        update: UpdateBlock,
    ) -> Result<Block> {
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
        let doc_dir = self.find_doc_dir(project, doc_id)?;
        self.delete_block_in_doc_dir(&doc_dir, project, block_id, None)
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

    pub fn get_reserved_block(
        &self,
        project: &ProjectName,
        reserved_id: &str,
    ) -> Result<Block> {
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
                let mut stored: StoredBlock =
                    serde_json::from_slice(&fs::read(block_path)?)?;

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

    fn find_doc_dir(
        &self,
        project: &ProjectName,
        doc_id: &DocumentId,
    ) -> Result<PathBuf> {
        let docs_root = self.project_dir(project).join("docs");
        self.find_doc_dir_recursive(&docs_root, doc_id)
            .ok_or_else(|| {
                LoreError::Validation(format!("document '{}' not found", doc_id))
            })
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
        docs.sort_by(|a, b| a.display_name.cmp(&b.display_name));
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
        let media_ref = self.persist_uploaded_media_in(
            doc_dir,
            &project_dir,
            &id,
            new_block.image_upload,
        )?;
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
        let metadata_path = doc_dir
            .join("blocks")
            .join(format!("{}.json", id.as_str()));
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
            .map_err(|_| {
                LoreError::Validation("internal: blob path not under project dir".into())
            })?
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
            .map_err(|_| {
                LoreError::Validation("internal: blob path not under project dir".into())
            })?
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

#[cfg(test)]
mod tests {
    use super::FileBlockStore;
    use crate::error::LoreError;
    use crate::model::{BlockType, NewBlock, OrderKey, ProjectName, UpdateBlock};
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

        store.rename_project(&info.slug, "New Name").unwrap();
        let meta = store.read_project_meta(&info.slug);
        assert_eq!(meta.display_name, "New Name");

        // empty name should fail
        assert!(store.rename_project(&info.slug, "  ").is_err());
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
        let b = store
            .create_project("Beta", Some(a.slug.as_str()))
            .unwrap();

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
        assert!(store
            .resolve_lore_link("00000000-0000-0000-0000-000000000000")
            .is_none());
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

        store
            .create_document(&project.slug, None, "Doc A")
            .unwrap();
        store
            .create_document(&project.slug, None, "Doc B")
            .unwrap();

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
        assert!(store
            .list_doc_blocks(&project.slug, &doc.id)
            .unwrap()
            .is_empty());
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
}
