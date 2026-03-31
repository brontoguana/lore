use crate::error::{LoreError, Result};
use crate::model::{
    Block, BlockId, BlockType, ContentRef, KeyFingerprint, MediaRef, NewBlock, OrderKey,
    ProjectName, StoredBlock, UpdateBlock,
};
use crate::order::generate_order_key;
use crate::versioning::{
    StoredBlockSnapshot, block_matches_snapshot, media_bytes, snapshot_from_stored_block,
};
use std::fs;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

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
        let projects_dir = self.root.join("projects");
        if !projects_dir.exists() {
            return Ok(Vec::new());
        }

        let mut projects = Vec::new();
        for entry in fs::read_dir(projects_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();
            if let Ok(project) = ProjectName::new(name) {
                projects.push(project);
            }
        }

        projects.sort();
        Ok(projects)
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

    pub fn ensure_layout(&self, project: &ProjectName) -> Result<()> {
        fs::create_dir_all(self.project_dir(project).join("blocks"))?;
        fs::create_dir_all(self.project_dir(project).join("blobs"))?;
        Ok(())
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
}
