pub mod api;
pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod librarian;
pub mod manager;
pub mod model;
pub mod order;
pub mod prompt;
pub mod store;
pub mod ui;
pub mod updater;
pub mod versioning;

pub use api::build_app;
pub use audit::{AuditActor, AuditActorKind, AuditStore, StoredAuditEvent};
pub use auth::{
    AgentBackend, AuthenticatedAgent, AuthenticatedMachine, AuthenticatedUser, CreatedAgentToken,
    LocalAuthStore, NewAgentToken, NewRole, NewUser, ProjectGrant, ProjectPermission, RoleName,
    StoredAgentToken, StoredMachine, UserName,
};
pub use config::{
    ColorMode, ExternalAuthConfig, ExternalAuthSecretUpdate, ExternalAuthStore, ExternalScheme,
    OidcConfig, OidcConfigStore, OidcLoginStateStore, OidcSecretUpdate, OidcUsernameClaim,
    ServerConfig, ServerConfigStore, UiTheme,
};
pub use error::{LoreError, Result};
pub use model::{
    Block, BlockId, BlockType, KeyFingerprint, NewBlock, OrderKey, ProjectName, UpdateBlock,
    reserved_block_display_name, slugify,
};
pub use order::generate_order_key;
pub use prompt::{current_datetime_prompt_line, current_datetime_prompt_line_at};
pub use store::{
    DocumentWriteEntry, DocumentWriteResult, FileBlockStore, parse_document_text,
    serialize_blocks_to_text,
};
pub use updater::{
    AutoUpdateConfig, AutoUpdateConfigStore, AutoUpdateStatus, AutoUpdateStatusStore,
    DEFAULT_UPDATE_REPO, ReleaseStream, SERVER_SYSTEMD_SERVICE_NAME, SERVER_SYSTEMD_UNIT_PATH,
    SelfUpdateOutcome, apply_update_to_version, check_for_update, maybe_apply_self_update,
    restart_server_via_systemd, server_systemd_unit_exists,
};
pub use versioning::{
    GitExportConfig, GitExportConfigStore, GitExportStatus, GitExportStatusStore,
    GitExportTokenUpdate, ProjectHistoryStore, ProjectVersionActor, ProjectVersionActorKind,
    ProjectVersionOperationType, StoredBlockSnapshot, StoredProjectVersion,
    StoredProjectVersionOperation,
};
