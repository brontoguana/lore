pub mod api;
pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod librarian;
pub mod model;
pub mod order;
pub mod store;
pub mod ui;
pub mod updater;
pub mod versioning;

pub use api::build_app;
pub use audit::{AuditActor, AuditActorKind, AuditStore, StoredAuditEvent};
pub use auth::{
    AuthenticatedAgent, AuthenticatedUser, CreatedAgentToken, LocalAuthStore, NewAgentToken,
    NewRole, NewUser, ProjectGrant, ProjectPermission, RoleName, StoredAgentToken, UserName,
};
pub use config::{
    ExternalAuthConfig, ExternalAuthSecretUpdate, ExternalAuthStore, ExternalScheme, OidcConfig,
    OidcConfigStore, OidcLoginStateStore, OidcSecretUpdate, OidcUsernameClaim, ServerConfig,
    ServerConfigStore, UiTheme,
};
pub use error::{LoreError, Result};
pub use model::{
    Block, BlockId, BlockType, KeyFingerprint, NewBlock, OrderKey, ProjectName, UpdateBlock,
};
pub use order::generate_order_key;
pub use store::FileBlockStore;
pub use updater::{
    AutoUpdateConfig, AutoUpdateConfigStore, AutoUpdateStatus, AutoUpdateStatusStore,
    DEFAULT_UPDATE_REPO, SelfUpdateOutcome, check_for_update, maybe_apply_self_update,
};
pub use versioning::{
    GitExportConfig, GitExportConfigStore, GitExportStatus, GitExportStatusStore,
    GitExportTokenUpdate, ProjectHistoryStore, ProjectVersionActor, ProjectVersionActorKind,
    ProjectVersionOperationType, StoredBlockSnapshot, StoredProjectVersion,
    StoredProjectVersionOperation,
};
