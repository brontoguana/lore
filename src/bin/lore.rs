use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use lore_core::updater::{download_update_to_path, hex_sha256};
use lore_core::{
    AgentBackend, Block, BlockType, DEFAULT_UPDATE_REPO, ProjectName, ReleaseStream,
    SelfUpdateOutcome, check_for_update, current_datetime_prompt_line,
    current_datetime_prompt_line_at,
    manager::{
        ManagerControlKind, ParsedManagerResponse, manager_control_decision_label,
        manager_response_display_content, parse_manager_control_response,
    },
    maybe_apply_self_update, slugify,
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{HashSet, VecDeque};
use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::future::Future;
use std::io;
use std::io::IsTerminal;
use std::path::Path;
use std::path::PathBuf;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::io::AsyncBufReadExt;

type CliResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const CLI_SELF_UPDATE_SKIP_ENV: &str = "LORE_SKIP_CLI_SELF_UPDATE";
const CLI_AUTO_UPDATE_INTERVAL_SECS: i64 = 24 * 60 * 60;
const STOP_POLL_INTERVAL_MS: u64 = 200;
const LORE_MACHINE_SERVICE_NAME: &str = "lore-machine.service";
const LORE_SERVICE_HANDOFF_READY_ENV: &str = "LORE_SERVICE_HANDOFF_READY";
const LORE_SERVICE_HANDOFF_PARENT_PID_ENV: &str = "LORE_SERVICE_HANDOFF_PARENT_PID";
const LORE_SERVICE_HANDOFF_CANONICAL_EXE_ENV: &str = "LORE_SERVICE_HANDOFF_CANONICAL_EXE";
const LORE_SERVICE_HANDOFF_TARGET_VERSION_ENV: &str = "LORE_SERVICE_HANDOFF_TARGET_VERSION";
const LORE_SERVICE_SYSTEMD_ENV: &str = "LORE_SERVICE_SYSTEMD";
const SYSTEMD_SERVICE_RESTART_EXIT_CODE: i32 = 75;
const CLI_BACKEND_TURN_FAILURE_LIMIT: u32 = 3;
const DEFAULT_CHAT_WINDOW_SIZE: usize = 22;
const AGY_INLINE_PROMPT_MAX_BYTES: usize = 24 * 1024;
const AGY_OAUTH_TOKEN_RELATIVE_PATH: &str = ".gemini/antigravity-cli/antigravity-oauth-token";
const AGY_FILE_TOKEN_SSH_CONNECTION: &str = "127.0.0.1 0 127.0.0.1 0";
const AGY_FILE_TOKEN_SSH_CLIENT: &str = "127.0.0.1 0 0";
const LORE_CLAUDE_ALLOW_ENV_AUTH_ENV: &str = "LORE_CLAUDE_ALLOW_ENV_AUTH";
const CLAUDE_AUTH_OVERRIDE_ENV_VARS: &[&str] = &[
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AWS_API_KEY",
    "ANTHROPIC_AWS_BASE_URL",
    "ANTHROPIC_VERTEX_PROJECT_ID",
    "ANTHROPIC_VERTEX_REGION",
];
const TOP_LEVEL_HELP_TEMPLATE: &str = "\
{before-help}{about-with-newline}
{usage-heading} {usage}

User Commands:
  setup-machine   Register this machine for Lore-managed agents
  setup-external  Configure this CLI with an external agent token without registering a machine

Agent Commands:
  config          Manage CLI configuration (url, token, project)
  project         Manage the repo-local Lore project marker
  projects        List all projects
  overview        Read the project overview
  file-map        Read or update the project file map
  context         Show the current project's agent context
  docs            List and manage documents
  blocks          Read, create, edit, and manage blocks within documents
  grep            Search blocks by content
  librarian       Ask the librarian a question or request an action
  history         View and manage block version history
  self-update     Check for and apply CLI updates
  agent           Run an agent daemon
  service         Run the machine service daemon (manages agents, responds to server commands)
  help            Print this message or the help of the given subcommand(s)

Options:
{options}{after-help}";

fn resolve_executable_path(executable: &str, fallback_relative_paths: &[&str]) -> PathBuf {
    let mut env_var = |name: &str| env::var_os(name);
    let home = user_home_dir_from_env(host_platform(), &mut env_var);
    resolve_executable_path_from(
        executable,
        fallback_relative_paths,
        home.as_ref().map(|path| path.as_os_str()),
        env::var_os("PATH").as_deref(),
    )
}

fn resolve_executable_path_from(
    executable: &str,
    fallback_relative_paths: &[&str],
    home: Option<&OsStr>,
    path: Option<&OsStr>,
) -> PathBuf {
    if executable.contains(std::path::MAIN_SEPARATOR) {
        return PathBuf::from(executable);
    }

    if let Some(home) = home {
        let home = PathBuf::from(home);
        for relative in fallback_relative_paths {
            let candidate = home.join(relative);
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    if let Some(path) = path {
        for dir in env::split_paths(path) {
            let candidate = dir.join(executable);
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    PathBuf::from(executable)
}

fn resolve_backend_executable(backend: AgentBackend) -> PathBuf {
    match backend {
        AgentBackend::Claude => {
            resolve_executable_path("claude", &[".local/bin/claude", ".npm-global/bin/claude"])
        }
        AgentBackend::Agy => resolve_executable_path("agy", &[".local/bin/agy"]),
        AgentBackend::Codex => {
            resolve_executable_path("codex", &[".local/bin/codex", ".npm-global/bin/codex"])
        }
        AgentBackend::OpenAi => PathBuf::from("openai"),
    }
}

fn agy_file_token_path_from(home: Option<&OsStr>) -> Option<PathBuf> {
    home.map(PathBuf::from)
        .map(|home| home.join(AGY_OAUTH_TOKEN_RELATIVE_PATH))
}

fn should_force_agy_file_token_auth_from(
    home: Option<&OsStr>,
    ssh_connection: Option<&OsStr>,
    ssh_client: Option<&OsStr>,
) -> bool {
    if ssh_connection.is_some() || ssh_client.is_some() {
        return false;
    }
    agy_file_token_path_from(home)
        .map(|path| path.is_file())
        .unwrap_or(false)
}

fn should_force_agy_file_token_auth() -> bool {
    let mut env_var = |name: &str| env::var_os(name);
    let home = user_home_dir_from_env(host_platform(), &mut env_var);
    should_force_agy_file_token_auth_from(
        home.as_ref().map(|path| path.as_os_str()),
        env::var_os("SSH_CONNECTION").as_deref(),
        env::var_os("SSH_CLIENT").as_deref(),
    )
}

fn configure_agy_auth_env(cmd: &mut tokio::process::Command) {
    if should_force_agy_file_token_auth() {
        // Antigravity CLI uses file-token storage in SSH sessions. Lore's
        // systemd service is headless but has the same token file, so make the
        // child select that auth path without changing the parent environment.
        cmd.env("SSH_CONNECTION", AGY_FILE_TOKEN_SSH_CONNECTION)
            .env("SSH_CLIENT", AGY_FILE_TOKEN_SSH_CLIENT);
    }
}

fn env_value_is_truthy(value: Option<&OsStr>) -> bool {
    value
        .and_then(|value| value.to_str())
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn claude_credentials_path_from(
    mut env_var: impl FnMut(&str) -> Option<OsString>,
) -> Option<PathBuf> {
    if let Some(config_dir) = env_var("CLAUDE_CONFIG_DIR") {
        return Some(PathBuf::from(config_dir).join(".credentials.json"));
    }
    user_home_dir_from_env(host_platform(), &mut env_var)
        .map(|home| home.join(".claude").join(".credentials.json"))
}

fn should_prefer_claude_login_auth_from(
    mut env_var: impl FnMut(&str) -> Option<OsString>,
    mut is_file: impl FnMut(&Path) -> bool,
) -> bool {
    if env_value_is_truthy(env_var(LORE_CLAUDE_ALLOW_ENV_AUTH_ENV).as_deref()) {
        return false;
    }

    claude_credentials_path_from(&mut env_var)
        .map(|path| is_file(&path))
        .unwrap_or(false)
}

fn should_prefer_claude_login_auth() -> bool {
    should_prefer_claude_login_auth_from(|name| env::var_os(name), |path| path.is_file())
}

fn configure_claude_auth_env(cmd: &mut tokio::process::Command) {
    if should_prefer_claude_login_auth() {
        for key in CLAUDE_AUTH_OVERRIDE_ENV_VARS {
            cmd.env_remove(key);
        }
    }
}

#[derive(Parser)]
#[command(name = "lore")]
#[command(about = "Lore CLI")]
#[command(version)]
#[command(help_template = TOP_LEVEL_HELP_TEMPLATE)]
struct Cli {
    /// Server URL (overrides config)
    #[arg(long, global = true)]
    url: Option<String>,
    /// API token (overrides config)
    #[arg(long, global = true)]
    token: Option<String>,
    /// Project slug (overrides config)
    #[arg(long, global = true)]
    project: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register this machine for Lore-managed agents
    #[command(name = "setup-machine", alias = "setup")]
    SetupMachine(SetupArgs),
    /// Configure this CLI with an external agent token without registering a machine
    #[command(name = "setup-external", alias = "login")]
    SetupExternal(SetupExternalArgs),
    /// Manage CLI configuration (url, token, project)
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage the repo-local Lore project marker
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// List all projects
    Projects,
    /// Read the project overview
    Overview,
    /// Read or update the project file map
    FileMap {
        #[command(subcommand)]
        command: FileMapCommand,
    },
    /// Show the current project's agent context
    Context,
    /// List and manage documents
    Docs {
        #[command(subcommand)]
        command: DocsCommand,
    },
    /// Read, create, edit, and manage blocks within documents
    Blocks {
        #[command(subcommand)]
        command: BlocksCommand,
    },
    /// Search blocks by content
    Grep(GrepArgs),
    /// Ask the librarian a question or request an action
    Librarian {
        #[command(subcommand)]
        command: LibrarianCommand,
    },
    /// View and manage block version history
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    /// Check for and apply CLI updates
    SelfUpdate {
        #[command(subcommand)]
        command: UpdateCommand,
    },
    /// Run an agent daemon
    Agent(AgentArgs),
    /// Run the machine service daemon (manages agents, responds to server commands)
    Service(ServiceArgs),
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Show current configuration
    Show,
    /// Set configuration values
    Set(ConfigSetArgs),
    /// Clear configuration values
    Clear(ConfigClearArgs),
}

#[derive(Subcommand)]
enum ProjectCommand {
    /// Show the resolved repo-local project marker for the current directory
    Show,
    /// Write or update the nearest repo-local .lore/project file
    SetLocal(ProjectSetLocalArgs),
    /// Remove the nearest repo-local .lore/project file
    ClearLocal,
}

#[derive(Args)]
struct ProjectSetLocalArgs {
    /// Project slug or display name
    project: String,
}

#[derive(Args)]
struct ConfigSetArgs {
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    project: Option<String>,
}

#[derive(Args)]
struct ConfigClearArgs {
    #[arg(long)]
    url: bool,
    #[arg(long)]
    token: bool,
    #[arg(long)]
    project: bool,
}

#[derive(Args)]
struct SetupExternalArgs {
    /// Lore server URL
    url: String,
    /// External agent token. If omitted, prompts on stdin.
    #[arg(long)]
    token: Option<String>,
    /// Optional legacy global project fallback. Prefer `lore project set-local`.
    #[arg(long)]
    project: Option<String>,
    /// Save the token without checking it against the server.
    #[arg(long)]
    no_verify: bool,
}

#[derive(Subcommand)]
enum FileMapCommand {
    /// Read the file map
    #[command(name = "read")]
    Read,
    /// Replace the entire file map content
    #[command(name = "update")]
    Update(FileMapUpdateArgs),
    /// Apply a find-and-replace within the file map
    #[command(name = "edit")]
    Edit(FileMapEditArgs),
}

#[derive(Args)]
struct FileMapUpdateArgs {
    /// New file map content
    content: String,
}

#[derive(Args)]
struct FileMapEditArgs {
    /// Exact text to find (must be unique)
    #[arg(long)]
    old: String,
    /// Replacement text
    #[arg(long)]
    new: String,
}

#[derive(Subcommand)]
enum DocsCommand {
    /// List documents in the current project (shows doc tree with IDs)
    List,
    /// Read a document as a single text with block markers
    Read(DocReadArgs),
    /// Write a document from block-marker text
    Write(DocWriteArgs),
    /// Append a new block to the end of a document
    Append(DocAppendArgs),
    /// Insert a new block after a matching markdown heading
    InsertAfterHeading(DocInsertAfterHeadingArgs),
    /// Create a new document
    Create(DocCreateArgs),
    /// Rename a document
    Rename(DocRenameArgs),
    /// Delete a document and all its contents
    Delete(DocDeleteArgs),
}

#[derive(Args)]
struct DocReadArgs {
    /// Document ID (UUID)
    doc_id: String,
    /// First block to include (omit for start of document)
    #[arg(long)]
    from: Option<String>,
    /// Last block to include (omit for end of document)
    #[arg(long)]
    to: Option<String>,
}

#[derive(Args)]
#[command(
    after_help = "Marker format:\n  Existing block from `docs read`:\n    @@block id=550e8400-e29b-41d4-a716-446655440000 type=markdown\n    Hello from Lore.\n    @@end\n\n  New block to create during `docs write`:\n    @@block id=intro type=markdown\n    This block will get a real UUID when written.\n    @@end\n\nRound-trip example:\n  lore docs read <doc-id> > /tmp/doc.txt\n  lore docs write <doc-id> --file /tmp/doc.txt\n\nNotes:\n  Existing blocks must keep their real UUID in `id=`.\n  New blocks must still include `id=`, but it can be any non-UUID placeholder.\n\nSafety:\n  Empty input is rejected unless you pass --allow-empty."
)]
struct DocWriteArgs {
    /// Document ID (UUID)
    doc_id: String,
    /// Read content from this file instead of stdin
    #[arg(long)]
    file: Option<String>,
    /// Read content from stdin explicitly
    #[arg(long)]
    stdin: bool,
    /// Permit empty input (otherwise empty stdin/file is rejected)
    #[arg(long)]
    allow_empty: bool,
    /// Show what would change without writing
    #[arg(long)]
    dry_run: bool,
    /// Print a text diff before writing, or with --dry-run
    #[arg(long)]
    diff: bool,
}

#[derive(Args)]
#[command(
    after_help = "Content sources:\n  lore docs append <doc-id> 'Short note'\n  lore docs append <doc-id> --file /tmp/note.md\n  lore docs append <doc-id> --stdin < /tmp/note.md\n\nUse --dry-run --diff to preview without creating a block."
)]
struct DocAppendArgs {
    /// Document ID (UUID)
    doc_id: String,
    /// Block content to append
    content: Option<String>,
    /// Block type
    #[arg(long = "type", value_enum, default_value_t = CliBlockType::Markdown)]
    block_type: CliBlockType,
    /// Read content from this file
    #[arg(long)]
    file: Option<String>,
    /// Read content from stdin
    #[arg(long)]
    stdin: bool,
    /// Show what would change without writing
    #[arg(long)]
    dry_run: bool,
    /// Print a text diff before writing, or with --dry-run
    #[arg(long)]
    diff: bool,
}

#[derive(Args)]
#[command(
    after_help = "Heading matching:\n  The heading can be the literal markdown line (`## Notes`) or just its text (`Notes`).\n  The match must be unique across markdown blocks.\n\nContent sources:\n  lore docs insert-after-heading <doc-id> Notes 'Short note'\n  lore docs insert-after-heading <doc-id> '## Notes' --stdin < /tmp/note.md"
)]
struct DocInsertAfterHeadingArgs {
    /// Document ID (UUID)
    doc_id: String,
    /// Heading text or literal markdown heading line to insert after
    heading: String,
    /// Block content to insert
    content: Option<String>,
    /// Block type
    #[arg(long = "type", value_enum, default_value_t = CliBlockType::Markdown)]
    block_type: CliBlockType,
    /// Read content from this file
    #[arg(long)]
    file: Option<String>,
    /// Read content from stdin
    #[arg(long)]
    stdin: bool,
    /// Show what would change without writing
    #[arg(long)]
    dry_run: bool,
    /// Print a text diff before writing, or with --dry-run
    #[arg(long)]
    diff: bool,
}

#[derive(Args)]
struct DocCreateArgs {
    /// Document display name
    name: String,
    /// Parent document ID for nesting (omit for top-level)
    #[arg(long)]
    parent: Option<String>,
}

#[derive(Args)]
struct DocRenameArgs {
    /// Document ID (UUID)
    doc_id: String,
    /// New display name
    name: String,
}

#[derive(Args)]
struct DocDeleteArgs {
    /// Document ID (UUID)
    doc_id: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Subcommand)]
enum BlocksCommand {
    /// List blocks in a document
    List(BlockListArgs),
    /// Read a block's content
    Read(BlockReadArgs),
    /// Read a block with surrounding context
    Around(AroundArgs),
    /// Create a new block in a document
    Create(BlockCreateArgs),
    /// Replace a block's entire content
    Update(BlockUpdateArgs),
    /// Append text to the end of an existing block
    Append(BlockAppendArgs),
    /// Apply a find-and-replace within a block
    Edit(BlockEditArgs),
    /// Move a block to a new position within a document
    Move(BlockMoveArgs),
    /// Delete a block from a document
    Delete(BlockDeleteArgs),
    /// Split a markdown block at a character position
    Split(BlockSplitArgs),
    /// Combine consecutive markdown blocks into one
    Combine(BlockCombineArgs),
}

#[derive(Args)]
struct BlockListArgs {
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

#[derive(Args)]
struct BlockReadArgs {
    /// Block ID (UUID)
    id: String,
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
    /// Starting line (0-based)
    #[arg(long)]
    offset: Option<usize>,
    /// Max lines to read
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Args)]
struct AroundArgs {
    /// Block ID (UUID)
    id: String,
    #[arg(long, default_value_t = 2)]
    before: usize,
    #[arg(long, default_value_t = 2)]
    after: usize,
}

#[derive(Args)]
#[command(
    after_help = "Content sources:\n  lore blocks create --doc <doc-id> 'Text'\n  lore blocks create --doc <doc-id> --file /tmp/block.md\n  lore blocks create --doc <doc-id> --stdin < /tmp/block.md\n\nPlacement modes:\n  --position append (default)\n  --position start\n  --position after --after <block-id>"
)]
struct BlockCreateArgs {
    /// Block content
    content: Option<String>,
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
    /// Block type
    #[arg(long = "type", value_enum, default_value_t = CliBlockType::Markdown)]
    block_type: CliBlockType,
    /// Read content from this file
    #[arg(long)]
    file: Option<String>,
    /// Read content from stdin
    #[arg(long)]
    stdin: bool,
    /// Explicit placement mode (default: append)
    #[arg(long, value_enum)]
    position: Option<BlockInsertPosition>,
    /// Place after this block ID (required with --position after)
    #[arg(long)]
    after: Option<String>,
    /// Show what would change without writing
    #[arg(long)]
    dry_run: bool,
    /// Print a text diff before writing, or with --dry-run
    #[arg(long)]
    diff: bool,
}

#[derive(Args)]
#[command(
    after_help = "Content sources:\n  lore blocks update <block-id> --doc <doc-id> 'Text'\n  lore blocks update <block-id> --doc <doc-id> --file /tmp/block.md\n  lore blocks update <block-id> --doc <doc-id> --stdin < /tmp/block.md"
)]
struct BlockUpdateArgs {
    /// Block ID (UUID)
    id: String,
    /// New content
    content: Option<String>,
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
    /// Block type (only if changing)
    #[arg(long = "type", value_enum)]
    block_type: Option<CliBlockType>,
    /// Read content from this file
    #[arg(long)]
    file: Option<String>,
    /// Read content from stdin
    #[arg(long)]
    stdin: bool,
    /// Show what would change without writing
    #[arg(long)]
    dry_run: bool,
    /// Print a text diff before writing, or with --dry-run
    #[arg(long)]
    diff: bool,
}

#[derive(Args)]
#[command(
    after_help = "Content sources:\n  lore blocks append <block-id> --doc <doc-id> 'More text'\n  lore blocks append <block-id> --doc <doc-id> --file /tmp/note.md\n  lore blocks append <block-id> --doc <doc-id> --stdin < /tmp/note.md\n\nBy default Lore inserts one newline between existing content and appended content. Use --separator '' to append directly."
)]
struct BlockAppendArgs {
    /// Block ID (UUID)
    id: String,
    /// Content to append
    content: Option<String>,
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
    /// Read content from this file
    #[arg(long)]
    file: Option<String>,
    /// Read content from stdin
    #[arg(long)]
    stdin: bool,
    /// Separator inserted between existing content and appended content
    #[arg(long, default_value = "\n")]
    separator: String,
    /// Show what would change without writing
    #[arg(long)]
    dry_run: bool,
    /// Print a text diff before writing, or with --dry-run
    #[arg(long)]
    diff: bool,
}

#[derive(Args)]
#[command(
    after_help = "Robust text sources:\n  lore blocks edit <block-id> --doc <doc-id> --old 'old' --new '- bullet'\n  lore blocks edit <block-id> --doc <doc-id> --old-file /tmp/old.txt --new-file /tmp/new.txt\n  lore blocks edit <block-id> --doc <doc-id> --old 'old' --new-stdin < /tmp/new.txt\n\nIf shell parsing is still ambiguous, use --new=-value or --new-file/--new-stdin."
)]
struct BlockEditArgs {
    /// Block ID (UUID)
    id: String,
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
    /// Exact text to find (must be unique within the block)
    #[arg(long, allow_hyphen_values = true)]
    old: Option<String>,
    /// Read exact text to find from this file
    #[arg(long = "old-file")]
    old_file: Option<String>,
    /// Read exact text to find from stdin
    #[arg(long = "old-stdin")]
    old_stdin: bool,
    /// Replacement text
    #[arg(long, allow_hyphen_values = true)]
    new: Option<String>,
    /// Read replacement text from this file
    #[arg(long = "new-file")]
    new_file: Option<String>,
    /// Read replacement text from stdin
    #[arg(long = "new-stdin")]
    new_stdin: bool,
    /// Show what would change without writing
    #[arg(long)]
    dry_run: bool,
    /// Print a text diff before writing, or with --dry-run
    #[arg(long)]
    diff: bool,
}

#[derive(Args)]
struct BlockMoveArgs {
    /// Block ID (UUID)
    id: String,
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
    /// Place after this block ID (omit to move to start)
    #[arg(long)]
    after: Option<String>,
}

#[derive(Args)]
struct BlockDeleteArgs {
    /// Block ID (UUID)
    id: String,
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
struct BlockSplitArgs {
    /// Block ID (UUID)
    id: String,
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
    /// Character position at which to split
    #[arg(long)]
    position: usize,
}

#[derive(Args)]
struct BlockCombineArgs {
    /// Block IDs to combine (minimum 2, in order)
    ids: Vec<String>,
    /// Document ID (UUID)
    #[arg(long)]
    doc: String,
}

#[derive(Args)]
struct GrepArgs {
    query: String,
    #[command(flatten)]
    filters: SearchFilters,
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Args)]
struct SetupArgs {
    /// Server URL (e.g. https://lore.example.com)
    url: String,
}

#[derive(Subcommand)]
enum LibrarianCommand {
    /// Ask the librarian a question
    Answer(LibrarianAnswerArgs),
    /// Request the librarian to perform an action
    Action(LibrarianActionArgs),
}

#[derive(Args)]
struct LibrarianAnswerArgs {
    question: String,
    #[command(flatten)]
    filters: SearchFilters,
    #[arg(long)]
    max_sources: Option<usize>,
    #[arg(long)]
    around: Option<usize>,
}

#[derive(Args)]
struct LibrarianActionArgs {
    instruction: String,
    #[command(flatten)]
    filters: SearchFilters,
    #[arg(long)]
    max_sources: Option<usize>,
    #[arg(long)]
    around: Option<usize>,
}

#[derive(Subcommand)]
enum HistoryCommand {
    /// List recent block changes
    List(HistoryListArgs),
    /// Show a specific version
    Show(HistoryShowArgs),
    /// Revert a block to a previous version
    Revert(HistoryRevertArgs),
}

#[derive(Subcommand)]
enum UpdateCommand {
    /// Show current update configuration
    Status,
    /// Check for available updates
    Check,
    /// Apply a pending update
    Apply,
    /// Enable automatic updates
    Enable(UpdateEnableArgs),
    /// Disable automatic updates
    Disable,
}

#[derive(Args)]
struct UpdateEnableArgs {
    #[arg(long, default_value = DEFAULT_UPDATE_REPO)]
    repo: String,
    #[arg(long, value_enum, default_value_t = CliReleaseStream::Stable)]
    stream: CliReleaseStream,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliReleaseStream {
    Stable,
    Prerelease,
}

impl From<CliReleaseStream> for ReleaseStream {
    fn from(value: CliReleaseStream) -> Self {
        match value {
            CliReleaseStream::Stable => ReleaseStream::Stable,
            CliReleaseStream::Prerelease => ReleaseStream::Prerelease,
        }
    }
}

#[derive(Args)]
struct HistoryListArgs {
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Args)]
struct HistoryShowArgs {
    id: String,
}

#[derive(Args)]
struct HistoryRevertArgs {
    id: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Args, Default, Clone)]
struct SearchFilters {
    #[arg(long = "block-type", value_enum)]
    block_type: Option<CliBlockType>,
    #[arg(long)]
    author: Option<String>,
    #[arg(long)]
    since_days: Option<u32>,
}

#[derive(Args)]
struct AgentArgs {
    name: String,
    #[arg(long)]
    fg: bool,
    /// Override the backend (claude, agy, codex). If not set, uses server config.
    #[arg(long)]
    backend: Option<String>,
}

#[derive(Args)]
struct ServiceArgs {
    /// Run in foreground (don't daemonize)
    #[arg(long)]
    fg: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliBlockType {
    Markdown,
    Html,
    Svg,
    Image,
}

impl From<CliBlockType> for BlockType {
    fn from(value: CliBlockType) -> Self {
        match value {
            CliBlockType::Markdown => BlockType::Markdown,
            CliBlockType::Html => BlockType::Html,
            CliBlockType::Svg => BlockType::Svg,
            CliBlockType::Image => BlockType::Image,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum BlockInsertPosition {
    Start,
    Append,
    After,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CliConfig {
    url: Option<String>,
    token: Option<String>,
    project: Option<String>,
    #[serde(default)]
    machine_name: Option<String>,
    #[serde(default)]
    agent_tokens: std::collections::HashMap<String, String>,
    #[serde(default)]
    auto_update_enabled: bool,
    #[serde(default = "default_update_repo_string")]
    update_repo: String,
    #[serde(default)]
    update_stream: ReleaseStream,
    #[serde(default)]
    last_update_check: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize)]
struct ProjectResolutionResponse {
    project: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedProject {
    value: String,
    source: ProjectSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProjectSource {
    Flag,
    Env,
    LocalFile(PathBuf),
}

#[derive(Debug)]
struct CliContext {
    client: reqwest::Client,
    url: String,
    token: Option<String>,
    project: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProjectSummary {
    project: String,
}

#[derive(Debug, Deserialize)]
struct BlockWindow {
    anchor: String,
    blocks: Vec<Block>,
}

#[derive(Debug, Deserialize)]
struct GrepMatch {
    block: Block,
    preview: String,
    #[serde(default)]
    document_id: Option<String>,
    #[serde(default)]
    document_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LibrarianActor {
    name: String,
}

#[derive(Debug, Deserialize)]
struct LibrarianAnswerBody {
    project: ProjectName,
    created_at: OffsetDateTime,
    actor: LibrarianActor,
    question: String,
    answer: Option<String>,
    status: String,
    error: Option<String>,
    context_blocks: Vec<Block>,
}

#[derive(Debug, Deserialize)]
struct ProjectLibrarianOperation {
    operation_type: String,
    block_id: Option<String>,
    after_block_id: Option<String>,
    block_type: Option<BlockType>,
    content_preview: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProjectLibrarianActionBody {
    project: ProjectName,
    created_at: OffsetDateTime,
    actor: LibrarianActor,
    instruction: String,
    summary: String,
    pending_action_id: Option<String>,
    requires_approval: bool,
    context_blocks: Vec<Block>,
    operations: Vec<ProjectLibrarianOperation>,
}

#[derive(Debug, Deserialize)]
struct ProjectHistorySummary {
    versions: Vec<UiProjectVersion>,
}

#[derive(Debug, Deserialize)]
struct UiProjectVersion {
    id: String,
    created_at: OffsetDateTime,
    actor: ProjectVersionActor,
    summary: String,
    operations: Vec<UiProjectVersionOperation>,
    git_commit: Option<String>,
    git_export_error: Option<String>,
    reverted_from_version_id: Option<String>,
    reverted_by_version_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProjectVersionActor {
    kind: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct UiProjectVersionOperation {
    operation_type: String,
    block_id: String,
    before_preview: Option<String>,
    after_preview: Option<String>,
    changed_fields: Vec<String>,
    diff_lines: Vec<UiDiffLine>,
    before_order: Option<String>,
    after_order: Option<String>,
    before_block_type: Option<String>,
    after_block_type: Option<String>,
    before_media_type: Option<String>,
    after_media_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UiDiffLine {
    kind: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug, Deserialize)]
struct DocBlockChunkResponse {
    content: String,
    total_lines: usize,
    offset: usize,
    limit: usize,
}

#[derive(Debug, Serialize)]
struct AskLibrarianRequest {
    question: String,
    block_type: Option<String>,
    author: Option<String>,
    since_days: Option<u32>,
    max_sources: Option<usize>,
    around: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ProjectLibrarianActionRequest {
    instruction: String,
    block_type: Option<String>,
    author: Option<String>,
    since_days: Option<u32>,
    max_sources: Option<usize>,
    around: Option<usize>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> CliResult<()> {
    let cli = Cli::parse();
    let mut config = load_cli_config()?;

    match cli.command {
        Command::SetupMachine(args) => return run_setup_machine(args, &mut config).await,
        Command::SetupExternal(args) => return run_setup_external(args, &mut config).await,
        Command::Config { command } => return run_config(command, &mut config),
        Command::Project { command } => return run_project_command(command),
        Command::SelfUpdate { command } => return run_update(command, &mut config).await,
        _ => {}
    }

    maybe_auto_update_cli(&mut config).await?;

    let context = build_context(&cli, &config)?;
    match cli.command {
        Command::Projects => projects_command(&context).await?,
        Command::Overview => overview_command(&context).await?,
        Command::FileMap { command } => file_map_command(&context, command).await?,
        Command::Context => context_command(&context).await?,
        Command::Docs { command } => docs_command(&context, command).await?,
        Command::Blocks { command } => blocks_command(&context, command).await?,
        Command::Grep(args) => grep_command(&context, args).await?,
        Command::Librarian { command } => librarian_command(&context, command).await?,
        Command::History { command } => history_command(&context, command).await?,
        Command::Agent(args) => agent_command(&context, args).await?,
        Command::Service(args) => service_command(&context, args).await?,
        Command::Config { .. }
        | Command::SetupExternal(_)
        | Command::Project { .. }
        | Command::SelfUpdate { .. }
        | Command::SetupMachine(_) => {}
    }
    Ok(())
}

fn run_config(command: ConfigCommand, config: &mut CliConfig) -> CliResult<()> {
    match command {
        ConfigCommand::Show => {
            println!("config path: {}", cli_config_path()?.display());
            println!("url: {}", config.url.as_deref().unwrap_or("(unset)"));
            println!(
                "token: {}",
                config.token.as_ref().map(|_| "(set)").unwrap_or("(unset)")
            );
            println!(
                "project (legacy global fallback, not used by default): {}",
                config.project.as_deref().unwrap_or("(unset)")
            );
            println!(
                "auto update: {}",
                if config.auto_update_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("update repo: {}", config.update_repo);
            println!("update stream: {}", config.update_stream.as_str());
            println!(
                "mode: {}",
                if config.machine_name.is_some() {
                    "machine"
                } else if config.token.is_some() {
                    "external"
                } else {
                    "(unset)"
                }
            );
        }
        ConfigCommand::Set(args) => {
            let set_project = args.project.is_some();
            if let Some(url) = args.url {
                config.url = Some(normalize_url(&url));
            }
            if let Some(token) = args.token {
                config.token = Some(token);
            }
            if let Some(project) = args.project {
                ProjectName::new(project.clone())?;
                config.project = Some(project);
            }
            save_cli_config(config)?;
            println!("saved {}", cli_config_path()?.display());
            if set_project {
                println!(
                    "note: config --project is legacy; prefer a repo-local .lore/project file or --project"
                );
            }
        }
        ConfigCommand::Clear(args) => {
            if !(args.url || args.token || args.project) {
                return Err(io::Error::other(
                    "select at least one of --url, --token, or --project",
                )
                .into());
            }
            if args.url {
                config.url = None;
            }
            if args.token {
                config.token = None;
            }
            if args.project {
                config.project = None;
            }
            save_cli_config(config)?;
            println!("saved {}", cli_config_path()?.display());
        }
    }
    Ok(())
}

async fn run_setup_machine(args: SetupArgs, config: &mut CliConfig) -> CliResult<()> {
    let url = normalize_url(&args.url);
    eprint!("Username: ");
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("username cannot be empty".into());
    }
    let password = read_password_hidden("Password: ")?;
    if password.is_empty() {
        return Err("password cannot be empty".into());
    }
    let default_machine = get_hostname();
    eprint!("Machine name [{}]: ", default_machine);
    let mut machine_name = String::new();
    io::stdin().read_line(&mut machine_name)?;
    let machine_name = machine_name.trim().to_string();
    let machine_name = if machine_name.is_empty() {
        default_machine
    } else {
        machine_name
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/machines/register", url))
        .json(&serde_json::json!({
            "username": username,
            "password": password,
            "machine_name": machine_name,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("registration failed ({}): {}", status, body).into());
    }
    let body: serde_json::Value = resp.json().await?;
    let token = body["token"]
        .as_str()
        .ok_or("server did not return a token")?
        .to_string();
    config.url = Some(url.clone());
    config.token = Some(token.clone());
    config.machine_name = Some(machine_name.clone());
    save_cli_config(config)?;
    println!("Registered machine \"{}\" on {}", machine_name, url);

    println!("Starting machine service...");
    let exe = resolved_current_exe()?;
    let lore_dir = service_root_dir()?;
    let log_path = lore_dir.join("service.log");
    stop_existing_service_daemons(&lore_dir).await;

    match install_or_restart_lore_machine_user_systemd_service(&exe) {
        Ok(unit_path) => {
            println!("Service installed and enabled via user systemd.");
            println!("  Unit: {}", unit_path.display());
            return Ok(());
        }
        Err(err) => {
            eprintln!(
                "warning: failed to install/start user systemd service ({err}); falling back to detached service"
            );
        }
    }

    let child = spawn_service_daemon(&exe, &url, &token, &log_path, &[])?;
    let pid = child.id();
    write_service_pid_file(&lore_dir, pid)?;
    println!("Service started (pid {})", pid);
    println!("  Log: {}", log_path.display());

    Ok(())
}

async fn run_setup_external(args: SetupExternalArgs, config: &mut CliConfig) -> CliResult<()> {
    let url = normalize_url(&args.url);
    let token = match args.token {
        Some(token) => token,
        None => read_password_hidden("External agent token: ")?,
    };
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err("token cannot be empty".into());
    }
    if token.starts_with("lore_mt_") {
        return Err(
            "setup-external expects an external agent token (lore_at_...), not a machine token; use lore setup-machine for managed machine agents"
                .into(),
        );
    }

    let project = args
        .project
        .map(|project| {
            ProjectName::new(project.clone())?;
            Ok::<String, Box<dyn Error + Send + Sync>>(project)
        })
        .transpose()?;

    let client = reqwest::Client::builder().build()?;
    let context = CliContext {
        client,
        url: url.clone(),
        token: Some(token.clone()),
        project: None,
    };
    let visible_projects = if args.no_verify {
        Vec::new()
    } else {
        let projects: Vec<ProjectSummary> = context.get_json("/v1/projects").await?;
        if let Some(project) = &project {
            let has_project = projects.iter().any(|summary| summary.project == *project);
            if !has_project {
                return Err(format!("token cannot read project {project:?}").into());
            }
        }
        projects
    };

    config.url = Some(url.clone());
    config.token = Some(token);
    config.project = project.clone();
    config.machine_name = None;
    config.agent_tokens.clear();
    save_cli_config(config)?;

    println!("Configured external-agent Lore CLI for {url}.");
    println!("saved {}", cli_config_path()?.display());
    if let Some(project) = project {
        println!("project: {project}");
    } else {
        println!("project: use `lore project set-local <project>` inside each repo.");
    }
    if !args.no_verify {
        println!("visible projects: {}", visible_projects.len());
    }
    Ok(())
}

fn run_project_command(command: ProjectCommand) -> CliResult<()> {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match command {
        ProjectCommand::Show => {
            if let Some(path) = find_cwd_project_file(&cwd) {
                let value = fs::read_to_string(&path)?;
                let project = value.trim();
                println!("project file: {}", path.display());
                if project.is_empty() {
                    println!("project: (empty)");
                } else {
                    println!("project: {project}");
                }
            } else {
                println!("No repo-local .lore/project found from {}.", cwd.display());
            }
        }
        ProjectCommand::SetLocal(args) => {
            let project = canonicalize_project_value(&args.project)?.to_string();
            let path = local_project_file_target(&cwd);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, format!("{project}\n"))?;
            let applies_to = path
                .parent()
                .and_then(Path::parent)
                .unwrap_or(cwd.as_path());
            println!(
                "Set local project '{}' for {}.",
                project,
                applies_to.display()
            );
            println!("project file: {}", path.display());
        }
        ProjectCommand::ClearLocal => {
            let Some(path) = find_cwd_project_file(&cwd) else {
                return Err(io::Error::other(
                    "no repo-local .lore/project found from current directory",
                )
                .into());
            };
            fs::remove_file(&path)?;
            println!("removed {}", path.display());
        }
    }
    Ok(())
}

async fn projects_command(context: &CliContext) -> CliResult<()> {
    let projects: Vec<ProjectSummary> = context.get_json("/v1/projects").await?;
    if projects.is_empty() {
        println!("No projects visible.");
        return Ok(());
    }
    for project in projects {
        println!("{}", project.project);
    }
    Ok(())
}

async fn overview_command(context: &CliContext) -> CliResult<()> {
    let project = context.require_project(None)?;
    let path = format!("/v1/projects/{}/reserved/_overview", project.as_str());
    let block: Block = context.get_json(&path).await?;
    if block.content.trim().is_empty() {
        println!("No overview set for {}.", project);
    } else {
        println!("{}", block.content);
    }
    Ok(())
}

async fn file_map_command(context: &CliContext, command: FileMapCommand) -> CliResult<()> {
    let project = context.require_project(None)?;
    let path = format!("/v1/projects/{}/reserved/_map", project.as_str());
    match command {
        FileMapCommand::Read => {
            let block: Block = context.get_json(&path).await?;
            if block.content.trim().is_empty() {
                println!("No file map set for {}.", project);
            } else {
                println!("{}", block.content);
            }
        }
        FileMapCommand::Update(args) => {
            let _block: Block = context
                .send_json(
                    Method::PATCH,
                    &path,
                    &serde_json::json!({ "content": args.content }),
                )
                .await?;
            println!("File map updated for {}.", project);
        }
        FileMapCommand::Edit(args) => {
            let existing: Block = context.get_json(&path).await?;
            let count = existing.content.matches(&args.old).count();
            if count == 0 {
                return Err("old string not found in file map".into());
            }
            if count > 1 {
                return Err(format!("old string found {count} times -- must be unique").into());
            }
            let new_content = existing.content.replacen(&args.old, &args.new, 1);
            let _block: Block = context
                .send_json(
                    Method::PATCH,
                    &path,
                    &serde_json::json!({ "content": new_content }),
                )
                .await?;
            println!("File map edited for {}.", project);
        }
    }
    Ok(())
}

async fn context_command(context: &CliContext) -> CliResult<()> {
    let text = context.get_text("/v1/context").await?;
    if text.trim().is_empty() {
        println!("No agent context set on any readable project.");
    } else {
        println!("{text}");
    }
    Ok(())
}

async fn run_update(command: UpdateCommand, config: &mut CliConfig) -> CliResult<()> {
    match command {
        UpdateCommand::Status => {
            println!(
                "auto update: {}",
                if config.auto_update_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("update repo: {}", config.update_repo);
            println!("update stream: {}", config.update_stream.as_str());
            println!(
                "last check: {}",
                config
                    .last_update_check
                    .map(format_time)
                    .unwrap_or_else(|| "(never)".into())
            );
        }
        UpdateCommand::Check => {
            let check = check_cli_for_updates(config).await?;
            print_update_check(&check);
            config.last_update_check = Some(OffsetDateTime::now_utc());
            save_cli_config(config)?;
        }
        UpdateCommand::Apply => {
            apply_cli_update(config).await?;
        }
        UpdateCommand::Enable(args) => {
            config.auto_update_enabled = true;
            config.update_repo = args.repo;
            config.update_stream = args.stream.into();
            save_cli_config(config)?;
            println!("saved {}", cli_config_path()?.display());
        }
        UpdateCommand::Disable => {
            config.auto_update_enabled = false;
            save_cli_config(config)?;
            println!("saved {}", cli_config_path()?.display());
        }
    }
    Ok(())
}

async fn docs_command(context: &CliContext, command: DocsCommand) -> CliResult<()> {
    match command {
        DocsCommand::List => {
            let project = context.require_project(None)?;
            let path = format!("/v1/projects/{}/documents", project.as_str());
            let resp: serde_json::Value = context.get_json(&path).await?;
            let docs = resp["documents"].as_array();
            match docs {
                Some(docs) if !docs.is_empty() => {
                    print_doc_tree(docs, 0);
                }
                _ => println!("No documents in {}.", project),
            }
        }
        DocsCommand::Read(args) => {
            let project = context.resolve_project_for_document(&args.doc_id).await?;
            let mut path = format!(
                "/v1/projects/{}/documents/{}/text",
                project.as_str(),
                args.doc_id
            );
            let mut sep = '?';
            if let Some(from) = &args.from {
                path.push_str(&format!("{}start_block_id={}", sep, from));
                sep = '&';
            }
            if let Some(to) = &args.to {
                path.push_str(&format!("{}end_block_id={}", sep, to));
            }
            let resp: serde_json::Value = context.get_json(&path).await?;
            let text = resp["content"].as_str().unwrap_or("");
            println!("{}", text);
        }
        DocsCommand::Write(args) => {
            let project = context.resolve_project_for_document(&args.doc_id).await?;
            let content = load_doc_write_content(&args)?;
            let path = format!(
                "/v1/projects/{}/documents/{}/text",
                project.as_str(),
                args.doc_id
            );
            if args.dry_run || args.diff {
                let before: serde_json::Value = context.get_json(&path).await?;
                let before_text = before["content"].as_str().unwrap_or("");
                print_project_context(&project);
                println!(
                    "{}: document {} would be rewritten.",
                    preview_label(args.dry_run),
                    args.doc_id
                );
                if args.diff {
                    print_text_diff("document", before_text, &content);
                }
                if args.dry_run {
                    return Ok(());
                }
            }
            let resp: serde_json::Value = context
                .send_json(
                    Method::PUT,
                    &path,
                    &serde_json::json!({ "content": content }),
                )
                .await?;
            let created = resp["created"].as_array().map(|a| a.len()).unwrap_or(0);
            let updated = resp["updated"].as_array().map(|a| a.len()).unwrap_or(0);
            let deleted = resp["deleted"].as_array().map(|a| a.len()).unwrap_or(0);
            print_project_context(&project);
            println!(
                "Document updated: {} created, {} updated, {} deleted.",
                created, updated, deleted
            );
        }
        DocsCommand::Append(args) => {
            let project = context.resolve_project_for_document(&args.doc_id).await?;
            let content = load_cli_text_input(
                args.content.as_ref(),
                args.file.as_ref(),
                args.stdin,
                "docs append",
            )?;
            let blocks = list_doc_blocks(context, &project, &args.doc_id).await?;
            let after_block_id = blocks.last().map(|block| block.id.as_str().to_string());
            if args.dry_run || args.diff {
                print_project_context(&project);
                println!(
                    "{}: document {} would receive a new {} block{}.",
                    preview_label(args.dry_run),
                    args.doc_id,
                    block_type_api_label(args.block_type),
                    after_block_id
                        .as_ref()
                        .map(|id| format!(" after {id}"))
                        .unwrap_or_else(|| " at start".to_string())
                );
                if args.diff {
                    print_text_diff("new block", "", &content);
                }
                if args.dry_run {
                    return Ok(());
                }
            }
            let block = create_doc_block(
                context,
                &project,
                &args.doc_id,
                args.block_type,
                content,
                after_block_id,
            )
            .await?;
            print_project_context(&project);
            println!("Appended block {}.", block.id);
        }
        DocsCommand::InsertAfterHeading(args) => {
            let project = context.resolve_project_for_document(&args.doc_id).await?;
            let content = load_cli_text_input(
                args.content.as_ref(),
                args.file.as_ref(),
                args.stdin,
                "docs insert-after-heading",
            )?;
            let blocks = list_doc_blocks(context, &project, &args.doc_id).await?;
            let anchor = find_unique_heading_block(&blocks, &args.heading)?;
            let after_block_id = Some(anchor.id.as_str().to_string());
            if args.dry_run || args.diff {
                print_project_context(&project);
                println!(
                    "{}: document {} would receive a new {} block after heading {:?} in block {}.",
                    preview_label(args.dry_run),
                    args.doc_id,
                    block_type_api_label(args.block_type),
                    args.heading,
                    anchor.id
                );
                if args.diff {
                    print_text_diff("new block", "", &content);
                }
                if args.dry_run {
                    return Ok(());
                }
            }
            let block = create_doc_block(
                context,
                &project,
                &args.doc_id,
                args.block_type,
                content,
                after_block_id,
            )
            .await?;
            print_project_context(&project);
            println!(
                "Inserted block {} after heading {:?}.",
                block.id, args.heading
            );
        }
        DocsCommand::Create(args) => {
            let project = match (&context.project, &args.parent) {
                (Some(_), _) => context.require_project(None)?,
                (None, Some(parent)) => context.resolve_project_for_document(parent).await?,
                (None, None) => context.require_project(None)?,
            };
            let path = format!("/v1/projects/{}/documents", project.as_str());
            let resp: serde_json::Value = context
                .send_json(
                    Method::POST,
                    &path,
                    &serde_json::json!({
                        "name": args.name,
                        "parent_document_id": args.parent
                    }),
                )
                .await?;
            let id = resp["id"].as_str().unwrap_or("?");
            let name = resp["name"].as_str().unwrap_or("?");
            print_project_context(&project);
            println!("Created document \"{}\" ({}).", name, id);
        }
        DocsCommand::Rename(args) => {
            let project = context.resolve_project_for_document(&args.doc_id).await?;
            let path = format!(
                "/v1/projects/{}/documents/{}",
                project.as_str(),
                args.doc_id
            );
            let _resp: serde_json::Value = context
                .send_json(
                    Method::PUT,
                    &path,
                    &serde_json::json!({ "name": args.name }),
                )
                .await?;
            print_project_context(&project);
            println!("Renamed document {} to \"{}\".", args.doc_id, args.name);
        }
        DocsCommand::Delete(args) => {
            let project = context.resolve_project_for_document(&args.doc_id).await?;
            if !args.yes {
                return Err(io::Error::other("delete requires --yes").into());
            }
            let path = format!(
                "/v1/projects/{}/documents/{}",
                project.as_str(),
                args.doc_id
            );
            context.send_no_content(Method::DELETE, &path).await?;
            print_project_context(&project);
            println!("Deleted document {}.", args.doc_id);
        }
    }
    Ok(())
}

fn print_doc_tree(docs: &[serde_json::Value], depth: usize) {
    for doc in docs {
        let id = doc["id"].as_str().unwrap_or("?");
        let name = doc["name"].as_str().unwrap_or("?");
        let indent = "  ".repeat(depth);
        println!("{}{} ({})", indent, name, id);
        if let Some(children) = doc["children"].as_array() {
            print_doc_tree(children, depth + 1);
        }
    }
}

async fn list_doc_blocks(
    context: &CliContext,
    project: &ProjectName,
    doc_id: &str,
) -> CliResult<Vec<Block>> {
    let path = format!(
        "/v1/projects/{}/documents/{}/blocks",
        project.as_str(),
        doc_id
    );
    context.get_json(&path).await
}

async fn create_doc_block(
    context: &CliContext,
    project: &ProjectName,
    doc_id: &str,
    block_type: CliBlockType,
    content: String,
    after_block_id: Option<String>,
) -> CliResult<Block> {
    let path = format!(
        "/v1/projects/{}/documents/{}/blocks",
        project.as_str(),
        doc_id
    );
    context
        .send_json(
            Method::POST,
            &path,
            &serde_json::json!({
                "block_type": block_type_api_label(block_type),
                "content": content,
                "after_block_id": after_block_id
            }),
        )
        .await
}

fn find_unique_heading_block<'a>(blocks: &'a [Block], heading: &str) -> CliResult<&'a Block> {
    let matches: Vec<&Block> = blocks
        .iter()
        .filter(|block| block.block_type == BlockType::Markdown)
        .filter(|block| {
            block
                .content
                .lines()
                .any(|line| markdown_heading_matches(line, heading))
        })
        .collect();
    match matches.as_slice() {
        [block] => Ok(*block),
        [] => Err(format!("heading {:?} not found in markdown blocks", heading).into()),
        _ => Err(format!(
            "heading {:?} matched {} blocks -- must be unique",
            heading,
            matches.len()
        )
        .into()),
    }
}

fn markdown_heading_matches(line: &str, heading: &str) -> bool {
    let trimmed_line = line.trim();
    let trimmed_heading = heading.trim();
    if trimmed_line.starts_with('#') && trimmed_line == trimmed_heading {
        return true;
    }
    let level = trimmed_line.chars().take_while(|ch| *ch == '#').count();
    if !(1..=6).contains(&level) {
        return false;
    }
    let text = trimmed_line[level..].trim();
    !text.is_empty() && text == trimmed_heading
}

fn print_project_context(project: &ProjectName) {
    println!("Project: {}", project.as_str());
}

fn preview_label(dry_run: bool) -> &'static str {
    if dry_run { "Dry run" } else { "Preview" }
}

async fn blocks_command(context: &CliContext, command: BlocksCommand) -> CliResult<()> {
    match command {
        BlocksCommand::List(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            let path = format!(
                "/v1/projects/{}/documents/{}/blocks",
                project.as_str(),
                args.doc
            );
            let mut blocks: Vec<Block> = context.get_json(&path).await?;
            blocks.truncate(args.limit.max(1));
            if blocks.is_empty() {
                println!("No blocks in document {}.", args.doc);
                return Ok(());
            }
            for block in &blocks {
                println!(
                    "{}  {:<8}  {}",
                    block.id,
                    block_type_label(block.block_type),
                    one_line_preview(&block.content, 72)
                );
            }
        }
        BlocksCommand::Read(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            let content = read_block_content(
                context,
                &project,
                &args.doc,
                &args.id,
                args.offset,
                args.limit,
            )
            .await?;
            println!("{}", content);
        }
        BlocksCommand::Around(args) => {
            let project = context.resolve_project_for_block(&args.id).await?;
            let path = format!(
                "/v1/projects/{}/blocks/{}/around?before={}&after={}",
                project.as_str(),
                args.id,
                args.before,
                args.after
            );
            let window: BlockWindow = context.get_json(&path).await?;
            for block in window.blocks {
                let marker = if block.id.as_str() == window.anchor {
                    "*"
                } else {
                    " "
                };
                println!(
                    "{} {}  {:<8}  {}",
                    marker,
                    block.id,
                    block_type_label(block.block_type),
                    one_line_preview(&block.content, 72)
                );
            }
        }
        BlocksCommand::Create(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            let content = load_cli_text_input(
                args.content.as_ref(),
                args.file.as_ref(),
                args.stdin,
                "blocks create",
            )?;
            let after_block_id = resolve_block_create_after(context, &project, &args).await?;
            if args.dry_run || args.diff {
                print_project_context(&project);
                println!(
                    "{}: document {} would receive a new {} block{}.",
                    preview_label(args.dry_run),
                    args.doc,
                    block_type_api_label(args.block_type),
                    after_block_id
                        .as_ref()
                        .map(|id| format!(" after {id}"))
                        .unwrap_or_else(|| " at start".to_string())
                );
                if args.diff {
                    print_text_diff("new block", "", &content);
                }
                if args.dry_run {
                    return Ok(());
                }
            }
            let path = format!(
                "/v1/projects/{}/documents/{}/blocks",
                project.as_str(),
                args.doc
            );
            let block: Block = context
                .send_json(
                    Method::POST,
                    &path,
                    &serde_json::json!({
                        "block_type": block_type_api_label(args.block_type),
                        "content": content,
                        "after_block_id": after_block_id
                    }),
                )
                .await?;
            print_project_context(&project);
            println!("Created block {}.", block.id);
        }
        BlocksCommand::Update(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            let content = load_cli_text_input(
                args.content.as_ref(),
                args.file.as_ref(),
                args.stdin,
                "blocks update",
            )?;
            if args.dry_run || args.diff {
                let before =
                    read_full_block_content(context, &project, &args.doc, &args.id).await?;
                print_project_context(&project);
                println!(
                    "{}: block {} would be updated.",
                    preview_label(args.dry_run),
                    args.id
                );
                if args.diff {
                    print_text_diff("block", &before, &content);
                }
                if args.dry_run {
                    return Ok(());
                }
            }
            let path = format!(
                "/v1/projects/{}/documents/{}/blocks/{}",
                project.as_str(),
                args.doc,
                args.id
            );
            let mut body = serde_json::json!({ "content": content });
            if let Some(bt) = args.block_type {
                body["block_type"] = serde_json::json!(block_type_api_label(bt));
            }
            let block: Block = context.send_json(Method::PATCH, &path, &body).await?;
            print_project_context(&project);
            println!("Updated block {}.", block.id);
        }
        BlocksCommand::Append(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            let appended = load_cli_text_input(
                args.content.as_ref(),
                args.file.as_ref(),
                args.stdin,
                "blocks append",
            )?;
            let before = read_full_block_content(context, &project, &args.doc, &args.id).await?;
            let content = append_block_content(&before, &appended, &args.separator);
            if args.dry_run || args.diff {
                print_project_context(&project);
                println!(
                    "{}: block {} would be appended.",
                    preview_label(args.dry_run),
                    args.id
                );
                if args.diff {
                    print_text_diff("block", &before, &content);
                }
                if args.dry_run {
                    return Ok(());
                }
            }
            let path = format!(
                "/v1/projects/{}/documents/{}/blocks/{}",
                project.as_str(),
                args.doc,
                args.id
            );
            let block: Block = context
                .send_json(
                    Method::PATCH,
                    &path,
                    &serde_json::json!({ "content": content }),
                )
                .await?;
            print_project_context(&project);
            println!("Appended block {}.", block.id);
        }
        BlocksCommand::Edit(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            if args.old_stdin && args.new_stdin {
                return Err("blocks edit cannot read both --old-stdin and --new-stdin from the same stdin stream; use --old-file or --new-file for one side".into());
            }
            let old_string = load_required_text_arg(
                "blocks edit",
                "old",
                args.old.as_ref(),
                args.old_file.as_ref(),
                args.old_stdin,
            )?;
            let new_string = load_required_text_arg(
                "blocks edit",
                "new",
                args.new.as_ref(),
                args.new_file.as_ref(),
                args.new_stdin,
            )?;
            let before = read_full_block_content(context, &project, &args.doc, &args.id).await?;
            let count = before.matches(&old_string).count();
            if count == 0 {
                return Err("old string not found in block".into());
            }
            if count > 1 {
                return Err(format!("old string found {count} times -- must be unique").into());
            }
            let after = before.replacen(&old_string, &new_string, 1);
            if args.dry_run || args.diff {
                print_project_context(&project);
                println!(
                    "{}: block {} would be edited.",
                    preview_label(args.dry_run),
                    args.id
                );
                if args.diff {
                    print_text_diff("block", &before, &after);
                }
                if args.dry_run {
                    return Ok(());
                }
            }
            let path = format!(
                "/v1/projects/{}/documents/{}/blocks/{}/edit",
                project.as_str(),
                args.doc,
                args.id
            );
            let block: Block = context
                .send_json(
                    Method::POST,
                    &path,
                    &serde_json::json!({
                        "old_string": old_string,
                        "new_string": new_string
                    }),
                )
                .await?;
            print_project_context(&project);
            println!("Edited block {}.", block.id);
        }
        BlocksCommand::Move(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            let path = format!(
                "/v1/projects/{}/documents/{}/blocks/{}/move",
                project.as_str(),
                args.doc,
                args.id
            );
            let block: Block = context
                .send_json(
                    Method::POST,
                    &path,
                    &serde_json::json!({ "after_block_id": args.after }),
                )
                .await?;
            print_project_context(&project);
            println!("Moved block {} to order {}.", block.id, block.order);
        }
        BlocksCommand::Delete(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            if !args.yes {
                return Err(io::Error::other("delete requires --yes").into());
            }
            let path = format!(
                "/v1/projects/{}/documents/{}/blocks/{}",
                project.as_str(),
                args.doc,
                args.id
            );
            context.send_no_content(Method::DELETE, &path).await?;
            print_project_context(&project);
            println!("Deleted block {}.", args.id);
        }
        BlocksCommand::Split(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            let path = format!(
                "/v1/projects/{}/documents/{}/blocks/{}/split",
                project.as_str(),
                args.doc,
                args.id
            );
            let resp: serde_json::Value = context
                .send_json(
                    Method::POST,
                    &path,
                    &serde_json::json!({ "position": args.position }),
                )
                .await?;
            let original = resp["original"]["id"].as_str().unwrap_or("?");
            let new_block = resp["new_block"]["id"].as_str().unwrap_or("?");
            print_project_context(&project);
            println!("Split block {} -> {} + {}.", args.id, original, new_block);
        }
        BlocksCommand::Combine(args) => {
            let project = context.resolve_project_for_document(&args.doc).await?;
            if args.ids.len() < 2 {
                return Err(io::Error::other("combine requires at least 2 block IDs").into());
            }
            let path = format!(
                "/v1/projects/{}/documents/{}/blocks/combine",
                project.as_str(),
                args.doc
            );
            let block: Block = context
                .send_json(
                    Method::POST,
                    &path,
                    &serde_json::json!({ "block_ids": args.ids }),
                )
                .await?;
            print_project_context(&project);
            println!("Combined into block {}.", block.id);
        }
    }
    Ok(())
}

async fn grep_command(context: &CliContext, args: GrepArgs) -> CliResult<()> {
    let project = context.require_project(None)?;
    let path = format!(
        "/v1/projects/{}/grep?q={}{}",
        project.as_str(),
        encode_query(&args.query),
        filter_query_suffix(&args.filters)
    );
    let mut matches: Vec<GrepMatch> = context.get_json(&path).await?;
    matches.truncate(args.limit.max(1));
    if matches.is_empty() {
        println!("No matching blocks.");
        return Ok(());
    }
    for entry in matches {
        let source = match (&entry.document_name, &entry.document_id) {
            (Some(name), Some(id)) => format!("  doc={} ({})", id, name),
            (None, Some(id)) => format!("  doc={id}"),
            _ => String::new(),
        };
        println!(
            "{}  {:<8}{}  {}",
            entry.block.id,
            block_type_label(entry.block.block_type),
            source,
            entry.preview
        );
    }
    Ok(())
}

async fn librarian_command(context: &CliContext, command: LibrarianCommand) -> CliResult<()> {
    match command {
        LibrarianCommand::Answer(args) => {
            let project = context.require_project(None)?;
            let path = format!("/v1/projects/{}/librarian/answer", project.as_str());
            let body = AskLibrarianRequest {
                question: args.question,
                block_type: args.filters.block_type.map(filter_block_type_label),
                author: args.filters.author,
                since_days: args.filters.since_days,
                max_sources: args.max_sources,
                around: args.around,
            };
            let response: LibrarianAnswerBody =
                context.send_json(Method::POST, &path, &body).await?;
            println!(
                "Answer librarian for {} at {}",
                response.project,
                format_time(response.created_at)
            );
            println!("Actor: {}", response.actor.name);
            println!("Question: {}", response.question);
            println!("Status: {}", response.status);
            if let Some(error) = response.error {
                println!("Error: {error}");
            }
            if let Some(answer) = response.answer {
                println!();
                println!("{answer}");
            }
            if !response.context_blocks.is_empty() {
                println!();
                println!("Sources:");
                for block in response.context_blocks {
                    println!(
                        "{}  {:<8}  {}",
                        block.id,
                        block_type_label(block.block_type),
                        one_line_preview(&block.content, 72)
                    );
                }
            }
        }
        LibrarianCommand::Action(args) => {
            let project = context.require_project(None)?;
            let path = format!("/v1/projects/{}/librarian/action", project.as_str());
            let body = ProjectLibrarianActionRequest {
                instruction: args.instruction,
                block_type: args.filters.block_type.map(filter_block_type_label),
                author: args.filters.author,
                since_days: args.filters.since_days,
                max_sources: args.max_sources,
                around: args.around,
            };
            let response: ProjectLibrarianActionBody =
                context.send_json(Method::POST, &path, &body).await?;
            println!(
                "Project librarian for {} at {}",
                response.project,
                format_time(response.created_at)
            );
            println!("Actor: {}", response.actor.name);
            println!("Instruction: {}", response.instruction);
            println!("Summary: {}", response.summary);
            if response.requires_approval {
                if let Some(id) = response.pending_action_id {
                    println!("Pending approval: {id}");
                } else {
                    println!("Pending approval");
                }
            } else {
                println!("Executed immediately");
            }
            if !response.operations.is_empty() {
                println!();
                println!("Operations:");
                for operation in response.operations {
                    let block = operation.block_id.unwrap_or_else(|| "(new block)".into());
                    let after = operation
                        .after_block_id
                        .map(|id| format!(" after {id}"))
                        .unwrap_or_default();
                    let block_type = operation
                        .block_type
                        .map(block_type_label)
                        .map(|value| format!(" {value}"))
                        .unwrap_or_default();
                    let preview = operation
                        .content_preview
                        .map(|value| format!(" {}", one_line_preview(&value, 64)))
                        .unwrap_or_default();
                    println!(
                        "{}  {}{}{}{}",
                        operation.operation_type, block, after, block_type, preview
                    );
                }
            }
            if !response.context_blocks.is_empty() {
                println!();
                println!("Sources:");
                for block in response.context_blocks {
                    println!(
                        "{}  {:<8}  {}",
                        block.id,
                        block_type_label(block.block_type),
                        one_line_preview(&block.content, 72)
                    );
                }
            }
        }
    }
    Ok(())
}

async fn history_command(context: &CliContext, command: HistoryCommand) -> CliResult<()> {
    match command {
        HistoryCommand::List(args) => {
            let project = context.require_project(None)?;
            let path = format!(
                "/v1/projects/{}/history?limit={}",
                project.as_str(),
                args.limit.max(1)
            );
            let history: ProjectHistorySummary = context.get_json(&path).await?;
            if history.versions.is_empty() {
                println!("No project versions recorded yet.");
                return Ok(());
            }
            for version in history.versions {
                print_version_summary(&version);
            }
        }
        HistoryCommand::Show(args) => {
            let project = context.require_project(None)?;
            let version = history_version(context, &project, &args.id).await?;
            print_version_detail(&version);
        }
        HistoryCommand::Revert(args) => {
            if !args.yes {
                return Err(io::Error::other("history revert requires --yes").into());
            }
            let project = context.require_project(None)?;
            let path = format!(
                "/v1/projects/{}/history/{}/revert",
                project.as_str(),
                args.id
            );
            let version: UiProjectVersion = context.send_empty_json(Method::POST, &path).await?;
            println!("Reverted into version {}.", version.id);
            print_version_summary(&version);
        }
    }
    Ok(())
}

async fn history_version(
    context: &CliContext,
    project: &ProjectName,
    id: &str,
) -> CliResult<UiProjectVersion> {
    let path = format!("/v1/projects/{}/history?limit=200", project.as_str());
    let history: ProjectHistorySummary = context.get_json(&path).await?;
    history
        .versions
        .into_iter()
        .find(|version| version.id == id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "version not found").into())
}

fn print_version_summary(version: &UiProjectVersion) {
    println!(
        "{}  {}  {} {}  {}",
        version.id,
        format_time(version.created_at),
        version.actor.kind,
        version.actor.name,
        version.summary
    );
    for operation in &version.operations {
        let changed = if operation.changed_fields.is_empty() {
            String::new()
        } else {
            format!(" [{}]", operation.changed_fields.join(", "))
        };
        println!(
            "  {} {}{}",
            operation.operation_type, operation.block_id, changed
        );
    }
    if let Some(commit) = &version.git_commit {
        println!("  git commit {commit}");
    }
    if let Some(error) = &version.git_export_error {
        println!("  git export error {error}");
    }
    if let Some(id) = &version.reverted_from_version_id {
        println!("  revert of {id}");
    }
    if let Some(id) = &version.reverted_by_version_id {
        println!("  reverted by {id}");
    }
    println!();
}

fn print_version_detail(version: &UiProjectVersion) {
    println!("Version: {}", version.id);
    println!("When: {}", format_time(version.created_at));
    println!("Actor: {} {}", version.actor.kind, version.actor.name);
    println!("Summary: {}", version.summary);
    if let Some(id) = &version.reverted_from_version_id {
        println!("Revert of: {id}");
    }
    if let Some(id) = &version.reverted_by_version_id {
        println!("Reverted by: {id}");
    }
    if let Some(commit) = &version.git_commit {
        println!("Git commit: {commit}");
    }
    if let Some(error) = &version.git_export_error {
        println!("Git export error: {error}");
    }
    println!();
    for operation in &version.operations {
        println!("{} {}", operation.operation_type, operation.block_id);
        if !operation.changed_fields.is_empty() {
            println!("Changed: {}", operation.changed_fields.join(", "));
        }
        print_meta_change(
            "Type",
            &operation.before_block_type,
            &operation.after_block_type,
        );
        print_meta_change("Order", &operation.before_order, &operation.after_order);
        print_meta_change(
            "Media",
            &operation.before_media_type,
            &operation.after_media_type,
        );
        if let Some(value) = &operation.before_preview {
            println!("Before: {}", value);
        }
        if let Some(value) = &operation.after_preview {
            println!("After: {}", value);
        }
        if !operation.diff_lines.is_empty() {
            println!("Diff:");
            for line in &operation.diff_lines {
                let prefix = match line.kind.as_str() {
                    "added" => "+",
                    "removed" => "-",
                    _ => " ",
                };
                println!("  {} {}", prefix, line.text);
            }
        }
        println!();
    }
}

fn print_meta_change(label: &str, before: &Option<String>, after: &Option<String>) {
    match (before.as_deref(), after.as_deref()) {
        (Some(left), Some(right)) if left != right => println!("{label}: {left} -> {right}"),
        (None, Some(right)) => println!("{label}: (none) -> {right}"),
        (Some(left), None) => println!("{label}: {left} -> (none)"),
        _ => {}
    }
}

fn print_block(block: &Block, include_blank_line: bool) {
    println!("Id: {}", block.id);
    println!("Project: {}", block.project);
    println!("Type: {}", block_type_label(block.block_type));
    println!("Order: {}", block.order);
    println!("Author: {}", block.author.as_str());
    println!("Created: {}", format_time(block.created_at));
    if let Some(media_type) = &block.media_type {
        println!("Media: {media_type}");
    }
    println!();
    println!("{}", block.content);
    if include_blank_line {
        println!();
    }
}

fn build_context(cli: &Cli, config: &CliConfig) -> CliResult<CliContext> {
    let url = cli
        .url
        .clone()
        .or_else(|| env::var("LORE_URL").ok())
        .or_else(|| config.url.clone())
        .unwrap_or_else(|| "http://127.0.0.1:7043".into());
    let token = cli
        .token
        .clone()
        .or_else(|| env::var("LORE_AGENT_TOKEN").ok())
        .or_else(|| env::var("LORE_TOKEN").ok())
        .or_else(|| config.token.clone());
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let project = resolve_context_project(cli, &cwd);
    if let Some(resolved) = &project {
        if let ProjectSource::LocalFile(path) = &resolved.source {
            eprintln!(
                "loaded project '{}' from {}",
                resolved.value,
                path.display()
            );
        }
    }
    Ok(CliContext {
        client: reqwest::Client::builder().build()?,
        url: normalize_url(&url),
        token,
        project: project.map(|resolved| resolved.value),
    })
}

impl CliContext {
    fn require_project(&self, project: Option<String>) -> CliResult<ProjectName> {
        let value = project.or_else(|| self.project.clone()).ok_or_else(|| {
            io::Error::other(
                "set --project, set LORE_PROJECT, or create .lore/project in this repo",
            )
        })?;
        // Try as slug first; if that fails, slugify the display name
        match ProjectName::new(&value) {
            Ok(name) => Ok(name),
            Err(_) => {
                let slug = slugify(&value);
                Ok(ProjectName::new(slug)?)
            }
        }
    }

    fn require_token(&self) -> CliResult<&str> {
        self.token.as_deref().ok_or_else(|| {
            io::Error::other(
                "run `lore setup-external <url> --token <token>`, set --token, or set LORE_TOKEN",
            )
            .into()
        })
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> CliResult<T> {
        self.send(Method::GET, path, None::<&()>).await
    }

    async fn resolve_project_for_document(&self, doc_id: &str) -> CliResult<ProjectName> {
        if let Some(project) = &self.project {
            return self.require_project(Some(project.clone()));
        }
        let response: ProjectResolutionResponse = self
            .get_json(&format!("/v1/documents/{}/project", doc_id))
            .await?;
        self.require_project(Some(response.project))
    }

    async fn resolve_project_for_block(&self, block_id: &str) -> CliResult<ProjectName> {
        if let Some(project) = &self.project {
            return self.require_project(Some(project.clone()));
        }
        let response: ProjectResolutionResponse = self
            .get_json(&format!("/v1/blocks/{}/project", block_id))
            .await?;
        self.require_project(Some(response.project))
    }

    async fn get_text(&self, path: &str) -> CliResult<String> {
        let url = format!("{}{}", self.url, path);
        let response = self
            .client
            .get(url)
            .bearer_auth(self.require_token()?)
            .send()
            .await?;
        if response.status().is_success() {
            return Ok(response.text().await?);
        }
        Err(response_error(response).await.into())
    }

    async fn send_json<T: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: &B,
    ) -> CliResult<T> {
        self.send(method, path, Some(body)).await
    }

    async fn send_empty_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
    ) -> CliResult<T> {
        self.send::<T, ()>(method, path, None).await
    }

    async fn send_no_content(&self, method: Method, path: &str) -> CliResult<()> {
        let url = format!("{}{}", self.url, path);
        let mut request = self.client.request(method, url);
        request = request.bearer_auth(self.require_token()?);
        let response = request.send().await?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(());
        }
        Err(response_error(response).await.into())
    }

    async fn send<T: DeserializeOwned, B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> CliResult<T> {
        let url = format!("{}{}", self.url, path);
        let mut request = self.client.request(method, url);
        request = request.bearer_auth(self.require_token()?);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await?;
        if response.status().is_success() {
            return Ok(response.json().await?);
        }
        Err(response_error(response).await.into())
    }
}

async fn response_error(response: reqwest::Response) -> io::Error {
    let status = response.status();
    let detail = response
        .json::<ErrorBody>()
        .await
        .map(|body| body.error)
        .unwrap_or_else(|_| status.to_string());
    io::Error::other(detail)
}

async fn maybe_auto_update_cli(config: &mut CliConfig) -> CliResult<()> {
    if !config.auto_update_enabled || env::var_os(CLI_SELF_UPDATE_SKIP_ENV).is_some() {
        return Ok(());
    }
    let now = OffsetDateTime::now_utc();
    if config
        .last_update_check
        .is_some_and(|value| now - value < time::Duration::seconds(CLI_AUTO_UPDATE_INTERVAL_SECS))
    {
        return Ok(());
    }
    match apply_cli_update(config).await {
        Ok(()) => {}
        Err(err) => eprintln!("warning: CLI self-update check failed: {err}"),
    }
    config.last_update_check = Some(now);
    save_cli_config(config)?;
    Ok(())
}

async fn check_cli_for_updates(config: &CliConfig) -> CliResult<lore_core::updater::UpdateCheck> {
    let client = reqwest::Client::new();
    check_for_update(
        &client,
        "lore",
        env!("CARGO_PKG_VERSION"),
        &config.update_repo,
        config.update_stream,
    )
    .await
    .map_err(|err| io::Error::other(err.to_string()).into())
}

async fn apply_cli_update(config: &mut CliConfig) -> CliResult<()> {
    apply_cli_update_with_source(config, config.update_repo.clone(), config.update_stream).await
}

fn resolved_current_exe() -> io::Result<PathBuf> {
    let p = env::current_exe()?;
    let s = p.to_string_lossy();
    if s.ends_with(" (deleted)") {
        Ok(PathBuf::from(&s[..s.len() - " (deleted)".len()]))
    } else {
        Ok(p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceUpdateFailureState {
    target_version: String,
    failures: u32,
    next_retry_at: OffsetDateTime,
    last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceHandoffReadyMarker {
    pid: u32,
    version: String,
}

#[derive(Debug, Clone)]
struct PreparedServiceUpdate {
    staged_executable: PathBuf,
    canonical_executable: PathBuf,
    target_version: String,
    source: &'static str,
}

#[derive(Debug, Clone)]
struct ServiceHandoff {
    ready_path: PathBuf,
    parent_pid: u32,
    canonical_executable: PathBuf,
    target_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceHandoffCompletion {
    ContinueUnmanaged,
    TransferredToSystemd,
}

#[derive(Debug, Clone, Copy)]
struct MachineServiceReadyStatus {
    update_requested: bool,
}

fn normalize_version_tag(value: &str) -> String {
    value.trim().trim_start_matches('v').to_string()
}

fn parse_cli_version_output(output: &str) -> Option<String> {
    output
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.split_whitespace().last())
        .map(normalize_version_tag)
}

fn read_binary_version(path: &Path) -> CliResult<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "version check failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
        .into());
    }
    parse_cli_version_output(&String::from_utf8_lossy(&output.stdout)).ok_or_else(|| {
        io::Error::other(format!("could not parse version from {}", path.display())).into()
    })
}

fn verify_binary_matches_target(path: &Path, target_version: &str) -> CliResult<()> {
    let actual = read_binary_version(path)?;
    let expected = normalize_version_tag(target_version);
    if actual != expected {
        return Err(io::Error::other(format!(
            "staged binary version mismatch: expected {expected}, got {actual}"
        ))
        .into());
    }
    Ok(())
}

fn write_executable_atomically(path: &Path, bytes: &[u8]) -> CliResult<()> {
    let tmp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    fs::write(&tmp_path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755))?;
    }
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn service_versions_dir(lore_dir: &Path) -> PathBuf {
    lore_dir.join("versions")
}

fn service_staged_binary_path(lore_dir: &Path, target_version: &str) -> CliResult<PathBuf> {
    let target = service_update_target()?;
    Ok(service_versions_dir(lore_dir)
        .join(normalize_version_tag(target_version))
        .join(format!("lore-{target}")))
}

fn service_update_failure_path(lore_dir: &Path) -> PathBuf {
    lore_dir.join("update-failure.json")
}

fn load_service_update_failure(lore_dir: &Path) -> Option<ServiceUpdateFailureState> {
    let path = service_update_failure_path(lore_dir);
    let data = fs::read(path).ok()?;
    serde_json::from_slice(&data).ok()
}

fn next_service_update_retry_delay_secs(failures: u32) -> i64 {
    std::cmp::min(5 * (1i64 << failures.saturating_sub(1)), 300)
}

fn current_service_update_backoff(
    lore_dir: &Path,
    target_version: &str,
) -> Option<std::time::Duration> {
    let state = load_service_update_failure(lore_dir)?;
    if state.target_version != normalize_version_tag(target_version) {
        return None;
    }
    let remaining = (state.next_retry_at - OffsetDateTime::now_utc()).whole_seconds();
    if remaining <= 0 {
        return None;
    }
    Some(std::time::Duration::from_secs(remaining as u64))
}

fn record_service_update_failure(lore_dir: &Path, target_version: &str, error: &str) {
    let path = service_update_failure_path(lore_dir);
    let normalized_target = normalize_version_tag(target_version);
    let failures = load_service_update_failure(lore_dir)
        .filter(|state| state.target_version == normalized_target)
        .map(|state| state.failures.saturating_add(1))
        .unwrap_or(1);
    let next_retry_at = OffsetDateTime::now_utc()
        + TimeDuration::seconds(next_service_update_retry_delay_secs(failures));
    let state = ServiceUpdateFailureState {
        target_version: normalized_target,
        failures,
        next_retry_at,
        last_error: error.to_string(),
    };
    if let Ok(bytes) = serde_json::to_vec_pretty(&state) {
        let _ = fs::write(path, bytes);
    }
}

fn clear_service_update_failure(lore_dir: &Path) {
    let _ = fs::remove_file(service_update_failure_path(lore_dir));
}

async fn service_ready_check(
    context: &CliContext,
    machine_token: &str,
) -> CliResult<MachineServiceReadyStatus> {
    let body: serde_json::Value = context
        .client
        .post(format!("{}/v1/machines/ready", context.url))
        .header("x-lore-key", machine_token)
        .header("x-lore-version", env!("CARGO_PKG_VERSION"))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(MachineServiceReadyStatus {
        update_requested: body["update_requested"].as_bool().unwrap_or(false),
    })
}

fn wait_for_handoff_ready_marker(
    ready_path: &Path,
    timeout: std::time::Duration,
) -> CliResult<ServiceHandoffReadyMarker> {
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if let Ok(bytes) = fs::read(ready_path) {
            let marker: ServiceHandoffReadyMarker = serde_json::from_slice(&bytes)?;
            return Ok(marker);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err(io::Error::other(format!(
        "timed out waiting for new service readiness marker at {}",
        ready_path.display()
    ))
    .into())
}

fn promote_staged_binary_to_canonical(
    staged_executable: &Path,
    canonical_executable: &Path,
) -> CliResult<()> {
    if staged_executable == canonical_executable {
        return Ok(());
    }
    let bytes = fs::read(staged_executable)?;
    if let Some(parent) = canonical_executable.parent() {
        fs::create_dir_all(parent)?;
    }
    write_executable_atomically(canonical_executable, &bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostPlatform {
    Unix,
    Windows,
}

fn host_platform() -> HostPlatform {
    if cfg!(windows) {
        HostPlatform::Windows
    } else {
        HostPlatform::Unix
    }
}

fn non_empty_env_os<F>(env_var: &mut F, name: &str) -> Option<OsString>
where
    F: FnMut(&str) -> Option<OsString>,
{
    env_var(name).filter(|value| !value.as_os_str().is_empty())
}

fn env_path<F>(env_var: &mut F, name: &str) -> Option<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    non_empty_env_os(env_var, name).map(PathBuf::from)
}

fn user_home_dir_from_env<F>(platform: HostPlatform, env_var: &mut F) -> Option<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    if let Some(home) = env_path(env_var, "HOME") {
        return Some(home);
    }
    if platform == HostPlatform::Windows {
        if let Some(profile) = env_path(env_var, "USERPROFILE") {
            return Some(profile);
        }
        let drive = non_empty_env_os(env_var, "HOMEDRIVE");
        let path = non_empty_env_os(env_var, "HOMEPATH");
        if let (Some(mut drive), Some(path)) = (drive, path) {
            drive.push(path);
            return Some(PathBuf::from(drive));
        }
    }
    None
}

fn legacy_service_root_dir_from_env<F>(platform: HostPlatform, mut env_var: F) -> PathBuf
where
    F: FnMut(&str) -> Option<OsString>,
{
    user_home_dir_from_env(platform, &mut env_var)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("lore-service")
}

fn service_root_dir_from_env<F>(platform: HostPlatform, mut env_var: F) -> PathBuf
where
    F: FnMut(&str) -> Option<OsString>,
{
    if let Some(dir) = env_path(&mut env_var, "LORE_SERVICE_DIR") {
        return dir;
    }
    user_home_dir_from_env(platform, &mut env_var)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".lore-service")
}

fn legacy_service_root_dir() -> PathBuf {
    legacy_service_root_dir_from_env(host_platform(), |name| env::var_os(name))
}

fn service_root_dir() -> CliResult<PathBuf> {
    let hidden_dir = service_root_dir_from_env(host_platform(), |name| env::var_os(name));
    let legacy_dir = legacy_service_root_dir();

    if !hidden_dir.exists() && legacy_dir.exists() {
        fs::rename(&legacy_dir, &hidden_dir).map_err(|e| {
            io::Error::other(format!(
                "failed to migrate service directory from {} to {}: {e}",
                legacy_dir.display(),
                hidden_dir.display()
            ))
        })?;
    }

    fs::create_dir_all(&hidden_dir)?;
    Ok(hidden_dir)
}

fn user_systemd_unit_dir_from_env<F>(platform: HostPlatform, mut env_var: F) -> Option<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    if platform != HostPlatform::Unix {
        return None;
    }
    if let Some(xdg_config_home) = env_path(&mut env_var, "XDG_CONFIG_HOME") {
        return Some(xdg_config_home.join("systemd").join("user"));
    }
    user_home_dir_from_env(platform, &mut env_var)
        .map(|home| home.join(".config").join("systemd").join("user"))
}

fn lore_machine_user_systemd_unit_path_from_env<F>(
    platform: HostPlatform,
    env_var: F,
) -> Option<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    user_systemd_unit_dir_from_env(platform, env_var).map(|dir| dir.join(LORE_MACHINE_SERVICE_NAME))
}

fn lore_machine_user_systemd_unit_path() -> Option<PathBuf> {
    lore_machine_user_systemd_unit_path_from_env(host_platform(), |name| env::var_os(name))
}

fn lore_machine_systemd_unit(exe: &Path, working_dir: &Path) -> String {
    format!(
        "[Unit]\n\
Description=Lore machine service\n\n\
[Service]\n\
Type=simple\n\
Environment={LORE_SERVICE_DAEMON_ENV}=1\n\
Environment={LORE_SERVICE_SYSTEMD_ENV}=1\n\
WorkingDirectory={}\n\
ExecStart={} service --fg\n\
Restart=on-failure\n\
RestartSec=10\n\n\
[Install]\n\
WantedBy=default.target\n",
        working_dir.display(),
        exe.display()
    )
}

fn write_lore_machine_user_systemd_unit(exe: &Path, working_dir: &Path) -> CliResult<PathBuf> {
    let unit_path = lore_machine_user_systemd_unit_path()
        .ok_or_else(|| io::Error::other("user systemd units are not available on this platform"))?;
    if let Some(parent) = unit_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&unit_path, lore_machine_systemd_unit(exe, working_dir))?;
    Ok(unit_path)
}

fn run_systemctl_user(args: &[&str]) -> CliResult<()> {
    let output = std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    Err(io::Error::other(format!(
        "systemctl --user {} failed: {detail}",
        args.join(" ")
    ))
    .into())
}

fn enable_user_linger_best_effort() {
    #[cfg(target_os = "linux")]
    {
        let Some(user) = env::var_os("USER") else {
            return;
        };
        let status = std::process::Command::new("loginctl")
            .arg("enable-linger")
            .arg(user)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if matches!(status, Ok(status) if !status.success()) {
            eprintln!(
                "warning: could not enable systemd lingering; the service may start only after login"
            );
        }
    }
}

fn service_systemd_working_dir() -> CliResult<PathBuf> {
    match service_home_dir() {
        Ok(path) => Ok(path),
        Err(_) => Ok(env::current_dir()?),
    }
}

fn install_or_restart_lore_machine_user_systemd_service(exe: &Path) -> CliResult<PathBuf> {
    let working_dir = service_systemd_working_dir()?;
    let unit_path = write_lore_machine_user_systemd_unit(exe, &working_dir)?;
    run_systemctl_user(&["daemon-reload"])?;
    enable_user_linger_best_effort();
    run_systemctl_user(&["enable", LORE_MACHINE_SERVICE_NAME])?;
    run_systemctl_user(&["restart", LORE_MACHINE_SERVICE_NAME])?;
    Ok(unit_path)
}

fn restart_existing_lore_machine_user_systemd_service(exe: &Path) -> CliResult<bool> {
    let Some(unit_path) = lore_machine_user_systemd_unit_path() else {
        return Ok(false);
    };
    if !unit_path.exists() {
        return Ok(false);
    }
    let working_dir = service_systemd_working_dir()?;
    let unit_path = write_lore_machine_user_systemd_unit(exe, &working_dir)?;
    run_systemctl_user(&["daemon-reload"])?;
    run_systemctl_user(&["enable", LORE_MACHINE_SERVICE_NAME])?;
    run_systemctl_user(&["restart", LORE_MACHINE_SERVICE_NAME])?;
    eprintln!(
        "[service] Restarted existing user systemd unit at {}",
        unit_path.display()
    );
    Ok(true)
}

fn cgroup_text_contains_systemd_unit(cgroup_text: &str, unit_name: &str) -> bool {
    let escaped_unit_name = unit_name.replace('-', "\\x2d");
    cgroup_text.contains(unit_name) || cgroup_text.contains(&escaped_unit_name)
}

fn current_process_in_systemd_unit(unit_name: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/proc/self/cgroup")
            .map(|text| cgroup_text_contains_systemd_unit(&text, unit_name))
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = unit_name;
        false
    }
}

fn write_service_pid_file(lore_dir: &Path, pid: u32) -> CliResult<()> {
    fs::write(lore_dir.join("service.pid"), pid.to_string())?;
    Ok(())
}

fn remove_owned_service_pid_file(lore_dir: &Path, pid: u32) {
    let pid_path = lore_dir.join("service.pid");
    let Ok(contents) = fs::read_to_string(&pid_path) else {
        return;
    };
    let Ok(recorded_pid) = contents.trim().parse::<u32>() else {
        return;
    };
    if recorded_pid == pid {
        let _ = fs::remove_file(pid_path);
    }
}

async fn stop_existing_service_daemons(lore_dir: &Path) {
    let pid_path = lore_dir.join("service.pid");
    if pid_path.exists() {
        if let Ok(pid_str) = fs::read_to_string(&pid_path)
            && let Ok(pid) = pid_str.trim().parse::<u32>()
            && is_process_running(pid)
        {
            eprintln!("Stopping existing service (pid {})", pid);
            kill_process(pid);
        }
        let _ = fs::remove_file(&pid_path);
    }
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("pkill")
            .args(["-f", "lore.*service.*--fg"])
            .status();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

fn service_handoff_from_env() -> CliResult<Option<ServiceHandoff>> {
    let Some(ready_path) = env::var_os(LORE_SERVICE_HANDOFF_READY_ENV) else {
        return Ok(None);
    };
    let parent_pid = env::var(LORE_SERVICE_HANDOFF_PARENT_PID_ENV)?
        .parse::<u32>()
        .map_err(|e| io::Error::other(format!("invalid handoff parent pid: {e}")))?;
    let canonical_executable = PathBuf::from(
        env::var(LORE_SERVICE_HANDOFF_CANONICAL_EXE_ENV)
            .map_err(|e| io::Error::other(format!("missing canonical exe for handoff: {e}")))?,
    );
    let target_version = env::var(LORE_SERVICE_HANDOFF_TARGET_VERSION_ENV)
        .map_err(|e| io::Error::other(format!("missing target version for handoff: {e}")))?;
    Ok(Some(ServiceHandoff {
        ready_path: PathBuf::from(ready_path),
        parent_pid,
        canonical_executable,
        target_version,
    }))
}

async fn complete_service_handoff(
    context: &CliContext,
    machine_token: &str,
    lore_dir: &Path,
    handoff: &ServiceHandoff,
) -> CliResult<ServiceHandoffCompletion> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let status = service_ready_check(context, machine_token).await?;
        if !status.update_requested {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "new service still seen as outdated after waiting for v{}",
                handoff.target_version
            ))
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let marker = ServiceHandoffReadyMarker {
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    fs::write(&handoff.ready_path, serde_json::to_vec(&marker)?)?;
    eprintln!(
        "[service] Standby update service is ready on v{}, waiting for old pid {} to exit",
        marker.version, handoff.parent_pid
    );

    let parent_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while is_process_running(handoff.parent_pid) {
        if std::time::Instant::now() >= parent_deadline {
            return Err(io::Error::other(format!(
                "old service pid {} did not exit after handoff",
                handoff.parent_pid
            ))
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    let staged_executable = resolved_current_exe()?;
    promote_staged_binary_to_canonical(&staged_executable, &handoff.canonical_executable)?;
    let _ = fs::remove_file(&handoff.ready_path);
    match restart_existing_lore_machine_user_systemd_service(&handoff.canonical_executable) {
        Ok(true) => {
            remove_owned_service_pid_file(lore_dir, std::process::id());
            Ok(ServiceHandoffCompletion::TransferredToSystemd)
        }
        Ok(false) => Ok(ServiceHandoffCompletion::ContinueUnmanaged),
        Err(err) => {
            eprintln!(
                "[service] Could not transfer handoff back to user systemd; continuing unmanaged: {err}"
            );
            Ok(ServiceHandoffCompletion::ContinueUnmanaged)
        }
    }
}

fn reuse_or_clear_staged_binary(staged_path: &Path, target_version: &str) -> CliResult<bool> {
    if !staged_path.exists() {
        return Ok(false);
    }

    match verify_binary_matches_target(staged_path, target_version) {
        Ok(()) => Ok(true),
        Err(err) => {
            eprintln!(
                "[service] Discarding invalid staged binary at {}: {err}",
                staged_path.display()
            );
            let _ = fs::remove_file(staged_path);
            Ok(false)
        }
    }
}

fn resolve_context_project(cli: &Cli, cwd: &Path) -> Option<ResolvedProject> {
    cli.project
        .clone()
        .map(|value| ResolvedProject {
            value,
            source: ProjectSource::Flag,
        })
        .or_else(|| {
            env::var("LORE_PROJECT").ok().map(|value| ResolvedProject {
                value,
                source: ProjectSource::Env,
            })
        })
        .or_else(|| resolve_cwd_project(cwd))
}

fn canonicalize_project_value(value: &str) -> CliResult<ProjectName> {
    match ProjectName::new(value) {
        Ok(name) => Ok(name),
        Err(_) => Ok(ProjectName::new(slugify(value))?),
    }
}

fn resolve_cwd_project(cwd: &Path) -> Option<ResolvedProject> {
    let path = find_cwd_project_file(cwd)?;
    let value = fs::read_to_string(&path).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(ResolvedProject {
        value: trimmed.to_string(),
        source: ProjectSource::LocalFile(path),
    })
}

fn find_cwd_project_file(cwd: &Path) -> Option<PathBuf> {
    for dir in cwd.ancestors() {
        let candidate = dir.join(".lore").join("project");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn local_project_file_target(cwd: &Path) -> PathBuf {
    find_cwd_project_file(cwd).unwrap_or_else(|| cwd.join(".lore").join("project"))
}

async fn read_block_content(
    context: &CliContext,
    project: &ProjectName,
    doc_id: &str,
    block_id: &str,
    offset: Option<usize>,
    limit: Option<usize>,
) -> CliResult<String> {
    match (offset, limit) {
        (Some(offset), limit) => {
            read_single_block_chunk(context, project, doc_id, block_id, offset, limit).await
        }
        (None, Some(limit)) => {
            read_single_block_chunk(context, project, doc_id, block_id, 0, Some(limit)).await
        }
        (None, None) => read_full_block_content(context, project, doc_id, block_id).await,
    }
}

async fn read_full_block_content(
    context: &CliContext,
    project: &ProjectName,
    doc_id: &str,
    block_id: &str,
) -> CliResult<String> {
    const CHUNK_LINES: usize = 256;

    let first_chunk =
        read_doc_block_chunk(context, project, doc_id, block_id, 0, Some(CHUNK_LINES)).await?;
    if first_chunk.total_lines <= first_chunk.limit {
        return decode_numbered_block_chunk(&first_chunk.content);
    }

    let mut parts = Vec::new();
    parts.push(decode_numbered_block_chunk(&first_chunk.content)?);
    let mut next_offset = first_chunk.offset + first_chunk.limit;
    while next_offset < first_chunk.total_lines {
        let chunk = read_doc_block_chunk(
            context,
            project,
            doc_id,
            block_id,
            next_offset,
            Some(CHUNK_LINES),
        )
        .await?;
        parts.push(decode_numbered_block_chunk(&chunk.content)?);
        if chunk.limit == 0 {
            break;
        }
        next_offset = chunk.offset + chunk.limit;
    }
    Ok(parts.join("\n"))
}

async fn read_single_block_chunk(
    context: &CliContext,
    project: &ProjectName,
    doc_id: &str,
    block_id: &str,
    offset: usize,
    limit: Option<usize>,
) -> CliResult<String> {
    let chunk = read_doc_block_chunk(context, project, doc_id, block_id, offset, limit).await?;
    decode_numbered_block_chunk(&chunk.content)
}

async fn read_doc_block_chunk(
    context: &CliContext,
    project: &ProjectName,
    doc_id: &str,
    block_id: &str,
    offset: usize,
    limit: Option<usize>,
) -> CliResult<DocBlockChunkResponse> {
    let mut path = format!(
        "/v1/projects/{}/documents/{}/blocks/{}?offset={}",
        project.as_str(),
        doc_id,
        block_id,
        offset
    );
    if let Some(limit) = limit {
        path.push_str("&limit=");
        path.push_str(&limit.to_string());
    }
    context.get_json(&path).await
}

fn decode_numbered_block_chunk(content: &str) -> CliResult<String> {
    let mut lines = Vec::new();
    for line in content.lines() {
        let (prefix, body) = line
            .split_once('\t')
            .ok_or_else(|| io::Error::other("invalid block chunk response: missing line number"))?;
        if prefix.parse::<usize>().is_err() {
            return Err(
                io::Error::other("invalid block chunk response: malformed line number").into(),
            );
        }
        lines.push(body);
    }
    Ok(lines.join("\n"))
}

async fn stage_binary_from_server(
    context: &CliContext,
    machine_token: &str,
    target_version: &str,
    staged_path: &Path,
) -> CliResult<bool> {
    if reuse_or_clear_staged_binary(staged_path, target_version)? {
        return Ok(true);
    }

    eprintln!("[service] Trying direct binary download from server...");
    let target = match service_update_target() {
        Ok(target) => target,
        Err(err) => {
            eprintln!("[service] Could not determine target-specific update path: {err}");
            return Ok(false);
        }
    };
    let url = format!("{}/v1/machines/binary/{target}", context.url);

    let resp = match context
        .client
        .get(&url)
        .header("x-lore-key", machine_token)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("[service] Server binary download failed: {e}");
            return Ok(false);
        }
    };
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        eprintln!("[service] No staged binary for target {target} on server, will try GitHub");
        return Ok(false);
    }
    if !resp.status().is_success() {
        eprintln!(
            "[service] Server binary download returned {}",
            resp.status()
        );
        return Ok(false);
    }

    let expected_sha = resp
        .headers()
        .get("x-lore-binary-sha256")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let served_version = resp
        .headers()
        .get("x-lore-binary-version")
        .and_then(|value| value.to_str().ok())
        .map(normalize_version_tag);
    let normalized_target = normalize_version_tag(target_version);
    if let Some(ref served_version) = served_version {
        if served_version != &normalized_target {
            return Err(io::Error::other(format!(
                "server served wrong version header for update: expected {normalized_target}, got {served_version}"
            ))
            .into());
        }
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| io::Error::other(format!("failed to read binary response: {e}")))?;
    if bytes.len() < 1024 {
        return Err(io::Error::other(format!("server binary too small ({}b)", bytes.len())).into());
    }
    if let Some(expected_sha) = expected_sha {
        let actual_sha = hex_sha256(&bytes);
        if actual_sha != expected_sha {
            return Err(io::Error::other(format!(
                "server binary checksum mismatch: expected {expected_sha}, got {actual_sha}"
            ))
            .into());
        }
    }

    if let Some(parent) = staged_path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_executable_atomically(staged_path, &bytes)?;
    verify_binary_matches_target(staged_path, target_version)?;
    eprintln!(
        "[service] Downloaded and verified staged server binary at {}",
        staged_path.display()
    );
    Ok(true)
}

async fn prepare_service_update(
    context: &CliContext,
    machine_token: &str,
    target_version: &str,
    repo: &str,
    lore_dir: &Path,
) -> CliResult<PreparedServiceUpdate> {
    let canonical_executable = resolved_current_exe()?;
    let staged_executable = service_staged_binary_path(lore_dir, target_version)?;
    let normalized_target = normalize_version_tag(target_version);

    let source =
        if stage_binary_from_server(context, machine_token, target_version, &staged_executable)
            .await?
        {
            "server"
        } else {
            let _ = reuse_or_clear_staged_binary(&staged_executable, target_version)?;
            let client = reqwest::Client::new();
            download_update_to_path(
                &client,
                "lore",
                env!("CARGO_PKG_VERSION"),
                target_version,
                repo,
                &staged_executable,
            )
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
            verify_binary_matches_target(&staged_executable, target_version)?;
            "github"
        };

    Ok(PreparedServiceUpdate {
        staged_executable,
        canonical_executable,
        target_version: normalized_target,
        source,
    })
}

fn service_update_target() -> io::Result<String> {
    let arch = match env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => {
            return Err(io::Error::other(format!(
                "unsupported architecture for direct server update: {other}"
            )));
        }
    };
    let os = match env::consts::OS {
        "linux" => "unknown-linux-gnu",
        "macos" => "apple-darwin",
        other => {
            return Err(io::Error::other(format!(
                "unsupported operating system for direct server update: {other}"
            )));
        }
    };
    Ok(format!("{arch}-{os}"))
}

async fn apply_cli_update_with_source(
    config: &mut CliConfig,
    repo: String,
    stream: ReleaseStream,
) -> CliResult<()> {
    let client = reqwest::Client::new();
    let executable_path = resolved_current_exe()?;
    match maybe_apply_self_update(
        &client,
        "lore",
        env!("CARGO_PKG_VERSION"),
        &repo,
        stream,
        &executable_path,
    )
    .await
    .map_err(|err| io::Error::other(err.to_string()))?
    {
        SelfUpdateOutcome::UpToDate(status) => {
            println!("{}", status.detail);
            config.update_repo = repo.clone();
            config.update_stream = stream;
            config.last_update_check = Some(status.checked_at);
            save_cli_config(config)?;
        }
        SelfUpdateOutcome::Updated(status) => {
            println!("{}", status.detail);
            config.update_repo = repo;
            config.update_stream = stream;
            config.last_update_check = Some(status.checked_at);
            save_cli_config(config)?;
            relaunch_cli(&executable_path);
        }
    }
    Ok(())
}

fn relaunch_cli(executable_path: &Path) -> ! {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let mut command = std::process::Command::new(executable_path);
    command.args(args);
    command.env(CLI_SELF_UPDATE_SKIP_ENV, "1");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = command.exec();
        eprintln!("error: failed to relaunch updated CLI: {err}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        match command.spawn() {
            Ok(_) => std::process::exit(0),
            Err(err) => {
                eprintln!("error: failed to relaunch updated CLI: {err}");
                std::process::exit(1);
            }
        }
    }
}

fn spawn_service_daemon(
    exe: &Path,
    url: &str,
    token: &str,
    log_path: &Path,
    extra_env: &[(&str, String)],
) -> CliResult<std::process::Child> {
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let mut command = std::process::Command::new(exe);
    command
        .args(["--url", url, "--token", token, "service", "--fg"])
        .env(LORE_SERVICE_DAEMON_ENV, "1")
        .env_remove(LORE_SERVICE_SYSTEMD_ENV)
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .stdin(std::process::Stdio::null());
    for (key, value) in extra_env {
        command.env(key, value);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    Ok(command.spawn()?)
}

fn print_update_check(check: &lore_core::updater::UpdateCheck) {
    println!("current version: {}", check.current_version);
    println!("latest version: {}", check.latest_version);
    println!(
        "status: {}",
        if check.needs_update {
            "update available"
        } else {
            "up to date"
        }
    );
    println!("detail: {}", check.detail);
}

fn load_cli_config() -> CliResult<CliConfig> {
    let path = cli_config_path()?;
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn save_cli_config(config: &CliConfig) -> CliResult<()> {
    let path = cli_config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(config)?)?;
    Ok(())
}

fn cli_config_path_from_env<F>(platform: HostPlatform, mut env_var: F) -> CliResult<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    if let Some(value) = env_path(&mut env_var, "XDG_CONFIG_HOME") {
        return Ok(value.join("lore").join("config.json"));
    }
    if let Some(home) = env_path(&mut env_var, "HOME") {
        return Ok(home.join(".config").join("lore").join("config.json"));
    }
    if platform == HostPlatform::Windows {
        if let Some(value) = env_path(&mut env_var, "APPDATA") {
            return Ok(value.join("lore").join("config.json"));
        }
        if let Some(value) = env_path(&mut env_var, "LOCALAPPDATA") {
            return Ok(value.join("lore").join("config.json"));
        }
    }
    if let Some(home) = user_home_dir_from_env(platform, &mut env_var) {
        return Ok(home.join(".config").join("lore").join("config.json"));
    }
    let detail = if platform == HostPlatform::Windows {
        "no config directory is available; set APPDATA, LOCALAPPDATA, USERPROFILE, HOME, or XDG_CONFIG_HOME"
    } else {
        "HOME is not set and XDG_CONFIG_HOME is unavailable"
    };
    Err(io::Error::other(detail).into())
}

fn cli_config_path() -> CliResult<PathBuf> {
    cli_config_path_from_env(host_platform(), |name| env::var_os(name))
}

fn default_update_repo_string() -> String {
    DEFAULT_UPDATE_REPO.to_string()
}

fn normalize_url(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

fn format_time(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| value.to_string())
}

fn format_prompt_history_time(timestamp_str: &str) -> String {
    let trimmed = timestamp_str.trim();
    if trimmed.is_empty() {
        return "unknown time".to_string();
    }
    time::OffsetDateTime::parse(trimmed, &time::format_description::well_known::Rfc3339)
        .map(format_time)
        .unwrap_or_else(|_| trimmed.to_string())
}

fn history_messages_excluding_pending<'a>(
    messages: Option<&'a Vec<serde_json::Value>>,
    pending_ids: &HashSet<u64>,
) -> Vec<&'a serde_json::Value> {
    let Some(messages) = messages else {
        return Vec::new();
    };
    messages
        .iter()
        .filter(|msg| {
            let id = msg["id"].as_u64().unwrap_or(0);
            id == 0 || !pending_ids.contains(&id)
        })
        .collect()
}

fn history_exchange_boundaries(messages: &[&serde_json::Value]) -> Vec<usize> {
    messages
        .iter()
        .enumerate()
        .filter(|(_, msg)| msg["role"].as_str() == Some("user"))
        .map(|(idx, _)| idx)
        .collect()
}

fn count_history_exchanges(messages: &[&serde_json::Value]) -> usize {
    history_exchange_boundaries(messages).len()
}

fn history_window_value(history: &serde_json::Value, key: &str) -> Option<usize> {
    history
        .get(key)
        .and_then(|value| value.as_u64())
        .map(|value| value as usize)
        .filter(|value| *value > 0)
}

fn history_prompt_window_size(history: &serde_json::Value) -> usize {
    history_window_value(history, "prompt_window_size")
        .or_else(|| history_window_value(history, "window_size"))
        .unwrap_or(DEFAULT_CHAT_WINDOW_SIZE)
}

fn history_auto_compact_window_size(history: &serde_json::Value) -> usize {
    history_window_value(history, "auto_compact_window_size")
        .or_else(|| history_window_value(history, "prompt_window_size"))
        .or_else(|| history_window_value(history, "window_size"))
        .unwrap_or(DEFAULT_CHAT_WINDOW_SIZE)
}

fn recent_history_exchange_tail<'a>(
    messages: &'a [&'a serde_json::Value],
    exchange_limit: usize,
) -> &'a [&'a serde_json::Value] {
    if exchange_limit == 0 || messages.is_empty() {
        return &messages[messages.len()..];
    }
    let boundaries = history_exchange_boundaries(messages);
    if boundaries.len() <= exchange_limit {
        return messages;
    }
    &messages[boundaries[boundaries.len() - exchange_limit]..]
}

fn recent_history_prompt_window<'a>(
    messages: &'a [&'a serde_json::Value],
    exchange_limit: usize,
) -> Vec<&'a serde_json::Value> {
    let recent = recent_history_exchange_tail(messages, exchange_limit);
    cap_history_prompt_rows(recent, exchange_limit)
}

fn cap_history_prompt_rows<'a>(
    messages: &'a [&'a serde_json::Value],
    exchange_limit: usize,
) -> Vec<&'a serde_json::Value> {
    if exchange_limit == 0 || messages.is_empty() {
        return Vec::new();
    }

    const AGENT_RESPONSE_EDGE_MESSAGES: usize = 8;
    let tool_limit = exchange_limit;
    let mut keep = vec![false; messages.len()];
    let mut kept_tools = 0usize;

    for (idx, msg) in messages.iter().enumerate().rev() {
        if msg["role"].as_str() == Some("tool") && kept_tools < tool_limit {
            keep[idx] = true;
            kept_tools += 1;
        }
    }

    let mut start = 0usize;
    while start < messages.len() {
        let end = messages[start + 1..]
            .iter()
            .position(|msg| msg["role"].as_str() == Some("user"))
            .map(|offset| start + 1 + offset)
            .unwrap_or(messages.len());

        if messages[start]["role"].as_str() == Some("user") {
            keep[start] = true;
        }

        let agent_rows: Vec<usize> = (start..end)
            .filter(|idx| {
                let role = messages[*idx]["role"].as_str();
                role != Some("user") && role != Some("tool")
            })
            .collect();

        if agent_rows.len() <= AGENT_RESPONSE_EDGE_MESSAGES.saturating_mul(2) {
            for idx in agent_rows {
                keep[idx] = true;
            }
        } else {
            for idx in agent_rows.iter().take(AGENT_RESPONSE_EDGE_MESSAGES) {
                keep[*idx] = true;
            }
            for idx in agent_rows.iter().rev().take(AGENT_RESPONSE_EDGE_MESSAGES) {
                keep[*idx] = true;
            }
        }

        start = end;
    }

    messages
        .iter()
        .enumerate()
        .filter_map(|(idx, msg)| keep[idx].then_some(*msg))
        .collect()
}

fn chat_content_for_prompt(content: &str, preserve_data_images: bool) -> String {
    if preserve_data_images {
        content.to_string()
    } else {
        replace_markdown_data_images_with_placeholders(content)
    }
}

fn chat_content_for_current_message_prompt(content: &str) -> String {
    chat_content_for_prompt(content, true)
}

fn chat_content_for_current_message_cli_prompt(content: &str) -> String {
    chat_content_for_prompt(content, false)
}

fn replace_markdown_data_images_with_placeholders(text: &str) -> String {
    let mut rest = text;
    let mut out = String::with_capacity(text.len().min(4096));
    loop {
        let Some(start) = rest.find("![") else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let candidate = &rest[start..];
        let Some(close_alt) = candidate.find("](") else {
            out.push_str(candidate);
            break;
        };
        let url_start = close_alt + 2;
        if !candidate[url_start..].starts_with("data:image/") {
            out.push_str(&candidate[..url_start]);
            rest = &candidate[url_start..];
            continue;
        }
        let Some(close_url) = candidate[url_start..].find(')') else {
            out.push_str(candidate);
            break;
        };
        let alt = candidate[2..close_alt]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let alt: String = alt.chars().take(80).collect();
        let data_url = &candidate[url_start..url_start + close_url];
        out.push_str(&data_image_prompt_placeholder(&alt, data_url));
        rest = &candidate[url_start + close_url + 1..];
    }
    out
}

fn data_image_prompt_placeholder(alt: &str, data_url: &str) -> String {
    let mime = data_url
        .strip_prefix("data:")
        .and_then(|value| value.split_once(';').map(|(mime, _)| mime))
        .filter(|value| !value.is_empty())
        .unwrap_or("image");
    let encoded_len = data_url
        .split_once(',')
        .map(|(_, encoded)| encoded.trim_end_matches('=').len())
        .unwrap_or(0);
    let approx_bytes = encoded_len.saturating_mul(3) / 4;
    let approx_kb = approx_bytes.div_ceil(1024);
    if alt.trim().is_empty() {
        format!("[image attachment omitted from text prompt: {mime}, ~{approx_kb} KB]")
    } else {
        format!("[image attachment omitted from text prompt: {alt}, {mime}, ~{approx_kb} KB]")
    }
}

#[derive(Debug)]
struct MarkdownDataImageAttachment {
    mime: String,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct CodexImageAttachmentFiles {
    dir: PathBuf,
    paths: Vec<PathBuf>,
}

impl CodexImageAttachmentFiles {
    fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
}

impl Drop for CodexImageAttachmentFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn markdown_data_image_extension(mime: &str) -> &'static str {
    match mime {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/webp" => "webp",
        "image/gif" => "gif",
        _ => "img",
    }
}

fn markdown_data_image_attachments(text: &str) -> Vec<MarkdownDataImageAttachment> {
    let mut rest = text;
    let mut attachments = Vec::new();
    loop {
        let Some(start) = rest.find("![") else {
            break;
        };
        let candidate = &rest[start..];
        let Some(close_alt) = candidate.find("](") else {
            break;
        };
        let url_start = close_alt + 2;
        if !candidate[url_start..].starts_with("data:image/") {
            rest = &candidate[url_start..];
            continue;
        }
        let Some(close_url) = candidate[url_start..].find(')') else {
            break;
        };
        let data_url = &candidate[url_start..url_start + close_url];
        if let Some((metadata, encoded)) = data_url
            .strip_prefix("data:")
            .and_then(|value| value.split_once(','))
        {
            let mut parts = metadata.split(';');
            let mime = parts.next().unwrap_or("").to_string();
            let is_base64 = parts.any(|part| part.eq_ignore_ascii_case("base64"));
            if mime.starts_with("image/")
                && is_base64
                && let Ok(bytes) = BASE64_STANDARD.decode(encoded)
            {
                attachments.push(MarkdownDataImageAttachment { mime, bytes });
            }
        }
        rest = &candidate[url_start + close_url + 1..];
    }
    attachments
}

fn create_codex_image_temp_dir() -> io::Result<PathBuf> {
    let base = env::temp_dir();
    let stamp = OffsetDateTime::now_utc().unix_timestamp_nanos();
    for attempt in 0..100u32 {
        let dir = base.join(format!(
            "lore-codex-images-{}-{stamp}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate temporary Codex image directory",
    ))
}

fn write_codex_image_attachments(content: &str) -> io::Result<Option<CodexImageAttachmentFiles>> {
    let attachments = markdown_data_image_attachments(content);
    if attachments.is_empty() {
        return Ok(None);
    }

    let dir = create_codex_image_temp_dir()?;
    let mut files = CodexImageAttachmentFiles {
        dir,
        paths: Vec::with_capacity(attachments.len()),
    };
    for (idx, attachment) in attachments.iter().enumerate() {
        let path = files.dir.join(format!(
            "lore-chat-image-{}.{}",
            idx + 1,
            markdown_data_image_extension(&attachment.mime)
        ));
        fs::write(&path, &attachment.bytes)?;
        files.paths.push(path);
    }
    Ok(Some(files))
}

fn history_compaction_split_index(
    messages: &[&serde_json::Value],
    window_size: usize,
) -> Option<usize> {
    let boundaries = history_exchange_boundaries(messages);
    let exchanges = boundaries.len();
    if exchanges < window_size || exchanges <= 2 {
        return None;
    }

    let target = window_size / 2;
    let keep_count = target.min(exchanges - 1);
    let keep_from_exchange = boundaries.len().saturating_sub(keep_count);
    boundaries.get(keep_from_exchange).copied()
}

fn one_line_preview(value: &str, max_chars: usize) -> String {
    let trimmed = value.lines().next().unwrap_or("").trim();
    truncate_chars(trimmed, max_chars)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let prefix = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}

fn block_type_label(value: BlockType) -> &'static str {
    match value {
        BlockType::Markdown => "markdown",
        BlockType::Html => "html",
        BlockType::Svg => "svg",
        BlockType::Image => "image",
    }
}

fn block_type_api_label(value: CliBlockType) -> &'static str {
    match value {
        CliBlockType::Markdown => "markdown",
        CliBlockType::Html => "html",
        CliBlockType::Svg => "svg",
        CliBlockType::Image => "image",
    }
}

fn filter_block_type_label(value: CliBlockType) -> String {
    match value {
        CliBlockType::Markdown => "markdown",
        CliBlockType::Html => "html",
        CliBlockType::Svg => "svg",
        CliBlockType::Image => "image",
    }
    .to_string()
}

fn filter_query_suffix(filters: &SearchFilters) -> String {
    let mut suffix = String::new();
    if let Some(block_type) = filters.block_type {
        suffix.push_str("&block_type=");
        suffix.push_str(&encode_query(&filter_block_type_label(block_type)));
    }
    if let Some(author) = &filters.author {
        suffix.push_str("&author=");
        suffix.push_str(&encode_query(author));
    }
    if let Some(days) = filters.since_days {
        suffix.push_str("&since_days=");
        suffix.push_str(&days.to_string());
    }
    suffix
}

fn encode_query(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            b' ' => output.push_str("%20"),
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

// --- Helpers ---

#[cfg(unix)]
fn read_password_hidden(prompt: &str) -> io::Result<String> {
    use std::io::BufRead;
    eprint!("{}", prompt);
    let orig = unsafe {
        let mut termios: libc::termios = std::mem::zeroed();
        libc::tcgetattr(0, &mut termios);
        let orig = termios;
        termios.c_lflag &= !libc::ECHO;
        libc::tcsetattr(0, libc::TCSANOW, &termios);
        orig
    };
    let mut password = String::new();
    io::stdin().lock().read_line(&mut password)?;
    unsafe {
        libc::tcsetattr(0, libc::TCSANOW, &orig);
    }
    eprintln!();
    Ok(password.trim().to_string())
}

#[cfg(windows)]
fn read_password_hidden(prompt: &str) -> io::Result<String> {
    use std::io::BufRead;
    eprint!("{}", prompt);
    unsafe extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> isize;
        fn GetConsoleMode(hConsoleHandle: isize, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: isize, dwMode: u32) -> i32;
    }
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // -10 as u32
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        GetConsoleMode(handle, &mut mode);
        SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT);
        let mut password = String::new();
        io::stdin().lock().read_line(&mut password)?;
        SetConsoleMode(handle, mode);
        eprintln!();
        Ok(password.trim().to_string())
    }
}

#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn kill_process(pid: u32) {
    let _ = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status();
}

#[cfg(unix)]
fn kill_process_tree(pid: u32) {
    let pgid = -(pid as i32);
    let rc = unsafe { libc::kill(pgid, libc::SIGKILL) };
    if rc == -1 {
        kill_process(pid);
    }
}

#[cfg(windows)]
fn is_process_running(pid: u32) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

#[cfg(windows)]
fn kill_process(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status();
}

#[cfg(windows)]
fn kill_process_tree(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status();
}

#[cfg(unix)]
fn configure_child_process_group(command: &mut tokio::process::Command) {
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_child_process_group(_command: &mut tokio::process::Command) {}

async fn terminate_child_process_tree(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id() {
        kill_process_tree(pid);
    } else {
        let _ = child.start_kill();
    }
    let _ = child.wait().await;
}

fn get_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

// --- Agent daemon ---

const LORE_DAEMON_ENV: &str = "LORE_DAEMON";

tokio::task_local! {
    static AGENT_CWD: PathBuf;
}

/// Returns the agent's working directory. Inside an agent task this is the
/// task-local folder; outside (standalone CLI commands) falls back to process cwd.
fn agent_cwd() -> PathBuf {
    AGENT_CWD
        .try_with(|p| p.clone())
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Resolve a path that may be relative against the agent's working directory.
fn resolve_agent_path(path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        agent_cwd().join(p)
    }
}

/// Convenience: the .lore/<agent_name> directory under the agent's cwd.
fn agent_lore_dir(agent_name: &str) -> PathBuf {
    agent_cwd().join(format!(".lore/{}", agent_name))
}

async fn agent_command(context: &CliContext, args: AgentArgs) -> CliResult<()> {
    let is_daemon = env::var(LORE_DAEMON_ENV).unwrap_or_default() == "1";

    // Resolve agent token: local config > provision from server
    let mut config = load_cli_config()?;
    let agent_token = if let Some(token) = config.agent_tokens.get(&args.name) {
        token.clone()
    } else {
        // Auto-provision: use machine token to create agent on server
        let machine_token = context
            .token
            .as_deref()
            .ok_or("no machine token configured. Run 'lore setup-machine <url>' first.")?;
        let backend_str = args
            .backend
            .as_deref()
            .map(|b| b.parse::<AgentBackend>().map(|backend| backend.to_string()))
            .transpose()?
            .unwrap_or_else(|| AgentBackend::Claude.to_string());
        eprintln!("Provisioning agent '{}'...", args.name);
        let resp = context
            .client
            .post(format!("{}/v1/agents/provision", context.url))
            .header("x-lore-key", machine_token)
            .header("x-lore-version", env!("CARGO_PKG_VERSION"))
            .json(&serde_json::json!({
                "name": args.name,
                "backend": backend_str,
                "inherit_owner_grants": true,
            }))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("provisioning failed ({}): {}", status, body).into());
        }
        let body: serde_json::Value = resp.json().await?;
        let token = body["token"]
            .as_str()
            .ok_or("server did not return an agent token")?
            .to_string();
        config.agent_tokens.insert(args.name.clone(), token.clone());
        save_cli_config(&config)?;
        eprintln!("Agent '{}' provisioned.", args.name);
        token
    };

    // Build an agent-specific context using the agent token
    let agent_context = CliContext {
        client: context.client.clone(),
        url: context.url.clone(),
        token: Some(agent_token),
        project: context.project.clone(),
    };

    if !args.fg && !is_daemon {
        // Kill any existing agent with this name
        let lore_dir = PathBuf::from(format!(".lore/{}", args.name));
        let pid_path = lore_dir.join("lore.pid");
        if pid_path.exists() {
            if let Ok(pid_str) = fs::read_to_string(&pid_path) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    let is_running = is_process_running(pid);
                    if is_running {
                        eprintln!("Stopping existing agent '{}' (pid {})", args.name, pid);
                        kill_process(pid);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }
            let _ = fs::remove_file(&pid_path);
        }

        // Daemonize: re-spawn ourselves in the background
        fs::create_dir_all(&lore_dir)?;
        let log_path = lore_dir.join("lore.log");
        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        let exe = resolved_current_exe()?;
        let mut cmd_args = vec![
            "--url".to_string(),
            context.url.clone(),
            "agent".to_string(),
            args.name.clone(),
        ];
        // Pass the agent token directly (not machine token) to the daemon
        cmd_args.insert(2, "--token".into());
        cmd_args.insert(3, agent_context.token.clone().unwrap());
        if let Some(ref b) = args.backend {
            cmd_args.push("--backend".into());
            cmd_args.push(b.clone());
        }

        let child = std::process::Command::new(&exe)
            .args(&cmd_args)
            .env(LORE_DAEMON_ENV, "1")
            .stdout(log_file.try_clone()?)
            .stderr(log_file)
            .stdin(std::process::Stdio::null())
            .spawn()?;

        let pid = child.id();
        fs::write(lore_dir.join("lore.pid"), pid.to_string())?;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        println!("Lore agent '{}' started (pid {})", args.name, pid);
        println!("  Log: {}", log_path.display());
        return Ok(());
    }

    let folder = std::env::current_dir()?;

    // If daemon child, write PID file
    if is_daemon {
        let lore_dir = folder.join(format!(".lore/{}", args.name));
        fs::create_dir_all(&lore_dir)?;
        fs::write(lore_dir.join("lore.pid"), std::process::id().to_string())?;
    }

    let cli_backend_override = args.backend.as_ref().and_then(|b| b.parse().ok());

    eprintln!(
        "[agent] Starting agent '{}' (backend: {})",
        args.name,
        cli_backend_override
            .map(|b: AgentBackend| b.to_string())
            .as_deref()
            .unwrap_or("server config")
    );

    // Main agent loop: poll for messages, process them
    AGENT_CWD
        .scope(folder, async move {
            let mut consecutive_errors: u32 = 0;
            let mut turn_failure_tracker = AgentTurnFailureTracker::default();
            loop {
                match agent_poll_and_process(
                    &agent_context,
                    &args.name,
                    cli_backend_override,
                    false,
                    &mut turn_failure_tracker,
                )
                .await
                {
                    Ok(AgentPollAction::Continue) => {
                        consecutive_errors = 0;
                    }
                    Ok(AgentPollAction::UpdateAvailable) => break,
                    Ok(AgentPollAction::Restart) => {
                        eprintln!("[agent] Restarting...");
                        break;
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        let delay =
                            std::cmp::min(5 * (1u64 << consecutive_errors.saturating_sub(1)), 60);
                        eprintln!("[agent] Error (#{consecutive_errors}, retry in {delay}s): {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                    }
                }
            }
        })
        .await;
    Ok(())
}

/// What the agent poll loop should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentPollAction {
    /// Keep polling for the next message.
    Continue,
    /// Restart this agent (e.g. /restart chat command).
    Restart,
    /// Server says an update is available — the *service* handles the actual
    /// update; standalone agents just stop.
    UpdateAvailable,
}

#[derive(Debug, Default)]
struct AgentTurnFailureTracker {
    key: Option<String>,
    count: u32,
}

impl AgentTurnFailureTracker {
    fn reset(&mut self) {
        self.key = None;
        self.count = 0;
    }

    fn record_failure(&mut self, backend: AgentBackend, message_ids: &[u64], detail: &str) -> u32 {
        let ids = message_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let key = format!("{backend}:{ids}:{detail}");
        if self.key.as_deref() == Some(key.as_str()) {
            self.count = self.count.saturating_add(1);
        } else {
            self.key = Some(key);
            self.count = 1;
        }
        self.count
    }
}

async fn take_stop_request(context: &CliContext) -> bool {
    let Some(token) = context.token.as_deref() else {
        return false;
    };
    match context
        .client
        .get(format!("{}/v1/chat/stop-requested", context.url))
        .header("x-lore-key", token)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(body) => body["stop_requested"].as_bool().unwrap_or(false),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

async fn wait_for_stop_request(context: &CliContext) {
    loop {
        if take_stop_request(context).await {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(STOP_POLL_INTERVAL_MS)).await;
    }
}

enum StopAware<T> {
    Completed(T),
    Stopped,
}

async fn race_with_stop<T, F>(context: &CliContext, future: F) -> StopAware<T>
where
    F: Future<Output = T>,
{
    tokio::select! {
        output = future => StopAware::Completed(output),
        _ = wait_for_stop_request(context) => StopAware::Stopped,
    }
}

async fn report_stop_acknowledged(context: &CliContext, token: &str) {
    let _ = context
        .client
        .post(format!("{}/v1/chat/respond", context.url))
        .header("x-lore-key", token)
        .json(&serde_json::json!({
            "tool_use": "control command acknowledged: /stop"
        }))
        .send()
        .await;
}

fn visible_agent_error_content(detail: &str) -> String {
    format!(
        "[Agent error: {}]",
        truncate_head_tail(detail.trim(), 900, 300)
    )
}

async fn complete_agent_turn_with_error(context: &CliContext, token: &str, detail: &str) {
    let _ = context
        .client
        .post(format!("{}/v1/chat/respond", context.url))
        .header("x-lore-key", token)
        .json(&serde_json::json!({
            "content": visible_agent_error_content(detail),
            "complete": true
        }))
        .send()
        .await;
}

async fn agent_poll_and_process(
    context: &CliContext,
    agent_name: &str,
    cli_backend_override: Option<AgentBackend>,
    service_managed: bool,
    turn_failure_tracker: &mut AgentTurnFailureTracker,
) -> CliResult<AgentPollAction> {
    let token = context.token.as_deref().ok_or("no token configured")?;

    // Long-poll for messages
    let cwd = agent_cwd();
    let cwd_str = cwd.to_string_lossy().into_owned();
    // Detect git branch if in a git repo (async to avoid blocking tokio threads)
    let git_branch = tokio::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(&cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        });
    // Read machine name once (blocking file read, but off the async thread)
    let machine_name = {
        let mn =
            tokio::task::spawn_blocking(|| load_cli_config().ok().and_then(|c| c.machine_name))
                .await;
        mn.ok().flatten()
    };
    let mut req = context
        .client
        .get(format!("{}/v1/chat/poll", context.url))
        .header("x-lore-key", token)
        .header("x-lore-cwd", &cwd_str)
        .header("x-lore-version", env!("CARGO_PKG_VERSION"));
    if let Some(ref machine) = machine_name {
        req = req.header("x-lore-machine", machine);
    }
    if let Some(ref branch) = git_branch {
        req = req.header("x-lore-git-branch", branch);
    }
    let resp = req.timeout(std::time::Duration::from_secs(35)).send().await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) if e.is_timeout() => return Ok(AgentPollAction::Continue), // Normal long-poll timeout
        Err(e) => return Err(e.into()),
    };

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(format!(
            "server rejected agent token ({status}) — agent may need re-provisioning"
        )
        .into());
    }
    let body: serde_json::Value = resp.error_for_status()?.json().await?;

    // Server says a CLI update is available.  The *service* handles the actual
    // binary swap; standalone agents just exit so the user can restart manually.
    if body["update_to"].as_str().is_some() && !service_managed {
        eprintln!("[agent] Server signalled update available");
        return Ok(AgentPollAction::UpdateAvailable);
    }

    let has_endpoint = body["endpoint_id"].as_str().is_some();
    let backend = cli_backend_override.unwrap_or_else(|| {
        body["backend"]
            .as_str()
            .and_then(|b| b.parse().ok())
            .unwrap_or(AgentBackend::Claude)
    });

    let acknowledge_control_command = |command: &str| {
        let command = command.to_string();
        async move {
            context
                .client
                .post(format!("{}/v1/chat/respond", context.url))
                .header("x-lore-key", token)
                .json(&serde_json::json!({
                    "complete": true,
                    "tool_use": format!("control command acknowledged: {command}")
                }))
                .send()
                .await
        }
    };

    if body["stop_requested"].as_bool().unwrap_or(false) {
        eprintln!("[agent] Received /stop command");
        let _ = acknowledge_control_command("/stop").await;
        return Ok(AgentPollAction::Continue);
    }

    let manage_requested = body["manage_requested"].as_bool().unwrap_or(false);

    let messages = body["messages"].as_array();

    if messages.is_none() || messages.unwrap().is_empty() {
        if manage_requested {
            maybe_run_manager(context, agent_name).await?;
        }
        return Ok(AgentPollAction::Continue);
    }

    let messages = messages.unwrap();

    // Check for slash commands from the server
    let mut regular_messages: Vec<&str> = Vec::new();
    let mut current_message_ids: Vec<u64> = Vec::new();
    for msg in messages {
        if let Some(content) = msg["content"].as_str() {
            let trimmed = content.trim();
            if trimmed == "/compact" {
                eprintln!("[agent] Received /compact command");
                let cb = if has_endpoint {
                    AgentBackend::OpenAi
                } else {
                    backend
                };
                do_compact(context, agent_name, true, cb).await?;
                return Ok(AgentPollAction::Continue);
            } else if trimmed == "/stop" {
                eprintln!("[agent] Received /stop command");
                let _ = acknowledge_control_command("/stop").await;
                return Ok(AgentPollAction::Continue);
            } else if trimmed == "/restart" {
                eprintln!("[agent] Received /restart — restarting");
                let _ = acknowledge_control_command("/restart").await;
                return Ok(AgentPollAction::Restart);
            } else {
                regular_messages.push(content);
                if let Some(id) = msg["id"].as_u64() {
                    current_message_ids.push(id);
                }
            }
        }
    }

    let combined = regular_messages.join("\n\n");

    if combined.trim().is_empty() {
        return Ok(AgentPollAction::Continue);
    }

    eprintln!(
        "[agent] Received message: {}...",
        &combined.chars().take(80).collect::<String>()
    );

    // Log user message to .lore chat log
    {
        let lore_dir = agent_lore_dir(agent_name);
        let _ = fs::create_dir_all(&lore_dir);
        let ts = time::OffsetDateTime::now_utc();
        let timestamp = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            ts.year(),
            ts.month() as u8,
            ts.day(),
            ts.hour(),
            ts.minute(),
            ts.second()
        );
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(lore_dir.join("lore.log"))
        {
            use std::io::Write;
            let _ = write!(f, "[{timestamp}] USER:\n{combined}\n\n");
        }
    }

    // Update status to thinking
    let _ = context
        .client
        .post(format!("{}/v1/chat/status", context.url))
        .header("x-lore-key", token)
        .json(&serde_json::json!({ "status": "thinking" }))
        .send()
        .await;

    // Get conversation history for context — if this fails, respond with an error
    // so the user sees something (their message was already consumed from the poll).
    let history: serde_json::Value = match context
        .client
        .get(format!("{}/v1/chat/history", context.url))
        .header("x-lore-key", token)
        .send()
        .await
    {
        Ok(resp) => match resp.error_for_status() {
            Ok(resp) => resp.json().await.unwrap_or(serde_json::Value::Null),
            Err(e) => {
                let err_msg = format!("[Agent error: failed to fetch history: {e}]");
                let _ = context
                    .client
                    .post(format!("{}/v1/chat/respond", context.url))
                    .header("x-lore-key", token)
                    .json(&serde_json::json!({ "text": err_msg, "complete": true }))
                    .send()
                    .await;
                return Ok(AgentPollAction::Continue);
            }
        },
        Err(e) => {
            let err_msg = format!("[Agent error: failed to fetch history: {e}]");
            let _ = context
                .client
                .post(format!("{}/v1/chat/respond", context.url))
                .header("x-lore-key", token)
                .json(&serde_json::json!({ "text": err_msg, "complete": true }))
                .send()
                .await;
            return Ok(AgentPollAction::Continue);
        }
    };

    // Build rich prompt with system context, git info, conversation history
    let summary = history["summary"].as_str().unwrap_or("");
    let window_size = history_prompt_window_size(&history);
    let hist_messages = history["messages"].as_array();
    let pins = history["pins"].as_array();
    let project_context = history["project_context"].as_str().unwrap_or("");
    let accessible_projects = history["accessible_projects"].as_str().unwrap_or("");
    let recent_activity = history["recent_activity"].as_str().unwrap_or("");
    let endpoint_runtime_context = if has_endpoint {
        api_endpoint_runtime_context(history.get("endpoint"))
    } else {
        None
    };
    let now = time::OffsetDateTime::now_utc();
    let model_override = model_override_from_history(&history, has_endpoint);
    let effort_override = history["effort"].as_str().map(|s| s.to_string());
    let current_runtime_context = if has_endpoint {
        endpoint_runtime_context
    } else {
        Some(cli_runtime_context(
            backend,
            model_override.as_deref(),
            effort_override.as_deref(),
        ))
    };

    let mut prompt_parts: Vec<String> = Vec::new();

    // Git repository context (gathered locally from the agent's working directory)
    // All git commands use async process to avoid blocking tokio threads.
    let mut git_section = String::new();
    // Get the repo root directory name
    let repo_name = tokio::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            std::path::Path::new(&s)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        });
    if let Some(ref repo) = repo_name {
        let branch_display = git_branch.as_deref().unwrap_or("unknown");
        git_section.push_str(&format!(
            "## Git Repository\n\n{repo}/ (branch: {branch_display})\n"
        ));

        // Last commit
        if let Some(last_commit) = tokio::process::Command::new("git")
            .args(["log", "-1", "--format=%h %s"])
            .current_dir(&cwd)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
        {
            git_section.push_str(&format!("  Last commit: {last_commit}\n"));
        }

        // Git status (modified/untracked files)
        if let Some(status_output) = tokio::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&cwd)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
        {
            git_section.push_str("  Status:\n");
            for line in status_output.lines().take(20) {
                git_section.push_str(&format!("    {line}\n"));
            }
            let total = status_output.lines().count();
            if total > 20 {
                git_section.push_str(&format!("    ... and {} more files\n", total - 20));
            }
        }

        // Recent commits (last 3)
        if let Some(log_output) = tokio::process::Command::new("git")
            .args(["log", "--oneline", "-3"])
            .current_dir(&cwd)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
        {
            git_section.push_str("  Recent commits:\n");
            for line in log_output.lines() {
                git_section.push_str(&format!("    {line}\n"));
            }
        }
    }
    // Pinned context
    if let Some(pins) = pins {
        if !pins.is_empty() {
            let mut pin_section = "## Pinned Context\n".to_string();
            let mut sorted_pins = pins
                .iter()
                .map(|pin| {
                    (
                        pin["id"].as_u64().unwrap_or(0),
                        pin["text"].as_str().unwrap_or(""),
                    )
                })
                .collect::<Vec<_>>();
            sorted_pins.sort_by_key(|(id, _)| *id);
            for (id, text) in sorted_pins {
                pin_section.push_str(&format!("- [pin #{id}] {text}\n"));
            }
            prompt_parts.push(pin_section);
        }
    }

    // Conversation summary
    if !summary.is_empty() {
        prompt_parts.push(format!(
            "## Conversation Summary\n\n{}",
            chat_content_for_prompt(summary, false)
        ));
    }

    // Previous conversation with stable absolute timestamps.
    if let Some(msgs) = hist_messages {
        let pending_ids: HashSet<u64> = current_message_ids.iter().copied().collect();
        let filtered = history_messages_excluding_pending(Some(msgs), &pending_ids);
        let recent = recent_history_prompt_window(&filtered, window_size);
        if !recent.is_empty() {
            prompt_parts.push("## Previous Conversation\nThe following is recent conversation history. This is context only \u{2014} do not respond to these messages. Only respond to the new message the user sends.\n".to_string());
            for msg in recent {
                let role = msg["role"].as_str().unwrap_or("user");
                let content = msg["content"].as_str().unwrap_or("");
                let timestamp = msg["timestamp"].as_str().unwrap_or("");
                let time_label = format_prompt_history_time(timestamp);
                let role_label = match role {
                    "user" => "User",
                    "tool" => "Tool",
                    "error" => "Error",
                    _ => "You",
                };
                let content = chat_content_for_prompt(content, false);
                if role == "user" {
                    prompt_parts.push(format!("\u{2500}\u{2500}\u{2500} {role_label} ({time_label}) \u{2500}\u{2500}\u{2500}\n{content}"));
                } else {
                    let truncated: String = content.chars().take(4000).collect();
                    prompt_parts.push(format!("\u{2500}\u{2500}\u{2500} {role_label} ({time_label}) \u{2500}\u{2500}\u{2500}\n{truncated}"));
                }
            }
        }
    }

    if let Some(runtime_context) = current_runtime_context {
        prompt_parts.push(runtime_context);
    }

    prompt_parts.push(format!("## Working Directory\n\n{cwd_str}"));

    if !git_section.is_empty() {
        prompt_parts.push(git_section);
    }

    if !recent_activity.is_empty() {
        prompt_parts.push(format!("## Recent Activity\n\n{recent_activity}"));
    }

    prompt_parts.push(format!(
        "## Current Date and Time\n\n{}",
        current_datetime_prompt_line_at(now)
    ));

    let current_message_prompt = if has_endpoint {
        chat_content_for_current_message_prompt(&combined)
    } else {
        chat_content_for_current_message_cli_prompt(&combined)
    };
    prompt_parts.push(format!("\n## New Message\n\n{current_message_prompt}"));

    let user_context = prompt_parts.join("\n\n");

    let (full_response, emitted_assistant_messages) = if has_endpoint {
        // API mode: run local agentic loop, proxy LLM calls through the server
        eprintln!("[agent] Using API endpoint mode");
        let endpoint_id = body["endpoint_id"].as_str().map(|s| s.to_string());
        run_api_agent_turn(
            context,
            agent_name,
            &user_context,
            project_context,
            accessible_projects,
            model_override.as_deref(),
            endpoint_id.as_deref(),
        )
        .await?
    } else {
        // CLI mode: spawn backend process — prepend system instructions to user context
        let system_instructions = build_lore_system_instructions(
            project_context,
            accessible_projects,
            &build_cli_tool_section(),
        );
        let full_prompt = format!("{system_instructions}\n\n---\n\n{user_context}");
        let codex_image_attachments = if matches!(backend, AgentBackend::Codex) {
            write_codex_image_attachments(&combined)?
        } else {
            None
        };
        let codex_image_paths: &[PathBuf] = codex_image_attachments
            .as_ref()
            .map(|files| files.paths())
            .unwrap_or(&[]);
        if !codex_image_paths.is_empty() {
            eprintln!(
                "[agent] Attaching {} current chat image(s) to Codex via --image",
                codex_image_paths.len()
            );
        }

        let prompt_path = {
            let lore_dir = agent_lore_dir(agent_name);
            let _ = fs::create_dir_all(&lore_dir);
            let prompt_path = lore_dir.join("prompt.txt");
            let _ = fs::write(&prompt_path, &full_prompt);
            prompt_path
        };

        let mut child = match spawn_backend(
            backend,
            &full_prompt,
            model_override.as_deref(),
            effort_override.as_deref(),
            context.token.as_deref(),
            codex_image_paths,
            Some(&prompt_path),
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                let detail = format!("spawn {} failed: {e}", backend);
                let failure_count =
                    turn_failure_tracker.record_failure(backend, &current_message_ids, &detail);
                if failure_count >= CLI_BACKEND_TURN_FAILURE_LIMIT {
                    let rec = AgentErrorRecord::new(
                        "cli",
                        format!(
                            "{detail}; stopping retries after {failure_count} failed attempts for this user turn. Fix the {backend} CLI or backend configuration, then send a new message to retry."
                        ),
                    );
                    let detail = rec.detail.clone();
                    record_agent_error(context, agent_name, rec).await;
                    complete_agent_turn_with_error(context, token, &detail).await;
                    turn_failure_tracker.reset();
                    return Ok(AgentPollAction::Continue);
                }
                let rec = AgentErrorRecord::new("cli", detail);
                let detail = rec.detail.clone();
                record_agent_error(context, agent_name, rec).await;
                complete_agent_turn_with_error(context, token, &detail).await;
                return Ok(AgentPollAction::Continue);
            }
        };
        turn_failure_tracker.reset();

        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stderr = child.stderr.take().ok_or("no stderr")?;
        let reader = tokio::io::BufReader::new(stdout);
        let stderr_reader = tokio::io::BufReader::new(stderr);
        let mut lines = reader.lines();
        let mut stderr_lines = stderr_reader.lines();
        let mut response = String::new();
        let mut emitted_assistant_messages = false;
        let mut stdout_done = false;
        let mut stderr_done = false;
        let mut stderr_preview_lines: VecDeque<String> = VecDeque::new();

        loop {
            if stdout_done && stderr_done {
                break;
            }
            tokio::select! {
                line = lines.next_line(), if !stdout_done => {
                    let Some(line) = line? else {
                        stdout_done = true;
                        continue;
                    };
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    if !backend_uses_json_lines(backend) {
                        if let Some(record) = classify_cli_non_json_output(backend, "stdout", &line) {
                            eprintln!("[agent] {}", record.detail);
                            terminate_child_process_tree(&mut child).await;
                            let detail = record.detail.clone();
                            record_agent_error(context, agent_name, record).await;
                            complete_agent_turn_with_error(context, token, &detail).await;
                            return Ok(AgentPollAction::Continue);
                        }
                        append_plain_output_line(&mut response, &line);
                        continue;
                    }
                    let parsed: serde_json::Value = match serde_json::from_str(&line) {
                        Ok(v) => v,
                        Err(_) => {
                            if let Some(record) = classify_cli_non_json_output(backend, "stdout", &line) {
                                eprintln!("[agent] {}", record.detail);
                                terminate_child_process_tree(&mut child).await;
                                let detail = record.detail.clone();
                                record_agent_error(context, agent_name, record).await;
                                complete_agent_turn_with_error(context, token, &detail).await;
                                return Ok(AgentPollAction::Continue);
                            }
                            continue;
                        },
                    };
                    for event in parse_backend_line(backend, &parsed) {
                        match event {
                            BackendEvent::Text(text) => {
                                if append_assistant_segment(&mut response, &text).is_some() {
                                    emitted_assistant_messages = true;
                                    let _ = context
                                        .client
                                        .post(format!("{}/v1/chat/respond", context.url))
                                        .header("x-lore-key", token)
                                        .json(&serde_json::json!({ "message": text }))
                                        .send()
                                        .await;
                                }
                            }
                            BackendEvent::ToolUse(detail) => {
                                let _ = context
                                    .client
                                    .post(format!("{}/v1/chat/respond", context.url))
                                    .header("x-lore-key", token)
                                    .json(&serde_json::json!({ "tool_use": detail }))
                                    .send()
                                    .await;
                            }
                            BackendEvent::Result(text) => {
                                if response.is_empty() && !text.is_empty() {
                                    response = text;
                                }
                            }
                            BackendEvent::Skip => {}
                        }
                    }
                }
                line = stderr_lines.next_line(), if !stderr_done => {
                    let Some(line) = line? else {
                        stderr_done = true;
                        continue;
                    };
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    stderr_preview_lines.push_back(sanitize_cli_output_preview(&line));
                    while stderr_preview_lines.len() > 8 {
                        stderr_preview_lines.pop_front();
                    }
                    if let Some(record) = classify_cli_non_json_output(backend, "stderr", &line) {
                        eprintln!("[agent] {}", record.detail);
                        terminate_child_process_tree(&mut child).await;
                        let detail = record.detail.clone();
                        record_agent_error(context, agent_name, record).await;
                        complete_agent_turn_with_error(context, token, &detail).await;
                        return Ok(AgentPollAction::Continue);
                    }
                }
                _ = wait_for_stop_request(context) => {
                    eprintln!("[agent] Stop requested during backend run; terminating child tree");
                    terminate_child_process_tree(&mut child).await;
                    let _ = acknowledge_control_command("/stop").await;
                    return Ok(AgentPollAction::Continue);
                }
            }
        }
        match child.wait().await {
            Ok(status) if status.success() => {}
            Ok(status) => {
                let detail = if stderr_preview_lines.is_empty() {
                    format!("{backend} exited with status {status}")
                } else {
                    format!(
                        "{backend} exited with status {status}; stderr: {}",
                        stderr_preview_lines
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" | ")
                    )
                };
                let rec = AgentErrorRecord::new("cli", &detail);
                record_agent_error(context, agent_name, rec).await;
                if !emitted_assistant_messages && response.trim().is_empty() {
                    response = visible_agent_error_content(&detail);
                }
            }
            Err(e) => {
                let detail = format!("failed to wait for {backend}: {e}");
                let rec = AgentErrorRecord::new("cli", &detail);
                record_agent_error(context, agent_name, rec).await;
                if !emitted_assistant_messages && response.trim().is_empty() {
                    response = visible_agent_error_content(&detail);
                }
            }
        }
        if !emitted_assistant_messages && response.trim().is_empty() {
            let detail = format!("{backend} exited without producing a response");
            let rec = AgentErrorRecord::new("cli", &detail);
            record_agent_error(context, agent_name, rec).await;
            response = visible_agent_error_content(&detail);
        }
        drop(codex_image_attachments);
        (response, emitted_assistant_messages)
    };

    // Send the complete response
    let mut complete_body = serde_json::json!({ "complete": true });
    if !emitted_assistant_messages {
        complete_body["content"] = serde_json::json!(full_response);
    }
    let _ = context
        .client
        .post(format!("{}/v1/chat/respond", context.url))
        .header("x-lore-key", token)
        .json(&complete_body)
        .send()
        .await;

    eprintln!("[agent] Response sent ({} chars)", full_response.len());

    // Log agent response to .lore chat log
    {
        let lore_dir = agent_lore_dir(agent_name);
        let ts = time::OffsetDateTime::now_utc();
        let timestamp = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            ts.year(),
            ts.month() as u8,
            ts.day(),
            ts.hour(),
            ts.minute(),
            ts.second()
        );
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(lore_dir.join("lore.log"))
        {
            use std::io::Write;
            let _ = write!(f, "[{timestamp}] AGENT:\n{full_response}\n\n");
        }
    }

    // Check if compaction is needed
    let compact_backend = if has_endpoint {
        AgentBackend::OpenAi
    } else {
        backend
    };
    if let Err(e) = maybe_auto_compact(context, agent_name, compact_backend).await {
        eprintln!("[agent] Compaction error: {e}");
    }

    // Manager turn: run locally if manage mode is enabled
    if let Err(e) = maybe_run_manager(context, agent_name).await {
        eprintln!("[manager] Error: {e}");
    }

    Ok(AgentPollAction::Continue)
}

async fn maybe_run_manager(context: &CliContext, agent_name: &str) -> CliResult<()> {
    let token = context.token.as_deref().ok_or("no token configured")?;

    let resp = context
        .client
        .get(format!("{}/v1/chat/manage", context.url))
        .header("x-lore-key", token)
        .send()
        .await?
        .error_for_status()?;
    let manage: serde_json::Value = resp.json().await?;

    if !manage["enabled"].as_bool().unwrap_or(false) {
        return Ok(());
    }

    let system_prompt = manage["system_prompt"].as_str().unwrap_or("").to_string();
    let progress_report_prompt = manage["progress_report_prompt"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let messages = manage["messages"].as_array();
    let backend_str = manage["backend"].as_str().unwrap_or("");
    let progress_report_only = manage["progress_report_only"].as_bool().unwrap_or(false);
    let has_endpoint = manage["has_endpoint"].as_bool().unwrap_or(false);
    let backend: AgentBackend = backend_str.parse().unwrap_or(AgentBackend::Claude);

    if progress_report_only {
        if progress_report_prompt.trim().is_empty() {
            return Ok(());
        }
        eprintln!("[manager] Generating missing progress report");
        let directive = "No new manager directive is being requested. Manager mode is active, but no progress report is currently pinned for the user. Use the recent conversation and goals to summarize current progress.";
        match run_manager_progress_report(
            context,
            agent_name,
            backend,
            has_endpoint,
            &progress_report_prompt,
            messages,
            directive,
        )
        .await
        {
            Ok(report) if !report.trim().is_empty() => {
                let report = report.trim().to_string();
                let _ = context
                    .client
                    .post(format!("{}/v1/chat/manager/progress", context.url))
                    .header("x-lore-key", token)
                    .json(&serde_json::json!({ "content": report }))
                    .send()
                    .await;

                let lore_dir = agent_lore_dir(agent_name);
                let _ = fs::create_dir_all(&lore_dir);
                let ts = time::OffsetDateTime::now_utc();
                let timestamp = format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                    ts.year(),
                    ts.month() as u8,
                    ts.day(),
                    ts.hour(),
                    ts.minute(),
                    ts.second()
                );
                if let Ok(mut f) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(lore_dir.join("lore.log"))
                {
                    use std::io::Write;
                    let _ = write!(f, "[{timestamp}] MANAGER PROGRESS:\n{report}\n\n");
                }
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("[manager] Progress report failed: {e}");
            }
        }
        return Ok(());
    }

    if system_prompt.is_empty() {
        return Ok(());
    }

    eprintln!("[manager] Running manager turn");
    let _ = context
        .client
        .post(format!("{}/v1/chat/manager/requested", context.url))
        .header("x-lore-key", token)
        .send()
        .await;

    let manager_response = if has_endpoint {
        match run_manager_endpoint(context, &system_prompt, messages).await {
            Ok(s) => s,
            Err(e) => {
                let rec = AgentErrorRecord::new("manager", format!("endpoint call failed: {e}"));
                record_agent_error(context, agent_name, rec).await;
                return Err(e);
            }
        }
    } else {
        match run_manager_cli(context, agent_name, backend, &system_prompt, messages).await {
            Ok(s) => s,
            Err(e) => {
                let rec = AgentErrorRecord::new("manager", format!("cli run failed: {e}"));
                record_agent_error(context, agent_name, rec).await;
                return Err(e);
            }
        }
    };

    if manager_response.is_empty() {
        eprintln!("[manager] Empty response, skipping");
        return Ok(());
    }

    let parsed_response = parse_manager_control_response(&manager_response);
    let delay_seconds = match parsed_response.control {
        ManagerControlKind::Wait(delay_seconds) => Some(delay_seconds),
        _ => None,
    };
    let stopped = matches!(
        parsed_response.control,
        ManagerControlKind::StoppingPoint | ManagerControlKind::RedFlag
    );
    let mut display = manager_response_display_content(&parsed_response);
    if display.trim().is_empty() {
        display = manager_response.trim().to_string();
    }

    eprintln!("[manager] Reporting to server (stopped={stopped})");

    let _ = context
        .client
        .post(format!("{}/v1/chat/manager", context.url))
        .header("x-lore-key", token)
        .json(&serde_json::json!({
            "content": manager_response.trim(),
            "stopped": stopped,
            "delay_seconds": if stopped { None } else { delay_seconds },
        }))
        .send()
        .await;

    let progress_report = if stopped || progress_report_prompt.trim().is_empty() {
        None
    } else {
        let directive = manager_progress_report_directive(&parsed_response, &display);
        match run_manager_progress_report(
            context,
            agent_name,
            backend,
            has_endpoint,
            &progress_report_prompt,
            messages,
            &directive,
        )
        .await
        {
            Ok(report) if !report.trim().is_empty() => {
                let report = report.trim().to_string();
                let _ = context
                    .client
                    .post(format!("{}/v1/chat/manager/progress", context.url))
                    .header("x-lore-key", token)
                    .json(&serde_json::json!({ "content": report }))
                    .send()
                    .await;
                Some(report)
            }
            Ok(_) => None,
            Err(e) => {
                eprintln!("[manager] Progress report failed: {e}");
                None
            }
        }
    };

    // Log manager response
    {
        let lore_dir = agent_lore_dir(agent_name);
        let _ = fs::create_dir_all(&lore_dir);
        let ts = time::OffsetDateTime::now_utc();
        let timestamp = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            ts.year(),
            ts.month() as u8,
            ts.day(),
            ts.hour(),
            ts.minute(),
            ts.second()
        );
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(lore_dir.join("lore.log"))
        {
            use std::io::Write;
            let _ = write!(f, "[{timestamp}] MANAGER:\n{display}\n\n");
            if let Some(report) = progress_report.as_deref() {
                let _ = write!(f, "[{timestamp}] MANAGER PROGRESS:\n{report}\n\n");
            }
        }
    }

    Ok(())
}

async fn run_manager_cli(
    context: &CliContext,
    agent_name: &str,
    backend: AgentBackend,
    system_prompt: &str,
    messages: Option<&Vec<serde_json::Value>>,
) -> CliResult<String> {
    let mut prompt_parts = Vec::new();
    prompt_parts.push(system_prompt.to_string());

    prompt_parts.push("\n## Recent Conversation\n".to_string());
    if let Some(msgs) = messages {
        for msg in msgs {
            let role = msg["role"].as_str().unwrap_or("user");
            let content = msg["content"].as_str().unwrap_or("");
            let label = if role == "user" { "User" } else { "Agent" };
            let content = chat_content_for_prompt(content, false);
            let truncated: String = content.chars().take(4000).collect();
            prompt_parts.push(format!("--- {label} ---\n{truncated}"));
        }
    }

    prompt_parts.push("\n## Instructions\n\nReview the conversation above and respond as the manager speaking directly to the agent. The first line of stdout must be exactly one of the control formats from the system prompt: STOPPING_POINT: <short reason>, RED_FLAG_POINT: <short reason>, WAIT_FOR_SECONDS: <1-600>, or CONTINUE. Do not write any preamble before that first line, and do not put control tokens after the first line. Give a concrete next instruction, not advice to the user. Do not ask the user for clarification or more input unless the stopping criteria explicitly require that. You may READ files from the working directory if needed to verify periodic checks, but you must NEVER edit, create, delete, or execute any files or commands. Your only output should be the control line followed by the manager's instruction text for the agent.".to_string());

    let full_prompt = prompt_parts.join("\n\n");
    run_manager_cli_prompt(
        context,
        agent_name,
        backend,
        &full_prompt,
        "manager_context.txt",
    )
    .await
}

async fn run_manager_progress_report(
    context: &CliContext,
    agent_name: &str,
    backend: AgentBackend,
    has_endpoint: bool,
    progress_report_prompt: &str,
    messages: Option<&Vec<serde_json::Value>>,
    directive: &str,
) -> CliResult<String> {
    let prompt = format!(
        "{progress_report_prompt}\n\nLATEST MANAGER CONTEXT:\n{directive}\n\n\
         Produce only the short progress report for the user."
    );
    if has_endpoint {
        run_manager_endpoint(context, &prompt, messages).await
    } else {
        run_manager_progress_report_cli(context, agent_name, backend, &prompt, messages).await
    }
}

async fn run_manager_progress_report_cli(
    context: &CliContext,
    agent_name: &str,
    backend: AgentBackend,
    system_prompt: &str,
    messages: Option<&Vec<serde_json::Value>>,
) -> CliResult<String> {
    let mut prompt_parts = Vec::new();
    prompt_parts.push(system_prompt.to_string());

    prompt_parts.push("\n## Recent Conversation\n".to_string());
    if let Some(msgs) = messages {
        for msg in msgs {
            let role = msg["role"].as_str().unwrap_or("user");
            let content = msg["content"].as_str().unwrap_or("");
            let label = if role == "user" { "User" } else { "Agent" };
            let content = chat_content_for_prompt(content, false);
            let truncated: String = content.chars().take(4000).collect();
            prompt_parts.push(format!("--- {label} ---\n{truncated}"));
        }
    }

    prompt_parts.push("\n## Instructions\n\nWrite the short progress report for the user. Do not use the manager control-line protocol. Do not write instructions to the agent. Do not ask the user for clarification or more input. You may READ files only if the recent conversation is insufficient to estimate status, but you must NEVER edit, create, delete, or execute any files or commands. Your only output should be the progress report text.".to_string());

    let full_prompt = prompt_parts.join("\n\n");
    run_manager_cli_prompt(
        context,
        agent_name,
        backend,
        &full_prompt,
        "manager_progress_context.txt",
    )
    .await
}

fn manager_progress_report_directive(parsed: &ParsedManagerResponse, display: &str) -> String {
    let mut directive = format!(
        "Decision: {}",
        manager_control_decision_label(parsed.control)
    );
    let body = parsed.content.trim();
    if body.is_empty() {
        let fallback = display.trim();
        if !fallback.is_empty() {
            directive.push_str("\nInstruction:\n");
            directive.push_str(fallback);
        }
    } else {
        directive.push_str("\nInstruction:\n");
        directive.push_str(body);
    }
    directive
}

async fn run_manager_cli_prompt(
    context: &CliContext,
    agent_name: &str,
    backend: AgentBackend,
    full_prompt: &str,
    context_filename: &str,
) -> CliResult<String> {
    // Save manager context for debugging
    let prompt_path = {
        let lore_dir = agent_lore_dir(agent_name);
        let _ = fs::create_dir_all(&lore_dir);
        let prompt_path = lore_dir.join(context_filename);
        let _ = fs::write(&prompt_path, full_prompt);
        prompt_path
    };

    let mut child = match spawn_backend(
        backend,
        full_prompt,
        None,
        None,
        context.token.as_deref(),
        &[],
        Some(&prompt_path),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            let rec = AgentErrorRecord::new("manager", format!("spawn {} failed: {e}", backend));
            record_agent_error(context, agent_name, rec).await;
            return Err(e);
        }
    };

    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let reader = tokio::io::BufReader::new(stdout);
    let stderr_reader = tokio::io::BufReader::new(stderr);
    let mut lines = reader.lines();
    let mut stderr_lines = stderr_reader.lines();
    let mut full_response = String::new();

    let read_output = async {
        let mut stdout_done = false;
        let mut stderr_done = false;
        loop {
            if stdout_done && stderr_done {
                break;
            }
            tokio::select! {
                line = lines.next_line(), if !stdout_done => {
                    let Some(line) = line? else {
                        stdout_done = true;
                        continue;
                    };
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    if !backend_uses_json_lines(backend) {
                        if let Some(record) = classify_cli_non_json_output(backend, "stdout", &line) {
                            return Err(record.detail.into());
                        }
                        append_plain_output_line(&mut full_response, &line);
                        continue;
                    }
                    let parsed: serde_json::Value = match serde_json::from_str(&line) {
                        Ok(v) => v,
                        Err(_) => {
                            if let Some(record) = classify_cli_non_json_output(backend, "stdout", &line) {
                                return Err(record.detail.into());
                            }
                            continue;
                        },
                    };
                    for event in parse_backend_line(backend, &parsed) {
                        match event {
                            BackendEvent::Text(text) => {
                                let _ = append_new_stream_text(&mut full_response, &text);
                            }
                            BackendEvent::Result(text) => {
                                if full_response.is_empty() && !text.is_empty() {
                                    full_response = text;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                line = stderr_lines.next_line(), if !stderr_done => {
                    let Some(line) = line? else {
                        stderr_done = true;
                        continue;
                    };
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    if let Some(record) = classify_cli_non_json_output(backend, "stderr", &line) {
                        return Err(record.detail.into());
                    }
                }
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };

    match tokio::time::timeout(std::time::Duration::from_secs(300), read_output).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("[manager] CLI read error: {e}");
            let rec = AgentErrorRecord::new("manager", format!("cli stdout read error: {e}"));
            record_agent_error(context, agent_name, rec).await;
            terminate_child_process_tree(&mut child).await;
        }
        Err(_) => {
            eprintln!("[manager] CLI timed out after 5 minutes, killing process tree");
            terminate_child_process_tree(&mut child).await;
            let rec =
                AgentErrorRecord::new("manager", format!("{} cli timed out after 300s", backend));
            record_agent_error(context, agent_name, rec).await;
            if full_response.is_empty() {
                full_response = "[Manager timed out after 5 minutes]".to_string();
            }
        }
    }

    let _ = child.wait().await;
    Ok(full_response)
}

async fn run_manager_endpoint(
    context: &CliContext,
    system_prompt: &str,
    messages: Option<&Vec<serde_json::Value>>,
) -> CliResult<String> {
    let token = context.token.as_deref().ok_or("no token configured")?;

    let mut api_messages = vec![serde_json::json!({ "role": "system", "content": system_prompt })];
    if let Some(msgs) = messages {
        for msg in msgs {
            let content = chat_content_for_prompt(msg["content"].as_str().unwrap_or(""), false);
            api_messages.push(serde_json::json!({
                "role": msg["role"].as_str().unwrap_or("user"),
                "content": content,
            }));
        }
    }

    let body = serde_json::json!({
        "messages": api_messages,
        "stream": false,
        "temperature": 0.3,
        "max_tokens": 2048,
    });

    let resp = context
        .client
        .post(format!("{}/v1/chat/manager/completions", context.url))
        .header("x-lore-key", token)
        .header("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(60))
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp.json().await?;

    if !status.is_success() {
        let err = resp_body["error"]["message"]
            .as_str()
            .or_else(|| resp_body["error"].as_str())
            .unwrap_or("unknown error");
        return Err(format!("Manager endpoint error ({}): {}", status, err).into());
    }

    let text = resp_body["choices"]
        .as_array()
        .and_then(|c| c.first())
        .and_then(|c| c["message"]["content"].as_str())
        .unwrap_or("")
        .to_string();

    Ok(text)
}

fn read_text_from_stdin() -> io::Result<String> {
    let mut buf = String::new();
    io::Read::read_to_string(&mut io::stdin(), &mut buf)?;
    Ok(buf)
}

fn load_cli_text_input(
    content: Option<&String>,
    file: Option<&String>,
    stdin: bool,
    command_name: &str,
) -> CliResult<String> {
    let source_count =
        usize::from(content.is_some()) + usize::from(file.is_some()) + usize::from(stdin);
    if source_count == 0 {
        return Err(format!(
            "{command_name} requires exactly one content source: positional content, --file, or --stdin"
        )
        .into());
    }
    if source_count > 1 {
        return Err(format!(
            "{command_name} accepts only one content source: positional content, --file, or --stdin"
        )
        .into());
    }

    if let Some(value) = content {
        return Ok(value.clone());
    }
    if let Some(path) = file {
        return Ok(fs::read_to_string(path)
            .map_err(|e| io::Error::other(format!("reading {}: {}", path, e)))?);
    }
    if io::stdin().is_terminal() {
        return Err(format!(
            "{command_name} cannot read from an interactive TTY; pipe data or use --file"
        )
        .into());
    }
    Ok(read_text_from_stdin()?)
}

fn load_required_text_arg(
    command_name: &str,
    label: &str,
    value: Option<&String>,
    file: Option<&String>,
    stdin: bool,
) -> CliResult<String> {
    let source_count =
        usize::from(value.is_some()) + usize::from(file.is_some()) + usize::from(stdin);
    if source_count == 0 {
        return Err(format!(
            "{command_name} requires --{label}, --{label}-file, or --{label}-stdin. For values beginning with '-', prefer --{label}=-value, --{label}-file, or --{label}-stdin."
        )
        .into());
    }
    if source_count > 1 {
        return Err(format!(
            "{command_name} accepts only one source for {label}: --{label}, --{label}-file, or --{label}-stdin"
        )
        .into());
    }
    load_cli_text_input(value, file, stdin, &format!("{command_name} --{label}"))
}

fn append_block_content(existing: &str, appended: &str, separator: &str) -> String {
    if existing.is_empty() {
        return appended.to_string();
    }
    if appended.is_empty() {
        return existing.to_string();
    }
    format!("{existing}{separator}{appended}")
}

fn print_text_diff(label: &str, before: &str, after: &str) {
    println!("--- {label}:before");
    println!("+++ {label}:after");
    if before == after {
        println!("  (no changes)");
        return;
    }

    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines: Vec<&str> = after.lines().collect();
    let mut prefix_len = 0;
    while prefix_len < before_lines.len()
        && prefix_len < after_lines.len()
        && before_lines[prefix_len] == after_lines[prefix_len]
    {
        prefix_len += 1;
    }

    let mut suffix_len = 0;
    while suffix_len + prefix_len < before_lines.len()
        && suffix_len + prefix_len < after_lines.len()
        && before_lines[before_lines.len() - 1 - suffix_len]
            == after_lines[after_lines.len() - 1 - suffix_len]
    {
        suffix_len += 1;
    }

    let context_start = prefix_len.saturating_sub(3);
    if context_start > 0 {
        println!("  ... {} unchanged line(s) omitted", context_start);
    }
    for line in &before_lines[context_start..prefix_len] {
        println!("  {line}");
    }
    for line in &before_lines[prefix_len..before_lines.len() - suffix_len] {
        println!("- {line}");
    }
    for line in &after_lines[prefix_len..after_lines.len() - suffix_len] {
        println!("+ {line}");
    }
    let suffix_start = before_lines.len() - suffix_len;
    let suffix_context_end = (suffix_start + 3).min(before_lines.len());
    for line in &before_lines[suffix_start..suffix_context_end] {
        println!("  {line}");
    }
    let omitted_suffix = before_lines.len().saturating_sub(suffix_context_end);
    if omitted_suffix > 0 {
        println!("  ... {omitted_suffix} unchanged line(s) omitted");
    }
}

fn load_doc_write_content(args: &DocWriteArgs) -> CliResult<String> {
    if args.file.is_some() && args.stdin {
        return Err("docs write accepts only one input source: --file or --stdin".into());
    }

    let content = match (&args.file, args.stdin) {
        (Some(file_path), false) => fs::read_to_string(file_path)
            .map_err(|e| io::Error::other(format!("reading {}: {}", file_path, e)))?,
        (None, true) => {
            if io::stdin().is_terminal() {
                return Err(
                    "docs write cannot read from an interactive TTY; pipe data or use --file"
                        .into(),
                );
            }
            read_text_from_stdin()?
        }
        (None, false) => {
            if io::stdin().is_terminal() {
                return Err(
                    "docs write requires --file or piped stdin; use --stdin to make stdin explicit"
                        .into(),
                );
            }
            read_text_from_stdin()?
        }
        (Some(_), true) => unreachable!(),
    };

    if content.trim().is_empty() && !args.allow_empty {
        return Err(
            "docs write refused empty input; pass --allow-empty if you intentionally want an empty document"
                .into(),
        );
    }

    Ok(content)
}

async fn resolve_block_create_after(
    context: &CliContext,
    project: &ProjectName,
    args: &BlockCreateArgs,
) -> CliResult<Option<String>> {
    match (args.position, args.after.as_ref()) {
        (Some(BlockInsertPosition::Start), Some(_)) => {
            return Err("blocks create does not allow --after with --position start".into());
        }
        (Some(BlockInsertPosition::Append), Some(_)) => {
            return Err("blocks create does not allow --after with --position append".into());
        }
        (Some(BlockInsertPosition::After), None) => {
            return Err("blocks create requires --after when --position after is used".into());
        }
        (Some(BlockInsertPosition::Start), None) => return Ok(None),
        (Some(BlockInsertPosition::After), Some(after)) => return Ok(Some(after.clone())),
        (None, Some(after)) => return Ok(Some(after.clone())),
        (Some(BlockInsertPosition::Append), None) | (None, None) => {}
    }

    let path = format!(
        "/v1/projects/{}/documents/{}/blocks",
        project.as_str(),
        args.doc
    );
    let blocks: Vec<Block> = context.get_json(&path).await?;
    Ok(blocks.last().map(|block| block.id.as_str().to_string()))
}

// --- Shared agent system prompt ---

fn build_lore_system_instructions(
    project_context: &str,
    accessible_projects: &str,
    tool_section: &str,
) -> String {
    let mut parts = Vec::new();

    parts.push("# Lore Agent Instructions

You are an AI agent connected to the Lore knowledge base. Lore organizes knowledge into projects and documents. Each project has an Overview, File Map, and Agent Context accessible via dedicated tools. Documents contain typed blocks (the content itself).

## Guidelines
- Be concise and direct. Provide clear answers.
- Read files before editing them.
- For project info: use get_project_overview, get_file_map, get_agent_context.
- For documents: use list_documents to see the doc tree, read_document to read the entire document as text, list_blocks for block structure, read_block for content, edit_block for targeted edits.
- For broad document changes, use read_document then write_document. For surgical edits, use edit_block.
- For large blocks, use read_block with offset/limit to read chunks.
- When a tool result is truncated, use more targeted queries rather than re-reading the same large result.
- If you encounter an error, explain it clearly and suggest alternatives.
- Do not make up content. If you can't find something, say so.
- For multi-step tasks, plan before acting. Use fewer tool calls per turn when possible.

## File Map Maintenance
Each project has a File Map listing key project files. Use get_file_map to read it, update_file_map or edit_file_map to modify it. Keep this map current: add files you discover are important, remove files that are deleted or no longer relevant. Only list files that are actionable for development.

## SVG Output
You can output inline SVG to present quick reports, diagrams, tables, and visual summaries to the user. Use <svg xmlns=\"http://www.w3.org/2000/svg\" ...>...</svg> with a self-contained design. Keep SVGs simple and readable. Do NOT use <foreignObject> — use only native SVG elements (<text>, <rect>, <circle>, <line>, <path>, <g>, etc). Use &amp; not & in SVG text.".to_string());

    if !project_context.is_empty() {
        parts.push(format!("## Project Context\n{project_context}"));
    }

    if !accessible_projects.is_empty() {
        parts.push(format!("## Accessible Projects\n{accessible_projects}"));
    }

    parts.push(format!("## Available Lore Tools\n{tool_section}"));

    parts.join("\n\n")
}

fn build_cli_tool_section() -> String {
    "You have access to the `lore` CLI tool in addition to your normal file and shell tools. Use these commands to interact with the Lore knowledge base:

Project info:
  lore projects                          List all accessible projects
  lore overview                          Read the project overview
  lore file-map read                     Read the project file map
  lore file-map update <content>         Replace the entire file map
  lore file-map edit --old <text> --new <text>   Find-and-replace within the file map
  lore context                           Show the project's agent context

Documents:
  lore docs list                         List documents (shows doc tree with IDs)
  lore docs read <doc-id> [--from <block-id>] [--to <block-id>]   Read entire document as text with markers like @@block id=<id> type=<type>
  lore docs write <doc-id> [--file <path>|--stdin] [--allow-empty] [--dry-run --diff]   Write document from marker format
  lore docs append <doc-id> [<content>|--file <path>|--stdin] [--dry-run --diff]   Append a new block
  lore docs insert-after-heading <doc-id> <heading> [<content>|--file <path>|--stdin]   Insert a new block after a unique heading
  lore docs create <name> [--parent <doc-id>]   Create a new document
  lore docs rename <doc-id> <new-name>   Rename a document
  lore docs delete <doc-id> --yes        Delete a document and all its contents

Blocks (reading):
  lore blocks list --doc <doc-id>        List blocks in a document
  lore blocks read <id> --doc <doc-id> [--offset N] [--limit N]   Read a block's content
  lore blocks around <id> [--before N] [--after N]   Read a block with surrounding context

Blocks (writing):
  lore blocks create --doc <doc-id> [<content>|--file <path>|--stdin] [--type markdown|html|svg|image] [--position start|append|after] [--after <id>] [--dry-run --diff]
  lore blocks update <id> --doc <doc-id> [<content>|--file <path>|--stdin] [--type markdown|html|svg|image] [--dry-run --diff]
  lore blocks append <id> --doc <doc-id> [<content>|--file <path>|--stdin] [--separator <text>] [--dry-run --diff]
  lore blocks edit <id> --doc <doc-id> (--old <text>|--old-file <path>|--old-stdin) (--new <text>|--new-file <path>|--new-stdin) [--dry-run --diff]
  lore blocks move <id> --doc <doc-id> [--after <id>]
  lore blocks delete <id> --doc <doc-id> --yes
  lore blocks split <id> --doc <doc-id> --position N
  lore blocks combine --doc <doc-id> <id1> <id2> [id3...]

Searching:
  lore grep <query> [--limit N]          Search blocks by content

History:
  lore history list                      List recent block changes
  lore history show <version-id>         Show a specific version
  lore history revert <version-id>       Revert a block to a previous version

Librarian (AI-powered):
  lore librarian answer <question>       Ask the librarian about project content
  lore librarian action <instruction>    Request a content action

Start by listing documents (lore docs list) to see the content structure, then use lore docs read <doc-id> to read entire documents, or lore blocks list --doc <doc-id> for block-level detail.".to_string()
}

fn build_api_tool_section(lore_tool_names: &[String]) -> String {
    if lore_tool_names.is_empty() {
        return "You have file tools (read_file, write_file, edit_file, list_directory, run_command, grep_search) to work with the local filesystem.".to_string();
    }
    format!("You have file tools (read_file, write_file, edit_file, list_directory, run_command, grep_search) to work with the local filesystem.

You also have Lore MCP tools to manage knowledge base content: {}. Use list_documents to see the doc tree, list_blocks for block structure, read_block for content, edit_block for targeted changes, update_block for full rewrites.", lore_tool_names.join(", "))
}

// --- Agent error logging ---
//
// Each error is written as one JSON line to .lore/<agent>/error-YYYY-MM-DD.jsonl
// and fire-and-forget reported to the server via POST /v1/chat/errors/report.
// Local retention: 3 days (files older than 3 days by filename date are deleted on every write).
// Per-entry cap: 8KB (preview_request/preview_response truncated to fit).
// Per-file cap: 10MB (further writes skipped once exceeded).

const ERROR_ENTRY_MAX_BYTES: usize = 8 * 1024;
const ERROR_FILE_MAX_BYTES: u64 = 10 * 1024 * 1024;
const ERROR_RETENTION_DAYS: i64 = 3;

#[derive(Debug, Clone, Serialize)]
struct AgentErrorRecord {
    ts: String,
    category: String, // llm_api | cli | tool | parse | manager
    detail: String,   // short human-readable message
    endpoint_id: Option<String>,
    status_code: Option<u16>,
    duration_ms: Option<u64>,
    preview_request: Option<String>,
    preview_response: Option<String>,
}

impl AgentErrorRecord {
    fn new(category: &str, detail: impl Into<String>) -> Self {
        let now = time::OffsetDateTime::now_utc();
        let ts = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            now.year(),
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        Self {
            ts,
            category: category.to_string(),
            detail: detail.into(),
            endpoint_id: None,
            status_code: None,
            duration_ms: None,
            preview_request: None,
            preview_response: None,
        }
    }
    fn with_status(mut self, s: u16) -> Self {
        self.status_code = Some(s);
        self
    }
    fn with_endpoint(mut self, e: Option<String>) -> Self {
        self.endpoint_id = e;
        self
    }
    fn with_preview_request(mut self, s: impl Into<String>) -> Self {
        self.preview_request = Some(truncate_preview(&s.into()));
        self
    }
    fn with_preview_response(mut self, s: impl Into<String>) -> Self {
        self.preview_response = Some(truncate_preview(&s.into()));
        self
    }
}

fn classify_cli_non_json_output(
    backend: AgentBackend,
    stream_name: &str,
    line: &str,
) -> Option<AgentErrorRecord> {
    let preview = sanitize_cli_output_preview(line);
    let detail = if looks_like_cli_auth_prompt(line) {
        format!(
            "{backend} emitted a non-JSON {stream_name} authentication prompt. Configure {backend} authentication for the service user or set a headless API-key auth path before retrying. Prompt: {preview}"
        )
    } else if looks_like_cli_startup_blocker(line) {
        format!(
            "{backend} emitted a non-JSON {stream_name} startup blocker. Check the installed {backend} CLI version and service configuration before retrying. Output: {preview}"
        )
    } else {
        return None;
    };
    Some(AgentErrorRecord::new("cli", detail).with_preview_response(preview))
}

fn looks_like_cli_startup_blocker(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if lower.contains("yolo mode is disabled")
        || lower.contains("disabled by your administrator")
        || lower.contains("securemodeenabled")
    {
        return true;
    }
    false
}

fn looks_like_cli_auth_prompt(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let mentions_auth = lower.contains("oauth")
        || lower.contains("auth")
        || lower.contains("login")
        || lower.contains("log in")
        || lower.contains("sign in")
        || lower.contains("authenticate")
        || lower.contains("authentication")
        || lower.contains("authorization")
        || lower.contains("api key")
        || lower.contains("google account");
    if !mentions_auth {
        return false;
    }
    lower.contains("browser")
        || lower.contains("visit")
        || lower.contains("open ")
        || lower.contains("url")
        || lower.contains("code")
        || lower.contains("please")
        || lower.contains("must")
        || lower.contains("need")
        || lower.contains("required")
        || lower.contains("credential")
        || lower.contains("failed")
        || lower.contains("missing")
        || lower.contains("account")
        || lower.contains("key")
        || lower.contains("permission")
        || lower.contains("token")
}

fn sanitize_cli_output_preview(line: &str) -> String {
    let mut out = Vec::new();
    for part in line.split_whitespace() {
        if part.starts_with("http://") || part.starts_with("https://") {
            out.push("[url]".to_string());
        } else if part.len() > 80 {
            out.push(format!(
                "{}...[redacted]",
                part.chars().take(24).collect::<String>()
            ));
        } else {
            out.push(part.to_string());
        }
    }
    let collapsed = out.join(" ");
    let count = collapsed.chars().count();
    if count <= 300 {
        collapsed
    } else {
        let mut shortened: String = collapsed.chars().take(300).collect();
        shortened.push_str("...");
        shortened
    }
}

fn truncate_preview(s: &str) -> String {
    // Keep the head and the tail so we can see the system prompt / opening request
    // shape AND the trailing part (often where the failing tool call or the last
    // user turn lives). Total budget: ~4KB chars, split ~2/3 head, 1/3 tail.
    truncate_head_tail(s, 2730, 1366)
}

fn truncate_head_tail(s: &str, head: usize, tail: usize) -> String {
    let total: usize = s.chars().count();
    if total <= head + tail {
        return s.to_string();
    }
    let head_part: String = s.chars().take(head).collect();
    let tail_part: String = s.chars().skip(total - tail).collect();
    let omitted = total - head - tail;
    format!("{head_part}\n\u{2026}[truncated {omitted} chars]\u{2026}\n{tail_part}")
}

fn today_utc_date() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        now.month() as u8,
        now.day()
    )
}

fn prune_old_error_files(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let today = time::OffsetDateTime::now_utc().date();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(date_part) = name
            .strip_prefix("error-")
            .and_then(|s| s.strip_suffix(".jsonl"))
        else {
            continue;
        };
        let parts: Vec<&str> = date_part.split('-').collect();
        if parts.len() != 3 {
            continue;
        }
        let (Ok(y), Ok(m), Ok(d)) = (
            parts[0].parse::<i32>(),
            parts[1].parse::<u8>(),
            parts[2].parse::<u8>(),
        ) else {
            continue;
        };
        let Some(month) = time::Month::try_from(m).ok() else {
            continue;
        };
        let Ok(file_date) = time::Date::from_calendar_date(y, month, d) else {
            continue;
        };
        if (today - file_date).whole_days() > ERROR_RETENTION_DAYS {
            let _ = fs::remove_file(&path);
        }
    }
}

async fn write_agent_error_locally(agent_name: &str, record: &AgentErrorRecord) {
    let dir = agent_lore_dir(agent_name);
    let record = record.clone();
    let _ = tokio::task::spawn_blocking(move || {
        if fs::create_dir_all(&dir).is_err() {
            return;
        }
        prune_old_error_files(&dir);
        let path = dir.join(format!("error-{}.jsonl", today_utc_date()));
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() >= ERROR_FILE_MAX_BYTES {
                return;
            }
        }
        let Ok(mut line) = serde_json::to_string(&record) else {
            return;
        };
        if line.len() > ERROR_ENTRY_MAX_BYTES {
            let mut trimmed = record.clone();
            trimmed.preview_response = trimmed
                .preview_response
                .map(|s| truncate_head_tail(&s, 350, 150));
            trimmed.preview_request = trimmed
                .preview_request
                .map(|s| truncate_head_tail(&s, 350, 150));
            line = serde_json::to_string(&trimmed).unwrap_or(line);
            if line.len() > ERROR_ENTRY_MAX_BYTES {
                trimmed.preview_response = None;
                trimmed.preview_request = None;
                line = serde_json::to_string(&trimmed).unwrap_or(line);
            }
        }
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
            use std::io::Write;
            let _ = writeln!(f, "{line}");
        }
    })
    .await;
}

async fn report_agent_error_to_server(context: &CliContext, record: &AgentErrorRecord) {
    let Some(token) = context.token.as_deref() else {
        return;
    };
    let url = format!("{}/v1/chat/errors/report", context.url);
    let body = serde_json::to_value(record).unwrap_or(serde_json::json!({}));
    let send = || async {
        context
            .client
            .post(&url)
            .header("x-lore-key", token)
            .timeout(std::time::Duration::from_secs(5))
            .json(&body)
            .send()
            .await
    };
    match send().await {
        Ok(r) if r.status().is_success() => {}
        _ => {
            // Single retry, then drop.
            let _ = send().await;
        }
    }
}

async fn record_agent_error(context: &CliContext, agent_name: &str, record: AgentErrorRecord) {
    write_agent_error_locally(agent_name, &record).await;
    report_agent_error_to_server(context, &record).await;
}

// --- API agent loop (runs on machine, proxies LLM calls through server) ---

const API_AGENT_MAX_TURNS: usize = 500;
const API_AGENT_MAX_CONTEXT_CHARS: usize = 400_000;
const API_AGENT_RATE_LIMIT_WAIT_SECS: u64 = 30;
const API_AGENT_MAX_RETRIES: usize = 2;
const API_AGENT_TRIMMED_STUB: &str = "[Content trimmed \u{2014} re-read if needed]";

fn api_user_content_from_markdown_images(text: &str) -> serde_json::Value {
    let mut rest = text;
    let mut parts = Vec::new();
    let mut saw_image = false;
    loop {
        let Some(start) = rest.find("![") else {
            if !rest.is_empty() {
                parts.push(serde_json::json!({ "type": "text", "text": rest }));
            }
            break;
        };
        if start > 0 {
            parts.push(serde_json::json!({ "type": "text", "text": &rest[..start] }));
        }
        let candidate = &rest[start..];
        let Some(close_alt) = candidate.find("](") else {
            parts.push(serde_json::json!({ "type": "text", "text": candidate }));
            break;
        };
        let url_start = close_alt + 2;
        if !candidate[url_start..].starts_with("data:image/") {
            parts.push(serde_json::json!({ "type": "text", "text": &candidate[..url_start] }));
            rest = &candidate[url_start..];
            continue;
        }
        let Some(close_url) = candidate[url_start..].find(')') else {
            parts.push(serde_json::json!({ "type": "text", "text": candidate }));
            break;
        };
        let url = &candidate[url_start..url_start + close_url];
        parts.push(serde_json::json!({
            "type": "image_url",
            "image_url": { "url": url }
        }));
        saw_image = true;
        rest = &candidate[url_start + close_url + 1..];
    }
    if saw_image {
        serde_json::Value::Array(parts)
    } else {
        serde_json::json!(text)
    }
}

fn api_endpoint_runtime_context(endpoint: Option<&serde_json::Value>) -> Option<String> {
    let endpoint = endpoint?;
    let name = endpoint
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("configured endpoint");
    let kind = endpoint
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("api");
    let model = endpoint
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("configured model");

    Some(format!(
        "## Current Runtime\n\nYou are currently running through the Lore API endpoint `{name}` ({kind}) using model `{model}`. Do not infer your current identity, provider, training origin, or capabilities from older assistant messages, conversation summaries, local backend names, or previous CLI-agent configuration. If asked who trained you or what model you are, answer from this current endpoint/model information. If the training origin is not known from the current model metadata, say that you do not know rather than repeating stale history."
    ))
}

fn cli_runtime_context(
    backend: AgentBackend,
    model_override: Option<&str>,
    effort_override: Option<&str>,
) -> String {
    let model = model_override
        .filter(|model| !model.trim().is_empty())
        .unwrap_or("default");
    let effort = effort_override
        .filter(|effort| !effort.trim().is_empty())
        .unwrap_or("default");
    format!(
        "## Current Runtime\n\nYou are currently running through the Lore `{backend}` CLI backend with model `{model}` and effort `{effort}`. Do not infer your current identity, provider, training origin, model, or capabilities from older assistant messages, conversation summaries, local backend names, or previous agent configuration. If asked who trained you or what model you are, answer from this current runtime information rather than repeating stale history."
    )
}

fn model_override_from_history(history: &serde_json::Value, endpoint_mode: bool) -> Option<String> {
    if endpoint_mode {
        return None;
    }
    history["model"].as_str().map(|s| s.to_string())
}

async fn run_api_agent_turn(
    context: &CliContext,
    agent_name: &str,
    user_context: &str,
    project_context: &str,
    accessible_projects: &str,
    model_override: Option<&str>,
    endpoint_id: Option<&str>,
) -> CliResult<(String, bool)> {
    let endpoint_id_owned = endpoint_id.map(|s| s.to_string());
    let token = context.token.as_deref().ok_or("no token configured")?;
    let mut tools = build_local_tools();

    let mut lore_tool_names = fetch_lore_tools(context).await;
    lore_tool_names.sort_by(|a, b| {
        a["function"]["name"]
            .as_str()
            .unwrap_or("")
            .cmp(b["function"]["name"].as_str().unwrap_or(""))
    });
    for t in &lore_tool_names {
        tools.push(t.clone());
    }
    let mut lore_name_list: Vec<String> = lore_tool_names
        .iter()
        .filter_map(|t| t["function"]["name"].as_str().map(|s| s.to_string()))
        .collect();
    lore_name_list.sort();
    lore_name_list.dedup();
    let lore_names: std::collections::HashSet<String> = lore_name_list.iter().cloned().collect();

    let system_content = build_lore_system_instructions(
        project_context,
        accessible_projects,
        &build_api_tool_section(&lore_name_list),
    );

    {
        let lore_dir = agent_lore_dir(agent_name);
        let _ = fs::create_dir_all(&lore_dir);
        let prompt_dump = format!(
            "=== SYSTEM PROMPT ===\n{system_content}\n\n=== USER CONTEXT ===\n{user_context}"
        );
        let _ = fs::write(lore_dir.join("prompt.txt"), &prompt_dump);
    }

    let mut messages: Vec<serde_json::Value> = vec![
        serde_json::json!({
            "role": "system",
            "content": system_content
        }),
        serde_json::json!({
            "role": "user",
            "content": api_user_content_from_markdown_images(user_context)
        }),
    ];

    let mut accumulated_text = String::new();
    let mut emitted_assistant_messages = false;
    let mut rate_limit_retried = false;
    let mut timeout_retries = 0usize;

    for turn in 0..API_AGENT_MAX_TURNS {
        if take_stop_request(context).await {
            report_stop_acknowledged(context, token).await;
            return Ok((String::new(), false));
        }

        trim_api_context(&mut messages);

        let mut body = serde_json::json!({
            "messages": messages,
            "tools": tools,
            "stream": false,
            "max_tokens": 16384,
        });
        if let Some(m) = model_override {
            body["model"] = serde_json::json!(m);
        }

        let resp = match race_with_stop(
            context,
            context
                .client
                .post(format!("{}/v1/chat/completions", context.url))
                .header("x-lore-key", token)
                .timeout(std::time::Duration::from_secs(120))
                .json(&body)
                .send(),
        )
        .await
        {
            StopAware::Completed(resp) => resp,
            StopAware::Stopped => {
                report_stop_acknowledged(context, token).await;
                return Ok((String::new(), false));
            }
        };

        let resp = match resp {
            Ok(r) => {
                timeout_retries = 0;
                r
            }
            Err(e) => {
                if e.is_timeout() && timeout_retries < API_AGENT_MAX_RETRIES {
                    timeout_retries += 1;
                    let _ = context.client
                        .post(format!("{}/v1/chat/respond", context.url))
                        .header("x-lore-key", token)
                        .json(&serde_json::json!({ "tool_use": format!("\u{23f3} Request timed out, retrying ({timeout_retries}/{API_AGENT_MAX_RETRIES})...") }))
                        .send().await;
                    continue;
                }
                let err_text = format!("API request error: {e}");
                let rec = AgentErrorRecord::new("llm_api", &err_text)
                    .with_endpoint(endpoint_id_owned.clone())
                    .with_preview_request(serde_json::to_string(&body).unwrap_or_default());
                record_agent_error(context, agent_name, rec).await;
                accumulated_text.push_str(&format!("\n\n[{err_text}]"));
                break;
            }
        };

        if take_stop_request(context).await {
            report_stop_acknowledged(context, token).await;
            return Ok((String::new(), false));
        }

        let status = resp.status();
        let resp_text = match race_with_stop(context, resp.text()).await {
            StopAware::Completed(text) => text.unwrap_or_default(),
            StopAware::Stopped => {
                report_stop_acknowledged(context, token).await;
                return Ok((String::new(), false));
            }
        };
        let resp_body: serde_json::Value =
            serde_json::from_str(&resp_text).unwrap_or(serde_json::Value::Null);

        if !status.is_success() {
            let err = resp_body["error"]["message"]
                .as_str()
                .or_else(|| resp_body["error"].as_str())
                .unwrap_or_else(|| {
                    if resp_text.is_empty() {
                        "unknown error"
                    } else {
                        resp_text.as_str()
                    }
                });

            if status.as_u16() == 429 && !rate_limit_retried {
                rate_limit_retried = true;
                let _ = context.client
                    .post(format!("{}/v1/chat/respond", context.url))
                    .header("x-lore-key", token)
                    .json(&serde_json::json!({ "tool_use": format!("\u{23f3} Rate limited, retrying in {API_AGENT_RATE_LIMIT_WAIT_SECS}s...") }))
                    .send().await;
                match race_with_stop(
                    context,
                    tokio::time::sleep(std::time::Duration::from_secs(
                        API_AGENT_RATE_LIMIT_WAIT_SECS,
                    )),
                )
                .await
                {
                    StopAware::Completed(()) => {}
                    StopAware::Stopped => {
                        report_stop_acknowledged(context, token).await;
                        return Ok((String::new(), false));
                    }
                }
                continue;
            }

            if status.as_u16() == 400 {
                let has_untrimmed = messages.iter().any(|m| {
                    m["role"].as_str() == Some("tool")
                        && m["content"]
                            .as_str()
                            .map(|s| s != API_AGENT_TRIMMED_STUB)
                            .unwrap_or(false)
                });
                if has_untrimmed {
                    aggressive_trim_api_context(&mut messages);
                    let _ = context.client
                        .post(format!("{}/v1/chat/respond", context.url))
                        .header("x-lore-key", token)
                        .json(&serde_json::json!({ "tool_use": "\u{2702}\u{fe0f} Context too large, trimming and retrying..." }))
                        .send().await;
                    continue;
                }
            }

            let detail = format!("API error ({status}): {err}");
            let rec = AgentErrorRecord::new("llm_api", &detail)
                .with_status(status.as_u16())
                .with_endpoint(endpoint_id_owned.clone())
                .with_preview_request(serde_json::to_string(&body).unwrap_or_default())
                .with_preview_response(resp_text.clone());
            record_agent_error(context, agent_name, rec).await;
            accumulated_text.push_str(&format!("\n\n[{detail}]"));
            break;
        }

        rate_limit_retried = false;

        let choice = resp_body["choices"].as_array().and_then(|c| c.first());
        let message = choice.and_then(|c| c.get("message"));
        let content = message
            .and_then(|m| m["content"].as_str())
            .unwrap_or("")
            .to_string();
        let finish_reason = choice
            .and_then(|c| c["finish_reason"].as_str())
            .unwrap_or("");
        let tool_calls = message.and_then(|m| m["tool_calls"].as_array()).cloned();

        if append_assistant_segment(&mut accumulated_text, &content).is_some() {
            emitted_assistant_messages = true;
            let _ = context
                .client
                .post(format!("{}/v1/chat/respond", context.url))
                .header("x-lore-key", token)
                .json(&serde_json::json!({ "message": content }))
                .send()
                .await;
        }

        if let Some(ref tcs) = tool_calls {
            if !tcs.is_empty() {
                messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": if content.is_empty() { serde_json::Value::Null } else { serde_json::json!(content) },
                    "tool_calls": tcs,
                }));

                for tc in tcs {
                    if take_stop_request(context).await {
                        report_stop_acknowledged(context, token).await;
                        return Ok((accumulated_text.clone(), emitted_assistant_messages));
                    }

                    let tool_id = tc["id"].as_str().unwrap_or("").to_string();
                    let func = tc.get("function");
                    let tool_name = func.and_then(|f| f["name"].as_str()).unwrap_or("");
                    let raw_args = func.and_then(|f| f["arguments"].as_str()).unwrap_or("{}");

                    let (tool_args, parse_error) =
                        match serde_json::from_str::<serde_json::Value>(raw_args) {
                            Ok(v) => (v, false),
                            Err(e) => {
                                let rec = AgentErrorRecord::new(
                                    "parse",
                                    format!("tool arg JSON parse failed: {e}"),
                                )
                                .with_endpoint(endpoint_id_owned.clone())
                                .with_preview_request(format!("tool={tool_name} args={raw_args}"));
                                record_agent_error(context, agent_name, rec).await;
                                (serde_json::json!({}), true)
                            }
                        };

                    let is_lore_tool = lore_names.contains(tool_name);
                    let display = if is_lore_tool {
                        format_lore_tool_display(tool_name, &tool_args)
                    } else {
                        format_local_tool_display(tool_name, &tool_args)
                    };
                    let _ = context
                        .client
                        .post(format!("{}/v1/chat/respond", context.url))
                        .header("x-lore-key", token)
                        .json(&serde_json::json!({ "tool_use": display }))
                        .send()
                        .await;

                    let result_text = if parse_error {
                        Some(
                            "Error: Failed to parse tool arguments (malformed JSON). Retry with valid JSON.".to_string(),
                        )
                    } else if is_lore_tool {
                        execute_lore_tool(context, tool_name, &tool_args).await
                    } else {
                        execute_local_tool(context, tool_name, &tool_args).await
                    };

                    let Some(result_text) = result_text.map(|raw| truncate_local_tool_result(&raw))
                    else {
                        report_stop_acknowledged(context, token).await;
                        return Ok((accumulated_text.clone(), emitted_assistant_messages));
                    };

                    messages.push(serde_json::json!({
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": result_text,
                    }));
                }

                if [300, 400, 475].contains(&turn) {
                    messages.push(serde_json::json!({
                        "role": "user",
                        "content": format!(
                            "You have used {turn} of {API_AGENT_MAX_TURNS} tool-calling turns. \
                            You have {} turns remaining. Wrap up your work soon.",
                            API_AGENT_MAX_TURNS - turn
                        ),
                    }));
                }
                continue;
            }
        }

        if finish_reason == "length" && content.trim().is_empty() {
            messages.push(serde_json::json!({ "role": "assistant", "content": content }));
            messages.push(serde_json::json!({ "role": "user", "content": "Your response was truncated. Please continue." }));
            continue;
        }
        if finish_reason == "length" && !content.is_empty() {
            accumulated_text
                .push_str("\n\n\u{26a0}\u{fe0f} Response was truncated (hit output token limit).");
        }

        break;
    }

    if accumulated_text.is_empty() {
        accumulated_text = "(no response)".to_string();
    }

    // Save API agent context for debugging
    {
        let lore_dir = agent_lore_dir(agent_name);
        let _ = fs::create_dir_all(&lore_dir);
        let debug: String = messages
            .iter()
            .map(|m| {
                let role = m["role"].as_str().unwrap_or("?");
                let content = m["content"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(200)
                    .collect::<String>();
                format!("[{role}] {content}\n")
            })
            .collect();
        let _ = fs::write(lore_dir.join("api_context.txt"), &debug);
    }

    Ok((accumulated_text, emitted_assistant_messages))
}

fn trim_api_context(messages: &mut Vec<serde_json::Value>) {
    let size: usize = messages
        .iter()
        .map(|m| serde_json::to_string(m).map(|s| s.len()).unwrap_or(0))
        .sum();
    if size <= API_AGENT_MAX_CONTEXT_CHARS {
        return;
    }

    for m in messages.iter_mut() {
        let role = m["role"].as_str().unwrap_or("");
        if role == "tool" {
            if let Some(s) = m["content"].as_str() {
                if s.len() > 500 && s != API_AGENT_TRIMMED_STUB {
                    m["content"] = serde_json::json!(API_AGENT_TRIMMED_STUB);
                }
            }
        } else if role == "assistant" {
            if let Some(s) = m["content"].as_str() {
                if s.len() > 2000 {
                    let preview: String = s.chars().take(500).collect();
                    m["content"] =
                        serde_json::json!(format!("{preview}\n[Earlier analysis trimmed]"));
                }
            }
        }
    }
}

fn aggressive_trim_api_context(messages: &mut Vec<serde_json::Value>) {
    for m in messages.iter_mut() {
        let role = m["role"].as_str().unwrap_or("");
        if role == "tool" {
            if let Some(s) = m["content"].as_str() {
                if s != API_AGENT_TRIMMED_STUB {
                    m["content"] = serde_json::json!(API_AGENT_TRIMMED_STUB);
                }
            }
        }
    }
}

fn truncate_local_tool_result(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= 1000 && text.len() <= 100_000 {
        return text.to_string();
    }
    let shown = if lines.len() > 1000 {
        1000
    } else {
        lines.len()
    };
    let truncated: String = lines[..shown].join("\n");
    format!(
        "{truncated}\n\n[Output truncated \u{2014} {shown} of {} lines shown]",
        lines.len()
    )
}

fn format_local_tool_display(name: &str, args: &serde_json::Value) -> String {
    let get_str = |key: &str| -> &str { args.get(key).and_then(|v| v.as_str()).unwrap_or("") };
    match name {
        "read_file" => format!("Read {}", short_path(get_str("path"))),
        "write_file" => format!("Write {}", short_path(get_str("path"))),
        "edit_file" => format!("Edit {}", short_path(get_str("path"))),
        "bash" => {
            let cmd = get_str("command");
            let truncated: String = cmd.chars().take(120).collect();
            format!("Bash: {truncated}")
        }
        "grep" => {
            let pattern = get_str("pattern");
            let path = if get_str("path").is_empty() {
                "."
            } else {
                get_str("path")
            };
            format!("Grep \"{pattern}\" in {}", short_path(path))
        }
        "glob" => format!("Glob {}", get_str("pattern")),
        "list_directory" => format!("List {}", short_path(get_str("path"))),
        _ => name.to_string(),
    }
}

async fn fetch_lore_tools(context: &CliContext) -> Vec<serde_json::Value> {
    let token = match context.token.as_deref() {
        Some(t) => t,
        None => return vec![],
    };
    let resp = context
        .client
        .get(format!("{}/v1/chat/lore-tools", context.url))
        .header("x-lore-key", token)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => {
            if let Ok(body) = r.json::<serde_json::Value>().await {
                body["tools"].as_array().cloned().unwrap_or_default()
            } else {
                vec![]
            }
        }
        _ => vec![],
    }
}

async fn execute_lore_tool(
    context: &CliContext,
    name: &str,
    args: &serde_json::Value,
) -> Option<String> {
    let token = match context.token.as_deref() {
        Some(t) => t,
        None => return Some("Error: no token configured".to_string()),
    };
    let resp = match race_with_stop(
        context,
        context
            .client
            .post(format!("{}/v1/chat/lore-tools", context.url))
            .header("x-lore-key", token)
            .timeout(std::time::Duration::from_secs(30))
            .json(&serde_json::json!({ "name": name, "arguments": args }))
            .send(),
    )
    .await
    {
        StopAware::Completed(resp) => resp,
        StopAware::Stopped => return None,
    };
    match resp {
        Ok(r) => match race_with_stop(context, r.json::<serde_json::Value>()).await {
            StopAware::Completed(Ok(body)) => Some(
                body["result"]
                    .as_str()
                    .unwrap_or("(empty result)")
                    .to_string(),
            ),
            StopAware::Completed(Err(_)) => {
                Some("Error: failed to parse server response".to_string())
            }
            StopAware::Stopped => None,
        },
        Err(e) => Some(format!("Error calling Lore tool: {e}")),
    }
}

async fn execute_local_tool(
    context: &CliContext,
    name: &str,
    args: &serde_json::Value,
) -> Option<String> {
    match name {
        "read_file" => Some(execute_read_file(args).await),
        "write_file" => Some(execute_write_file(args).await),
        "edit_file" => Some(execute_edit_file(args).await),
        "bash" => execute_bash(context, args).await,
        "grep" => execute_grep(context, args).await,
        "glob" => execute_glob(context, args).await,
        "list_directory" => Some(execute_list_directory(args).await),
        _ => Some(format!("Unknown tool: {name}")),
    }
}

async fn wait_for_child_output(
    child: tokio::process::Child,
    timeout: std::time::Duration,
    timeout_message: &'static str,
    context: &CliContext,
) -> Option<Result<std::process::Output, io::Error>> {
    let pid = child.id();
    let wait = child.wait_with_output();
    tokio::pin!(wait);

    tokio::select! {
        output = &mut wait => Some(output),
        _ = tokio::time::sleep(timeout) => {
            if let Some(pid) = pid {
                kill_process_tree(pid);
            }
            let _ = wait.await;
            Some(Err(io::Error::new(io::ErrorKind::TimedOut, timeout_message)))
        }
        _ = wait_for_stop_request(context) => {
            if let Some(pid) = pid {
                kill_process_tree(pid);
            }
            let _ = wait.await;
            None
        }
    }
}

fn format_lore_tool_display(name: &str, args: &serde_json::Value) -> String {
    let get_str = |key: &str| -> &str { args.get(key).and_then(|v| v.as_str()).unwrap_or("") };
    let short_id = |key: &str| -> String {
        let id = get_str(key);
        if id.starts_with('_') {
            id.to_string()
        } else if id.len() > 8 {
            id[..8].to_string()
        } else {
            id.to_string()
        }
    };
    match name {
        "list_projects" => "\u{1f4cb} list_projects".into(),
        "list_documents" => format!("\u{1f4c1} list_documents {}", get_str("project")),
        "create_document" => format!("\u{1f4c4} create_document \"{}\"", get_str("name")),
        "rename_document" => format!("\u{1f4c4} rename_document \"{}\"", get_str("name")),
        "delete_document" => format!(
            "\u{1f5d1}\u{fe0f} delete_document {}",
            short_id("document_id")
        ),
        "list_blocks" => format!("\u{1f4cb} list_blocks {}", short_id("document_id")),
        "read_block" => format!("\u{1f4d6} read_block {}", short_id("block_id")),
        "update_block" => format!("\u{270f}\u{fe0f} update_block {}", short_id("block_id")),
        "edit_block" => format!("\u{270f}\u{fe0f} edit_block {}", short_id("block_id")),
        "create_block" => format!("\u{270f}\u{fe0f} create_block {}", short_id("document_id")),
        "delete_block" => format!("\u{1f5d1}\u{fe0f} delete_block {}", short_id("block_id")),
        "move_block" => format!("\u{1f4e6} move_block {}", short_id("block_id")),
        "grep_blocks" => format!("\u{1f50d} grep_blocks \"{}\"", get_str("query")),
        _ => format!("\u{1f527} {name}"),
    }
}

fn build_local_tools() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file's contents with line numbers. Use offset and limit for large files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File path (absolute or relative)" },
                        "offset": { "type": "integer", "description": "Starting line number (1-based)" },
                        "limit": { "type": "integer", "description": "Max number of lines to read" }
                    },
                    "required": ["path"]
                }
            }
        }),
        serde_json::json!({
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "Write content to a file, creating parent directories as needed. Overwrites existing content.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File path to write to" },
                        "content": { "type": "string", "description": "Content to write" }
                    },
                    "required": ["path", "content"]
                }
            }
        }),
        serde_json::json!({
            "type": "function",
            "function": {
                "name": "edit_file",
                "description": "Replace exact text in a file. old_string must match exactly (including whitespace) and must be unique in the file. Read the file first.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File path to edit" },
                        "old_string": { "type": "string", "description": "Exact text to find (must be unique in file)" },
                        "new_string": { "type": "string", "description": "Replacement text" }
                    },
                    "required": ["path", "old_string", "new_string"]
                }
            }
        }),
        serde_json::json!({
            "type": "function",
            "function": {
                "name": "bash",
                "description": "Run a shell command. Returns stdout, stderr, and exit code. Times out after 120 seconds.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "Shell command to execute" }
                    },
                    "required": ["command"]
                }
            }
        }),
        serde_json::json!({
            "type": "function",
            "function": {
                "name": "grep",
                "description": "Search for a regex pattern in files recursively. Returns matching lines with file paths and line numbers.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string", "description": "Regex pattern to search for" },
                        "path": { "type": "string", "description": "Directory or file to search (default: current dir)" },
                        "include": { "type": "string", "description": "File glob to include (e.g. '*.rs')" }
                    },
                    "required": ["pattern"]
                }
            }
        }),
        serde_json::json!({
            "type": "function",
            "function": {
                "name": "glob",
                "description": "Find files matching a glob pattern.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string", "description": "Glob pattern (e.g. '*.rs', '**/*.ts')" },
                        "path": { "type": "string", "description": "Base directory (default: current dir)" }
                    },
                    "required": ["pattern"]
                }
            }
        }),
        serde_json::json!({
            "type": "function",
            "function": {
                "name": "list_directory",
                "description": "List files and directories in a path. Directories end with /.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Directory to list (default: current dir)" }
                    }
                }
            }
        }),
    ]
}

async fn execute_read_file(args: &serde_json::Value) -> String {
    let path = match args["path"].as_str() {
        Some(p) => p.to_string(),
        None => return "Error: path is required".to_string(),
    };
    let resolved = resolve_agent_path(&path);
    let offset = args["offset"].as_u64().unwrap_or(0) as usize;
    let limit = args["limit"].as_u64().map(|l| l as usize);

    // Run blocking file read off the async runtime
    tokio::task::spawn_blocking(move || match fs::read_to_string(&resolved) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = if offset > 0 {
                offset.saturating_sub(1)
            } else {
                0
            };
            let end = match limit {
                Some(l) => (start + l).min(lines.len()),
                None => lines.len(),
            };
            if start >= lines.len() {
                return format!(
                    "Error: offset {offset} beyond end of file ({} lines)",
                    lines.len()
                );
            }
            let mut result = String::new();
            for (i, line) in lines[start..end].iter().enumerate() {
                result.push_str(&format!("{:>6}\t{}\n", start + i + 1, line));
            }
            if result.is_empty() {
                "(empty file)".to_string()
            } else {
                result
            }
        }
        Err(e) => format!("Error reading {}: {e}", path),
    })
    .await
    .unwrap_or_else(|e| format!("Error: task failed: {e}"))
}

async fn execute_write_file(args: &serde_json::Value) -> String {
    let path = match args["path"].as_str() {
        Some(p) => p.to_string(),
        None => return "Error: path is required".to_string(),
    };
    let resolved = resolve_agent_path(&path);
    let content = args["content"].as_str().unwrap_or("").to_string();
    tokio::task::spawn_blocking(move || {
        if let Some(parent) = resolved.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::write(&resolved, &content) {
            Ok(()) => format!("Wrote {} bytes to {}", content.len(), path),
            Err(e) => format!("Error writing {}: {e}", path),
        }
    })
    .await
    .unwrap_or_else(|e| format!("Error: task failed: {e}"))
}

async fn execute_edit_file(args: &serde_json::Value) -> String {
    let path = match args["path"].as_str() {
        Some(p) => p.to_string(),
        None => return "Error: path is required".to_string(),
    };
    let resolved = resolve_agent_path(&path);
    let old_string = match args["old_string"].as_str() {
        Some(s) => s.to_string(),
        None => return "Error: old_string is required".to_string(),
    };
    let new_string = args["new_string"].as_str().unwrap_or("").to_string();
    tokio::task::spawn_blocking(move || {
        let content = match fs::read_to_string(&resolved) {
            Ok(c) => c,
            Err(e) => return format!("Error reading {}: {e}", path),
        };
        let count = content.matches(old_string.as_str()).count();
        if count == 0 {
            return format!("Error: old_string not found in {}", path);
        }
        if count > 1 {
            return format!("Error: old_string found {count} times in {} \u{2014} must be unique. Provide more surrounding context.", path);
        }
        let new_content = content.replacen(&old_string, &new_string, 1);
        match fs::write(&resolved, new_content) {
            Ok(()) => format!("Edited {}: replaced 1 occurrence", path),
            Err(e) => format!("Error writing {}: {e}", path),
        }
    }).await.unwrap_or_else(|e| format!("Error: task failed: {e}"))
}

async fn execute_bash(context: &CliContext, args: &serde_json::Value) -> Option<String> {
    let command = match args["command"].as_str() {
        Some(c) => c,
        None => return Some("Error: command is required".to_string()),
    };
    let mut cmd = tokio::process::Command::new("bash");
    cmd.args(["-lc", command])
        .current_dir(&agent_cwd())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    configure_child_process_group(&mut cmd);
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return Some(format!("Error running command: {e}")),
    };
    let result = wait_for_child_output(
        child,
        std::time::Duration::from_secs(120),
        "command timed out after 120 seconds",
        context,
    )
    .await;
    match result {
        Some(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);
            let mut r = String::new();
            if !stdout.is_empty() {
                r.push_str(&stdout);
            }
            if !stderr.is_empty() {
                if !r.is_empty() {
                    r.push('\n');
                }
                r.push_str(&format!("(stderr) {stderr}"));
            }
            if exit_code != 0 {
                r.push_str(&format!("\n(exit code: {exit_code})"));
            }
            if r.is_empty() {
                Some(format!("(no output, exit code: {exit_code})"))
            } else {
                Some(r)
            }
        }
        Some(Err(e)) if e.kind() == io::ErrorKind::TimedOut => Some(format!("Error: {e}")),
        Some(Err(e)) => Some(format!("Error running command: {e}")),
        None => None,
    }
}

async fn execute_grep(context: &CliContext, args: &serde_json::Value) -> Option<String> {
    let pattern = match args["pattern"].as_str() {
        Some(p) => p,
        None => return Some("Error: pattern is required".to_string()),
    };
    let path = args["path"].as_str().unwrap_or(".");
    let resolved = resolve_agent_path(path);
    let include = args["include"].as_str();
    let mut cmd = tokio::process::Command::new("grep");
    cmd.args(["-rn", "--color=never"]);
    if let Some(inc) = include {
        cmd.args(["--include", inc]);
    }
    cmd.arg("--").arg(pattern).arg(&resolved);
    cmd.current_dir(&agent_cwd());
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    configure_child_process_group(&mut cmd);
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return Some(format!("Error: {e}")),
    };
    match wait_for_child_output(
        child,
        std::time::Duration::from_secs(30),
        "grep timed out",
        context,
    )
    .await
    {
        Some(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() {
                Some("No matches found".to_string())
            } else {
                Some(stdout.to_string())
            }
        }
        Some(Err(e)) if e.kind() == io::ErrorKind::TimedOut => Some(format!("Error: {e}")),
        Some(Err(e)) => Some(format!("Error: {e}")),
        None => None,
    }
}

async fn execute_glob(context: &CliContext, args: &serde_json::Value) -> Option<String> {
    let pattern = match args["pattern"].as_str() {
        Some(p) => p,
        None => return Some("Error: pattern is required".to_string()),
    };
    let path = args["path"].as_str().unwrap_or(".");
    let resolved = resolve_agent_path(path);
    let mut cmd = tokio::process::Command::new("find");
    cmd.arg(&resolved).args(["-name", pattern, "-type", "f"]);
    cmd.current_dir(&agent_cwd());
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    configure_child_process_group(&mut cmd);
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return Some(format!("Error: {e}")),
    };
    match wait_for_child_output(
        child,
        std::time::Duration::from_secs(15),
        "glob search timed out",
        context,
    )
    .await
    {
        Some(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() {
                Some("No files found".to_string())
            } else {
                Some(stdout.to_string())
            }
        }
        Some(Err(e)) if e.kind() == io::ErrorKind::TimedOut => Some(format!("Error: {e}")),
        Some(Err(e)) => Some(format!("Error: {e}")),
        None => None,
    }
}

async fn execute_list_directory(args: &serde_json::Value) -> String {
    let path = args["path"].as_str().unwrap_or(".").to_string();
    let resolved = resolve_agent_path(&path);
    tokio::task::spawn_blocking(move || match fs::read_dir(&resolved) {
        Ok(entries) => {
            let mut items: Vec<String> = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                items.push(if is_dir { format!("{name}/") } else { name });
            }
            items.sort();
            if items.is_empty() {
                "(empty directory)".to_string()
            } else {
                items.join("\n")
            }
        }
        Err(e) => format!("Error listing {}: {e}", path),
    })
    .await
    .unwrap_or_else(|e| format!("Error: task failed: {e}"))
}

// --- API-based compaction (for API agents without CLI) ---

async fn run_api_compaction(context: &CliContext, prompt: &str) -> CliResult<String> {
    let token = context.token.as_deref().ok_or("no token configured")?;

    let body = serde_json::json!({
        "messages": [
            { "role": "system", "content": "You are a conversation compactor. Produce a concise summary." },
            { "role": "user", "content": prompt },
        ],
        "stream": false,
        "max_tokens": 4096,
        "temperature": 0.3,
    });

    let resp = context
        .client
        .post(format!("{}/v1/chat/completions", context.url))
        .header("x-lore-key", token)
        .timeout(std::time::Duration::from_secs(60))
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp.json().await?;
    if !status.is_success() {
        let err = resp_body["error"]["message"]
            .as_str()
            .unwrap_or("unknown error");
        return Err(format!("Compaction error ({status}): {err}").into());
    }

    let text = resp_body["choices"]
        .as_array()
        .and_then(|c| c.first())
        .and_then(|c| c["message"]["content"].as_str())
        .unwrap_or("")
        .to_string();
    Ok(text)
}

const COMPACTION_SYSTEM_PROMPT: &str = r#"You are compacting conversation history for an LLM that will continue this work in a future session. The LLM cannot see these messages — only your summary. Write high-signal notes that help it pick up where things left off.

Write ONLY what a new session needs to know:
- Decisions made and WHY (the reasoning matters more than the action)
- What changed: "refactored compaction from token-based to message-count" not "edited context.ts lines 200-350"
- Bugs found, root causes identified, fixes applied
- Requirements or constraints the user stated
- Work in progress or explicitly planned next steps
- Anything surprising or non-obvious that was discovered

Do NOT include:
- Small talk, greetings, acknowledgments
- Step-by-step narration of tool use ("read file X, then edited Y")
- File contents or code snippets (the LLM can re-read files)
- Things that are obvious from reading the current code
- Alternatives that were discussed then rejected (unless the rejection reason is important)

Keep it concise. A few dense paragraphs are better than an exhaustive log. If there is a current summary, integrate the new messages into it — update or replace outdated information rather than appending."#;

async fn maybe_auto_compact(
    context: &CliContext,
    agent_name: &str,
    backend: AgentBackend,
) -> CliResult<()> {
    do_compact(context, agent_name, false, backend).await
}

async fn do_compact(
    context: &CliContext,
    _agent_name: &str,
    aggressive: bool,
    backend: AgentBackend,
) -> CliResult<()> {
    let token = context.token.as_deref().ok_or("no token configured")?;

    // Get current history
    let history: serde_json::Value = context
        .client
        .get(format!("{}/v1/chat/history", context.url))
        .header("x-lore-key", token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let window_size = history_auto_compact_window_size(&history);
    let messages = match history["messages"].as_array() {
        Some(m) => m,
        None => return Ok(()),
    };
    let messages: Vec<&serde_json::Value> = messages.iter().collect();

    let exchange_count = count_history_exchanges(&messages);
    let Some(compact_count) = history_compaction_split_index(&messages, window_size) else {
        return Ok(());
    };

    let to_compact = &messages[..compact_count];
    let to_keep = &messages[compact_count..];
    let kept_exchanges = count_history_exchanges(to_keep);
    let summarized_exchanges = exchange_count.saturating_sub(kept_exchanges);

    eprintln!(
        "[agent] Compacting {summarized_exchanges} exchanges (total {exchange_count}, keeping {kept_exchanges}, window {window_size}{})",
        if aggressive { ", aggressive" } else { "" },
    );

    // Build compaction input
    let current_summary = history["summary"].as_str().unwrap_or("");
    let mut input = String::new();
    if !current_summary.is_empty() {
        input.push_str(&format!(
            "<current_summary>\n{current_summary}\n</current_summary>\n\n"
        ));
    }
    input.push_str("<messages_to_compact>\n");
    for msg in to_compact {
        let role = msg["role"].as_str().unwrap_or("user");
        if role == "tool" {
            continue;
        }
        let content = msg["content"].as_str().unwrap_or("");
        let content = chat_content_for_prompt(content, false);
        if role == "user" {
            input.push_str(&format!("User: {content}\n"));
        } else {
            let truncated: String = content.chars().take(4000).collect();
            input.push_str(&format!("Assistant: {truncated}\n\n"));
        }
    }
    input.push_str("</messages_to_compact>");

    // Run compaction through the agent's backend
    let full_prompt = build_compaction_prompt(&input);
    let new_summary = run_compaction(context, backend, &full_prompt).await?;

    if new_summary.is_empty() {
        eprintln!("[agent] Compaction produced empty summary, skipping");
        return Ok(());
    }

    // Post compacted state to server
    let kept_ids: Vec<&serde_json::Value> = to_keep.iter().map(|m| &m["id"]).collect();
    let _ = context
        .client
        .post(format!("{}/v1/chat/compact", context.url))
        .header("x-lore-key", token)
        .json(&serde_json::json!({
            "summary": new_summary,
            "keep_message_ids": kept_ids,
        }))
        .send()
        .await?
        .error_for_status()?;

    eprintln!(
        "[agent] Compaction complete. {} messages remaining",
        to_keep.len()
    );
    Ok(())
}

// --- Backend dispatch ---

enum BackendEvent {
    Text(String),
    ToolUse(String),
    Result(String),
    Skip,
}

fn append_new_stream_text(accumulated: &mut String, next: &str) -> Option<String> {
    if next.is_empty() {
        return None;
    }
    if accumulated.is_empty() {
        accumulated.push_str(next);
        return Some(next.to_string());
    }
    if next.starts_with(accumulated.as_str()) {
        let delta = &next[accumulated.len()..];
        if delta.is_empty() {
            return None;
        }
        accumulated.clear();
        accumulated.push_str(next);
        return Some(delta.to_string());
    }
    if accumulated.ends_with(next) {
        return None;
    }
    let max_overlap = accumulated.len().min(next.len());
    for overlap in (1..=max_overlap).rev() {
        if accumulated.is_char_boundary(accumulated.len() - overlap)
            && next.is_char_boundary(overlap)
            && accumulated[accumulated.len() - overlap..] == next[..overlap]
        {
            let delta = &next[overlap..];
            if delta.is_empty() {
                return None;
            }
            accumulated.push_str(delta);
            return Some(delta.to_string());
        }
    }
    accumulated.push_str(next);
    Some(next.to_string())
}

fn append_assistant_segment(accumulated: &mut String, next: &str) -> Option<String> {
    if next.is_empty() {
        return None;
    }
    let chunk =
        if !accumulated.is_empty() && !accumulated.ends_with('\n') && !next.starts_with('\n') {
            format!("\n\n{next}")
        } else {
            next.to_string()
        };
    accumulated.push_str(&chunk);
    Some(chunk)
}

fn short_path(p: &str) -> String {
    let path = std::path::Path::new(p);
    let file = path
        .file_name()
        .map(|f| f.to_string_lossy())
        .unwrap_or_default();
    let dir = path
        .parent()
        .and_then(|d| d.file_name())
        .map(|d| d.to_string_lossy());
    match dir {
        Some(d) if !d.is_empty() && d != "." => format!("{d}/{file}"),
        _ => file.to_string(),
    }
}

fn format_tool_use_claude(name: &str, input: &serde_json::Value) -> String {
    match name {
        "Read" => format!(
            "Read {}",
            input["file_path"]
                .as_str()
                .map(short_path)
                .unwrap_or_default()
        ),
        "Edit" => format!(
            "Edit {}",
            input["file_path"]
                .as_str()
                .map(short_path)
                .unwrap_or_default()
        ),
        "Write" => format!(
            "Write {}",
            input["file_path"]
                .as_str()
                .map(short_path)
                .unwrap_or_default()
        ),
        "MultiEdit" => format!(
            "MultiEdit {}",
            input["file_path"]
                .as_str()
                .map(short_path)
                .unwrap_or_default()
        ),
        "Bash" => {
            let cmd = input["command"].as_str().unwrap_or("");
            let truncated: String = cmd.chars().take(120).collect();
            format!("Bash: {truncated}")
        }
        "Grep" => {
            let pattern = input["pattern"].as_str().unwrap_or("");
            let path = input["path"]
                .as_str()
                .map(|p| short_path(p))
                .unwrap_or_else(|| ".".to_string());
            format!("Grep \"{pattern}\" in {path}")
        }
        "Glob" => format!("Glob {}", input["pattern"].as_str().unwrap_or("")),
        "WebSearch" => {
            let query = input["query"].as_str().unwrap_or("");
            let truncated: String = query.chars().take(100).collect();
            format!("WebSearch: {truncated}")
        }
        "WebFetch" => {
            let url = input["url"].as_str().unwrap_or("");
            let truncated: String = url.chars().take(100).collect();
            format!("WebFetch: {truncated}")
        }
        "LSP" => {
            let op = input["operation"].as_str().unwrap_or("");
            let file = input["filePath"]
                .as_str()
                .map(short_path)
                .unwrap_or_default();
            format!("LSP {op} {file}")
        }
        _ => name.to_string(),
    }
}

fn format_tool_use_codex(item: &serde_json::Value) -> Option<String> {
    if item["type"].as_str() == Some("command_execution") {
        let cmd = item["command"]
            .as_str()
            .unwrap_or("")
            .trim_start_matches("/bin/bash -lc ");
        let truncated: String = cmd.chars().take(120).collect();
        return Some(format!("Bash: {truncated}"));
    }

    if item["type"].as_str() == Some("file_change") {
        let changes = item.get("changes").and_then(|v| v.as_array())?;
        let mut details = Vec::new();
        for change in changes {
            let path = change.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path.is_empty() {
                continue;
            }
            let detail = match change.get("kind").and_then(|v| v.as_str()).unwrap_or("") {
                "add" | "create" | "write" => format!("Write {}", short_path(path)),
                "delete" | "remove" => format!("Delete {}", short_path(path)),
                _ => format!("Edit {}", short_path(path)),
            };
            details.push(detail);
        }
        return if details.is_empty() {
            Some("Edit files".to_string())
        } else {
            Some(details.join("\n"))
        };
    }

    let tool_name = item
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| item.get("tool_name").and_then(|v| v.as_str()))
        .or_else(|| item.get("call_name").and_then(|v| v.as_str()))
        .or_else(|| {
            item.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
        })?;

    let parse_args = |value: Option<&serde_json::Value>| -> serde_json::Value {
        match value {
            Some(serde_json::Value::Object(map)) => serde_json::Value::Object(map.clone()),
            Some(serde_json::Value::String(text)) => {
                serde_json::from_str(text).unwrap_or_else(|_| serde_json::json!({}))
            }
            _ => serde_json::json!({}),
        }
    };

    let args = parse_args(item.get("arguments"))
        .as_object()
        .map(|_| parse_args(item.get("arguments")))
        .unwrap_or_else(|| {
            let input_args = parse_args(item.get("input"));
            if input_args.is_object() {
                input_args
            } else {
                parse_args(item.get("args"))
            }
        });

    let detail = match tool_name {
        "read_file" | "write_file" | "edit_file" | "bash" | "grep" | "glob" | "list_directory" => {
            format_local_tool_display(tool_name, &args)
        }
        "functions.exec_command" | "exec_command" => {
            let cmd = args
                .get("cmd")
                .or_else(|| args.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let truncated: String = cmd.chars().take(120).collect();
            format!("Bash: {truncated}")
        }
        "functions.apply_patch" | "apply_patch" => "Edit files".to_string(),
        "functions.view_image" | "view_image" => {
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path.is_empty() {
                "View image".to_string()
            } else {
                format!("View image {}", short_path(path))
            }
        }
        _ => tool_name.to_string(),
    };
    Some(detail)
}

async fn spawn_backend(
    backend: AgentBackend,
    prompt: &str,
    model: Option<&str>,
    effort: Option<&str>,
    agent_token: Option<&str>,
    image_paths: &[PathBuf],
    prompt_file: Option<&Path>,
) -> CliResult<tokio::process::Child> {
    use tokio::io::AsyncWriteExt;

    let cwd = agent_cwd();
    let mut writes_prompt_to_stdin = true;
    let mut child = match backend {
        AgentBackend::Claude => {
            let mut args = vec![
                "-p".to_string(),
                "--output-format".to_string(),
                "stream-json".to_string(),
                "--verbose".to_string(),
                "--permission-mode".to_string(),
                "bypassPermissions".to_string(),
                "--no-session-persistence".to_string(),
            ];
            if let Some(m) = model {
                args.push("--model".to_string());
                args.push(m.to_string());
            }
            if let Some(e) = effort {
                args.push("--effort".to_string());
                args.push(e.to_string());
            }
            let mut cmd =
                tokio::process::Command::new(resolve_backend_executable(AgentBackend::Claude));
            cmd.args(&args)
                .current_dir(&cwd)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .env_remove("CLAUDECODE");
            configure_claude_auth_env(&mut cmd);
            configure_child_process_group(&mut cmd);
            if let Some(token) = agent_token {
                cmd.env("LORE_AGENT_TOKEN", token);
            }
            cmd.spawn()?
        }
        AgentBackend::Agy => {
            let args = agy_print_args(prompt, prompt_file)?;
            writes_prompt_to_stdin = false;
            let mut cmd =
                tokio::process::Command::new(resolve_backend_executable(AgentBackend::Agy));
            cmd.args(&args)
                .current_dir(&cwd)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            configure_agy_auth_env(&mut cmd);
            configure_child_process_group(&mut cmd);
            if let Some(token) = agent_token {
                cmd.env("LORE_AGENT_TOKEN", token);
            }
            cmd.spawn()?
        }
        AgentBackend::Codex => {
            let args = codex_exec_args(model, effort, image_paths);
            let mut cmd =
                tokio::process::Command::new(resolve_backend_executable(AgentBackend::Codex));
            cmd.args(&args)
                .current_dir(&cwd)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            configure_child_process_group(&mut cmd);
            if let Some(token) = agent_token {
                cmd.env("LORE_AGENT_TOKEN", token);
            }
            cmd.spawn()?
        }
        AgentBackend::OpenAi => {
            return Err("OpenAI backend is not yet implemented. Use claude, agy, or codex.".into());
        }
    };

    if writes_prompt_to_stdin {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(prompt.as_bytes()).await?;
            drop(stdin);
        }
    }

    Ok(child)
}

fn agy_print_args(prompt: &str, prompt_file: Option<&Path>) -> CliResult<Vec<String>> {
    let prompt_arg = if prompt.as_bytes().len() <= AGY_INLINE_PROMPT_MAX_BYTES {
        prompt.to_string()
    } else if let Some(prompt_file) = prompt_file {
        agy_prompt_file_instruction(prompt_file)
    } else {
        return Err(format!(
            "agy prompt is {} bytes, exceeding the inline limit of {} bytes, and no prompt file was available",
            prompt.as_bytes().len(),
            AGY_INLINE_PROMPT_MAX_BYTES
        )
        .into());
    };

    Ok(vec![
        "--dangerously-skip-permissions".to_string(),
        "--print-timeout".to_string(),
        "15m".to_string(),
        "-p".to_string(),
        prompt_arg,
    ])
}

fn agy_prompt_file_instruction(prompt_file: &Path) -> String {
    let display_path = fs::canonicalize(prompt_file).unwrap_or_else(|_| prompt_file.to_path_buf());
    format!(
        "Read the complete Lore prompt from this file:\n{}\n\nFollow the file contents exactly as the prompt for this run. Do not summarize the file. Return only the response requested by that prompt.",
        display_path.display()
    )
}

struct PromptFileCleanup(PathBuf);

impl Drop for PromptFileCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn backend_uses_json_lines(backend: AgentBackend) -> bool {
    matches!(backend, AgentBackend::Claude | AgentBackend::Codex)
}

fn append_plain_output_line(output: &mut String, line: &str) {
    if !output.is_empty() {
        output.push('\n');
    }
    output.push_str(line);
}

fn codex_exec_args(
    model: Option<&str>,
    effort: Option<&str>,
    image_paths: &[PathBuf],
) -> Vec<String> {
    let mut args = vec![
        "exec".to_string(),
        "--json".to_string(),
        "--dangerously-bypass-approvals-and-sandbox".to_string(),
        "--ephemeral".to_string(),
    ];
    if let Some(m) = model {
        args.push("--model".to_string());
        args.push(m.to_string());
    }
    if let Some(e) = effort {
        args.push("-c".to_string());
        args.push(format!("model_reasoning_effort=\"{e}\""));
    }
    for path in image_paths {
        args.push("--image".to_string());
        args.push(path.to_string_lossy().into_owned());
    }
    args.push("-".to_string());
    args
}

fn parse_backend_line(backend: AgentBackend, parsed: &serde_json::Value) -> Vec<BackendEvent> {
    match backend {
        AgentBackend::Claude => parse_claude_line(parsed),
        AgentBackend::Agy => vec![BackendEvent::Skip],
        AgentBackend::Codex => parse_codex_line(parsed),
        AgentBackend::OpenAi => vec![BackendEvent::Skip],
    }
}

fn parse_claude_line(parsed: &serde_json::Value) -> Vec<BackendEvent> {
    match parsed["type"].as_str() {
        Some("assistant") => {
            let mut events = Vec::new();
            if let Some(content) = parsed["message"]["content"].as_array() {
                let mut text = String::new();
                for block in content {
                    if block["type"].as_str() == Some("text") {
                        if let Some(t) = block["text"].as_str() {
                            text.push_str(t);
                        }
                    } else if block["type"].as_str() == Some("tool_use") {
                        if let Some(name) = block["name"].as_str() {
                            let input = &block["input"];
                            events.push(BackendEvent::ToolUse(format_tool_use_claude(name, input)));
                        }
                    }
                }
                if !text.is_empty() {
                    events.insert(0, BackendEvent::Text(text));
                }
            }
            if events.is_empty() {
                vec![BackendEvent::Skip]
            } else {
                events
            }
        }
        Some("result") => {
            let text = parsed["result"].as_str().unwrap_or("").to_string();
            vec![BackendEvent::Result(text)]
        }
        _ => vec![BackendEvent::Skip],
    }
}

fn parse_codex_line(parsed: &serde_json::Value) -> Vec<BackendEvent> {
    match parsed["type"].as_str() {
        Some("item.completed") => {
            if let Some(item) = parsed.get("item") {
                if item["type"].as_str() == Some("agent_message") {
                    if let Some(text) = item["text"].as_str() {
                        if !text.is_empty() {
                            return vec![BackendEvent::Text(text.to_string())];
                        }
                    }
                } else if let Some(detail) = format_tool_use_codex(item) {
                    return vec![BackendEvent::ToolUse(detail)];
                }
            }
            vec![BackendEvent::Skip]
        }
        Some("turn.completed") => vec![BackendEvent::Result(String::new())],
        _ => vec![BackendEvent::Skip],
    }
}

fn build_compaction_prompt(input: &str) -> String {
    format!(
        "{COMPACTION_SYSTEM_PROMPT}\n\n{input}\n\n## Current Date and Time\n\n{}",
        current_datetime_prompt_line()
    )
}

/// Run a prompt through the backend and collect the full text output.
/// Used for compaction where we need the complete response, not streaming.
async fn run_compaction(
    context: &CliContext,
    backend: AgentBackend,
    prompt: &str,
) -> CliResult<String> {
    match backend {
        AgentBackend::Claude => {
            // Claude without --output-format returns plain text
            use tokio::io::AsyncWriteExt;
            let mut cmd =
                tokio::process::Command::new(resolve_backend_executable(AgentBackend::Claude));
            cmd.args(["-p", "--model", "sonnet", "--no-session-persistence"])
                .current_dir(&agent_cwd())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .env_remove("CLAUDECODE");
            configure_claude_auth_env(&mut cmd);
            if let Some(token) = context.token.as_deref() {
                cmd.env("LORE_AGENT_TOKEN", token);
            }
            let mut child = cmd.spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(prompt.as_bytes()).await?;
                drop(stdin);
            }
            let output = child.wait_with_output().await?;
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        AgentBackend::Agy | AgentBackend::Codex => {
            // Codex streams JSON lines; Antigravity (`agy`) print mode returns plain text.
            let mut _agy_prompt_file_cleanup = None;
            let prompt_file_path = if matches!(backend, AgentBackend::Agy)
                && prompt.as_bytes().len() > AGY_INLINE_PROMPT_MAX_BYTES
            {
                let prompt_dir = agent_cwd().join(".lore");
                fs::create_dir_all(&prompt_dir)?;
                let unique = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_nanos())
                    .unwrap_or_default();
                let path = prompt_dir.join(format!(
                    "agy-compaction-{}-{unique}.txt",
                    std::process::id()
                ));
                fs::write(&path, prompt)?;
                _agy_prompt_file_cleanup = Some(PromptFileCleanup(path.clone()));
                Some(path)
            } else {
                None
            };
            let mut child = spawn_backend(
                backend,
                prompt,
                None,
                None,
                context.token.as_deref(),
                &[],
                prompt_file_path.as_deref(),
            )
            .await?;
            let stdout = child.stdout.take().ok_or("no stdout")?;
            let stderr = child.stderr.take().ok_or("no stderr")?;
            let reader = tokio::io::BufReader::new(stdout);
            let stderr_reader = tokio::io::BufReader::new(stderr);
            let mut lines = reader.lines();
            let mut stderr_lines = stderr_reader.lines();
            let mut result = String::new();
            let mut stdout_done = false;
            let mut stderr_done = false;

            loop {
                if stdout_done && stderr_done {
                    break;
                }
                tokio::select! {
                    line = lines.next_line(), if !stdout_done => {
                        let Some(line) = line? else {
                            stdout_done = true;
                            continue;
                        };
                        let line = line.trim().to_string();
                        if line.is_empty() {
                            continue;
                        }
                        if !backend_uses_json_lines(backend) {
                            if let Some(record) = classify_cli_non_json_output(backend, "stdout", &line) {
                                terminate_child_process_tree(&mut child).await;
                                return Err(record.detail.into());
                            }
                            append_plain_output_line(&mut result, &line);
                            continue;
                        }
                        let parsed: serde_json::Value = match serde_json::from_str(&line) {
                            Ok(v) => v,
                            Err(_) => {
                                if let Some(record) = classify_cli_non_json_output(backend, "stdout", &line) {
                                    terminate_child_process_tree(&mut child).await;
                                    return Err(record.detail.into());
                                }
                                continue;
                            },
                        };
                        for event in parse_backend_line(backend, &parsed) {
                            match event {
                                BackendEvent::Text(text) => {
                                    let _ = append_new_stream_text(&mut result, &text);
                                }
                                BackendEvent::Result(text) => {
                                    if result.is_empty() && !text.is_empty() {
                                        result = text;
                                    }
                                }
                                BackendEvent::ToolUse(_) | BackendEvent::Skip => {}
                            }
                        }
                    }
                    line = stderr_lines.next_line(), if !stderr_done => {
                        let Some(line) = line? else {
                            stderr_done = true;
                            continue;
                        };
                        let line = line.trim().to_string();
                        if line.is_empty() {
                            continue;
                        }
                        if let Some(record) = classify_cli_non_json_output(backend, "stderr", &line) {
                            terminate_child_process_tree(&mut child).await;
                            return Err(record.detail.into());
                        }
                    }
                }
            }
            let _ = child.wait().await;
            Ok(result.trim().to_string())
        }
        AgentBackend::OpenAi => run_api_compaction(context, prompt).await,
    }
}

// --- Machine service daemon ---

const LORE_SERVICE_DAEMON_ENV: &str = "LORE_SERVICE_DAEMON";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedAgent {
    name: String,
    pid: u32,
    folder: String,
    token: String,
    #[serde(default)]
    backend: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DesiredMachineAgent {
    name: String,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
}

struct ServiceState {
    agents: Vec<ManagedAgent>,
    state_dir: PathBuf,
    /// Runtime task handles for each agent, keyed by agent name.
    tasks: std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    desired_agent_errors: std::collections::HashMap<String, String>,
}

impl ServiceState {
    fn load(state_dir: &Path) -> Self {
        let agents_file = state_dir.join("agents.json");
        let agents = if agents_file.exists() {
            fs::read(&agents_file)
                .ok()
                .and_then(|data| serde_json::from_slice(&data).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Self {
            agents,
            state_dir: state_dir.to_path_buf(),
            tasks: std::collections::HashMap::new(),
            desired_agent_errors: std::collections::HashMap::new(),
        }
    }

    fn save(&self) {
        let _ = fs::create_dir_all(&self.state_dir);
        let _ = fs::write(
            self.state_dir.join("agents.json"),
            serde_json::to_vec_pretty(&self.agents).unwrap_or_default(),
        );
    }

    fn check_agents(&mut self) {
        let mut dead: Vec<String> = Vec::new();
        for (name, handle) in &self.tasks {
            if handle.is_finished() {
                eprintln!("[service] Agent '{}' task finished, will restart", name);
                dead.push(name.clone());
            }
        }
        for name in &dead {
            self.tasks.remove(name);
        }
    }

    fn start_agent_tasks(&mut self, context: &CliContext) {
        for agent in &self.agents {
            if self.tasks.contains_key(&agent.name) {
                continue; // already running
            }
            let handle = spawn_agent_task(context, agent);
            eprintln!("[service] Started agent '{}' as task", agent.name);
            self.tasks.insert(agent.name.clone(), handle);
        }
    }

    fn agent_statuses(&self) -> Vec<serde_json::Value> {
        let mut statuses: Vec<serde_json::Value> = self
            .agents
            .iter()
            .map(|a| {
                let running = self
                    .tasks
                    .get(&a.name)
                    .map(|h| !h.is_finished())
                    .unwrap_or(false);
                let status = if running { "running" } else { "restarting" };
                serde_json::json!({
                    "name": a.name,
                    "pid": std::process::id(),
                    "status": status,
                    "folder": a.folder,
                })
            })
            .collect();
        for (name, error) in &self.desired_agent_errors {
            if self.agents.iter().any(|a| a.name == *name) {
                continue;
            }
            statuses.push(serde_json::json!({
                "name": name,
                "pid": std::process::id(),
                "status": error,
            }));
        }
        statuses
    }

    fn reconcile_desired_agents(
        &mut self,
        context: &CliContext,
        desired_agents: &[DesiredMachineAgent],
    ) {
        let config = match load_cli_config() {
            Ok(config) => config,
            Err(e) => {
                eprintln!("[service] Cannot reconcile desired agents: {e}");
                return;
            }
        };
        self.reconcile_desired_agents_from_config(Some(context), desired_agents, &config);
    }

    fn reconcile_desired_agents_from_config(
        &mut self,
        context: Option<&CliContext>,
        desired_agents: &[DesiredMachineAgent],
        config: &CliConfig,
    ) {
        let desired_names: HashSet<String> = desired_agents
            .iter()
            .map(|agent| agent.name.clone())
            .collect();
        self.desired_agent_errors
            .retain(|name, _| desired_names.contains(name));

        let mut changed = false;
        for desired in desired_agents {
            if let Some(index) = self
                .agents
                .iter()
                .position(|agent| agent.name == desired.name)
            {
                self.desired_agent_errors.remove(&desired.name);
                if self.agents[index].backend != desired.backend {
                    eprintln!(
                        "[service] Updating desired agent '{}' backend from {:?} to {:?}",
                        desired.name, self.agents[index].backend, desired.backend
                    );
                    self.agents[index].backend = desired.backend.clone();
                    changed = true;
                    if let Some(context) = context {
                        if let Some(handle) = self.tasks.remove(&desired.name) {
                            handle.abort();
                        }
                        let agent = self.agents[index].clone();
                        let handle = spawn_agent_task(context, &agent);
                        self.tasks.insert(desired.name.clone(), handle);
                    }
                }
                continue;
            }

            let Some(token) = config.agent_tokens.get(&desired.name).cloned() else {
                eprintln!(
                    "[service] Desired agent '{}' is assigned here but missing from local token config",
                    desired.name
                );
                self.desired_agent_errors
                    .insert(desired.name.clone(), "missing_token".to_string());
                continue;
            };

            let folder_source = desired.cwd.as_deref().unwrap_or("~");
            let folder = match resolve_existing_service_path(folder_source) {
                Ok((_, folder)) => folder.to_string_lossy().into_owned(),
                Err(e) => {
                    eprintln!(
                        "[service] Desired agent '{}' has unusable folder '{}': {e}",
                        desired.name, folder_source
                    );
                    self.desired_agent_errors
                        .insert(desired.name.clone(), "invalid_folder".to_string());
                    continue;
                }
            };

            let managed = ManagedAgent {
                name: desired.name.clone(),
                pid: 0,
                folder,
                token,
                backend: desired.backend.clone(),
            };
            eprintln!(
                "[service] Reconciled desired agent '{}' into local management",
                desired.name
            );
            self.agents.push(managed);
            self.desired_agent_errors.remove(&desired.name);
            changed = true;
        }

        if changed {
            self.save();
            if let Some(context) = context {
                self.start_agent_tasks(context);
            }
        }
    }

    fn stop_agent(&mut self, name: &str) -> serde_json::Value {
        if self.agents.iter().any(|a| a.name == name) {
            if let Some(handle) = self.tasks.remove(name) {
                eprintln!("[service] Cancelling current task for agent '{}'", name);
                handle.abort();
                serde_json::json!({ "ok": true, "agent_name": name })
            } else {
                serde_json::json!({ "ok": true, "agent_name": name, "note": "agent was not running" })
            }
        } else {
            serde_json::json!({ "error": format!("agent '{}' not managed by this service", name) })
        }
    }

    fn remove_agent(&mut self, name: &str) -> serde_json::Value {
        if let Some(index) = self.agents.iter().position(|a| a.name == name) {
            // Stop the task if running
            if let Some(handle) = self.tasks.remove(name) {
                eprintln!("[service] Removing agent '{}'", name);
                handle.abort();
            } else {
                eprintln!("[service] Removing agent '{}'", name);
            }

            self.agents.remove(index);
            self.save();

            if let Ok(mut config) = load_cli_config() {
                config.agent_tokens.remove(name);
                let _ = save_cli_config(&config);
            }

            serde_json::json!({ "ok": true, "agent_name": name })
        } else {
            serde_json::json!({ "error": format!("agent '{}' not managed by this service", name) })
        }
    }

    fn restart_agent(&mut self, context: &CliContext, name: &str) -> serde_json::Value {
        if let Some(agent) = self.agents.iter().find(|a| a.name == name).cloned() {
            // Stop if running
            if let Some(handle) = self.tasks.remove(name) {
                handle.abort();
            }
            // Restart as new task
            let handle = spawn_agent_task(context, &agent);
            eprintln!("[service] Restarted agent '{}' as task", name);
            self.tasks.insert(name.to_string(), handle);
            self.save();
            serde_json::json!({ "ok": true, "agent_name": name, "pid": std::process::id() })
        } else {
            serde_json::json!({ "error": format!("agent '{}' not managed by this service", name) })
        }
    }

    fn stop_all_agents(&mut self) {
        for (name, handle) in self.tasks.drain() {
            eprintln!("[service] Stopping agent '{}'", name);
            handle.abort();
        }
    }
}

/// Spawn an agent as a tokio task within this process.
fn spawn_agent_task(context: &CliContext, agent: &ManagedAgent) -> tokio::task::JoinHandle<()> {
    let folder = PathBuf::from(&agent.folder);
    let name = agent.name.clone();
    let backend_override = service_managed_backend_override(agent);
    let ctx = CliContext {
        client: context.client.clone(),
        url: context.url.clone(),
        token: Some(agent.token.clone()),
        project: None,
    };

    // Ensure .lore dir exists
    let lore_dir = folder.join(format!(".lore/{}", name));
    let _ = fs::create_dir_all(&lore_dir);

    tokio::spawn(AGENT_CWD.scope(folder, async move {
        eprintln!("[agent] Task started for '{}'", name);
        let mut consecutive_errors: u32 = 0;
        let mut turn_failure_tracker = AgentTurnFailureTracker::default();
        loop {
            let outcome = agent_poll_and_process(
                &ctx,
                &name,
                backend_override,
                true,
                &mut turn_failure_tracker,
            )
            .await;
            match outcome {
                Ok(AgentPollAction::Continue) => {
                    consecutive_errors = 0;
                }
                Ok(AgentPollAction::Restart) => {
                    eprintln!("[agent] Task for '{}' restarting", name);
                    break;
                }
                Ok(AgentPollAction::UpdateAvailable) => {
                    // Service handles updates centrally — just keep polling.
                    eprintln!(
                        "[agent] '{}' ignoring update_to (service handles updates)",
                        name
                    );
                    consecutive_errors = 0;
                }
                Err(e) => {
                    consecutive_errors += 1;
                    // Exponential backoff: 5s, 10s, 20s, 40s, capped at 60s
                    let delay =
                        std::cmp::min(5 * (1u64 << consecutive_errors.saturating_sub(1)), 60);
                    eprintln!(
                        "[agent] '{}' error (#{consecutive_errors}, retry in {delay}s): {e}",
                        name
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                }
            }
        }
    }))
}

fn service_managed_backend_override(_agent: &ManagedAgent) -> Option<AgentBackend> {
    // Service-managed agents receive the current backend in every server poll.
    // Do not capture the cached agents.json backend here; otherwise a backend
    // switch can race with an already-running long-polling task and consume the
    // next turn using the old backend.
    None
}

/// Rotate log file if it exceeds 2MB. Keeps one `.1` backup.
fn rotate_log_if_needed(log_path: &Path) {
    const MAX_LOG_SIZE: u64 = 2 * 1024 * 1024; // 2MB
    if let Ok(meta) = fs::metadata(log_path) {
        if meta.len() > MAX_LOG_SIZE {
            let backup = log_path.with_extension("log.1");
            let _ = fs::rename(log_path, &backup);
            // Service's stderr is still pointing at the old inode, which is now
            // the backup file. The next write will go there, but the file won't
            // grow because we'll re-open on the next daemon spawn/restart.
            // For the running process, just truncate and carry on.
            let _ = fs::write(
                log_path,
                format!(
                    "[service] Log rotated at {}\n",
                    time::OffsetDateTime::now_utc()
                ),
            );
            eprintln!("[service] Log rotated ({} -> .log.1)", log_path.display());
        }
    }
}

/// Migrate old-style standalone `lore agent` processes into the service's managed agents.
/// Scans /proc for running `lore ... agent <name>` processes, adopts them (gets cwd, backend),
/// kills them, and adds them to agents.json so the service can re-spawn them under supervision.
fn migrate_old_agents(_context: &CliContext, svc_state: &mut ServiceState) {
    let config = match load_cli_config() {
        Ok(c) => c,
        Err(_) => return,
    };

    if config.agent_tokens.is_empty() {
        return;
    }

    eprintln!("[service] Checking for old-style agents to migrate...");
    let my_pid = std::process::id();

    for (agent_name, agent_token) in &config.agent_tokens {
        // Find a running process for this agent by scanning /proc
        let found = find_old_agent_process(agent_name, my_pid);

        let (folder, old_pid) = match found {
            Some(info) => info,
            None => {
                // Agent isn't running, but we know about it from config.
                let home = service_home_dir()
                    .unwrap_or_else(|_| PathBuf::from("/tmp"))
                    .to_string_lossy()
                    .into_owned();
                eprintln!(
                    "[service] Agent '{}' not running, importing with folder={}",
                    agent_name, home
                );
                (home, None)
            }
        };

        // Kill the old process if running
        if let Some(pid) = old_pid {
            eprintln!(
                "[service] Killing old-style agent '{}' (pid {})",
                agent_name, pid
            );
            kill_process(pid);
            std::thread::sleep(std::time::Duration::from_millis(300));
        }

        // Add to managed agents
        let managed = ManagedAgent {
            name: agent_name.clone(),
            pid: 0, // will be spawned by restart_crashed_agents
            folder,
            token: agent_token.clone(),
            backend: None,
        };
        svc_state.agents.push(managed);
        eprintln!("[service] Migrated agent '{}'", agent_name);
    }

    svc_state.save();
}

/// Scan /proc for a running `lore ... agent <name>` process.
/// Returns (cwd, pid) if found.
fn find_old_agent_process(agent_name: &str, exclude_pid: u32) -> Option<(String, Option<u32>)> {
    #[cfg(target_os = "linux")]
    {
        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return None,
        };

        for entry in proc_dir.flatten() {
            let pid_str = entry.file_name().to_string_lossy().into_owned();
            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            if pid == exclude_pid || pid == std::process::id() {
                continue;
            }

            // Read cmdline
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            let cmdline = match fs::read(&cmdline_path) {
                Ok(data) => data,
                Err(_) => continue,
            };

            let args: Vec<String> = cmdline
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();

            // Look for: ... lore ... agent <name>
            let has_lore = args.first().map(|a| a.contains("lore")).unwrap_or(false);
            let agent_idx = args.iter().position(|a| a == "agent");
            let matches = has_lore
                && agent_idx
                    .and_then(|i| args.get(i + 1))
                    .map(|n| n == agent_name)
                    .unwrap_or(false);

            if !matches {
                continue;
            }

            // Get cwd
            let cwd_link = format!("/proc/{}/cwd", pid);
            let cwd = fs::read_link(&cwd_link)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| {
                    service_home_dir()
                        .unwrap_or_else(|_| PathBuf::from("/tmp"))
                        .to_string_lossy()
                        .into_owned()
                });

            return Some((cwd, Some(pid)));
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (agent_name, exclude_pid);
        None
    }
}

async fn service_command(context: &CliContext, args: ServiceArgs) -> CliResult<()> {
    let is_daemon = env::var(LORE_SERVICE_DAEMON_ENV).unwrap_or_default() == "1";
    let machine_token = context
        .token
        .as_deref()
        .ok_or("no machine token configured. Run 'lore setup-machine <url>' first.")?;

    if !args.fg && !is_daemon {
        // Daemonize
        let lore_dir = service_root_dir()?;
        let log_path = lore_dir.join("service.log");
        let exe = resolved_current_exe()?;
        stop_existing_service_daemons(&lore_dir).await;
        match install_or_restart_lore_machine_user_systemd_service(&exe) {
            Ok(unit_path) => {
                println!("Lore service installed and enabled via user systemd.");
                println!("  Unit: {}", unit_path.display());
                return Ok(());
            }
            Err(err) => {
                eprintln!(
                    "warning: failed to install/start user systemd service ({err}); falling back to detached service"
                );
            }
        }

        let child = spawn_service_daemon(&exe, &context.url, machine_token, &log_path, &[])?;
        let pid = child.id();
        write_service_pid_file(&lore_dir, pid)?;
        println!("Lore service started (pid {})", pid);
        println!("  Log: {}", log_path.display());
        return Ok(());
    }

    // Write PID file for daemon mode
    let lore_dir = service_root_dir()?;
    if is_daemon {
        write_service_pid_file(&lore_dir, std::process::id())?;
    }

    eprintln!(
        "[service] Machine service starting (version {})",
        env!("CARGO_PKG_VERSION")
    );

    let handoff = service_handoff_from_env()?;

    // Load managed agents state
    let mut svc_state = ServiceState::load(&lore_dir);

    // Migrate old-style standalone agents if this is the first service run
    if svc_state.agents.is_empty() {
        migrate_old_agents(context, &mut svc_state);
    }

    eprintln!(
        "[service] Loaded {} managed agent(s)",
        svc_state.agents.len()
    );

    if let Some(handoff) = handoff.as_ref() {
        if complete_service_handoff(context, machine_token, &lore_dir, handoff).await?
            == ServiceHandoffCompletion::TransferredToSystemd
        {
            eprintln!("[service] Handoff transferred to user systemd; exiting staged process");
            return Ok(());
        }
    }

    // Rotate service log if it's grown large (>2MB)
    let service_log_path = lore_dir.join("service.log");

    if handoff.is_none() {
        match service_poll_and_execute(context, machine_token, &mut svc_state).await {
            Ok(Some((target_version, repo))) => {
                eprintln!(
                    "[service] Startup update to v{} required before starting agents",
                    normalize_version_tag(&target_version)
                );
                handle_service_update_request(
                    context,
                    machine_token,
                    &lore_dir,
                    &service_log_path,
                    &mut svc_state,
                    target_version,
                    repo,
                )
                .await;
            }
            Ok(None) => {}
            Err(e) => eprintln!("[service] Startup update check failed before agents started: {e}"),
        }
    }

    // Start all agents as tasks within this process after handoff/update checks.
    svc_state.check_agents();
    svc_state.start_agent_tasks(context);

    rotate_log_if_needed(&service_log_path);

    // Graceful shutdown on SIGTERM/SIGINT
    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        shutdown_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        eprintln!("[service] Shutdown signal received");
    });

    let mut consecutive_service_errors: u32 = 0;

    loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!("[service] Shutting down gracefully...");
            svc_state.stop_all_agents();
            svc_state.save();
            remove_owned_service_pid_file(&lore_dir, std::process::id());
            eprintln!("[service] Shutdown complete");
            return Ok(());
        }
        // Check agent health and restart dead tasks
        svc_state.check_agents();
        svc_state.start_agent_tasks(context);

        // Periodic log rotation check (cheap stat call)
        rotate_log_if_needed(&service_log_path);

        let poll_start = std::time::Instant::now();
        match service_poll_and_execute(context, machine_token, &mut svc_state).await {
            Ok(update_info) => {
                consecutive_service_errors = 0;
                if let Some((target_version, repo)) = update_info {
                    handle_service_update_request(
                        context,
                        machine_token,
                        &lore_dir,
                        &service_log_path,
                        &mut svc_state,
                        target_version,
                        repo,
                    )
                    .await;
                }
            }
            Err(e) => {
                consecutive_service_errors += 1;
                let delay = std::cmp::min(
                    5 * (1u64 << consecutive_service_errors.saturating_sub(1)),
                    120,
                );
                eprintln!(
                    "[service] Error (#{consecutive_service_errors}, retry in {delay}s): {e}"
                );
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                continue;
            }
        }

        // If the server held us for >5s (long-poll timeout, no command), re-poll
        // immediately so there's always an open connection ready for commands.
        // If it returned fast (<5s, had a command), brief pause to avoid tight loops.
        if poll_start.elapsed() < std::time::Duration::from_secs(5) {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

async fn handle_service_update_request(
    context: &CliContext,
    machine_token: &str,
    lore_dir: &Path,
    service_log_path: &Path,
    svc_state: &mut ServiceState,
    target_version: String,
    repo: String,
) {
    if let Some(delay) = current_service_update_backoff(lore_dir, &target_version) {
        eprintln!(
            "[service] Delaying retry of v{} for {}s after previous failed update",
            normalize_version_tag(&target_version),
            delay.as_secs()
        );
        return;
    }

    eprintln!(
        "[service] Server-directed self-update to v{target_version} requested; staging replacement while current service stays live"
    );

    match prepare_service_update(context, machine_token, &target_version, &repo, lore_dir).await {
        Ok(prepared) => {
            if current_process_in_systemd_unit(LORE_MACHINE_SERVICE_NAME) {
                match promote_staged_binary_to_canonical(
                    &prepared.staged_executable,
                    &prepared.canonical_executable,
                )
                .and_then(|_| {
                    verify_binary_matches_target(
                        &prepared.canonical_executable,
                        &prepared.target_version,
                    )
                }) {
                    Ok(()) => {
                        clear_service_update_failure(lore_dir);
                        eprintln!(
                            "[service] Installed v{} from {} into {}; asking systemd to restart this service",
                            prepared.target_version,
                            prepared.source,
                            prepared.canonical_executable.display()
                        );
                        svc_state.stop_all_agents();
                        svc_state.save();
                        remove_owned_service_pid_file(lore_dir, std::process::id());
                        std::process::exit(SYSTEMD_SERVICE_RESTART_EXIT_CODE);
                    }
                    Err(e) => {
                        record_service_update_failure(lore_dir, &target_version, &e.to_string());
                        eprintln!("[service] Systemd-managed update install failed: {e}");
                        return;
                    }
                }
            }

            let ready_path = lore_dir.join(format!("handoff-{}.json", uuid::Uuid::new_v4()));
            let handoff_env = [
                (
                    LORE_SERVICE_HANDOFF_READY_ENV,
                    ready_path.display().to_string(),
                ),
                (
                    LORE_SERVICE_HANDOFF_PARENT_PID_ENV,
                    std::process::id().to_string(),
                ),
                (
                    LORE_SERVICE_HANDOFF_CANONICAL_EXE_ENV,
                    prepared.canonical_executable.display().to_string(),
                ),
                (
                    LORE_SERVICE_HANDOFF_TARGET_VERSION_ENV,
                    prepared.target_version.clone(),
                ),
            ];
            match spawn_service_daemon(
                &prepared.staged_executable,
                &context.url,
                machine_token,
                service_log_path,
                &handoff_env,
            ) {
                Ok(child) => {
                    match wait_for_handoff_ready_marker(
                        &ready_path,
                        std::time::Duration::from_secs(60),
                    ) {
                        Ok(marker) => {
                            clear_service_update_failure(lore_dir);
                            eprintln!(
                                "[service] New v{} service ready from {}, stopping agents and handing off to pid {}",
                                marker.version,
                                prepared.source,
                                child.id()
                            );
                            svc_state.stop_all_agents();
                            svc_state.save();
                            std::process::exit(0);
                        }
                        Err(e) => {
                            let _ = fs::remove_file(&ready_path);
                            kill_process(child.id());
                            let _ = write_service_pid_file(lore_dir, std::process::id());
                            record_service_update_failure(
                                lore_dir,
                                &target_version,
                                &e.to_string(),
                            );
                            eprintln!("[service] Update handoff failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    record_service_update_failure(lore_dir, &target_version, &e.to_string());
                    eprintln!("[service] Failed to spawn staged service: {e}");
                }
            }
        }
        Err(e) => {
            record_service_update_failure(lore_dir, &target_version, &e.to_string());
            eprintln!("[service] Update staging failed: {e}");
        }
    }
}

/// Returns Some((target_version, repo)) if the service should self-update.
async fn service_poll_and_execute(
    context: &CliContext,
    machine_token: &str,
    svc_state: &mut ServiceState,
) -> CliResult<Option<(String, String)>> {
    let agent_statuses = svc_state.agent_statuses();

    let resp = context
        .client
        .post(format!("{}/v1/machines/poll", context.url))
        .header("x-lore-key", machine_token)
        .header("x-lore-version", env!("CARGO_PKG_VERSION"))
        .json(&serde_json::json!({ "agent_statuses": agent_statuses }))
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) if e.is_timeout() => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(
            format!("server rejected machine token ({status}) — check token config").into(),
        );
    }
    let body: serde_json::Value = resp.error_for_status()?.json().await?;

    let desired_agents: Vec<DesiredMachineAgent> =
        serde_json::from_value(body["desired_agents"].clone()).unwrap_or_default();
    svc_state.reconcile_desired_agents(context, &desired_agents);

    // Check for self-update request
    if let Some(target_version) = body["update_to"].as_str() {
        let repo = body["update_repo"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                load_cli_config()
                    .ok()
                    .map(|cfg| cfg.update_repo)
                    .unwrap_or_else(default_update_repo_string)
            });
        return Ok(Some((target_version.to_string(), repo)));
    }

    let commands = match body["commands"].as_array() {
        Some(c) if !c.is_empty() => c.clone(),
        _ => return Ok(None),
    };

    for cmd in &commands {
        let cmd_id = cmd["id"].as_str().unwrap_or("");
        let cmd_type = cmd["command_type"].as_str().unwrap_or("");
        let params = &cmd["params"];

        eprintln!("[service] Executing command: {} ({})", cmd_type, cmd_id);

        let result = match cmd_type {
            "list_dir" => service_handle_list_dir(params).await,
            "mkdir" => service_handle_mkdir(params).await,
            "create_agent" => {
                let r =
                    service_handle_create_agent(context, machine_token, params, svc_state).await;
                svc_state.save();
                r
            }
            "stop_agent" => {
                let name = params["agent_name"].as_str().unwrap_or("");
                Ok(svc_state.stop_agent(name))
            }
            "remove_agent" => {
                let name = params["agent_name"].as_str().unwrap_or("");
                Ok(svc_state.remove_agent(name))
            }
            "restart_agent" => {
                let name = params["agent_name"].as_str().unwrap_or("");
                Ok(svc_state.restart_agent(context, name))
            }
            other => Ok(serde_json::json!({ "error": format!("unknown command: {other}") })),
        };

        let result_data = match result {
            Ok(data) => data,
            Err(e) => serde_json::json!({ "error": e.to_string() }),
        };

        // Post result back to server
        let _ = context
            .client
            .post(format!(
                "{}/v1/machines/command/{}/result",
                context.url, cmd_id
            ))
            .header("x-lore-key", machine_token)
            .json(&serde_json::json!({ "data": result_data }))
            .send()
            .await;
    }

    Ok(None)
}

fn service_home_dir() -> CliResult<PathBuf> {
    let mut env_var = |name: &str| env::var_os(name);
    let raw_home = user_home_dir_from_env(host_platform(), &mut env_var).unwrap_or_else(|| {
        if cfg!(windows) {
            PathBuf::from(".")
        } else {
            PathBuf::from("/")
        }
    });
    Ok(fs::canonicalize(&raw_home)?)
}

fn ensure_path_within_home(path: &Path, home: &Path) -> CliResult<()> {
    if path.starts_with(home) {
        Ok(())
    } else {
        Err("path must stay within your home directory".into())
    }
}

fn resolve_existing_service_path(path_str: &str) -> CliResult<(PathBuf, PathBuf)> {
    let home = service_home_dir()?;
    let requested = if path_str == "~" || path_str.is_empty() {
        home.clone()
    } else {
        PathBuf::from(path_str)
    };
    let resolved = fs::canonicalize(&requested)?;
    ensure_path_within_home(&resolved, &home)?;
    Ok((home, resolved))
}

async fn service_handle_list_dir(params: &serde_json::Value) -> CliResult<serde_json::Value> {
    let path_str = params["path"].as_str().unwrap_or("~");
    let (home, path) = match resolve_existing_service_path(path_str) {
        Ok(v) => v,
        Err(e) => {
            return Ok(serde_json::json!({
                "error": e.to_string(),
            }));
        }
    };

    if !path.exists() {
        return Ok(serde_json::json!({
            "error": format!("path does not exist: {}", path.display()),
        }));
    }

    if !path.is_dir() {
        return Ok(serde_json::json!({
            "error": format!("not a directory: {}", path.display()),
        }));
    }

    let mut entries = Vec::new();
    match fs::read_dir(&path) {
        Ok(read_dir) => {
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') {
                    continue;
                }
                let is_dir = entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
                entries.push(serde_json::json!({
                    "name": name,
                    "is_dir": is_dir,
                }));
            }
        }
        Err(e) => {
            return Ok(serde_json::json!({ "error": format!("cannot read directory: {e}") }));
        }
    }

    entries.sort_by(|a, b| {
        let a_dir = a["is_dir"].as_bool().unwrap_or(false);
        let b_dir = b["is_dir"].as_bool().unwrap_or(false);
        match (a_dir, b_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                let a_name = a["name"].as_str().unwrap_or("");
                let b_name = b["name"].as_str().unwrap_or("");
                a_name.to_lowercase().cmp(&b_name.to_lowercase())
            }
        }
    });

    Ok(serde_json::json!({
        "path": path.to_string_lossy(),
        "home": home.to_string_lossy(),
        "entries": entries,
    }))
}

async fn service_handle_mkdir(params: &serde_json::Value) -> CliResult<serde_json::Value> {
    let base_path = params["path"].as_str().unwrap_or("~");
    let name = params["name"].as_str().unwrap_or("").trim();

    if name.is_empty() {
        return Ok(serde_json::json!({ "error": "missing folder name" }));
    }
    if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Ok(serde_json::json!({ "error": "invalid folder name" }));
    }

    let (home, parent) = match resolve_existing_service_path(base_path) {
        Ok(v) => v,
        Err(e) => return Ok(serde_json::json!({ "error": e.to_string() })),
    };

    let new_path = parent.join(name);
    ensure_path_within_home(&new_path, &home)?;
    fs::create_dir(&new_path)?;

    Ok(serde_json::json!({
        "ok": true,
        "path": new_path.to_string_lossy(),
    }))
}

async fn service_handle_create_agent(
    context: &CliContext,
    machine_token: &str,
    params: &serde_json::Value,
    svc_state: &mut ServiceState,
) -> CliResult<serde_json::Value> {
    let agent_name = params["agent_name"].as_str().ok_or("missing agent_name")?;
    let folder = params["folder"].as_str().ok_or("missing folder")?;
    let backend = params["backend"]
        .as_str()
        .unwrap_or("claude")
        .parse::<AgentBackend>()
        .unwrap_or(AgentBackend::Claude)
        .to_string();
    let grants = params["grants"].clone();
    let (_, folder_path) = match resolve_existing_service_path(folder) {
        Ok(v) => v,
        Err(e) => return Ok(serde_json::json!({ "error": e.to_string() })),
    };

    // Provision the agent via the API
    let resp = context
        .client
        .post(format!("{}/v1/agents/provision", context.url))
        .header("x-lore-key", machine_token)
        .header("x-lore-version", env!("CARGO_PKG_VERSION"))
        .json(&serde_json::json!({
            "name": agent_name,
            "backend": backend,
            "grants": grants,
        }))
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Ok(serde_json::json!({
            "error": format!("provisioning failed ({}): {}", status, body),
        }));
    }

    let prov_body: serde_json::Value = resp.json().await?;
    let agent_token = prov_body["token"].as_str().unwrap_or("");
    let agent_slug = prov_body["name"].as_str().unwrap_or(agent_name);

    // Save agent token in CLI config
    let mut config = load_cli_config()?;
    config
        .agent_tokens
        .insert(agent_slug.to_string(), agent_token.to_string());
    save_cli_config(&config)?;

    // Create managed agent entry
    let managed = ManagedAgent {
        name: agent_slug.to_string(),
        pid: 0,
        folder: folder_path.to_string_lossy().into_owned(),
        token: agent_token.to_string(),
        backend: Some(backend),
    };

    // Start the agent as a task within this process
    let handle = spawn_agent_task(context, &managed);
    eprintln!(
        "[service] Agent '{}' started in {} as task",
        agent_slug, managed.folder,
    );
    svc_state.tasks.insert(agent_slug.to_string(), handle);
    svc_state.agents.push(managed.clone());

    Ok(serde_json::json!({
        "ok": true,
        "agent_name": agent_slug,
        "folder": managed.folder,
        "pid": std::process::id(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        AGY_OAUTH_TOKEN_RELATIVE_PATH, BlocksCommand, Cli, Command, DocWriteArgs, ProjectSource,
        ResolvedProject, agy_print_args, api_endpoint_runtime_context,
        api_user_content_from_markdown_images, append_assistant_segment, append_block_content,
        append_new_stream_text, append_plain_output_line, backend_uses_json_lines,
        build_compaction_prompt, cgroup_text_contains_systemd_unit,
        chat_content_for_current_message_cli_prompt, chat_content_for_current_message_prompt,
        chat_content_for_prompt, codex_exec_args, count_history_exchanges, find_cwd_project_file,
        format_prompt_history_time, history_auto_compact_window_size,
        history_compaction_split_index, history_messages_excluding_pending,
        history_prompt_window_size, load_cli_text_input, load_doc_write_content,
        load_required_text_arg, looks_like_cli_auth_prompt, lore_machine_systemd_unit,
        lore_machine_user_systemd_unit_path_from_env, markdown_data_image_attachments,
        markdown_heading_matches, next_service_update_retry_delay_secs, parse_cli_version_output,
        parse_codex_line, recent_history_exchange_tail, recent_history_prompt_window,
        remove_owned_service_pid_file, resolve_context_project, resolve_executable_path_from,
        reuse_or_clear_staged_binary, sanitize_cli_output_preview, service_update_target,
        should_force_agy_file_token_auth_from, write_codex_image_attachments,
    };
    use clap::Parser;
    use lore_core::AgentBackend;
    use serde_json::json;
    use std::collections::HashSet;
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn env_lookup<'a>(
        pairs: &'a [(&'a str, &'a str)],
    ) -> impl FnMut(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    #[test]
    fn append_new_stream_text_converts_snapshots_to_deltas() {
        let mut accumulated = String::new();

        assert_eq!(
            append_new_stream_text(&mut accumulated, "First"),
            Some("First".to_string())
        );
        assert_eq!(accumulated, "First");

        assert_eq!(
            append_new_stream_text(&mut accumulated, "First second"),
            Some(" second".to_string())
        );
        assert_eq!(accumulated, "First second");
    }

    #[test]
    fn append_new_stream_text_ignores_exact_repeats() {
        let mut accumulated = "First second".to_string();

        assert_eq!(
            append_new_stream_text(&mut accumulated, "First second"),
            None
        );
        assert_eq!(accumulated, "First second");
    }

    #[test]
    fn append_new_stream_text_passes_through_real_deltas() {
        let mut accumulated = String::new();

        assert_eq!(
            append_new_stream_text(&mut accumulated, "First"),
            Some("First".to_string())
        );
        assert_eq!(
            append_new_stream_text(&mut accumulated, " second"),
            Some(" second".to_string())
        );
        assert_eq!(accumulated, "First second");
    }

    #[test]
    fn append_new_stream_text_merges_partial_overlap_without_duplication() {
        let mut accumulated = "First second".to_string();

        assert_eq!(
            append_new_stream_text(&mut accumulated, " second third"),
            Some(" third".to_string())
        );
        assert_eq!(accumulated, "First second third");
    }

    #[test]
    fn append_assistant_segment_inserts_blank_line_between_turns() {
        let mut accumulated = String::new();

        assert_eq!(
            append_assistant_segment(&mut accumulated, "First update"),
            Some("First update".to_string())
        );
        assert_eq!(
            append_assistant_segment(&mut accumulated, "Second update"),
            Some("\n\nSecond update".to_string())
        );
        assert_eq!(accumulated, "First update\n\nSecond update");
    }

    #[test]
    fn agy_backend_collects_plain_output_lines() {
        let mut output = String::new();

        assert!(!backend_uses_json_lines(AgentBackend::Agy));
        append_plain_output_line(&mut output, "first line");
        append_plain_output_line(&mut output, "second line");

        assert_eq!(output, "first line\nsecond line");
    }

    #[test]
    fn agy_print_args_keep_small_prompts_inline() {
        let args = agy_print_args("short prompt", None).unwrap();

        assert_eq!(args.last().map(String::as_str), Some("short prompt"));
    }

    #[test]
    fn agy_print_args_use_prompt_file_for_large_prompts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manager_context.txt");
        fs::write(&path, "full prompt").unwrap();
        let large_prompt = "x".repeat(super::AGY_INLINE_PROMPT_MAX_BYTES + 1);

        let args = agy_print_args(&large_prompt, Some(&path)).unwrap();
        let prompt_arg = args.last().unwrap();

        assert!(prompt_arg.contains("Read the complete Lore prompt from this file:"));
        assert!(prompt_arg.contains("manager_context.txt"));
        assert!(!prompt_arg.contains(&large_prompt));
    }

    #[test]
    fn agy_print_args_error_for_large_prompts_without_file() {
        let large_prompt = "x".repeat(super::AGY_INLINE_PROMPT_MAX_BYTES + 1);
        let err = agy_print_args(&large_prompt, None).unwrap_err().to_string();

        assert!(err.contains("exceeding the inline limit"));
        assert!(err.contains("no prompt file was available"));
    }

    #[test]
    fn cli_compaction_prompt_keeps_current_datetime_at_tail() {
        let prompt =
            build_compaction_prompt("<messages_to_compact>\nUser: hello\n</messages_to_compact>");
        assert!(prompt.starts_with("You are compacting conversation history"));
        assert!(prompt.contains("## Current Date and Time\n\nCurrent date and time: "));
        assert!(
            prompt.rfind("Current date and time: ").unwrap()
                > prompt.find("<messages_to_compact>").unwrap()
        );
    }

    #[test]
    fn prompt_history_time_uses_stable_absolute_timestamp() {
        assert_eq!(
            format_prompt_history_time("2026-06-19T10:11:12Z"),
            "2026-06-19T10:11:12Z"
        );
        assert_eq!(format_prompt_history_time("not-rfc3339"), "not-rfc3339");
    }

    #[test]
    fn service_update_target_matches_supported_runtime_targets() {
        let target = service_update_target().unwrap();
        assert!(matches!(
            target.as_str(),
            "x86_64-unknown-linux-gnu"
                | "aarch64-unknown-linux-gnu"
                | "x86_64-apple-darwin"
                | "aarch64-apple-darwin"
        ));
    }

    #[test]
    fn parse_cli_version_output_extracts_version() {
        assert_eq!(
            parse_cli_version_output("lore 0.1.65-rc110\n"),
            Some("0.1.65-rc110".to_string())
        );
    }

    #[test]
    fn backend_executable_resolution_prefers_user_local_fallbacks() {
        let home = tempfile::tempdir().unwrap();
        let path_dir = tempfile::tempdir().unwrap();
        let fallback = home.path().join(".local/bin/agy");
        fs::create_dir_all(fallback.parent().unwrap()).unwrap();
        fs::write(&fallback, "").unwrap();
        let system = path_dir.path().join("agy");
        fs::write(&system, "").unwrap();
        let path = std::env::join_paths([path_dir.path()]).unwrap();

        assert_eq!(
            resolve_executable_path_from(
                "agy",
                &[".local/bin/agy"],
                Some(home.path().as_os_str()),
                Some(path.as_os_str())
            ),
            fallback
        );
    }

    #[test]
    fn backend_executable_resolution_uses_path_when_no_user_local_fallback_exists() {
        let home = tempfile::tempdir().unwrap();
        let path_dir = tempfile::tempdir().unwrap();
        let system = path_dir.path().join("agy");
        fs::write(&system, "").unwrap();
        let path = std::env::join_paths([path_dir.path()]).unwrap();

        assert_eq!(
            resolve_executable_path_from(
                "agy",
                &[".local/bin/agy"],
                Some(home.path().as_os_str()),
                Some(path.as_os_str())
            ),
            system
        );
    }

    #[test]
    fn cli_config_path_uses_windows_appdata_when_home_is_absent() {
        let path = super::cli_config_path_from_env(
            super::HostPlatform::Windows,
            env_lookup(&[("APPDATA", r"C:\Users\stoate\AppData\Roaming")]),
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\stoate\AppData\Roaming")
                .join("lore")
                .join("config.json")
        );
    }

    #[test]
    fn cli_config_path_preserves_windows_home_when_it_is_set() {
        let path = super::cli_config_path_from_env(
            super::HostPlatform::Windows,
            env_lookup(&[
                ("HOME", r"C:\Users\stoate"),
                ("APPDATA", r"C:\Users\stoate\AppData\Roaming"),
            ]),
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\stoate")
                .join(".config")
                .join("lore")
                .join("config.json")
        );
    }

    #[test]
    fn cli_config_path_uses_windows_userprofile_fallback_when_home_is_absent() {
        let path = super::cli_config_path_from_env(
            super::HostPlatform::Windows,
            env_lookup(&[("USERPROFILE", r"C:\Users\stoate")]),
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\stoate")
                .join(".config")
                .join("lore")
                .join("config.json")
        );
    }

    #[test]
    fn service_root_dir_uses_windows_userprofile_when_home_is_absent() {
        let path = super::service_root_dir_from_env(
            super::HostPlatform::Windows,
            env_lookup(&[("USERPROFILE", r"C:\Users\stoate")]),
        );

        assert_eq!(
            path,
            PathBuf::from(r"C:\Users\stoate").join(".lore-service")
        );
    }

    #[test]
    fn service_root_dir_honors_explicit_override() {
        let path = super::service_root_dir_from_env(
            super::HostPlatform::Windows,
            env_lookup(&[
                ("LORE_SERVICE_DIR", r"D:\Lore\Service"),
                ("USERPROFILE", r"C:\Users\stoate"),
            ]),
        );

        assert_eq!(path, PathBuf::from(r"D:\Lore\Service"));
    }

    #[test]
    fn lore_machine_user_systemd_unit_path_uses_xdg_config_home() {
        let path = lore_machine_user_systemd_unit_path_from_env(
            super::HostPlatform::Unix,
            env_lookup(&[("XDG_CONFIG_HOME", "/home/main/.config")]),
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from("/home/main/.config")
                .join("systemd")
                .join("user")
                .join(super::LORE_MACHINE_SERVICE_NAME)
        );
    }

    #[test]
    fn lore_machine_user_systemd_unit_path_falls_back_to_home() {
        let path = lore_machine_user_systemd_unit_path_from_env(
            super::HostPlatform::Unix,
            env_lookup(&[("HOME", "/home/main")]),
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from("/home/main")
                .join(".config")
                .join("systemd")
                .join("user")
                .join(super::LORE_MACHINE_SERVICE_NAME)
        );
    }

    #[test]
    fn lore_machine_systemd_unit_restarts_on_failure_and_runs_foreground_service() {
        let unit = lore_machine_systemd_unit(
            PathBuf::from("/home/main/.local/bin/lore").as_path(),
            PathBuf::from("/home/main").as_path(),
        );

        assert!(unit.contains("Environment=LORE_SERVICE_DAEMON=1"));
        assert!(unit.contains("Environment=LORE_SERVICE_SYSTEMD=1"));
        assert!(unit.contains("WorkingDirectory=/home/main"));
        assert!(unit.contains("ExecStart=/home/main/.local/bin/lore service --fg"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn cgroup_detection_matches_systemd_unit_but_not_login_session_scope() {
        assert!(cgroup_text_contains_systemd_unit(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/lore-machine.service\n",
            super::LORE_MACHINE_SERVICE_NAME
        ));
        assert!(cgroup_text_contains_systemd_unit(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/lore\\x2dmachine.service\n",
            super::LORE_MACHINE_SERVICE_NAME
        ));
        assert!(!cgroup_text_contains_systemd_unit(
            "0::/user.slice/user-1000.slice/session-46.scope\n",
            super::LORE_MACHINE_SERVICE_NAME
        ));
    }

    #[test]
    fn agy_file_token_auth_is_forced_only_for_headless_token_env() {
        let home = tempfile::tempdir().unwrap();
        let token_path = home.path().join(AGY_OAUTH_TOKEN_RELATIVE_PATH);
        fs::create_dir_all(token_path.parent().unwrap()).unwrap();

        assert!(!should_force_agy_file_token_auth_from(
            Some(home.path().as_os_str()),
            None,
            None
        ));

        fs::write(&token_path, "token").unwrap();
        assert!(should_force_agy_file_token_auth_from(
            Some(home.path().as_os_str()),
            None,
            None
        ));
        assert!(!should_force_agy_file_token_auth_from(
            Some(home.path().as_os_str()),
            Some(OsStr::new("real ssh")),
            None
        ));
    }

    #[test]
    fn claude_login_auth_preferred_when_credentials_exist() {
        let home = tempfile::tempdir().unwrap();
        let credentials_path = home.path().join(".claude/.credentials.json");
        fs::create_dir_all(credentials_path.parent().unwrap()).unwrap();
        fs::write(&credentials_path, "{}").unwrap();
        let home_str = home.path().to_string_lossy().to_string();

        assert!(super::should_prefer_claude_login_auth_from(
            env_lookup(&[
                ("HOME", home_str.as_str()),
                ("ANTHROPIC_API_KEY", "stale-key")
            ]),
            |path| path.is_file()
        ));
    }

    #[test]
    fn claude_env_auth_can_be_explicitly_allowed() {
        let home = tempfile::tempdir().unwrap();
        let credentials_path = home.path().join(".claude/.credentials.json");
        fs::create_dir_all(credentials_path.parent().unwrap()).unwrap();
        fs::write(&credentials_path, "{}").unwrap();
        let home_str = home.path().to_string_lossy().to_string();

        assert!(!super::should_prefer_claude_login_auth_from(
            env_lookup(&[
                ("HOME", home_str.as_str()),
                ("ANTHROPIC_API_KEY", "intentional-key"),
                (super::LORE_CLAUDE_ALLOW_ENV_AUTH_ENV, "1")
            ]),
            |path| path.is_file()
        ));
    }

    #[test]
    fn claude_env_auth_preserved_when_login_credentials_are_absent() {
        let home = tempfile::tempdir().unwrap();
        let home_str = home.path().to_string_lossy().to_string();

        assert!(!super::should_prefer_claude_login_auth_from(
            env_lookup(&[
                ("HOME", home_str.as_str()),
                ("ANTHROPIC_API_KEY", "headless-key")
            ]),
            |path| path.is_file()
        ));
    }

    #[test]
    fn claude_config_dir_credentials_are_detected() {
        let config = tempfile::tempdir().unwrap();
        let credentials_path = config.path().join(".credentials.json");
        fs::write(&credentials_path, "{}").unwrap();
        let config_str = config.path().to_string_lossy().to_string();

        assert!(super::should_prefer_claude_login_auth_from(
            env_lookup(&[("CLAUDE_CONFIG_DIR", config_str.as_str())]),
            |path| path.is_file()
        ));
    }

    #[test]
    fn agent_turn_failure_tracker_caps_identical_backend_turn_failures() {
        let mut tracker = super::AgentTurnFailureTracker::default();
        let message_ids = [269];
        let detail = "spawn agy failed: Broken pipe (os error 32)";

        assert_eq!(
            tracker.record_failure(AgentBackend::Agy, &message_ids, detail),
            1
        );
        assert_eq!(
            tracker.record_failure(AgentBackend::Agy, &message_ids, detail),
            2
        );
        assert_eq!(
            tracker.record_failure(AgentBackend::Agy, &message_ids, detail),
            super::CLI_BACKEND_TURN_FAILURE_LIMIT
        );
    }

    #[test]
    fn agent_turn_failure_tracker_resets_for_new_turn_or_error() {
        let mut tracker = super::AgentTurnFailureTracker::default();

        assert_eq!(
            tracker.record_failure(AgentBackend::Agy, &[269], "spawn agy failed: Broken pipe"),
            1
        );
        assert_eq!(
            tracker.record_failure(AgentBackend::Agy, &[270], "spawn agy failed: Broken pipe"),
            1
        );
        assert_eq!(
            tracker.record_failure(
                AgentBackend::Agy,
                &[270],
                "spawn agy failed: permission denied"
            ),
            1
        );
        assert_eq!(
            tracker.record_failure(
                AgentBackend::Agy,
                &[270],
                "spawn agy failed: permission denied"
            ),
            2
        );
        tracker.reset();
        assert_eq!(
            tracker.record_failure(
                AgentBackend::Agy,
                &[270],
                "spawn agy failed: permission denied"
            ),
            1
        );
    }

    #[test]
    fn cli_auth_prompt_detection_matches_oauth_login_prompts() {
        assert!(looks_like_cli_auth_prompt(
            "OAuth login required. Open https://example.test/auth and enter the code."
        ));
        assert!(looks_like_cli_auth_prompt(
            "Please login to continue using Antigravity CLI."
        ));
        assert!(super::classify_cli_non_json_output(
            AgentBackend::Agy,
            "stdout",
            "To continue, sign in with your Google Account by visiting https://example.test/login"
        )
        .unwrap()
        .detail
        .contains("agy emitted a non-JSON stdout authentication prompt"));
    }

    #[test]
    fn visible_agent_error_content_is_bounded_and_marked() {
        let detail = format!(
            "codex exited without producing a response {}",
            "x".repeat(2_000)
        );
        let content = super::visible_agent_error_content(&detail);

        assert!(content.starts_with("[Agent error: codex exited without producing a response"));
        assert!(content.ends_with(']'));
        assert!(content.len() < 1_300);
    }

    #[test]
    fn cli_runtime_context_pins_current_backend_identity() {
        let context = super::cli_runtime_context(AgentBackend::Codex, None, Some("high"));

        assert!(context.contains("Lore `codex` CLI backend"));
        assert!(context.contains("model `default`"));
        assert!(context.contains("effort `high`"));
        assert!(context.contains("Do not infer your current identity"));
        assert!(context.contains("older assistant messages"));
        assert!(context.contains("stale history"));
    }

    #[test]
    fn service_managed_agent_uses_server_poll_backend_not_cached_backend() {
        let agent = super::ManagedAgent {
            name: "general".into(),
            pid: 0,
            folder: "/tmp".into(),
            token: "lore_at_test".into(),
            backend: Some("claude".into()),
        };

        assert_eq!(super::service_managed_backend_override(&agent), None);
    }

    #[test]
    fn cli_non_json_detection_matches_agy_startup_blockers() {
        let record = super::classify_cli_non_json_output(
            AgentBackend::Agy,
            "stdout",
            "YOLO mode is disabled by your administrator.",
        )
        .unwrap();

        assert!(record.detail.contains("startup blocker"));
        assert!(record.detail.contains("agy emitted a non-JSON stdout"));
    }

    #[test]
    fn cli_auth_prompt_detection_ignores_plain_non_json_noise() {
        assert!(!looks_like_cli_auth_prompt(
            "Loaded cached model preferences from disk"
        ));
        assert!(
            super::classify_cli_non_json_output(
                AgentBackend::Codex,
                "stderr",
                "Loaded cached model preferences from disk"
            )
            .is_none()
        );
    }

    #[test]
    fn cli_auth_prompt_preview_redacts_urls_and_long_tokens() {
        let preview = sanitize_cli_output_preview(&format!(
            "Visit https://example.test/auth?code=abc and enter {} to login",
            "a".repeat(100)
        ));

        assert!(preview.contains("[url]"));
        assert!(!preview.contains("https://example.test"));
        assert!(preview.contains("[redacted]"));
    }

    #[test]
    fn service_update_retry_backoff_is_exponential_and_capped() {
        assert_eq!(next_service_update_retry_delay_secs(1), 5);
        assert_eq!(next_service_update_retry_delay_secs(2), 10);
        assert_eq!(next_service_update_retry_delay_secs(3), 20);
        assert_eq!(next_service_update_retry_delay_secs(10), 300);
    }

    #[test]
    fn reuse_or_clear_staged_binary_removes_invalid_cached_file() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("lore");
        fs::write(&staged, b"not a real executable").unwrap();

        let reused = reuse_or_clear_staged_binary(&staged, "0.1.65-rc110").unwrap();
        assert!(!reused);
        assert!(!staged.exists());
    }

    #[test]
    fn remove_owned_service_pid_file_only_removes_matching_pid() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("service.pid");
        fs::write(&pid_path, "12345").unwrap();

        remove_owned_service_pid_file(dir.path(), 67890);
        assert_eq!(fs::read_to_string(&pid_path).unwrap(), "12345");

        remove_owned_service_pid_file(dir.path(), 12345);
        assert!(!pid_path.exists());
    }

    #[test]
    fn service_reconciles_missing_desired_agent_from_local_token_cache() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = super::ServiceState {
            agents: Vec::new(),
            state_dir: dir.path().to_path_buf(),
            tasks: std::collections::HashMap::new(),
            desired_agent_errors: std::collections::HashMap::new(),
        };
        let mut config = super::CliConfig::default();
        config
            .agent_tokens
            .insert("marketing".into(), "lore_at_test".into());
        let desired = vec![super::DesiredMachineAgent {
            name: "marketing".into(),
            backend: Some("claude".into()),
            cwd: None,
        }];

        state.reconcile_desired_agents_from_config(None, &desired, &config);

        assert_eq!(state.agents.len(), 1);
        assert_eq!(state.agents[0].name, "marketing");
        assert_eq!(state.agents[0].token, "lore_at_test");
        assert_eq!(state.agents[0].backend.as_deref(), Some("claude"));
        assert!(state.desired_agent_errors.is_empty());
        let saved = fs::read_to_string(dir.path().join("agents.json")).unwrap();
        assert!(saved.contains("\"name\": \"marketing\""));
    }

    #[test]
    fn service_updates_existing_desired_agent_backend_from_server_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = super::ServiceState {
            agents: vec![super::ManagedAgent {
                name: "website".into(),
                pid: 0,
                folder: "/tmp".into(),
                token: "lore_at_test".into(),
                backend: Some("claude".into()),
            }],
            state_dir: dir.path().to_path_buf(),
            tasks: std::collections::HashMap::new(),
            desired_agent_errors: std::collections::HashMap::new(),
        };
        let config = super::CliConfig::default();
        let desired = vec![super::DesiredMachineAgent {
            name: "website".into(),
            backend: Some("codex".into()),
            cwd: None,
        }];

        state.reconcile_desired_agents_from_config(None, &desired, &config);

        assert_eq!(state.agents.len(), 1);
        assert_eq!(state.agents[0].backend.as_deref(), Some("codex"));
        let saved = fs::read_to_string(dir.path().join("agents.json")).unwrap();
        assert!(saved.contains("\"backend\": \"codex\""));
    }

    #[test]
    fn service_reports_desired_agent_missing_token_without_importing_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = super::ServiceState {
            agents: Vec::new(),
            state_dir: dir.path().to_path_buf(),
            tasks: std::collections::HashMap::new(),
            desired_agent_errors: std::collections::HashMap::new(),
        };
        let config = super::CliConfig::default();
        let desired = vec![super::DesiredMachineAgent {
            name: "marketing".into(),
            backend: Some("claude".into()),
            cwd: None,
        }];

        state.reconcile_desired_agents_from_config(None, &desired, &config);

        assert!(state.agents.is_empty());
        let statuses = state.agent_statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0]["name"], json!("marketing"));
        assert_eq!(statuses[0]["status"], json!("missing_token"));
    }

    #[test]
    fn parse_codex_line_surfaces_structured_file_reads() {
        let events = parse_codex_line(&json!({
            "type": "item.completed",
            "item": {
                "type": "custom_tool_call",
                "name": "read_file",
                "arguments": {
                    "path": "/tmp/example.txt"
                }
            }
        }));

        assert_eq!(events.len(), 1);
        match &events[0] {
            super::BackendEvent::ToolUse(detail) => assert_eq!(detail, "Read tmp/example.txt"),
            _ => panic!("unexpected event"),
        }
    }

    #[test]
    fn parse_codex_line_surfaces_apply_patch_edits() {
        let events = parse_codex_line(&json!({
            "type": "item.completed",
            "item": {
                "type": "custom_tool_call",
                "name": "functions.apply_patch",
                "arguments": {
                    "patch": "*** Begin Patch\n*** End Patch\n"
                }
            }
        }));

        assert_eq!(events.len(), 1);
        match &events[0] {
            super::BackendEvent::ToolUse(detail) => assert_eq!(detail, "Edit files"),
            _ => panic!("unexpected event"),
        }
    }

    #[test]
    fn parse_codex_line_surfaces_file_change_updates() {
        let events = parse_codex_line(&json!({
            "type": "item.completed",
            "item": {
                "type": "file_change",
                "changes": [
                    {
                        "path": "/tmp/example.txt",
                        "kind": "update"
                    }
                ],
                "status": "completed"
            }
        }));

        assert_eq!(events.len(), 1);
        match &events[0] {
            super::BackendEvent::ToolUse(detail) => assert_eq!(detail, "Edit tmp/example.txt"),
            _ => panic!("unexpected event"),
        }
    }

    #[test]
    fn parse_codex_line_surfaces_file_change_creates_and_deletes() {
        let events = parse_codex_line(&json!({
            "type": "item.completed",
            "item": {
                "type": "file_change",
                "changes": [
                    {
                        "path": "/tmp/new.txt",
                        "kind": "add"
                    },
                    {
                        "path": "/tmp/old.txt",
                        "kind": "delete"
                    }
                ],
                "status": "completed"
            }
        }));

        assert_eq!(events.len(), 1);
        match &events[0] {
            super::BackendEvent::ToolUse(detail) => {
                assert_eq!(detail, "Write tmp/new.txt\nDelete tmp/old.txt")
            }
            _ => panic!("unexpected event"),
        }
    }

    #[test]
    fn history_messages_excluding_pending_excludes_current_unread_batch() {
        let messages = vec![
            json!({ "id": 1, "role": "user", "content": "older 1" }),
            json!({ "id": 2, "role": "assistant", "content": "older 2" }),
            json!({ "id": 3, "role": "user", "content": "new unread 1" }),
            json!({ "id": 4, "role": "user", "content": "new unread 2" }),
        ];

        let pending_ids: HashSet<u64> = [3, 4].into_iter().collect();
        let recent = history_messages_excluding_pending(Some(&messages), &pending_ids);
        let ids: Vec<u64> = recent.iter().filter_map(|msg| msg["id"].as_u64()).collect();

        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn history_messages_excluding_pending_keeps_remaining_order_for_windowing() {
        let messages = vec![
            json!({ "id": 1, "role": "user", "content": "m1" }),
            json!({ "id": 2, "role": "assistant", "content": "m2" }),
            json!({ "id": 3, "role": "user", "content": "m3" }),
            json!({ "id": 4, "role": "assistant", "content": "m4" }),
            json!({ "id": 5, "role": "user", "content": "current unread" }),
        ];

        let pending_ids: HashSet<u64> = [5].into_iter().collect();
        let filtered = history_messages_excluding_pending(Some(&messages), &pending_ids);
        let recent = &filtered[filtered.len().saturating_sub(2)..];
        let ids: Vec<u64> = recent.iter().filter_map(|msg| msg["id"].as_u64()).collect();

        assert_eq!(ids, vec![3, 4]);
    }

    #[test]
    fn recent_history_exchange_tail_uses_exchange_count_not_message_count() {
        let messages = vec![
            json!({ "id": 1, "role": "user", "content": "u1" }),
            json!({ "id": 2, "role": "assistant", "content": "a1-1" }),
            json!({ "id": 3, "role": "assistant", "content": "a1-2" }),
            json!({ "id": 4, "role": "user", "content": "u2" }),
            json!({ "id": 5, "role": "assistant", "content": "a2" }),
            json!({ "id": 6, "role": "user", "content": "u3" }),
            json!({ "id": 7, "role": "assistant", "content": "a3" }),
        ];

        let refs: Vec<&serde_json::Value> = messages.iter().collect();
        let recent = recent_history_exchange_tail(&refs, 2);
        let ids: Vec<u64> = recent.iter().filter_map(|msg| msg["id"].as_u64()).collect();

        assert_eq!(ids, vec![4, 5, 6, 7]);
    }

    #[test]
    fn history_prompt_window_prefers_cache_aware_server_value() {
        let history = json!({
            "window_size": 22,
            "prompt_window_size": 50,
        });

        assert_eq!(history_prompt_window_size(&history), 50);
    }

    #[test]
    fn history_auto_compact_window_prefers_cache_aware_server_value() {
        let history = json!({
            "window_size": 22,
            "prompt_window_size": 50,
            "auto_compact_window_size": 60,
        });

        assert_eq!(history_auto_compact_window_size(&history), 60);
    }

    #[test]
    fn history_window_helpers_fallback_to_legacy_window_size() {
        let history = json!({
            "window_size": 22,
        });

        assert_eq!(history_prompt_window_size(&history), 22);
        assert_eq!(history_auto_compact_window_size(&history), 22);
    }

    #[test]
    fn recent_history_prompt_window_caps_tool_rows_separately() {
        let mut messages = Vec::new();
        messages.push(json!({ "id": 1, "role": "user", "content": "u1" }));
        for id in 2..=11u64 {
            messages.push(json!({ "id": id, "role": "tool", "content": format!("tool-{id}") }));
        }
        messages.push(json!({ "id": 12, "role": "assistant", "content": "a1" }));
        messages.push(json!({ "id": 13, "role": "user", "content": "u2" }));
        messages.push(json!({ "id": 14, "role": "assistant", "content": "a2" }));

        let refs: Vec<&serde_json::Value> = messages.iter().collect();
        let recent = recent_history_prompt_window(&refs, 2);
        let tool_ids: Vec<u64> = recent
            .iter()
            .filter(|msg| msg["role"].as_str() == Some("tool"))
            .filter_map(|msg| msg["id"].as_u64())
            .collect();
        let ids: Vec<u64> = recent.iter().filter_map(|msg| msg["id"].as_u64()).collect();

        assert_eq!(tool_ids, vec![10, 11]);
        assert_eq!(ids, vec![1, 10, 11, 12, 13, 14]);
    }

    #[test]
    fn recent_history_prompt_window_caps_each_agent_response_edges() {
        let mut messages = Vec::new();
        messages.push(json!({ "id": 1, "role": "user", "content": "u1" }));
        for id in 2..=36u64 {
            messages
                .push(json!({ "id": id, "role": "assistant", "content": format!("status-{id}") }));
        }
        messages.push(json!({ "id": 37, "role": "user", "content": "u2" }));
        messages.push(json!({ "id": 38, "role": "assistant", "content": "a2" }));

        let refs: Vec<&serde_json::Value> = messages.iter().collect();
        let recent = recent_history_prompt_window(&refs, 2);
        let assistant_ids: Vec<u64> = recent
            .iter()
            .filter(|msg| msg["role"].as_str() == Some("assistant"))
            .filter_map(|msg| msg["id"].as_u64())
            .collect();
        let user_ids: Vec<u64> = recent
            .iter()
            .filter(|msg| msg["role"].as_str() == Some("user"))
            .filter_map(|msg| msg["id"].as_u64())
            .collect();

        assert_eq!(
            assistant_ids,
            vec![2, 3, 4, 5, 6, 7, 8, 9, 29, 30, 31, 32, 33, 34, 35, 36, 38]
        );
        assert_eq!(user_ids, vec![1, 37]);
    }

    #[test]
    fn api_user_content_converts_markdown_data_images_to_multimodal_parts() {
        let content = api_user_content_from_markdown_images(
            "before\n\n![phone](data:image/png;base64,aGVsbG8=)\n\nafter",
        );
        let parts = content.as_array().expect("content should be parts");
        assert_eq!(parts[0]["type"], "text");
        assert_eq!(parts[0]["text"], "before\n\n");
        assert_eq!(parts[1]["type"], "image_url");
        assert_eq!(
            parts[1]["image_url"]["url"],
            "data:image/png;base64,aGVsbG8="
        );
        assert_eq!(parts[2]["text"], "\n\nafter");

        assert_eq!(
            api_user_content_from_markdown_images("plain text"),
            json!("plain text")
        );
    }

    #[test]
    fn chat_prompt_content_omits_data_images_unless_preserved() {
        let content = "before\n\n![phone screenshot.png](data:image/png;base64,aGVsbG8=)\n\nafter";
        let sanitized = chat_content_for_prompt(content, false);

        assert!(sanitized.contains("before"));
        assert!(sanitized.contains("after"));
        assert!(sanitized.contains("phone screenshot.png"));
        assert!(sanitized.contains("image/png"));
        assert!(sanitized.contains("~1 KB"));
        assert!(!sanitized.contains("data:image"));
        assert!(!sanitized.contains("aGVsbG8="));
        assert_eq!(chat_content_for_prompt(content, true), content);
        assert_eq!(chat_content_for_current_message_prompt(content), content);

        let cli_current = chat_content_for_current_message_cli_prompt(content);
        assert!(cli_current.contains("[image attachment omitted from text prompt"));
        assert!(!cli_current.contains("data:image"));
        assert!(!cli_current.contains("aGVsbG8="));
    }

    #[test]
    fn current_chat_images_can_be_attached_to_codex_exec() {
        let content = "look\n\n![shot](data:image/png;base64,aGVsbG8=)\n\nagain";
        let attachments = markdown_data_image_attachments(content);

        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].mime, "image/png");
        assert_eq!(attachments[0].bytes, b"hello");

        let files = write_codex_image_attachments(content)
            .unwrap()
            .expect("image attachment files");
        assert_eq!(files.paths().len(), 1);
        assert!(files.paths()[0].ends_with("lore-chat-image-1.png"));
        assert_eq!(fs::read(&files.paths()[0]).unwrap(), b"hello");

        let image = PathBuf::from("/tmp/lore-current-image.png");
        let args = codex_exec_args(Some("gpt-5.5"), Some("high"), &[image.clone()]);
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--image", image.to_string_lossy().as_ref()])
        );
        assert_eq!(args.last().map(String::as_str), Some("-"));
    }

    #[test]
    fn api_endpoint_runtime_context_overrides_stale_identity_history() {
        let context = api_endpoint_runtime_context(Some(&json!({
            "name": "Krasis via SSH",
            "kind": "openai",
            "model": "Qwen3.6-35B-A3B-vision",
        })))
        .expect("endpoint context should render");

        assert!(context.contains("Krasis via SSH"));
        assert!(context.contains("Qwen3.6-35B-A3B-vision"));
        assert!(context.contains("Do not infer your current identity"));
        assert!(context.contains("older assistant messages"));
        assert!(context.contains("conversation summaries"));
        assert!(context.contains("stale history"));
    }

    #[test]
    fn endpoint_mode_ignores_legacy_backend_model_override() {
        let history = json!({
            "model": "opus",
            "endpoint": {
                "name": "Krasis via SSH",
                "model": "Qwen3.6-35B-A3B-vision"
            }
        });

        assert_eq!(super::model_override_from_history(&history, true), None);
        assert_eq!(
            super::model_override_from_history(&history, false).as_deref(),
            Some("opus")
        );
    }

    #[test]
    fn history_compaction_split_index_keeps_half_the_window_in_exchanges() {
        let mut messages = Vec::new();
        for i in 1..=22u64 {
            messages.push(json!({ "id": (i * 2) - 1, "role": "user", "content": format!("u{i}") }));
            messages.push(json!({ "id": i * 2, "role": "assistant", "content": format!("a{i}") }));
        }

        let refs: Vec<&serde_json::Value> = messages.iter().collect();
        let split_idx = history_compaction_split_index(&refs, 22).unwrap();
        let to_keep = &refs[split_idx..];

        assert_eq!(count_history_exchanges(&refs), 22);
        assert_eq!(count_history_exchanges(to_keep), 11);
        assert_eq!(to_keep.first().and_then(|msg| msg["id"].as_u64()), Some(23));
    }

    #[test]
    fn load_cli_text_input_accepts_positional_content() {
        let content = "hello".to_string();
        let loaded = load_cli_text_input(Some(&content), None, false, "blocks create").unwrap();
        assert_eq!(loaded, "hello");
    }

    #[test]
    fn load_cli_text_input_accepts_file_content() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "from file").unwrap();
        let path = file.path().display().to_string();
        let loaded = load_cli_text_input(None, Some(&path), false, "blocks create").unwrap();
        assert_eq!(loaded, "from file");
    }

    #[test]
    fn load_doc_write_content_rejects_empty_file_without_override() {
        let file = NamedTempFile::new().unwrap();
        let args = DocWriteArgs {
            doc_id: "doc".into(),
            file: Some(file.path().display().to_string()),
            stdin: false,
            allow_empty: false,
            dry_run: false,
            diff: false,
        };
        let err = load_doc_write_content(&args).unwrap_err();
        assert!(err.to_string().contains("refused empty input"));
    }

    #[test]
    fn load_doc_write_content_allows_empty_file_with_override() {
        let file = NamedTempFile::new().unwrap();
        let args = DocWriteArgs {
            doc_id: "doc".into(),
            file: Some(file.path().display().to_string()),
            stdin: false,
            allow_empty: true,
            dry_run: false,
            diff: false,
        };
        let loaded = load_doc_write_content(&args).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_doc_write_content_rejects_multiple_sources() {
        let file = NamedTempFile::new().unwrap();
        let args = DocWriteArgs {
            doc_id: "doc".into(),
            file: Some(file.path().display().to_string()),
            stdin: true,
            allow_empty: false,
            dry_run: false,
            diff: false,
        };
        let err = load_doc_write_content(&args).unwrap_err();
        assert!(err.to_string().contains("only one input source"));
    }

    #[test]
    fn blocks_edit_parser_accepts_leading_dash_replacement() {
        let cli = Cli::try_parse_from([
            "lore", "blocks", "edit", "block-id", "--doc", "doc-id", "--old", "item", "--new",
            "- bullet",
        ])
        .unwrap();
        let Command::Blocks { command } = cli.command else {
            panic!("expected blocks command");
        };
        let BlocksCommand::Edit(args) = command else {
            panic!("expected blocks edit command");
        };
        assert_eq!(args.old.as_deref(), Some("item"));
        assert_eq!(args.new.as_deref(), Some("- bullet"));
    }

    #[test]
    fn blocks_edit_text_sources_explain_missing_values() {
        let err = load_required_text_arg("blocks edit", "new", None, None, false).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("--new-file"));
        assert!(message.contains("beginning with '-'"));
    }

    #[test]
    fn append_block_content_uses_separator_only_between_non_empty_sides() {
        assert_eq!(append_block_content("", "added", "\n"), "added");
        assert_eq!(append_block_content("base", "", "\n"), "base");
        assert_eq!(append_block_content("base", "added", "\n"), "base\nadded");
        assert_eq!(append_block_content("base", "added", ""), "baseadded");
    }

    #[test]
    fn markdown_heading_match_accepts_literal_or_plain_heading_text() {
        assert!(markdown_heading_matches("## Notes", "Notes"));
        assert!(markdown_heading_matches("## Notes", "## Notes"));
        assert!(markdown_heading_matches("  ### Follow ups  ", "Follow ups"));
        assert!(!markdown_heading_matches("Not a heading", "Not a heading"));
        assert!(!markdown_heading_matches("####### Too deep", "Too deep"));
    }

    #[test]
    fn resolve_context_project_prefers_explicit_project_flag() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".lore")).unwrap();
        fs::write(dir.path().join(".lore").join("project"), "cwd-project\n").unwrap();

        let cli = Cli {
            url: None,
            token: None,
            project: Some("flag-project".into()),
            command: Command::Projects,
        };

        assert_eq!(
            resolve_context_project(&cli, dir.path()),
            Some(ResolvedProject {
                value: "flag-project".into(),
                source: ProjectSource::Flag,
            })
        );
    }

    #[test]
    fn resolve_context_project_falls_back_to_cwd_project_file() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        fs::create_dir_all(nested.join(".unused")).unwrap();
        fs::create_dir_all(dir.path().join(".lore")).unwrap();
        fs::write(dir.path().join(".lore").join("project"), "lore\n").unwrap();

        let cli = Cli {
            url: None,
            token: None,
            project: None,
            command: Command::Projects,
        };

        assert_eq!(
            resolve_context_project(&cli, &nested),
            Some(ResolvedProject {
                value: "lore".into(),
                source: ProjectSource::LocalFile(dir.path().join(".lore").join("project")),
            })
        );
        assert_eq!(
            find_cwd_project_file(&nested),
            Some(dir.path().join(".lore").join("project"))
        );
    }

    #[test]
    fn resolve_context_project_ignores_legacy_config_and_empty_cwd_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".lore")).unwrap();
        fs::write(dir.path().join(".lore").join("project"), "\n").unwrap();

        let cli = Cli {
            url: None,
            token: None,
            project: None,
            command: Command::Projects,
        };

        assert_eq!(resolve_context_project(&cli, dir.path()), None);
    }

    #[test]
    fn local_project_file_target_prefers_nearest_existing_marker() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("repo").join("src");
        fs::create_dir_all(nested.clone()).unwrap();
        fs::create_dir_all(dir.path().join("repo").join(".lore")).unwrap();
        let existing = dir.path().join("repo").join(".lore").join("project");
        fs::write(&existing, "lore\n").unwrap();

        assert_eq!(super::local_project_file_target(&nested), existing);
    }

    #[test]
    fn decode_numbered_block_chunk_preserves_content_lines() {
        let content =
            super::decode_numbered_block_chunk("1\tfirst line\n2\t\n3\tthird\twith tab").unwrap();
        assert_eq!(content, "first line\n\nthird\twith tab");
    }

    #[test]
    fn codex_exec_args_include_reasoning_effort_override() {
        let args = codex_exec_args(Some("gpt-5.4"), Some("xhigh"), &[]);

        assert!(args.windows(2).any(|pair| pair == ["--model", "gpt-5.4"]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "model_reasoning_effort=\"xhigh\""])
        );
        assert_eq!(args.last().map(String::as_str), Some("-"));
    }
}
