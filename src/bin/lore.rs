use clap::{Args, Parser, Subcommand, ValueEnum};
use lore_core::{
    AgentBackend, Block, BlockType, DEFAULT_UPDATE_REPO, ProjectName, ReleaseStream,
    SelfUpdateOutcome, apply_update_to_version, check_for_update, maybe_apply_self_update,
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use time::OffsetDateTime;
use tokio::io::AsyncBufReadExt;

type CliResult<T> = Result<T, Box<dyn Error>>;
const CLI_SELF_UPDATE_SKIP_ENV: &str = "LORE_SKIP_CLI_SELF_UPDATE";
const CLI_AUTO_UPDATE_INTERVAL_SECS: i64 = 24 * 60 * 60;

#[derive(Parser)]
#[command(name = "lore")]
#[command(about = "Lore CLI")]
#[command(version)]
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
    /// Manage CLI configuration (url, token, project)
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// List all projects
    Projects,
    /// Read and list blocks
    Blocks {
        #[command(subcommand)]
        command: BlocksCommand,
    },
    /// Search blocks by content
    Grep(GrepArgs),
    /// Add a new block to the current project
    Add(WriteBlockArgs),
    /// Update an existing block
    Update(UpdateBlockArgs),
    /// Move a block to a new position
    Move(MoveBlockArgs),
    /// Delete a block
    Delete(DeleteBlockArgs),
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
    /// Show the current project's agent context
    Context,
    /// Connect to a Lore server (interactive setup)
    Setup(SetupArgs),
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

#[derive(Subcommand)]
enum BlocksCommand {
    /// List blocks in the current project
    List(ListBlocksArgs),
    /// Read a single block by ID
    Read(ReadBlockArgs),
    /// Read a block with surrounding context
    Around(AroundArgs),
}

#[derive(Args)]
struct ListBlocksArgs {
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Args)]
struct ReadBlockArgs {
    id: String,
}

#[derive(Args)]
struct AroundArgs {
    id: String,
    #[arg(long, default_value_t = 2)]
    before: usize,
    #[arg(long, default_value_t = 2)]
    after: usize,
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
struct WriteBlockArgs {
    content: String,
    #[arg(long = "type", value_enum, default_value_t = CliBlockType::Markdown)]
    block_type: CliBlockType,
    #[arg(long)]
    after_block_id: Option<String>,
}

#[derive(Args)]
struct UpdateBlockArgs {
    id: String,
    content: String,
    #[arg(long = "type", value_enum, default_value_t = CliBlockType::Markdown)]
    block_type: CliBlockType,
    #[arg(long)]
    after_block_id: Option<String>,
}

#[derive(Args)]
struct MoveBlockArgs {
    id: String,
    #[arg(long)]
    after_block_id: Option<String>,
}

#[derive(Args)]
struct DeleteBlockArgs {
    id: String,
    #[arg(long)]
    yes: bool,
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
    /// Override the backend (claude, gemini, codex). If not set, uses server config.
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

#[derive(Debug)]
struct CliContext {
    client: reqwest::Client,
    url: String,
    token: Option<String>,
    project: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProjectSummary {
    project: ProjectName,
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

#[derive(Debug, Serialize)]
struct CreateProjectBlockRequest {
    block_type: BlockType,
    content: String,
    after_block_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct UpdateProjectBlockRequest {
    block_type: BlockType,
    content: String,
    after_block_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct MoveBlockRequest {
    after_block_id: Option<String>,
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
        Command::Config { command } => return run_config(command, &mut config),
        Command::SelfUpdate { command } => return run_update(command, &mut config).await,
        Command::Setup(args) => {
            let url = normalize_url(&args.url);
            // Interactive login
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
            // Machine name (default to hostname)
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
            // Register machine with server
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
            save_cli_config(&config)?;
            println!("Registered machine \"{}\" on {}", machine_name, url);

            // Auto-start the machine service daemon
            println!("Starting machine service...");
            let exe = resolved_current_exe()?;
            let lore_dir = env::var("HOME").map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("lore-service");
            fs::create_dir_all(&lore_dir)?;
            let log_path = lore_dir.join("service.log");
            let pid_path = lore_dir.join("service.pid");

            // Kill existing service if running
            if pid_path.exists() {
                if let Ok(pid_str) = fs::read_to_string(&pid_path) {
                    if let Ok(pid) = pid_str.trim().parse::<u32>() {
                        if is_process_running(pid) {
                            kill_process(pid);
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        }
                    }
                }
                let _ = fs::remove_file(&pid_path);
            }

            let log_file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)?;
            let child = std::process::Command::new(&exe)
                .args(["--url", &url, "--token", &token, "service", "--fg"])
                .env(LORE_SERVICE_DAEMON_ENV, "1")
                .stdout(log_file.try_clone()?)
                .stderr(log_file)
                .stdin(std::process::Stdio::null())
                .spawn()?;
            let pid = child.id();
            fs::write(&pid_path, pid.to_string())?;
            println!("Service started (pid {})", pid);
            println!("  Log: {}", log_path.display());

            return Ok(());
        }
        _ => {}
    }

    maybe_auto_update_cli(&mut config).await?;

    let context = build_context(&cli, &config)?;
    match cli.command {
        Command::Projects => projects_command(&context).await?,
        Command::Context => context_command(&context).await?,
        Command::Blocks { command } => blocks_command(&context, command).await?,
        Command::Grep(args) => grep_command(&context, args).await?,
        Command::Add(args) => add_command(&context, args).await?,
        Command::Update(args) => update_command(&context, args).await?,
        Command::Move(args) => move_command(&context, args).await?,
        Command::Delete(args) => delete_command(&context, args).await?,
        Command::Librarian { command } => librarian_command(&context, command).await?,
        Command::History { command } => history_command(&context, command).await?,
        Command::Agent(args) => agent_command(&context, args).await?,
        Command::Service(args) => service_command(&context, args).await?,
        Command::Config { .. } | Command::SelfUpdate { .. } | Command::Setup(_) => {}
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
                "project: {}",
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
        }
        ConfigCommand::Set(args) => {
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

async fn blocks_command(context: &CliContext, command: BlocksCommand) -> CliResult<()> {
    match command {
        BlocksCommand::List(args) => {
            let project = context.require_project(None)?;
            let path = format!("/v1/projects/{}/blocks", project.as_str());
            let mut blocks: Vec<Block> = context.get_json(&path).await?;
            blocks.truncate(args.limit.max(1));
            if blocks.is_empty() {
                println!("No blocks in {}.", project);
                return Ok(());
            }
            for block in blocks {
                println!(
                    "{}  {:<8}  {}",
                    block.id,
                    block_type_label(block.block_type),
                    one_line_preview(&block.content, 72)
                );
            }
        }
        BlocksCommand::Read(args) => {
            let project = context.require_project(None)?;
            let path = format!("/v1/projects/{}/blocks/{}", project.as_str(), args.id);
            let block: Block = context.get_json(&path).await?;
            print_block(&block, false);
        }
        BlocksCommand::Around(args) => {
            let project = context.require_project(None)?;
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
        println!(
            "{}  {:<8}  {}",
            entry.block.id,
            block_type_label(entry.block.block_type),
            entry.preview
        );
    }
    Ok(())
}

async fn add_command(context: &CliContext, args: WriteBlockArgs) -> CliResult<()> {
    let project = context.require_project(None)?;
    let path = format!("/v1/projects/{}/blocks", project.as_str());
    let block: Block = context
        .send_json(
            Method::POST,
            &path,
            &CreateProjectBlockRequest {
                block_type: args.block_type.into(),
                content: args.content,
                after_block_id: args.after_block_id,
            },
        )
        .await?;
    println!("Created block {} in {}.", block.id, block.project);
    Ok(())
}

async fn update_command(context: &CliContext, args: UpdateBlockArgs) -> CliResult<()> {
    let project = context.require_project(None)?;
    let path = format!("/v1/projects/{}/blocks/{}", project.as_str(), args.id);
    let block: Block = context
        .send_json(
            Method::PATCH,
            &path,
            &UpdateProjectBlockRequest {
                block_type: args.block_type.into(),
                content: args.content,
                after_block_id: args.after_block_id,
            },
        )
        .await?;
    println!("Updated block {}.", block.id);
    Ok(())
}

async fn move_command(context: &CliContext, args: MoveBlockArgs) -> CliResult<()> {
    let project = context.require_project(None)?;
    let path = format!("/v1/projects/{}/blocks/{}/move", project.as_str(), args.id);
    let block: Block = context
        .send_json(
            Method::POST,
            &path,
            &MoveBlockRequest {
                after_block_id: args.after_block_id,
            },
        )
        .await?;
    println!("Moved block {} to order {}.", block.id, block.order);
    Ok(())
}

async fn delete_command(context: &CliContext, args: DeleteBlockArgs) -> CliResult<()> {
    if !args.yes {
        return Err(io::Error::other("delete requires --yes").into());
    }
    let project = context.require_project(None)?;
    let path = format!("/v1/projects/{}/blocks/{}", project.as_str(), args.id);
    context.send_no_content(Method::DELETE, &path).await?;
    println!("Deleted block {}.", args.id);
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
        .or_else(|| env::var("LORE_TOKEN").ok())
        .or_else(|| config.token.clone());
    let project = cli
        .project
        .clone()
        .or_else(|| env::var("LORE_PROJECT").ok())
        .or_else(|| config.project.clone());
    Ok(CliContext {
        client: reqwest::Client::builder().build()?,
        url: normalize_url(&url),
        token,
        project,
    })
}

impl CliContext {
    fn require_project(&self, project: Option<String>) -> CliResult<ProjectName> {
        let value = project
            .or_else(|| self.project.clone())
            .ok_or_else(|| io::Error::other("set --project, LORE_PROJECT, or config project"))?;
        Ok(ProjectName::new(value)?)
    }

    fn require_token(&self) -> CliResult<&str> {
        self.token
            .as_deref()
            .ok_or_else(|| io::Error::other("set --token, LORE_TOKEN, or config token").into())
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> CliResult<T> {
        self.send(Method::GET, path, None::<&()>).await
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

async fn apply_cli_update_to_target(config: &mut CliConfig, target_version: &str, repo: &str) -> CliResult<()> {
    let client = reqwest::Client::new();
    let executable_path = resolved_current_exe()?;
    match apply_update_to_version(
        &client,
        "lore",
        env!("CARGO_PKG_VERSION"),
        target_version,
        repo,
        &executable_path,
    )
    .await
    .map_err(|err| io::Error::other(err.to_string()))?
    {
        SelfUpdateOutcome::UpToDate(status) => {
            eprintln!("[update] {}", status.detail);
            config.last_update_check = Some(status.checked_at);
            save_cli_config(config)?;
        }
        SelfUpdateOutcome::Updated(status) => {
            eprintln!("[update] {}", status.detail);
            config.last_update_check = Some(status.checked_at);
            save_cli_config(config)?;
        }
    }
    Ok(())
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

fn cli_config_path() -> CliResult<PathBuf> {
    if let Ok(value) = env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(value).join("lore").join("config.json"));
    }
    let home = env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| io::Error::other("HOME is not set and XDG_CONFIG_HOME is unavailable"))?;
    Ok(home.join(".config").join("lore").join("config.json"))
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

fn format_relative_time(timestamp_str: &str, now: OffsetDateTime) -> String {
    let parsed = time::OffsetDateTime::parse(
        timestamp_str,
        &time::format_description::well_known::Rfc3339,
    );
    match parsed {
        Ok(ts) => {
            let diff = now - ts;
            let secs = diff.whole_seconds();
            if secs < 0 {
                "just now".to_string()
            } else if secs < 60 {
                "just now".to_string()
            } else if secs < 3600 {
                let mins = secs / 60;
                if mins == 1 { "1 min ago".to_string() } else { format!("{mins} mins ago") }
            } else if secs < 86400 {
                let hours = secs / 3600;
                if hours == 1 { "1 hour ago".to_string() } else { format!("{hours} hours ago") }
            } else {
                let days = secs / 86400;
                if days == 1 { "1 day ago".to_string() } else { format!("{days} days ago") }
            }
        }
        Err(_) => "unknown time".to_string(),
    }
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

fn get_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

// --- Agent daemon ---

const LORE_DAEMON_ENV: &str = "LORE_DAEMON";

async fn agent_command(context: &CliContext, args: AgentArgs) -> CliResult<()> {
    let is_daemon = env::var(LORE_DAEMON_ENV).unwrap_or_default() == "1";

    // Resolve agent token: local config > provision from server
    let mut config = load_cli_config()?;
    let agent_token = if let Some(token) = config.agent_tokens.get(&args.name) {
        token.clone()
    } else {
        // Auto-provision: use machine token to create agent on server
        let machine_token = context.token.as_deref().ok_or(
            "no machine token configured. Run 'lore setup <url>' first.",
        )?;
        let backend_str = args.backend.as_deref().unwrap_or("claude");
        eprintln!("Provisioning agent '{}'...", args.name);
        let resp = context
            .client
            .post(format!("{}/v1/agents/provision", context.url))
            .header("x-lore-key", machine_token)
            .header("x-lore-version", env!("CARGO_PKG_VERSION"))
            .json(&serde_json::json!({
                "name": args.name,
                "backend": backend_str,
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

    // If daemon child, write PID file
    if is_daemon {
        let lore_dir = PathBuf::from(format!(".lore/{}", args.name));
        fs::create_dir_all(&lore_dir)?;
        fs::write(lore_dir.join("lore.pid"), std::process::id().to_string())?;
    }

    let cli_backend_override = args.backend.as_ref().and_then(|b| b.parse().ok());

    eprintln!("[agent] Starting agent '{}' (backend: {})", args.name,
        cli_backend_override.map(|b: AgentBackend| b.to_string()).as_deref().unwrap_or("server config"));

    // Main agent loop: poll for messages, process them
    loop {
        match agent_poll_and_process(&agent_context, &args.name, cli_backend_override).await {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[agent] Error: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

async fn agent_poll_and_process(context: &CliContext, agent_name: &str, cli_backend_override: Option<AgentBackend>) -> CliResult<()> {
    let token = context.token.as_deref().ok_or("no token configured")?;

    // Long-poll for messages
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Detect git branch if in a git repo
    let git_branch = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        });
    let mut req = context
        .client
        .get(format!("{}/v1/chat/poll", context.url))
        .header("x-lore-key", token)
        .header("x-lore-cwd", &cwd)
        .header("x-lore-version", env!("CARGO_PKG_VERSION"));
    if let Some(ref machine) = load_cli_config().ok().and_then(|c| c.machine_name) {
        req = req.header("x-lore-machine", machine);
    }
    if let Some(ref branch) = git_branch {
        req = req.header("x-lore-git-branch", branch);
    }
    let resp = req
        .timeout(std::time::Duration::from_secs(35))
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) if e.is_timeout() => return Ok(()), // Normal long-poll timeout
        Err(e) => return Err(e.into()),
    };

    let body: serde_json::Value = resp.error_for_status()?.json().await?;

    // Check if server is requesting a CLI update
    if let Some(update_version) = body["update_to"].as_str() {
        eprintln!("[agent] Server requested update to v{update_version}, updating...");
        let mut cfg = load_cli_config()?;
        let repo = body["update_repo"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| cfg.update_repo.clone());
        match apply_cli_update_to_target(&mut cfg, update_version, &repo).await {
            Ok(()) => {
                eprintln!("[agent] Updated CLI, restarting...");
                std::process::exit(0);
            }
            Err(e) => eprintln!("[agent] Update failed: {e}"),
        }
    }

    let has_endpoint = body["endpoint_id"].as_str().is_some();
    let backend = cli_backend_override.unwrap_or_else(|| {
        body["backend"]
            .as_str()
            .and_then(|b| b.parse().ok())
            .unwrap_or(AgentBackend::Claude)
    });

    let messages = body["messages"].as_array();

    if messages.is_none() || messages.unwrap().is_empty() {
        return Ok(());
    }

    let messages = messages.unwrap();

    // Check for slash commands from the server
    let mut regular_messages: Vec<&str> = Vec::new();
    for msg in messages {
        if let Some(content) = msg["content"].as_str() {
            let trimmed = content.trim();
            if trimmed == "/compact" {
                eprintln!("[agent] Received /compact command");
                let cb = if has_endpoint { AgentBackend::OpenAi } else { backend };
                do_compact(context, agent_name, true, cb).await?;
                return Ok(());
            } else if trimmed == "/stop" {
                eprintln!("[agent] Received /stop command");
                return Ok(());
            } else if trimmed == "/restart" {
                eprintln!("[agent] Received /restart — exiting for restart");
                std::process::exit(0);
            } else {
                regular_messages.push(content);
            }
        }
    }

    let combined = regular_messages.join("\n\n");

    if combined.trim().is_empty() {
        return Ok(());
    }

    eprintln!("[agent] Received message: {}...", &combined.chars().take(80).collect::<String>());

    // Log user message to .lore chat log
    {
        let lore_dir = PathBuf::from(format!(".lore/{}", agent_name));
        let _ = fs::create_dir_all(&lore_dir);
        let ts = time::OffsetDateTime::now_utc();
        let timestamp = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            ts.year(), ts.month() as u8, ts.day(), ts.hour(), ts.minute(), ts.second());
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(lore_dir.join("lore.log")) {
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

    // Get conversation history for context
    let history_resp = context
        .client
        .get(format!("{}/v1/chat/history", context.url))
        .header("x-lore-key", token)
        .send()
        .await?
        .error_for_status()?;
    let history: serde_json::Value = history_resp.json().await?;

    // Build rich prompt with system context, git info, conversation history
    let summary = history["summary"].as_str().unwrap_or("");
    let window_size = history["window_size"].as_u64().unwrap_or(22) as usize;
    let hist_messages = history["messages"].as_array();
    let pins = history["pins"].as_array();
    let project_context = history["project_context"].as_str().unwrap_or("");
    let accessible_projects = history["accessible_projects"].as_str().unwrap_or("");
    let recent_activity = history["recent_activity"].as_str().unwrap_or("");

    let mut prompt_parts: Vec<String> = Vec::new();

    // Current date/time
    let now = time::OffsetDateTime::now_utc();
    let weekday = match now.weekday() {
        time::Weekday::Monday => "Monday",
        time::Weekday::Tuesday => "Tuesday",
        time::Weekday::Wednesday => "Wednesday",
        time::Weekday::Thursday => "Thursday",
        time::Weekday::Friday => "Friday",
        time::Weekday::Saturday => "Saturday",
        time::Weekday::Sunday => "Sunday",
    };
    let month = match now.month() {
        time::Month::January => "January",
        time::Month::February => "February",
        time::Month::March => "March",
        time::Month::April => "April",
        time::Month::May => "May",
        time::Month::June => "June",
        time::Month::July => "July",
        time::Month::August => "August",
        time::Month::September => "September",
        time::Month::October => "October",
        time::Month::November => "November",
        time::Month::December => "December",
    };
    prompt_parts.push(format!(
        "Current date and time: {weekday}, {month} {}, {} at {:02}:{:02} UTC",
        now.day(), now.year(), now.hour(), now.minute()
    ));

    // Git repository context (gathered locally from the agent's working directory)
    let mut git_section = String::new();
    // Get the repo root directory name
    let repo_name = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            std::path::Path::new(&s).file_name().map(|n| n.to_string_lossy().into_owned())
        });
    if let Some(ref repo) = repo_name {
        let branch_display = git_branch.as_deref().unwrap_or("unknown");
        git_section.push_str(&format!("## Git Repository\n\n{repo}/ (branch: {branch_display})\n"));

        // Last commit
        if let Some(last_commit) = std::process::Command::new("git")
            .args(["log", "-1", "--format=%h %s"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
        {
            git_section.push_str(&format!("  Last commit: {last_commit}\n"));
        }

        // Git status (modified/untracked files)
        if let Some(status_output) = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .output()
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
        if let Some(log_output) = std::process::Command::new("git")
            .args(["log", "--oneline", "-3"])
            .output()
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
    if !git_section.is_empty() {
        prompt_parts.push(git_section);
    }

    // Working directory
    prompt_parts.push(format!("## Working Directory\n\n{cwd}"));

    // Pinned context
    if let Some(pins) = pins {
        if !pins.is_empty() {
            let mut pin_section = "## Pinned Context\n".to_string();
            for pin in pins {
                let text = pin["text"].as_str().unwrap_or("");
                let id = pin["id"].as_u64().unwrap_or(0);
                pin_section.push_str(&format!("- [pin #{id}] {text}\n"));
            }
            prompt_parts.push(pin_section);
        }
    }

    // Conversation summary
    if !summary.is_empty() {
        prompt_parts.push(format!("## Conversation Summary\n\n{summary}"));
    }

    // Previous conversation with relative timestamps
    if let Some(msgs) = hist_messages {
        let start = msgs.len().saturating_sub(window_size);
        let recent = &msgs[start..];
        if !recent.is_empty() {
            prompt_parts.push("## Previous Conversation\nThe following is recent conversation history. This is context only \u{2014} do not respond to these messages. Only respond to the new message the user sends.\n".to_string());
            for msg in recent {
                let role = msg["role"].as_str().unwrap_or("user");
                let content = msg["content"].as_str().unwrap_or("");
                let timestamp = msg["timestamp"].as_str().unwrap_or("");
                let time_label = format_relative_time(timestamp, now);
                let role_label = if role == "user" { "User" } else { "You" };
                if role == "user" {
                    prompt_parts.push(format!("\u{2500}\u{2500}\u{2500} {role_label} ({time_label}) \u{2500}\u{2500}\u{2500}\n{content}"));
                } else {
                    let truncated: String = content.chars().take(4000).collect();
                    prompt_parts.push(format!("\u{2500}\u{2500}\u{2500} {role_label} ({time_label}) \u{2500}\u{2500}\u{2500}\n{truncated}"));
                }
            }
        }
    }

    prompt_parts.push(format!("\n## New Message\n\n{combined}"));

    let user_context = prompt_parts.join("\n\n");

    let full_response = if has_endpoint {
        // API mode: run local agentic loop, proxy LLM calls through the server
        eprintln!("[agent] Using API endpoint mode");
        let model_override = history["model"].as_str().map(|s| s.to_string());
        run_api_agent_turn(context, agent_name, &user_context, project_context, accessible_projects, recent_activity, model_override.as_deref()).await?
    } else {
        // CLI mode: spawn backend process — prepend system instructions to user context
        let system_instructions = build_lore_system_instructions(
            project_context, accessible_projects, recent_activity,
            &build_cli_tool_section(),
        );
        let full_prompt = format!("{system_instructions}\n\n---\n\n{user_context}");

        {
            let lore_dir = PathBuf::from(format!(".lore/{}", agent_name));
            let _ = fs::create_dir_all(&lore_dir);
            let _ = fs::write(lore_dir.join("prompt.txt"), &full_prompt);
        }

        let model_override = history["model"].as_str().map(|s| s.to_string());
        let effort_override = history["effort"].as_str().map(|s| s.to_string());
        let mut child = spawn_backend(backend, &full_prompt, model_override.as_deref(), effort_override.as_deref()).await?;

        let stdout = child.stdout.take().ok_or("no stdout")?;
        let reader = tokio::io::BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut response = String::new();

        while let Some(line) = lines.next_line().await? {
            let line = line.trim().to_string();
            if line.is_empty() { continue; }
            let parsed: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for event in parse_backend_line(backend, &parsed) {
                match event {
                    BackendEvent::Text(text) => {
                        response.push_str(&text);
                        let _ = context.client
                            .post(format!("{}/v1/chat/respond", context.url))
                            .header("x-lore-key", token)
                            .json(&serde_json::json!({ "text": text }))
                            .send().await;
                    }
                    BackendEvent::ToolUse(detail) => {
                        let _ = context.client
                            .post(format!("{}/v1/chat/respond", context.url))
                            .header("x-lore-key", token)
                            .json(&serde_json::json!({ "tool_use": detail }))
                            .send().await;
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
        let _ = child.wait().await;
        response
    };

    // Send the complete response
    let _ = context
        .client
        .post(format!("{}/v1/chat/respond", context.url))
        .header("x-lore-key", token)
        .json(&serde_json::json!({
            "complete": true,
            "content": full_response,
        }))
        .send()
        .await;

    eprintln!("[agent] Response sent ({} chars)", full_response.len());

    // Log agent response to .lore chat log
    {
        let lore_dir = PathBuf::from(format!(".lore/{}", agent_name));
        let ts = time::OffsetDateTime::now_utc();
        let timestamp = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            ts.year(), ts.month() as u8, ts.day(), ts.hour(), ts.minute(), ts.second());
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(lore_dir.join("lore.log")) {
            use std::io::Write;
            let _ = write!(f, "[{timestamp}] AGENT:\n{full_response}\n\n");
        }
    }

    // Check if compaction is needed
    let compact_backend = if has_endpoint { AgentBackend::OpenAi } else { backend };
    if let Err(e) = maybe_auto_compact(context, agent_name, compact_backend).await {
        eprintln!("[agent] Compaction error: {e}");
    }

    // Manager turn: run locally if manage mode is enabled
    if let Err(e) = maybe_run_manager(context, agent_name).await {
        eprintln!("[manager] Error: {e}");
    }

    Ok(())
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
    let messages = manage["messages"].as_array();
    let backend_str = manage["backend"].as_str().unwrap_or("");

    if system_prompt.is_empty() {
        return Ok(());
    }

    eprintln!("[manager] Running manager turn");

    let has_endpoint = manage["has_endpoint"].as_bool().unwrap_or(false);
    let manager_response = if has_endpoint {
        run_manager_endpoint(context, &system_prompt, messages).await?
    } else {
        let backend: AgentBackend = backend_str.parse().unwrap_or(AgentBackend::Claude);
        run_manager_cli(agent_name, backend, &system_prompt, messages).await?
    };

    if manager_response.is_empty() {
        eprintln!("[manager] Empty response, skipping");
        return Ok(());
    }

    let has_stop = manager_response.contains("STOPPING_POINT");
    let has_red = manager_response.contains("RED_FLAG_POINT");
    let stopped = has_stop || has_red;

    let display = if has_stop {
        manager_response.replace("STOPPING_POINT", "\u{2705}")
    } else if has_red {
        manager_response.replace("RED_FLAG_POINT", "\u{1f6a9}")
    } else {
        manager_response.clone()
    };

    eprintln!("[manager] Reporting to server (stopped={stopped})");

    let _ = context
        .client
        .post(format!("{}/v1/chat/manager", context.url))
        .header("x-lore-key", token)
        .json(&serde_json::json!({
            "content": display,
            "stopped": stopped,
        }))
        .send()
        .await;

    // Log manager response
    {
        let lore_dir = PathBuf::from(format!(".lore/{}", agent_name));
        let _ = fs::create_dir_all(&lore_dir);
        let ts = time::OffsetDateTime::now_utc();
        let timestamp = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            ts.year(), ts.month() as u8, ts.day(), ts.hour(), ts.minute(), ts.second());
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(lore_dir.join("lore.log")) {
            use std::io::Write;
            let _ = write!(f, "[{timestamp}] MANAGER:\n{display}\n\n");
        }
    }

    Ok(())
}

async fn run_manager_cli(
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
            let truncated: String = content.chars().take(4000).collect();
            prompt_parts.push(format!("--- {label} ---\n{truncated}"));
        }
    }

    prompt_parts.push("\n## Instructions\n\nReview the conversation above and provide your guidance. You may READ files from the working directory if needed to verify periodic checks, but you must NEVER edit, create, delete, or execute any files or commands. Your only output should be your guidance text.".to_string());

    let full_prompt = prompt_parts.join("\n\n");

    // Save manager context for debugging
    {
        let lore_dir = PathBuf::from(format!(".lore/{}", agent_name));
        let _ = fs::create_dir_all(&lore_dir);
        let _ = fs::write(lore_dir.join("manager_context.txt"), &full_prompt);
    }

    let mut child = spawn_backend(backend, &full_prompt, None, None).await?;

    let stdout = child.stdout.take().ok_or("no stdout")?;
    let reader = tokio::io::BufReader::new(stdout);
    let mut lines = reader.lines();
    let mut full_response = String::new();

    let read_output = async {
        while let Some(line) = lines.next_line().await? {
            let line = line.trim().to_string();
            if line.is_empty() { continue; }
            let parsed: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for event in parse_backend_line(backend, &parsed) {
                match event {
                    BackendEvent::Text(text) => full_response.push_str(&text),
                    BackendEvent::Result(text) => {
                        if full_response.is_empty() && !text.is_empty() {
                            full_response = text;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };

    match tokio::time::timeout(std::time::Duration::from_secs(300), read_output).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("[manager] CLI read error: {e}"),
        Err(_) => {
            eprintln!("[manager] CLI timed out after 5 minutes, killing process");
            let _ = child.kill().await;
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

    let mut api_messages = vec![
        serde_json::json!({ "role": "system", "content": system_prompt }),
    ];
    if let Some(msgs) = messages {
        for msg in msgs {
            api_messages.push(serde_json::json!({
                "role": msg["role"].as_str().unwrap_or("user"),
                "content": msg["content"].as_str().unwrap_or(""),
            }));
        }
    }

    let body = serde_json::json!({
        "messages": api_messages,
        "stream": false,
        "temperature": 0.3,
        "max_tokens": 2048,
    });

    let resp = context.client
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
        let err = resp_body["error"]["message"].as_str()
            .or_else(|| resp_body["error"].as_str())
            .unwrap_or("unknown error");
        return Err(format!("Manager endpoint error ({}): {}", status, err).into());
    }

    let text = resp_body["choices"].as_array()
        .and_then(|c| c.first())
        .and_then(|c| c["message"]["content"].as_str())
        .unwrap_or("")
        .to_string();

    Ok(text)
}

// --- Shared agent system prompt ---

fn build_lore_system_instructions(
    project_context: &str,
    accessible_projects: &str,
    recent_activity: &str,
    tool_section: &str,
) -> String {
    let mut parts = Vec::new();

    parts.push("# Lore Agent Instructions

You are an AI agent connected to the Lore knowledge base. Lore organizes knowledge into projects (management containers) and documents (content containers with typed blocks). Projects have reserved blocks: _agent-context, _overview, and _map. Documents contain regular content blocks.

## Guidelines
- Be concise and direct. Provide clear answers.
- Read files before editing them.
- For Lore content: use list_documents to see the doc tree, list_blocks for block structure, read_block for content, edit_block for targeted edits.
- For large blocks, use read_block with offset/limit to read chunks.
- When a tool result is truncated, use more targeted queries rather than re-reading the same large result.
- If you encounter an error, explain it clearly and suggest alternatives.
- Do not make up content. If you can't find something, say so.
- For multi-step tasks, plan before acting. Use fewer tool calls per turn when possible.

## File Map Maintenance
You have access to a file map (_map) on each project that lists key project files. Keep this map current: add files you discover are important, remove files that are deleted or no longer relevant. Only list files that are actionable for development.

## SVG Output
You can output inline SVG to present quick reports, diagrams, tables, and visual summaries to the user. Use <svg xmlns=\"http://www.w3.org/2000/svg\" ...>...</svg> with a self-contained design. Keep SVGs simple and readable. Do NOT use <foreignObject> — use only native SVG elements (<text>, <rect>, <circle>, <line>, <path>, <g>, etc). Use &amp; not & in SVG text.".to_string());

    if !project_context.is_empty() {
        parts.push(format!("## Project Context\n{project_context}"));
    }

    if !accessible_projects.is_empty() {
        parts.push(format!("## Accessible Projects\n{accessible_projects}"));
    }

    if !recent_activity.is_empty() {
        parts.push(format!("## Recent Activity\n{recent_activity}"));
    }

    parts.push(format!("## Available Lore Tools\n{tool_section}"));

    parts.join("\n\n")
}

fn build_cli_tool_section() -> String {
    "You have access to the `lore` CLI tool in addition to your normal file and shell tools. Use these commands to interact with the Lore knowledge base:

Project navigation:
  lore projects                          List all accessible projects
  lore context                           Show the current project's agent context

Reading content:
  lore blocks list [--limit N]           List blocks in the current project
  lore blocks read <block-id>            Read a single block by ID
  lore blocks around <id> [--before N] [--after N]   Read a block with surrounding context

Searching:
  lore grep <query> [--limit N]          Search blocks by content across projects

Writing content:
  lore add <content> [--type markdown|code|data] [--after-block-id ID]   Add a new block
  lore update <id> <content> [--type markdown|code|data]                  Update an existing block
  lore move <id> [--after-block-id ID]   Move a block to a new position
  lore delete <id> [--yes]               Delete a block

History:
  lore history list                      List recent block changes
  lore history show <version-id>         Show a specific version
  lore history revert <version-id>       Revert a block to a previous version

Librarian (AI-powered):
  lore librarian answer <question>       Ask the librarian a question about project content
  lore librarian action <instruction>    Request the librarian to perform a content action".to_string()
}

fn build_api_tool_section(lore_tool_names: &[String]) -> String {
    if lore_tool_names.is_empty() {
        return "You have file tools (read_file, write_file, edit_file, list_directory, run_command, grep_search) to work with the local filesystem.".to_string();
    }
    format!("You have file tools (read_file, write_file, edit_file, list_directory, run_command, grep_search) to work with the local filesystem.

You also have Lore MCP tools to manage knowledge base content: {}. Use list_documents to see the doc tree, list_blocks for block structure, read_block for content, edit_block for targeted changes, update_block for full rewrites.", lore_tool_names.join(", "))
}

// --- API agent loop (runs on machine, proxies LLM calls through server) ---

const API_AGENT_MAX_TURNS: usize = 500;
const API_AGENT_MAX_CONTEXT_CHARS: usize = 400_000;
const API_AGENT_RATE_LIMIT_WAIT_SECS: u64 = 30;
const API_AGENT_MAX_RETRIES: usize = 2;
const API_AGENT_TRIMMED_STUB: &str = "[Content trimmed \u{2014} re-read if needed]";

async fn run_api_agent_turn(
    context: &CliContext,
    agent_name: &str,
    user_context: &str,
    project_context: &str,
    accessible_projects: &str,
    recent_activity: &str,
    model_override: Option<&str>,
) -> CliResult<String> {
    let token = context.token.as_deref().ok_or("no token configured")?;
    let mut tools = build_local_tools();

    let lore_tool_names = fetch_lore_tools(context).await;
    for t in &lore_tool_names {
        tools.push(t.clone());
    }
    let lore_names: std::collections::HashSet<String> = lore_tool_names.iter()
        .filter_map(|t| t["function"]["name"].as_str().map(|s| s.to_string()))
        .collect();
    let lore_name_list: Vec<String> = lore_names.iter().cloned().collect();

    let system_content = build_lore_system_instructions(
        project_context, accessible_projects, recent_activity,
        &build_api_tool_section(&lore_name_list),
    );

    {
        let lore_dir = PathBuf::from(format!(".lore/{}", agent_name));
        let _ = fs::create_dir_all(&lore_dir);
        let prompt_dump = format!("=== SYSTEM PROMPT ===\n{system_content}\n\n=== USER CONTEXT ===\n{user_context}");
        let _ = fs::write(lore_dir.join("prompt.txt"), &prompt_dump);
    }

    let mut messages: Vec<serde_json::Value> = vec![
        serde_json::json!({
            "role": "system",
            "content": system_content
        }),
        serde_json::json!({
            "role": "user",
            "content": user_context
        }),
    ];

    let mut accumulated_text = String::new();
    let mut rate_limit_retried = false;
    let mut timeout_retries = 0usize;

    for turn in 0..API_AGENT_MAX_TURNS {
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

        let resp = context.client
            .post(format!("{}/v1/chat/completions", context.url))
            .header("x-lore-key", token)
            .timeout(std::time::Duration::from_secs(120))
            .json(&body)
            .send()
            .await;

        let resp = match resp {
            Ok(r) => { timeout_retries = 0; r }
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
                accumulated_text.push_str(&format!("\n\n[{err_text}]"));
                break;
            }
        };

        let status = resp.status();
        let resp_body: serde_json::Value = resp.json().await?;

        if !status.is_success() {
            let err = resp_body["error"]["message"].as_str()
                .or_else(|| resp_body["error"].as_str())
                .unwrap_or("unknown error");

            if status.as_u16() == 429 && !rate_limit_retried {
                rate_limit_retried = true;
                let _ = context.client
                    .post(format!("{}/v1/chat/respond", context.url))
                    .header("x-lore-key", token)
                    .json(&serde_json::json!({ "tool_use": format!("\u{23f3} Rate limited, retrying in {API_AGENT_RATE_LIMIT_WAIT_SECS}s...") }))
                    .send().await;
                tokio::time::sleep(std::time::Duration::from_secs(API_AGENT_RATE_LIMIT_WAIT_SECS)).await;
                continue;
            }

            if status.as_u16() == 400 {
                let has_untrimmed = messages.iter().any(|m|
                    m["role"].as_str() == Some("tool") &&
                    m["content"].as_str().map(|s| s != API_AGENT_TRIMMED_STUB).unwrap_or(false)
                );
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

            accumulated_text.push_str(&format!("\n\n[API error ({status}): {err}]"));
            break;
        }

        rate_limit_retried = false;

        let choice = resp_body["choices"].as_array().and_then(|c| c.first());
        let message = choice.and_then(|c| c.get("message"));
        let content = message.and_then(|m| m["content"].as_str()).unwrap_or("").to_string();
        let finish_reason = choice.and_then(|c| c["finish_reason"].as_str()).unwrap_or("");
        let tool_calls = message.and_then(|m| m["tool_calls"].as_array()).cloned();

        if !content.is_empty() {
            accumulated_text.push_str(&content);
            let _ = context.client
                .post(format!("{}/v1/chat/respond", context.url))
                .header("x-lore-key", token)
                .json(&serde_json::json!({ "text": &content }))
                .send().await;
        }

        if let Some(ref tcs) = tool_calls {
            if !tcs.is_empty() {
                messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": if content.is_empty() { serde_json::Value::Null } else { serde_json::json!(content) },
                    "tool_calls": tcs,
                }));

                for tc in tcs {
                    let tool_id = tc["id"].as_str().unwrap_or("").to_string();
                    let func = tc.get("function");
                    let tool_name = func.and_then(|f| f["name"].as_str()).unwrap_or("");
                    let raw_args = func.and_then(|f| f["arguments"].as_str()).unwrap_or("{}");

                    let (tool_args, parse_error) = match serde_json::from_str::<serde_json::Value>(raw_args) {
                        Ok(v) => (v, false),
                        Err(_) => (serde_json::json!({}), true),
                    };

                    let is_lore_tool = lore_names.contains(tool_name);
                    let display = if is_lore_tool {
                        format_lore_tool_display(tool_name, &tool_args)
                    } else {
                        format_local_tool_display(tool_name, &tool_args)
                    };
                    let _ = context.client
                        .post(format!("{}/v1/chat/respond", context.url))
                        .header("x-lore-key", token)
                        .json(&serde_json::json!({ "tool_use": display }))
                        .send().await;

                    let result_text = if parse_error {
                        "Error: Failed to parse tool arguments (malformed JSON). Retry with valid JSON.".to_string()
                    } else if is_lore_tool {
                        let raw = execute_lore_tool(context, tool_name, &tool_args).await;
                        truncate_local_tool_result(&raw)
                    } else {
                        let raw = execute_local_tool(tool_name, &tool_args).await;
                        truncate_local_tool_result(&raw)
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
            accumulated_text.push_str("\n\n\u{26a0}\u{fe0f} Response was truncated (hit output token limit).");
        }

        break;
    }

    if accumulated_text.is_empty() {
        accumulated_text = "(no response)".to_string();
    }

    // Save API agent context for debugging
    {
        let lore_dir = PathBuf::from(format!(".lore/{}", agent_name));
        let _ = fs::create_dir_all(&lore_dir);
        let debug: String = messages.iter().map(|m| {
            let role = m["role"].as_str().unwrap_or("?");
            let content = m["content"].as_str().unwrap_or("").chars().take(200).collect::<String>();
            format!("[{role}] {content}\n")
        }).collect();
        let _ = fs::write(lore_dir.join("api_context.txt"), &debug);
    }

    Ok(accumulated_text)
}

fn trim_api_context(messages: &mut Vec<serde_json::Value>) {
    let size: usize = messages.iter().map(|m| {
        serde_json::to_string(m).map(|s| s.len()).unwrap_or(0)
    }).sum();
    if size <= API_AGENT_MAX_CONTEXT_CHARS { return; }

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
                    m["content"] = serde_json::json!(format!("{preview}\n[Earlier analysis trimmed]"));
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
    let shown = if lines.len() > 1000 { 1000 } else { lines.len() };
    let truncated: String = lines[..shown].join("\n");
    format!("{truncated}\n\n[Output truncated \u{2014} {shown} of {} lines shown]", lines.len())
}

fn format_local_tool_display(name: &str, args: &serde_json::Value) -> String {
    let get_str = |key: &str| -> &str {
        args.get(key).and_then(|v| v.as_str()).unwrap_or("")
    };
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
            let path = if get_str("path").is_empty() { "." } else { get_str("path") };
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
    let resp = context.client
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

async fn execute_lore_tool(context: &CliContext, name: &str, args: &serde_json::Value) -> String {
    let token = match context.token.as_deref() {
        Some(t) => t,
        None => return "Error: no token configured".to_string(),
    };
    let resp = context.client
        .post(format!("{}/v1/chat/lore-tools", context.url))
        .header("x-lore-key", token)
        .timeout(std::time::Duration::from_secs(30))
        .json(&serde_json::json!({ "name": name, "arguments": args }))
        .send()
        .await;
    match resp {
        Ok(r) => {
            if let Ok(body) = r.json::<serde_json::Value>().await {
                body["result"].as_str().unwrap_or("(empty result)").to_string()
            } else {
                "Error: failed to parse server response".to_string()
            }
        }
        Err(e) => format!("Error calling Lore tool: {e}"),
    }
}

fn format_lore_tool_display(name: &str, args: &serde_json::Value) -> String {
    let get_str = |key: &str| -> &str {
        args.get(key).and_then(|v| v.as_str()).unwrap_or("")
    };
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
        "delete_document" => format!("\u{1f5d1}\u{fe0f} delete_document {}", short_id("document_id")),
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

async fn execute_local_tool(name: &str, args: &serde_json::Value) -> String {
    match name {
        "read_file" => execute_read_file(args).await,
        "write_file" => execute_write_file(args),
        "edit_file" => execute_edit_file(args),
        "bash" => execute_bash(args).await,
        "grep" => execute_grep(args).await,
        "glob" => execute_glob(args).await,
        "list_directory" => execute_list_directory(args),
        _ => format!("Unknown tool: {name}"),
    }
}

async fn execute_read_file(args: &serde_json::Value) -> String {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return "Error: path is required".to_string(),
    };
    let offset = args["offset"].as_u64().unwrap_or(0) as usize;
    let limit = args["limit"].as_u64().map(|l| l as usize);

    match fs::read_to_string(path) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = if offset > 0 { offset.saturating_sub(1) } else { 0 };
            let end = match limit {
                Some(l) => (start + l).min(lines.len()),
                None => lines.len(),
            };
            if start >= lines.len() {
                return format!("Error: offset {offset} beyond end of file ({} lines)", lines.len());
            }
            let mut result = String::new();
            for (i, line) in lines[start..end].iter().enumerate() {
                result.push_str(&format!("{:>6}\t{}\n", start + i + 1, line));
            }
            if result.is_empty() { "(empty file)".to_string() } else { result }
        }
        Err(e) => format!("Error reading {path}: {e}"),
    }
}

fn execute_write_file(args: &serde_json::Value) -> String {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return "Error: path is required".to_string(),
    };
    let content = args["content"].as_str().unwrap_or("");
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::write(path, content) {
        Ok(()) => format!("Wrote {} bytes to {path}", content.len()),
        Err(e) => format!("Error writing {path}: {e}"),
    }
}

fn execute_edit_file(args: &serde_json::Value) -> String {
    let path = match args["path"].as_str() {
        Some(p) => p,
        None => return "Error: path is required".to_string(),
    };
    let old_string = match args["old_string"].as_str() {
        Some(s) => s,
        None => return "Error: old_string is required".to_string(),
    };
    let new_string = args["new_string"].as_str().unwrap_or("");
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return format!("Error reading {path}: {e}"),
    };
    let count = content.matches(old_string).count();
    if count == 0 {
        return format!("Error: old_string not found in {path}");
    }
    if count > 1 {
        return format!("Error: old_string found {count} times in {path} \u{2014} must be unique. Provide more surrounding context.");
    }
    let new_content = content.replacen(old_string, new_string, 1);
    match fs::write(path, new_content) {
        Ok(()) => format!("Edited {path}: replaced 1 occurrence"),
        Err(e) => format!("Error writing {path}: {e}"),
    }
}

async fn execute_bash(args: &serde_json::Value) -> String {
    let command = match args["command"].as_str() {
        Some(c) => c,
        None => return "Error: command is required".to_string(),
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        tokio::process::Command::new("bash")
            .args(["-lc", command])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
    ).await;
    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);
            let mut r = String::new();
            if !stdout.is_empty() { r.push_str(&stdout); }
            if !stderr.is_empty() {
                if !r.is_empty() { r.push('\n'); }
                r.push_str(&format!("(stderr) {stderr}"));
            }
            if exit_code != 0 { r.push_str(&format!("\n(exit code: {exit_code})")); }
            if r.is_empty() { format!("(no output, exit code: {exit_code})") } else { r }
        }
        Ok(Err(e)) => format!("Error running command: {e}"),
        Err(_) => "Error: command timed out after 120 seconds".to_string(),
    }
}

async fn execute_grep(args: &serde_json::Value) -> String {
    let pattern = match args["pattern"].as_str() {
        Some(p) => p,
        None => return "Error: pattern is required".to_string(),
    };
    let path = args["path"].as_str().unwrap_or(".");
    let include = args["include"].as_str();
    let mut cmd = tokio::process::Command::new("grep");
    cmd.args(["-rn", "--color=never"]);
    if let Some(inc) = include { cmd.args(["--include", inc]); }
    cmd.arg("--").arg(pattern).arg(path);
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    match tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output()).await {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() { "No matches found".to_string() } else { stdout.to_string() }
        }
        Ok(Err(e)) => format!("Error: {e}"),
        Err(_) => "Error: grep timed out".to_string(),
    }
}

async fn execute_glob(args: &serde_json::Value) -> String {
    let pattern = match args["pattern"].as_str() {
        Some(p) => p,
        None => return "Error: pattern is required".to_string(),
    };
    let path = args["path"].as_str().unwrap_or(".");
    let mut cmd = tokio::process::Command::new("find");
    cmd.arg(path).args(["-name", pattern, "-type", "f"]);
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    match tokio::time::timeout(std::time::Duration::from_secs(15), cmd.output()).await {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() { "No files found".to_string() } else { stdout.to_string() }
        }
        Ok(Err(e)) => format!("Error: {e}"),
        Err(_) => "Error: glob search timed out".to_string(),
    }
}

fn execute_list_directory(args: &serde_json::Value) -> String {
    let path = args["path"].as_str().unwrap_or(".");
    match fs::read_dir(path) {
        Ok(entries) => {
            let mut items: Vec<String> = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                items.push(if is_dir { format!("{name}/") } else { name });
            }
            items.sort();
            if items.is_empty() { "(empty directory)".to_string() } else { items.join("\n") }
        }
        Err(e) => format!("Error listing {path}: {e}"),
    }
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

    let resp = context.client
        .post(format!("{}/v1/chat/completions", context.url))
        .header("x-lore-key", token)
        .timeout(std::time::Duration::from_secs(60))
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp.json().await?;
    if !status.is_success() {
        let err = resp_body["error"]["message"].as_str().unwrap_or("unknown error");
        return Err(format!("Compaction error ({status}): {err}").into());
    }

    let text = resp_body["choices"].as_array()
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

async fn maybe_auto_compact(context: &CliContext, agent_name: &str, backend: AgentBackend) -> CliResult<()> {
    do_compact(context, agent_name, false, backend).await
}

async fn do_compact(context: &CliContext, agent_name: &str, aggressive: bool, backend: AgentBackend) -> CliResult<()> {
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

    let window_size = history["window_size"].as_u64().unwrap_or(22) as usize;
    let messages = match history["messages"].as_array() {
        Some(m) => m,
        None => return Ok(()),
    };

    // Count unpinned messages (message pairs = user+assistant grouped)
    // For simplicity, count all messages and check against window threshold
    let msg_count = messages.len();
    if msg_count < window_size {
        return Ok(());
    }

    let target = if aggressive {
        window_size / 2
    } else {
        window_size.saturating_sub(7).max(1)
    };
    let compact_count = msg_count.saturating_sub(target).max(1).min(msg_count.saturating_sub(1));

    let to_compact = &messages[..compact_count];
    let to_keep = &messages[compact_count..];

    eprintln!(
        "[agent] Compacting {compact_count} messages (total {msg_count}, window {window_size}{})",
        if aggressive { ", aggressive" } else { "" }
    );

    // Build compaction input
    let current_summary = history["summary"].as_str().unwrap_or("");
    let mut input = String::new();
    if !current_summary.is_empty() {
        input.push_str(&format!("<current_summary>\n{current_summary}\n</current_summary>\n\n"));
    }
    input.push_str("<messages_to_compact>\n");
    for msg in to_compact {
        let role = msg["role"].as_str().unwrap_or("user");
        let content = msg["content"].as_str().unwrap_or("");
        if role == "user" {
            input.push_str(&format!("User: {content}\n"));
        } else {
            let truncated: String = content.chars().take(4000).collect();
            input.push_str(&format!("Assistant: {truncated}\n\n"));
        }
    }
    input.push_str("</messages_to_compact>");

    // Run compaction through the agent's backend
    let full_prompt = format!("{COMPACTION_SYSTEM_PROMPT}\n\n{input}");
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

    eprintln!("[agent] Compaction complete. {} messages remaining", to_keep.len());
    Ok(())
}

// --- Backend dispatch ---

enum BackendEvent {
    Text(String),
    ToolUse(String),
    Result(String),
    Skip,
}

fn short_path(p: &str) -> String {
    let path = std::path::Path::new(p);
    let file = path.file_name().map(|f| f.to_string_lossy()).unwrap_or_default();
    let dir = path.parent().and_then(|d| d.file_name()).map(|d| d.to_string_lossy());
    match dir {
        Some(d) if !d.is_empty() && d != "." => format!("{d}/{file}"),
        _ => file.to_string(),
    }
}

fn format_tool_use_claude(name: &str, input: &serde_json::Value) -> String {
    match name {
        "Read" => format!("Read {}", input["file_path"].as_str().map(short_path).unwrap_or_default()),
        "Edit" => format!("Edit {}", input["file_path"].as_str().map(short_path).unwrap_or_default()),
        "Write" => format!("Write {}", input["file_path"].as_str().map(short_path).unwrap_or_default()),
        "MultiEdit" => format!("MultiEdit {}", input["file_path"].as_str().map(short_path).unwrap_or_default()),
        "Bash" => {
            let cmd = input["command"].as_str().unwrap_or("");
            let truncated: String = cmd.chars().take(120).collect();
            format!("Bash: {truncated}")
        }
        "Grep" => {
            let pattern = input["pattern"].as_str().unwrap_or("");
            let path = input["path"].as_str().map(|p| short_path(p)).unwrap_or_else(|| ".".to_string());
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
            let file = input["filePath"].as_str().map(short_path).unwrap_or_default();
            format!("LSP {op} {file}")
        }
        _ => name.to_string(),
    }
}

fn format_tool_use_gemini(name: &str, input: &serde_json::Value) -> String {
    match name {
        "read_file" => format!("Read {}", input["file_path"].as_str().map(short_path).unwrap_or_default()),
        "replace" => format!("Edit {}", input["file_path"].as_str().map(short_path).unwrap_or_default()),
        "write_file" => format!("Write {}", input["file_path"].as_str().map(short_path).unwrap_or_default()),
        "run_shell_command" => {
            let cmd = input["command"].as_str().unwrap_or("");
            let truncated: String = cmd.chars().take(120).collect();
            format!("Bash: {truncated}")
        }
        "grep_search" => {
            let pattern = input["pattern"].as_str().unwrap_or("");
            let path = input["dir_path"].as_str().map(|p| short_path(p)).unwrap_or_else(|| ".".to_string());
            format!("Grep \"{pattern}\" in {path}")
        }
        "glob" => format!("Glob {}", input["pattern"].as_str().unwrap_or("")),
        "google_web_search" => {
            let query = input["query"].as_str().unwrap_or("");
            let truncated: String = query.chars().take(100).collect();
            format!("WebSearch: {truncated}")
        }
        "web_fetch" => {
            let url = input["url"].as_str().unwrap_or("");
            let truncated: String = url.chars().take(100).collect();
            format!("WebFetch: {truncated}")
        }
        _ => name.to_string(),
    }
}

fn format_tool_use_codex(item: &serde_json::Value) -> String {
    if item["type"].as_str() == Some("command_execution") {
        let cmd = item["command"].as_str().unwrap_or("")
            .trim_start_matches("/bin/bash -lc ");
        let truncated: String = cmd.chars().take(120).collect();
        format!("Bash: {truncated}")
    } else {
        item["type"].as_str().unwrap_or("unknown").to_string()
    }
}

async fn spawn_backend(
    backend: AgentBackend,
    prompt: &str,
    model: Option<&str>,
    effort: Option<&str>,
) -> CliResult<tokio::process::Child> {
    use tokio::io::AsyncWriteExt;

    let mut child = match backend {
        AgentBackend::Claude => {
            let mut args = vec![
                "-p".to_string(),
                "--output-format".to_string(), "stream-json".to_string(),
                "--verbose".to_string(),
                "--permission-mode".to_string(), "bypassPermissions".to_string(),
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
            tokio::process::Command::new("claude")
                .args(&args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .env_remove("CLAUDECODE")
                .spawn()?
        }
        AgentBackend::Gemini => {
            let mut args = vec![
                "-o".to_string(), "stream-json".to_string(),
                "--yolo".to_string(),
            ];
            if let Some(m) = model {
                args.push("-m".to_string());
                args.push(m.to_string());
            }
            args.push("-p".to_string());
            args.push(String::new());
            tokio::process::Command::new("gemini")
                .args(&args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?
        }
        AgentBackend::Codex => {
            let mut args = vec![
                "exec".to_string(), "--json".to_string(),
                "--dangerously-bypass-approvals-and-sandbox".to_string(),
                "--ephemeral".to_string(), "-".to_string(),
            ];
            if let Some(m) = model {
                args.push("--model".to_string());
                args.push(m.to_string());
            }
            tokio::process::Command::new("codex")
                .args(&args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?
        }
        AgentBackend::OpenAi => {
            return Err("OpenAI backend is not yet implemented. Use claude, gemini, or codex.".into());
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(prompt.as_bytes()).await?;
        drop(stdin);
    }

    Ok(child)
}

fn parse_backend_line(backend: AgentBackend, parsed: &serde_json::Value) -> Vec<BackendEvent> {
    match backend {
        AgentBackend::Claude => parse_claude_line(parsed),
        AgentBackend::Gemini => parse_gemini_line(parsed),
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
            if events.is_empty() { vec![BackendEvent::Skip] } else { events }
        }
        Some("result") => {
            let text = parsed["result"].as_str().unwrap_or("").to_string();
            vec![BackendEvent::Result(text)]
        }
        _ => vec![BackendEvent::Skip],
    }
}

fn parse_gemini_line(parsed: &serde_json::Value) -> Vec<BackendEvent> {
    match parsed["type"].as_str() {
        Some("message") => {
            if parsed["role"].as_str() == Some("assistant") {
                if let Some(content) = parsed["content"].as_str() {
                    if !content.is_empty() {
                        return vec![BackendEvent::Text(content.to_string())];
                    }
                }
            }
            vec![BackendEvent::Skip]
        }
        Some("tool_use") => {
            let name = parsed["tool_name"].as_str().unwrap_or("");
            let params = &parsed["parameters"];
            vec![BackendEvent::ToolUse(format_tool_use_gemini(name, params))]
        }
        Some("result") => vec![BackendEvent::Result(String::new())],
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
                } else if item["type"].as_str() == Some("command_execution") {
                    return vec![BackendEvent::ToolUse(format_tool_use_codex(item))];
                }
            }
            vec![BackendEvent::Skip]
        }
        Some("turn.completed") => vec![BackendEvent::Result(String::new())],
        _ => vec![BackendEvent::Skip],
    }
}

/// Run a prompt through the backend and collect the full text output.
/// Used for compaction where we need the complete response, not streaming.
async fn run_compaction(context: &CliContext, backend: AgentBackend, prompt: &str) -> CliResult<String> {
    match backend {
        AgentBackend::Claude => {
            // Claude without --output-format returns plain text
            use tokio::io::AsyncWriteExt;
            let mut child = tokio::process::Command::new("claude")
                .args(["-p", "--model", "sonnet", "--no-session-persistence"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .env_remove("CLAUDECODE")
                .spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(prompt.as_bytes()).await?;
                drop(stdin);
            }
            let output = child.wait_with_output().await?;
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        AgentBackend::Gemini | AgentBackend::Codex => {
            // Spawn in JSON mode, parse streaming output, accumulate text
            let mut child = spawn_backend(backend, prompt, None, None).await?;
            let stdout = child.stdout.take().ok_or("no stdout")?;
            let reader = tokio::io::BufReader::new(stdout);
            let mut lines = reader.lines();
            let mut result = String::new();

            while let Some(line) = lines.next_line().await? {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let parsed: serde_json::Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                for event in parse_backend_line(backend, &parsed) {
                    match event {
                        BackendEvent::Text(text) => result.push_str(&text),
                        BackendEvent::Result(text) => {
                            if result.is_empty() && !text.is_empty() {
                                result = text;
                            }
                        }
                        BackendEvent::ToolUse(_) | BackendEvent::Skip => {}
                    }
                }
            }
            let _ = child.wait().await;
            Ok(result.trim().to_string())
        }
        AgentBackend::OpenAi => {
            run_api_compaction(context, prompt).await
        }
    }
}

// --- Machine service daemon ---

const LORE_SERVICE_DAEMON_ENV: &str = "LORE_SERVICE_DAEMON";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedAgent {
    name: String,
    pid: u32,
    folder: String,
    backend: String,
    token: String,
}

struct ServiceState {
    agents: Vec<ManagedAgent>,
    state_dir: PathBuf,
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
        Self { agents, state_dir: state_dir.to_path_buf() }
    }

    fn save(&self) {
        let _ = fs::create_dir_all(&self.state_dir);
        let _ = fs::write(
            self.state_dir.join("agents.json"),
            serde_json::to_vec_pretty(&self.agents).unwrap_or_default(),
        );
    }

    fn check_agents(&mut self) {
        for agent in &mut self.agents {
            if agent.pid != 0 && !is_process_running(agent.pid) {
                eprintln!("[service] Agent '{}' (pid {}) is no longer running", agent.name, agent.pid);
                agent.pid = 0;
            }
        }
    }

    fn restart_crashed_agents(&mut self, context: &CliContext) {
        for agent in &mut self.agents {
            if agent.pid == 0 {
                match spawn_agent_process(context, agent) {
                    Ok(pid) => {
                        eprintln!("[service] Restarted agent '{}' (pid {})", agent.name, pid);
                        agent.pid = pid;
                    }
                    Err(e) => {
                        eprintln!("[service] Failed to restart agent '{}': {e}", agent.name);
                    }
                }
            }
        }
        self.save();
    }

    fn agent_statuses(&self) -> Vec<serde_json::Value> {
        self.agents.iter().map(|a| {
            let status = if a.pid != 0 && is_process_running(a.pid) { "running" } else { "stopped" };
            serde_json::json!({
                "name": a.name,
                "pid": a.pid,
                "status": status,
                "folder": a.folder,
            })
        }).collect()
    }

    fn stop_agent(&mut self, name: &str) -> serde_json::Value {
        if let Some(agent) = self.agents.iter_mut().find(|a| a.name == name) {
            if agent.pid != 0 && is_process_running(agent.pid) {
                eprintln!("[service] Stopping agent '{}' (pid {})", name, agent.pid);
                kill_process(agent.pid);
                agent.pid = 0;
                self.save();
                serde_json::json!({ "ok": true, "agent_name": name })
            } else {
                agent.pid = 0;
                self.save();
                serde_json::json!({ "ok": true, "agent_name": name, "note": "agent was not running" })
            }
        } else {
            serde_json::json!({ "error": format!("agent '{}' not managed by this service", name) })
        }
    }

    fn remove_agent(&mut self, name: &str) -> serde_json::Value {
        if let Some(index) = self.agents.iter().position(|a| a.name == name) {
            let agent = self.agents[index].clone();
            if agent.pid != 0 && is_process_running(agent.pid) {
                eprintln!("[service] Removing agent '{}' (pid {})", name, agent.pid);
                kill_process(agent.pid);
                std::thread::sleep(std::time::Duration::from_millis(300));
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
        if let Some(agent) = self.agents.iter_mut().find(|a| a.name == name) {
            // Stop if running
            if agent.pid != 0 && is_process_running(agent.pid) {
                kill_process(agent.pid);
                // Brief wait for process to exit
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            // Restart
            match spawn_agent_process(context, agent) {
                Ok(pid) => {
                    eprintln!("[service] Restarted agent '{}' (pid {})", name, pid);
                    agent.pid = pid;
                    self.save();
                    serde_json::json!({ "ok": true, "agent_name": name, "pid": pid })
                }
                Err(e) => {
                    agent.pid = 0;
                    self.save();
                    serde_json::json!({ "error": format!("restart failed: {e}") })
                }
            }
        } else {
            serde_json::json!({ "error": format!("agent '{}' not managed by this service", name) })
        }
    }

    fn stop_all_agents(&mut self) {
        for agent in &mut self.agents {
            if agent.pid != 0 && is_process_running(agent.pid) {
                eprintln!("[service] Stopping agent '{}' (pid {})", agent.name, agent.pid);
                kill_process(agent.pid);
                agent.pid = 0;
            }
        }
        self.save();
    }
}

fn spawn_agent_process(context: &CliContext, agent: &ManagedAgent) -> CliResult<u32> {
    let exe = resolved_current_exe()?;
    let lore_dir = PathBuf::from(&agent.folder).join(format!(".lore/{}", agent.name));
    fs::create_dir_all(&lore_dir)?;

    let log_path = lore_dir.join("lore.log");
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let child = std::process::Command::new(&exe)
        .current_dir(&agent.folder)
        .args([
            "--url", &context.url,
            "--token", &agent.token,
            "agent", &agent.name,
        ])
        .env(LORE_DAEMON_ENV, "1")
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .stdin(std::process::Stdio::null())
        .spawn()?;

    let pid = child.id();
    fs::write(lore_dir.join("lore.pid"), pid.to_string())?;
    Ok(pid)
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

        let (folder, backend, old_pid) = match found {
            Some(info) => info,
            None => {
                // Agent isn't running, but we know about it from config.
                // Use HOME as default folder, claude as default backend.
                let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                eprintln!(
                    "[service] Agent '{}' not running, importing with folder={}",
                    agent_name, home
                );
                (home, "claude".to_string(), None)
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
            backend,
            token: agent_token.clone(),
        };
        svc_state.agents.push(managed);
        eprintln!("[service] Migrated agent '{}'", agent_name);
    }

    svc_state.save();
}

/// Scan /proc for a running `lore ... agent <name>` process.
/// Returns (cwd, backend, pid) if found.
fn find_old_agent_process(agent_name: &str, exclude_pid: u32) -> Option<(String, String, Option<u32>)> {
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
                    env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
                });

            // Parse backend from args (--backend <value>)
            let backend = args
                .iter()
                .position(|a| a == "--backend")
                .and_then(|i| args.get(i + 1))
                .cloned()
                .unwrap_or_else(|| "claude".to_string());

            return Some((cwd, backend, Some(pid)));
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
    let machine_token = context.token.as_deref().ok_or(
        "no machine token configured. Run 'lore setup <url>' first.",
    )?;

    if !args.fg && !is_daemon {
        // Daemonize
        let lore_dir = env::var("HOME").map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("lore-service");
        fs::create_dir_all(&lore_dir)?;
        let log_path = lore_dir.join("service.log");
        let pid_path = lore_dir.join("service.pid");

        // Kill existing service if running
        if pid_path.exists() {
            if let Ok(pid_str) = fs::read_to_string(&pid_path) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    if is_process_running(pid) {
                        eprintln!("Stopping existing service (pid {})", pid);
                        kill_process(pid);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }
            let _ = fs::remove_file(&pid_path);
        }

        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let exe = resolved_current_exe()?;
        let child = std::process::Command::new(&exe)
            .args(["--url", &context.url, "--token", machine_token, "service", "--fg"])
            .env(LORE_SERVICE_DAEMON_ENV, "1")
            .stdout(log_file.try_clone()?)
            .stderr(log_file)
            .stdin(std::process::Stdio::null())
            .spawn()?;
        let pid = child.id();
        fs::write(&pid_path, pid.to_string())?;
        println!("Lore service started (pid {})", pid);
        println!("  Log: {}", log_path.display());
        return Ok(());
    }

    // Write PID file for daemon mode
    let lore_dir = env::var("HOME").map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("lore-service");
    fs::create_dir_all(&lore_dir)?;
    if is_daemon {
        fs::write(lore_dir.join("service.pid"), std::process::id().to_string())?;
    }

    eprintln!("[service] Machine service starting (version {})", env!("CARGO_PKG_VERSION"));

    // Load managed agents state
    let mut svc_state = ServiceState::load(&lore_dir);

    // Migrate old-style standalone agents if this is the first service run
    if svc_state.agents.is_empty() {
        migrate_old_agents(context, &mut svc_state);
    }

    eprintln!("[service] Loaded {} managed agent(s)", svc_state.agents.len());

    // Check and restart any crashed agents on startup
    svc_state.check_agents();
    svc_state.restart_crashed_agents(context);

    loop {
        // Check agent health before each poll
        svc_state.check_agents();
        svc_state.restart_crashed_agents(context);

        let poll_start = std::time::Instant::now();
        match service_poll_and_execute(context, machine_token, &mut svc_state).await {
            Ok(update_info) => {
                if let Some((target_version, repo)) = update_info {
                    eprintln!("[service] Self-update to v{target_version} requested, stopping all agents...");
                    svc_state.stop_all_agents();
                    let mut cfg = load_cli_config()?;
                    match apply_cli_update_to_target(&mut cfg, &target_version, &repo).await {
                        Ok(()) => {
                            eprintln!("[service] Updated CLI binary, re-launching service...");
                            let exe = resolved_current_exe()?;
                            let args_vec: Vec<String> = env::args().skip(1).collect();
                            let mut cmd = std::process::Command::new(&exe);
                            cmd.args(&args_vec);
                            cmd.env(LORE_SERVICE_DAEMON_ENV, "1");
                            #[cfg(unix)]
                            {
                                use std::os::unix::process::CommandExt;
                                let err = cmd.exec();
                                eprintln!("[service] Failed to re-exec: {err}");
                                std::process::exit(1);
                            }
                            #[cfg(not(unix))]
                            {
                                match cmd.spawn() {
                                    Ok(_) => std::process::exit(0),
                                    Err(e) => {
                                        eprintln!("[service] Failed to re-exec: {e}");
                                        std::process::exit(1);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[service] Update failed: {e}");
                            // Restart agents that were stopped
                            svc_state.restart_crashed_agents(context);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[service] Error: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
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

    let body: serde_json::Value = resp.error_for_status()?.json().await?;

    // Check for self-update request
    if let Some(target_version) = body["update_to"].as_str() {
        let repo = body["update_repo"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| load_cli_config().ok().map(|cfg| cfg.update_repo).unwrap_or_else(default_update_repo_string));
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
                let r = service_handle_create_agent(context, machine_token, params, svc_state).await;
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
            .post(format!("{}/v1/machines/command/{}/result", context.url, cmd_id))
            .header("x-lore-key", machine_token)
            .json(&serde_json::json!({ "data": result_data }))
            .send()
            .await;
    }

    Ok(None)
}

fn service_home_dir() -> CliResult<PathBuf> {
    let raw_home = env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/"));
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
    let backend = params["backend"].as_str().unwrap_or("claude");
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
    config.agent_tokens.insert(agent_slug.to_string(), agent_token.to_string());
    save_cli_config(&config)?;

    // Create managed agent entry
    let mut managed = ManagedAgent {
        name: agent_slug.to_string(),
        pid: 0,
        folder: folder_path.to_string_lossy().into_owned(),
        backend: backend.to_string(),
        token: agent_token.to_string(),
    };

    // Start the agent process
    match spawn_agent_process(context, &managed) {
        Ok(pid) => {
            managed.pid = pid;
            eprintln!(
                "[service] Agent '{}' started in {} (pid {})",
                agent_slug,
                managed.folder,
                pid
            );
        }
        Err(e) => {
            eprintln!("[service] Failed to start agent '{}': {e}", agent_slug);
        }
    }

    svc_state.agents.push(managed.clone());

    Ok(serde_json::json!({
        "ok": true,
        "agent_name": agent_slug,
        "folder": managed.folder,
        "pid": managed.pid,
    }))
}
