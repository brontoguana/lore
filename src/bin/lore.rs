use clap::{Args, Parser, Subcommand, ValueEnum};
use lore_core::{
    AgentBackend, Block, BlockType, DEFAULT_UPDATE_REPO, ProjectName, SelfUpdateOutcome,
    check_for_update, maybe_apply_self_update,
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
struct Cli {
    #[arg(long, global = true)]
    url: Option<String>,
    #[arg(long, global = true)]
    token: Option<String>,
    #[arg(long, global = true)]
    project: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Projects,
    Blocks {
        #[command(subcommand)]
        command: BlocksCommand,
    },
    Grep(GrepArgs),
    Add(WriteBlockArgs),
    Update(UpdateBlockArgs),
    Move(MoveBlockArgs),
    Delete(DeleteBlockArgs),
    Librarian {
        #[command(subcommand)]
        command: LibrarianCommand,
    },
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    SelfUpdate {
        #[command(subcommand)]
        command: UpdateCommand,
    },
    Context,
    Setup(SetupArgs),
    Agent(AgentArgs),
}

#[derive(Subcommand)]
enum ConfigCommand {
    Show,
    Set(ConfigSetArgs),
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
    List(ListBlocksArgs),
    Read(ReadBlockArgs),
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
    Answer(LibrarianAnswerArgs),
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
    List(HistoryListArgs),
    Show(HistoryShowArgs),
    Revert(HistoryRevertArgs),
}

#[derive(Subcommand)]
enum UpdateCommand {
    Status,
    Check,
    Apply,
    Enable(UpdateEnableArgs),
    Disable,
}

#[derive(Args)]
struct UpdateEnableArgs {
    #[arg(long, default_value = DEFAULT_UPDATE_REPO)]
    repo: String,
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
    agent_tokens: std::collections::HashMap<String, String>,
    #[serde(default)]
    auto_update_enabled: bool,
    #[serde(default = "default_update_repo_string")]
    update_repo: String,
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
            config.token = Some(token);
            save_cli_config(&config)?;
            println!("Registered machine \"{}\" on {}", machine_name, url);
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
    )
    .await
    .map_err(|err| io::Error::other(err.to_string()).into())
}

async fn apply_cli_update(config: &mut CliConfig) -> CliResult<()> {
    let client = reqwest::Client::new();
    let executable_path = env::current_exe()?;
    match maybe_apply_self_update(
        &client,
        "lore",
        env!("CARGO_PKG_VERSION"),
        &config.update_repo,
        &executable_path,
    )
    .await
    .map_err(|err| io::Error::other(err.to_string()))?
    {
        SelfUpdateOutcome::UpToDate(status) => {
            println!("{}", status.detail);
            config.last_update_check = Some(status.checked_at);
            save_cli_config(config)?;
        }
        SelfUpdateOutcome::Updated(status) => {
            println!("{}", status.detail);
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
    extern "system" {
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

        let exe = env::current_exe()?;
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

    // Resolve backend: CLI flag > server config > default
    let backend = if let Some(ref b) = args.backend {
        b.parse().unwrap_or(AgentBackend::Claude)
    } else {
        let token = agent_context.token.as_deref().unwrap_or("");
        match agent_context
            .client
            .get(format!("{}/v1/chat/config", agent_context.url))
            .header("x-lore-key", token)
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    json["backend"]
                        .as_str()
                        .and_then(|b| b.parse().ok())
                        .unwrap_or(AgentBackend::Claude)
                } else {
                    AgentBackend::Claude
                }
            }
            Err(_) => AgentBackend::Claude,
        }
    };

    eprintln!("[agent] Starting agent '{}' (backend: {backend})", args.name);

    // Main agent loop: poll for messages, process them
    loop {
        match agent_poll_and_process(&agent_context, &args.name, backend).await {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[agent] Error: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

async fn agent_poll_and_process(context: &CliContext, agent_name: &str, backend: AgentBackend) -> CliResult<()> {
    let token = context.token.as_deref().ok_or("no token configured")?;

    // Long-poll for messages
    let resp = context
        .client
        .get(format!("{}/v1/chat/poll", context.url))
        .header("x-lore-key", token)
        .timeout(std::time::Duration::from_secs(35))
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) if e.is_timeout() => return Ok(()), // Normal long-poll timeout
        Err(e) => return Err(e.into()),
    };

    let body: serde_json::Value = resp.error_for_status()?.json().await?;
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
                do_compact(context, agent_name, true, backend).await?;
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

    // Build the prompt: summary + pins + recent messages + new message
    let summary = history["summary"].as_str().unwrap_or("");
    let window_size = history["window_size"].as_u64().unwrap_or(22) as usize;
    let hist_messages = history["messages"].as_array();
    let pins = history["pins"].as_array();

    let mut prompt_parts: Vec<String> = Vec::new();

    if !summary.is_empty() {
        prompt_parts.push(format!("## Conversation Summary\n\n{summary}"));
    }

    // Include pinned context
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

    if let Some(msgs) = hist_messages {
        // Take last window_size messages for context
        let start = msgs.len().saturating_sub(window_size);
        let recent = &msgs[start..];
        if !recent.is_empty() {
            prompt_parts.push("## Previous Conversation\nThe following is recent conversation history.\n".to_string());
            for msg in recent {
                let role = msg["role"].as_str().unwrap_or("user");
                let content = msg["content"].as_str().unwrap_or("");
                if role == "user" {
                    prompt_parts.push(format!("User: {content}"));
                } else {
                    let truncated: String = content.chars().take(4000).collect();
                    prompt_parts.push(format!("Assistant: {truncated}"));
                }
            }
        }
    }

    prompt_parts.push(format!("\n## New Message\n\n{combined}"));

    let full_prompt = prompt_parts.join("\n\n");

    // Read model/effort overrides from conversation state
    let model_override = history["model"].as_str().map(|s| s.to_string());
    let effort_override = history["effort"].as_str().map(|s| s.to_string());

    // Spawn the backend CLI process
    let mut child = spawn_backend(backend, &full_prompt, model_override.as_deref(), effort_override.as_deref()).await?;

    // Read streaming JSON from stdout
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let reader = tokio::io::BufReader::new(stdout);
    let mut lines = reader.lines();
    let mut full_response = String::new();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        match parse_backend_line(backend, &parsed) {
            BackendEvent::Text(text) => {
                full_response.push_str(&text);
                let _ = context
                    .client
                    .post(format!("{}/v1/chat/respond", context.url))
                    .header("x-lore-key", token)
                    .json(&serde_json::json!({ "text": text }))
                    .send()
                    .await;
            }
            BackendEvent::Result(text) => {
                if full_response.is_empty() && !text.is_empty() {
                    full_response = text;
                }
            }
            BackendEvent::Skip => {}
        }
    }

    // Wait for process to finish
    let _ = child.wait().await;

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

    // Check if compaction is needed
    if let Err(e) = maybe_auto_compact(context, agent_name, backend).await {
        eprintln!("[agent] Compaction error: {e}");
    }

    Ok(())
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
    let new_summary = run_compaction(backend, &full_prompt).await?;

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
    Result(String),
    Skip,
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

fn parse_backend_line(backend: AgentBackend, parsed: &serde_json::Value) -> BackendEvent {
    match backend {
        AgentBackend::Claude => parse_claude_line(parsed),
        AgentBackend::Gemini => parse_gemini_line(parsed),
        AgentBackend::Codex => parse_codex_line(parsed),
        AgentBackend::OpenAi => BackendEvent::Skip,
    }
}

fn parse_claude_line(parsed: &serde_json::Value) -> BackendEvent {
    match parsed["type"].as_str() {
        Some("assistant") => {
            if let Some(content) = parsed["message"]["content"].as_array() {
                let mut text = String::new();
                for block in content {
                    if block["type"].as_str() == Some("text") {
                        if let Some(t) = block["text"].as_str() {
                            text.push_str(t);
                        }
                    }
                }
                if !text.is_empty() {
                    return BackendEvent::Text(text);
                }
            }
            BackendEvent::Skip
        }
        Some("result") => {
            let text = parsed["result"].as_str().unwrap_or("").to_string();
            BackendEvent::Result(text)
        }
        _ => BackendEvent::Skip,
    }
}

fn parse_gemini_line(parsed: &serde_json::Value) -> BackendEvent {
    match parsed["type"].as_str() {
        Some("message") => {
            if parsed["role"].as_str() == Some("assistant") {
                if let Some(content) = parsed["content"].as_str() {
                    if !content.is_empty() {
                        return BackendEvent::Text(content.to_string());
                    }
                }
            }
            BackendEvent::Skip
        }
        Some("result") => BackendEvent::Result(String::new()),
        _ => BackendEvent::Skip,
    }
}

fn parse_codex_line(parsed: &serde_json::Value) -> BackendEvent {
    match parsed["type"].as_str() {
        Some("item.completed") => {
            if let Some(item) = parsed.get("item") {
                if item["type"].as_str() == Some("agent_message") {
                    if let Some(text) = item["text"].as_str() {
                        if !text.is_empty() {
                            return BackendEvent::Text(text.to_string());
                        }
                    }
                }
            }
            BackendEvent::Skip
        }
        Some("turn.completed") => BackendEvent::Result(String::new()),
        _ => BackendEvent::Skip,
    }
}

/// Run a prompt through the backend and collect the full text output.
/// Used for compaction where we need the complete response, not streaming.
async fn run_compaction(backend: AgentBackend, prompt: &str) -> CliResult<String> {
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
                match parse_backend_line(backend, &parsed) {
                    BackendEvent::Text(text) => result.push_str(&text),
                    BackendEvent::Result(text) => {
                        if result.is_empty() && !text.is_empty() {
                            result = text;
                        }
                    }
                    BackendEvent::Skip => {}
                }
            }
            let _ = child.wait().await;
            Ok(result.trim().to_string())
        }
        AgentBackend::OpenAi => {
            Err("OpenAI backend is not yet implemented".into())
        }
    }
}
