use clap::{Parser, Subcommand};
use lore_core::{
    AutoUpdateConfigStore, AutoUpdateStatus, AutoUpdateStatusStore, DEFAULT_UPDATE_REPO,
    ExternalScheme, FileBlockStore, LocalAuthStore, ServerConfigStore, UiTheme, UserName,
    build_app, maybe_apply_self_update, restart_server_via_systemd, server_systemd_unit_exists,
};
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

const SELF_UPDATE_SKIP_ENV: &str = "LORE_SKIP_SELF_UPDATE";
const SERVICE_NAME: &str = "lore-server";
const CADDY_SERVICE_NAME: &str = "lore-caddy";
const SUDOERS_FILE_NAME: &str = "lore-server-restart";

#[derive(Parser)]
#[command(name = "lore-server")]
#[command(about = "Lore knowledge server")]
#[command(version)]
struct Cli {
    /// Data directory (default: ~/lore)
    #[arg(long, global = true)]
    data_dir: Option<String>,

    /// Bind address (default: 127.0.0.1:7043)
    #[arg(long, global = true)]
    bind: Option<String>,

    #[command(subcommand)]
    command: Option<ServerCommand>,
}

#[derive(Subcommand)]
enum ServerCommand {
    /// Start the server (default if no command given)
    Start,
    /// Install lore-server as a system daemon
    Install {
        /// Domain name for HTTPS (e.g. lore.example.com) — prompted if not given
        #[arg(long)]
        domain: Option<String>,
        /// Do not install/manage Lore's bundled Caddy proxy; print a Caddy reverse-proxy snippet instead
        #[arg(long)]
        no_caddy: bool,
    },
    /// Remove lore-server and Caddy daemons
    Uninstall,
    /// Show daemon status
    Status,
    /// Update lore-server to the latest release
    Update,
    /// Remove all services and binaries but keep data (for a fresh reinstall)
    Clean,
    /// Create the initial admin account (required before first run)
    CreateAdmin,
    /// Temporarily bypass browser login IP and passkey restrictions for one user
    Bypass {
        /// Lore username to allow; prompted if omitted
        #[arg(long)]
        user: Option<String>,
        /// Bypass lifetime in minutes; prompted if omitted
        #[arg(long)]
        minutes: Option<u64>,
    },
    /// Allow one correct-password browser login for a user for a short TTL
    #[command(hide = true)]
    AllowLoginBypass {
        /// Lore username to allow
        #[arg(long)]
        user: String,
        /// Bypass lifetime, e.g. 15m, 1h, 300s
        #[arg(long, default_value = "15m")]
        ttl: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let data_root = cli
        .data_dir
        .clone()
        .or_else(|| env::var("LORE_DATA_ROOT").ok())
        .unwrap_or_else(|| default_data_dir());

    let bind = cli
        .bind
        .clone()
        .or_else(|| env::var("LORE_BIND").ok())
        .unwrap_or_else(|| "127.0.0.1:7043".to_string());

    match cli.command.unwrap_or(ServerCommand::Start) {
        ServerCommand::Start => {
            ensure_data_dir(&data_root);
            prompt_initial_admin_if_needed(&data_root);
            run_server(data_root, bind).await;
        }
        ServerCommand::Install { domain, no_caddy } => {
            ensure_data_dir(&data_root);
            prompt_initial_admin_if_needed(&data_root);
            let domain = domain.unwrap_or_else(|| prompt_domain());
            daemon_install(&data_root, &bind, &domain, !no_caddy);
        }
        ServerCommand::Uninstall => daemon_uninstall(&data_root),
        ServerCommand::Status => daemon_status(&data_root),
        ServerCommand::Update => run_update(),
        ServerCommand::Clean => run_clean(&data_root),
        ServerCommand::CreateAdmin => {
            ensure_data_dir(&data_root);
            create_admin_interactive(&data_root);
        }
        ServerCommand::Bypass { user, minutes } => {
            ensure_data_dir(&data_root);
            allow_login_bypass_interactive(&data_root, user, minutes);
        }
        ServerCommand::AllowLoginBypass { user, ttl } => {
            ensure_data_dir(&data_root);
            allow_login_bypass(&data_root, &user, &ttl);
        }
    }
}

fn run_update() {
    use std::process::Command;
    let status = Command::new("sh")
        .arg("-c")
        .arg("curl -fsSL https://raw.githubusercontent.com/brontoguana/lore/main/scripts/install-server.sh | sh")
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("error: failed to run update: {e}");
            std::process::exit(1);
        }
    }
}

fn run_clean(data_root: &str) {
    eprintln!("cleaning lore-server installation (data in {data_root} will be kept)");
    eprintln!();

    // Migrate any old user-level services first
    migrate_user_services();

    // Stop and remove caddy service
    let caddy_unit = system_unit_path(CADDY_SERVICE_NAME);
    if caddy_unit.exists() {
        sudo_systemctl(&["disable", "--now", CADDY_SERVICE_NAME]);
        if sudo_rm(&caddy_unit) {
            eprintln!("removed service: {}", caddy_unit.display());
        }
    }

    // Stop and remove lore-server service
    let lore_unit = system_unit_path(SERVICE_NAME);
    if lore_unit.exists() {
        sudo_systemctl(&["disable", "--now", SERVICE_NAME]);
        if sudo_rm(&lore_unit) {
            eprintln!("removed service: {}", lore_unit.display());
        }
    }

    remove_restart_sudoers();
    sudo_systemctl(&["daemon-reload"]);

    // Remove Caddyfile and caddy dirs from data root
    let data_path = PathBuf::from(data_root);
    for name in ["Caddyfile", "caddy-data", "caddy-config"] {
        let p = data_path.join(name);
        if p.is_dir() {
            if let Err(err) = fs::remove_dir_all(&p) {
                eprintln!("warning: cannot remove {}: {err}", p.display());
            } else {
                eprintln!("removed: {}", p.display());
            }
        } else if p.is_file() {
            if let Err(err) = fs::remove_file(&p) {
                eprintln!("warning: cannot remove {}: {err}", p.display());
            } else {
                eprintln!("removed: {}", p.display());
            }
        }
    }

    // Remove binaries
    let bin_dir = local_bin_dir();
    for bin in ["lore-server", "caddy"] {
        let p = bin_dir.join(bin);
        if p.exists() {
            if let Err(err) = fs::remove_file(&p) {
                eprintln!("warning: cannot remove {}: {err}", p.display());
            } else {
                eprintln!("removed: {}", p.display());
            }
        }
    }

    eprintln!();
    eprintln!("clean complete — all services stopped and binaries removed");
    eprintln!("data preserved in: {data_root}");
    eprintln!();
    eprintln!("to reinstall:");
    eprintln!(
        "  curl -fsSL https://raw.githubusercontent.com/brontoguana/lore/main/scripts/install-server.sh | sh"
    );
}

fn default_data_dir() -> String {
    env::var("HOME")
        .map(|h| format!("{h}/lore"))
        .unwrap_or_else(|_| "./lore".to_string())
}

fn ensure_data_dir(data_root: &str) {
    if let Err(err) = fs::create_dir_all(data_root) {
        eprintln!("error: cannot create data directory {data_root}: {err}");
        std::process::exit(1);
    }
}

fn prompt_initial_admin_if_needed(data_root: &str) {
    let auth = LocalAuthStore::new(PathBuf::from(data_root));
    match auth.has_users() {
        Ok(true) => return,
        Ok(false) => {}
        Err(_) => return, // can't check, let the server handle it
    }

    // Require a tty — never allow bootstrap via the web UI
    if !atty::is(atty::Stream::Stdin) {
        eprintln!("error: no admin account exists");
        eprintln!("run `lore-server create-admin` to create one before starting the server");
        std::process::exit(1);
    }

    eprintln!();
    eprintln!("No admin account exists yet. Let's create one.");
    eprintln!();

    let username = {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        loop {
            eprint!("Admin username: ");
            io::stderr().flush().ok();
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                eprintln!("aborted");
                std::process::exit(1);
            }
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                break trimmed;
            }
            eprintln!("username cannot be empty");
        }
    };

    let password = loop {
        eprint!("Admin password: ");
        io::stderr().flush().ok();
        let pass = read_password_no_echo();
        if pass.is_empty() {
            eprintln!("aborted");
            std::process::exit(1);
        }
        if pass.len() < 12 {
            eprintln!("password must be at least 12 characters");
            continue;
        }
        eprint!("Confirm password: ");
        io::stderr().flush().ok();
        let confirm = read_password_no_echo();
        if pass != confirm {
            eprintln!("passwords do not match — try again");
            continue;
        }
        break pass;
    };

    match auth.bootstrap_admin(UserName::new(username.clone()).unwrap(), password) {
        Ok(_) => eprintln!("admin account '{}' created\n", username),
        Err(err) => {
            eprintln!("error creating admin account: {err}");
            std::process::exit(1);
        }
    }
}

fn create_admin_interactive(data_root: &str) {
    let auth = LocalAuthStore::new(PathBuf::from(data_root));
    match auth.has_users() {
        Ok(true) => {
            eprintln!("an admin account already exists — use the web UI to manage accounts");
            return;
        }
        Ok(false) => {}
        Err(err) => {
            eprintln!("error checking database: {err}");
            std::process::exit(1);
        }
    }

    if !atty::is(atty::Stream::Stdin) {
        eprintln!("error: create-admin requires an interactive terminal");
        std::process::exit(1);
    }

    eprintln!();
    eprintln!("Create the initial admin account.");
    eprintln!();

    let username = {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        loop {
            eprint!("Admin username: ");
            io::stderr().flush().ok();
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                eprintln!("aborted");
                std::process::exit(1);
            }
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                break trimmed;
            }
            eprintln!("username cannot be empty");
        }
    };

    let password = loop {
        eprint!("Admin password: ");
        io::stderr().flush().ok();
        let pass = read_password_no_echo();
        if pass.is_empty() {
            eprintln!("aborted");
            std::process::exit(1);
        }
        if pass.len() < 12 {
            eprintln!("password must be at least 12 characters");
            continue;
        }
        eprint!("Confirm password: ");
        io::stderr().flush().ok();
        let confirm = read_password_no_echo();
        if pass != confirm {
            eprintln!("passwords do not match — try again");
            continue;
        }
        break pass;
    };

    match auth.bootstrap_admin(UserName::new(username.clone()).unwrap(), password) {
        Ok(_) => eprintln!(
            "admin account '{}' created — you can now start the server\n",
            username
        ),
        Err(err) => {
            eprintln!("error creating admin account: {err}");
            std::process::exit(1);
        }
    }
}

fn allow_login_bypass(data_root: &str, username: &str, ttl: &str) {
    let auth = LocalAuthStore::new(PathBuf::from(data_root));
    let ttl = match parse_ttl(ttl) {
        Ok(ttl) => ttl,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };
    let username = match UserName::new(username.to_string()) {
        Ok(username) => username,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };
    match auth.grant_login_bypass(&username, ttl) {
        Ok(expires_at) => {
            eprintln!(
                "allowed one correct-password browser login for '{}' until {}; IP and passkey restrictions will be bypassed for that login",
                username.as_str(),
                expires_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| "unknown".to_string())
            );
        }
        Err(err) => {
            eprintln!("error granting login bypass: {err}");
            std::process::exit(1);
        }
    }
}

fn allow_login_bypass_interactive(data_root: &str, user: Option<String>, minutes: Option<u64>) {
    let username = match user {
        Some(user) if !user.trim().is_empty() => user.trim().to_string(),
        _ => prompt_required("What user: "),
    };
    let minutes = match minutes {
        Some(minutes) if minutes > 0 => minutes,
        _ => loop {
            let value = prompt_required("How many minutes: ");
            match value.trim().parse::<u64>() {
                Ok(minutes) if minutes > 0 => break minutes,
                _ => eprintln!("minutes must be a positive number"),
            }
        },
    };
    allow_login_bypass(data_root, &username, &format!("{minutes}m"));
}

fn prompt_required(prompt: &str) -> String {
    if !atty::is(atty::Stream::Stdin) {
        eprintln!("error: this command requires an interactive terminal or explicit arguments");
        std::process::exit(1);
    }
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
        eprint!("{prompt}");
        io::stderr().flush().ok();
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            eprintln!("aborted");
            std::process::exit(1);
        }
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
        eprintln!("value cannot be empty");
    }
}

fn parse_ttl(value: &str) -> lore_core::Result<std::time::Duration> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(lore_core::LoreError::Validation(
            "ttl cannot be empty".into(),
        ));
    }
    let (number, multiplier) = match trimmed.chars().last().unwrap() {
        's' | 'S' => (&trimmed[..trimmed.len() - 1], 1),
        'm' | 'M' => (&trimmed[..trimmed.len() - 1], 60),
        'h' | 'H' => (&trimmed[..trimmed.len() - 1], 60 * 60),
        ch if ch.is_ascii_digit() => (trimmed, 1),
        _ => {
            return Err(lore_core::LoreError::Validation(
                "ttl must end with s, m, h, or be seconds".into(),
            ));
        }
    };
    let amount = number
        .parse::<u64>()
        .map_err(|_| lore_core::LoreError::Validation("ttl amount must be a number".into()))?;
    if amount == 0 {
        return Err(lore_core::LoreError::Validation(
            "ttl must be positive".into(),
        ));
    }
    let seconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| lore_core::LoreError::Validation("ttl is too large".into()))?;
    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(unix)]
fn read_password_no_echo() -> String {
    let stdin_fd = io::stdin().as_raw_fd();
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    let has_termios = unsafe { libc::tcgetattr(stdin_fd, termios.as_mut_ptr()) } == 0;
    let original = if has_termios {
        let t = unsafe { termios.assume_init() };
        let mut noecho = t;
        noecho.c_lflag &= !libc::ECHO;
        unsafe {
            libc::tcsetattr(stdin_fd, libc::TCSANOW, &noecho);
        }
        Some(t)
    } else {
        None
    };

    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);

    if let Some(orig) = original {
        unsafe {
            libc::tcsetattr(stdin_fd, libc::TCSANOW, &orig);
        }
    }
    eprintln!();
    line.trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string()
}

#[cfg(windows)]
fn read_password_no_echo() -> String {
    unsafe extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> isize;
        fn GetConsoleMode(hConsoleHandle: isize, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: isize, dwMode: u32) -> i32;
    }
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        GetConsoleMode(handle, &mut mode);
        SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT);
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        SetConsoleMode(handle, mode);
        eprintln!();
        line.trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string()
    }
}

async fn run_server(data_root: String, bind: String) {
    let data_root_path = PathBuf::from(&data_root);

    if env::var_os(SELF_UPDATE_SKIP_ENV).is_none() {
        if let Err(err) = maybe_update_server(&data_root_path).await {
            eprintln!("warning: server self-update check failed: {err}");
        }
    }

    let store = FileBlockStore::new(data_root.clone());
    if let Ok(infos) = store.list_project_infos() {
        for info in &infos {
            if let Err(e) = store.migrate_project_to_documents(&info.slug) {
                eprintln!("warning: migration failed for {}: {e}", info.slug.as_str());
            }
        }
    }
    // Sync project directory names with display names
    let renames = store.sync_project_slugs();
    if !renames.is_empty() {
        let auth = LocalAuthStore::new(data_root_path.clone());
        for (old_slug, new_slug) in &renames {
            eprintln!(
                "synced project slug: '{}' -> '{}'",
                old_slug.as_str(),
                new_slug.as_str()
            );
            if let Err(e) = auth.rename_project_in_grants(old_slug, new_slug) {
                eprintln!("warning: failed to update grants for rename: {e}");
            }
        }
    }
    let app = build_app(store);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|err| panic!("failed to bind {bind}: {err}"));

    let addr: SocketAddr = listener.local_addr().expect("listener has local address");
    eprintln!("lore-server listening on http://{addr}");
    eprintln!("data directory: {data_root}");
    axum::serve(listener, app)
        .await
        .expect("server exited with error");
}

// --- system service management (systemd) ---

const SYSTEM_UNIT_DIR: &str = "/etc/systemd/system";

fn system_unit_path(name: &str) -> PathBuf {
    PathBuf::from(SYSTEM_UNIT_DIR).join(format!("{name}.service"))
}

fn sudoers_path() -> PathBuf {
    PathBuf::from("/etc/sudoers.d").join(SUDOERS_FILE_NAME)
}

fn sudo_write_file(path: &PathBuf, content: &str) -> bool {
    let mut child = match std::process::Command::new("sudo")
        .args(["tee", &path.to_string_lossy()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(content.as_bytes());
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn sudo_systemctl(args: &[&str]) -> bool {
    std::process::Command::new("sudo")
        .arg("systemctl")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn sudo_rm(path: &PathBuf) -> bool {
    std::process::Command::new("sudo")
        .args(["rm", "-f", &path.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn find_command_path(command: &str) -> Option<String> {
    let output = std::process::Command::new("which")
        .arg(command)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn restart_sudoers_content(user: &str, systemctl: &str, include_caddy: bool) -> String {
    let mut commands = vec![
        format!("{systemctl} restart {SERVICE_NAME}"),
        format!("{systemctl} start {SERVICE_NAME}"),
    ];
    if include_caddy {
        commands.push(format!("{systemctl} restart {CADDY_SERVICE_NAME}"));
        commands.push(format!("{systemctl} start {CADDY_SERVICE_NAME}"));
    }
    commands.push(format!("{systemctl} daemon-reload"));
    format!("{user} ALL=(root) NOPASSWD: {}\n", commands.join(", "))
}

fn install_restart_sudoers(user: &str, include_caddy: bool) -> bool {
    let systemctl = find_command_path("systemctl").unwrap_or_else(|| "/bin/systemctl".to_string());
    let sudoers = restart_sudoers_content(user, &systemctl, include_caddy);
    let path = sudoers_path();
    if !sudo_write_file(&path, &sudoers) {
        return false;
    }
    std::process::Command::new("sudo")
        .args(["chmod", "0440", &path.to_string_lossy()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn remove_restart_sudoers() {
    let path = sudoers_path();
    if path.exists() && sudo_rm(&path) {
        eprintln!("removed {}", path.display());
    }
}

fn current_username() -> String {
    env::var("USER").unwrap_or_else(|_| {
        String::from_utf8_lossy(
            &std::process::Command::new("whoami")
                .output()
                .map(|o| o.stdout)
                .unwrap_or_default(),
        )
        .trim()
        .to_string()
    })
}

fn migrate_user_services() {
    let user_unit_dir = if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("systemd").join("user")
    } else {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user")
    };

    let old_lore = user_unit_dir.join(format!("{SERVICE_NAME}.service"));
    let old_caddy = user_unit_dir.join(format!("{CADDY_SERVICE_NAME}.service"));

    if !old_lore.exists() && !old_caddy.exists() {
        return;
    }

    eprintln!("migrating from user-level services to system services...");
    if old_caddy.exists() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", CADDY_SERVICE_NAME])
            .status();
        let _ = fs::remove_file(&old_caddy);
    }
    if old_lore.exists() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", SERVICE_NAME])
            .status();
        let _ = fs::remove_file(&old_lore);
    }
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    eprintln!("old user services removed");
}

fn lore_systemd_unit(user: &str, exe: &Path, data_dir: &Path, bind: &str) -> String {
    format!(
        "\
[Unit]
Description=Lore knowledge server
After=network.target

[Service]
Type=simple
User={user}
ExecStart={exe} --data-dir {data_dir} --bind {bind} start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
",
        exe = exe.display(),
        data_dir = data_dir.display(),
    )
}

fn caddy_systemd_unit(user: &str, caddy: &Path, data_dir: &Path) -> String {
    format!(
        "\
[Unit]
Description=Caddy reverse proxy for Lore
After=network.target {SERVICE_NAME}.service
Wants={SERVICE_NAME}.service

[Service]
Type=simple
User={user}
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart={caddy} run --config {caddyfile}
Environment=XDG_DATA_HOME={caddy_data}
Environment=XDG_CONFIG_HOME={caddy_config}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
",
        caddy = caddy.display(),
        caddyfile = data_dir.join("Caddyfile").display(),
        caddy_data = data_dir.join("caddy-data").display(),
        caddy_config = data_dir.join("caddy-config").display(),
    )
}

fn daemon_install(data_root: &str, bind: &str, domain: &str, manage_caddy: bool) {
    let exe = env::current_exe().unwrap_or_else(|err| {
        eprintln!("error: cannot determine executable path: {err}");
        std::process::exit(1);
    });

    let data_root_abs = fs::canonicalize(data_root).unwrap_or_else(|_| {
        let p = PathBuf::from(data_root);
        if p.is_absolute() {
            p
        } else {
            env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(p)
        }
    });

    let user = current_username();

    let config_store = ServerConfigStore::new(&data_root_abs, bind_port(bind));
    let default_theme = config_store
        .load()
        .map(|config| config.default_theme)
        .unwrap_or(UiTheme::Parchment);
    if let Err(err) = config_store.update(
        ExternalScheme::Https,
        domain.to_string(),
        443,
        default_theme,
    ) {
        eprintln!("warning: could not save public setup address: {err}");
    }

    // --- migrate from old user-level services if present ---
    migrate_user_services();

    let caddy_path = if manage_caddy {
        // --- download caddy ---
        Some(match find_caddy_binary() {
            Some(path) => {
                eprintln!("found caddy at {}", path.display());
                path
            }
            None => {
                eprintln!("caddy not found, downloading...");
                download_caddy().unwrap_or_else(|err| {
                    eprintln!("error: {err}");
                    std::process::exit(1);
                })
            }
        })
    } else {
        eprintln!("external proxy mode: skipping Lore-managed Caddy install");
        None
    };

    if manage_caddy {
        // --- write Caddyfile (user-writable data dir) ---
        write_caddyfile(data_root, domain, bind);
        let _ = fs::create_dir_all(data_root_abs.join("caddy-data"));
        let _ = fs::create_dir_all(data_root_abs.join("caddy-config"));
    }

    // --- install system services (requires sudo) ---
    eprintln!();
    eprintln!("installing system services (requires sudo)...");

    let lore_unit = lore_systemd_unit(&user, &exe, &data_root_abs, bind);

    let caddy_unit = caddy_path
        .as_ref()
        .map(|caddy_path| caddy_systemd_unit(&user, caddy_path, &data_root_abs));

    let lore_unit_path = system_unit_path(SERVICE_NAME);
    let caddy_unit_path = system_unit_path(CADDY_SERVICE_NAME);

    if !sudo_write_file(&lore_unit_path, &lore_unit) {
        eprintln!(
            "error: could not write {} (is sudo available?)",
            lore_unit_path.display()
        );
        std::process::exit(1);
    }
    println!("wrote {}", lore_unit_path.display());

    if let Some(caddy_unit) = &caddy_unit {
        if !sudo_write_file(&caddy_unit_path, caddy_unit) {
            eprintln!("error: could not write {}", caddy_unit_path.display());
            std::process::exit(1);
        }
        println!("wrote {}", caddy_unit_path.display());
    } else {
        println!("skipped {}", caddy_unit_path.display());
        if caddy_unit_path.exists() {
            eprintln!(
                "warning: existing {} remains installed; --no-caddy did not modify it",
                caddy_unit_path.display()
            );
        }
    }

    if install_restart_sudoers(&user, manage_caddy) {
        println!("wrote {}", sudoers_path().display());
    } else {
        eprintln!("warning: could not write {}", sudoers_path().display());
        eprintln!("future lore-server update runs may still prompt for sudo");
    }

    sudo_systemctl(&["daemon-reload"]);

    if sudo_systemctl(&["enable", "--now", SERVICE_NAME]) {
        println!("lore-server started");
    } else {
        eprintln!("warning: could not start lore-server service");
    }

    if manage_caddy {
        if sudo_systemctl(&["enable", "--now", CADDY_SERVICE_NAME]) {
            println!("caddy started");
        } else {
            eprintln!("warning: could not start caddy service");
        }
    }

    println!();
    println!("lore installed:");
    println!("  server:    http://{bind} (local only)");
    if manage_caddy {
        println!("  public:    https://{domain}");
    } else {
        println!("  public:    https://{domain} (after you wire your external proxy)");
    }
    println!("  data:      {}", data_root_abs.display());
    if !manage_caddy {
        println!();
        println!("add this Caddy site block to your existing Caddyfile:");
        println!();
        print!("{}", caddy_reverse_proxy_block(domain, bind));
    }
    println!();
    println!("useful commands:");
    println!("  lore-server status");
    println!("  lore-server uninstall");
    println!("  lore-server update");
    println!();
    if manage_caddy {
        println!("future lore-server update runs can restart services without another sudo prompt");
    } else {
        println!(
            "future lore-server update runs can restart lore-server without another sudo prompt"
        );
    }
}

fn daemon_uninstall(data_root: &str) {
    eprintln!("stopping and removing services (requires sudo)...");

    // Stop and remove caddy service
    let caddy_unit = system_unit_path(CADDY_SERVICE_NAME);
    if caddy_unit.exists() {
        sudo_systemctl(&["disable", "--now", CADDY_SERVICE_NAME]);
        if sudo_rm(&caddy_unit) {
            println!("removed {}", caddy_unit.display());
        }
    }

    // Remove Caddyfile and caddy dirs
    let data_path = PathBuf::from(data_root);
    for name in ["Caddyfile", "caddy-data", "caddy-config"] {
        let p = data_path.join(name);
        if p.is_dir() {
            let _ = fs::remove_dir_all(&p);
        } else if p.is_file() {
            let _ = fs::remove_file(&p);
        }
    }

    // Remove caddy binary
    let caddy_bin = local_bin_dir().join("caddy");
    if caddy_bin.exists() {
        let _ = fs::remove_file(&caddy_bin);
    }

    // Stop and remove lore-server service
    let lore_unit = system_unit_path(SERVICE_NAME);
    if lore_unit.exists() {
        sudo_systemctl(&["disable", "--now", SERVICE_NAME]);
        if sudo_rm(&lore_unit) {
            println!("removed {}", lore_unit.display());
        }
    } else {
        println!("no service file found");
    }

    remove_restart_sudoers();
    sudo_systemctl(&["daemon-reload"]);

    println!("uninstalled (data preserved in {data_root})");
}

fn daemon_status(data_root: &str) {
    let lore_unit = system_unit_path(SERVICE_NAME);
    if !lore_unit.exists() {
        println!("lore is not installed");
        println!("run: lore-server install");
        return;
    }

    // Show domain if configured
    let caddyfile = PathBuf::from(data_root).join("Caddyfile");
    if caddyfile.exists() {
        if let Ok(content) = fs::read_to_string(&caddyfile) {
            if let Some(domain) = content.split_whitespace().next() {
                println!("domain: {domain}");
                println!();
            }
        }
    }

    let _ = std::process::Command::new("systemctl")
        .args(["status", SERVICE_NAME])
        .status();

    let caddy_unit = system_unit_path(CADDY_SERVICE_NAME);
    if caddy_unit.exists() {
        println!();
        let _ = std::process::Command::new("systemctl")
            .args(["status", CADDY_SERVICE_NAME])
            .status();
    }
}

fn local_bin_dir() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local").join("bin")
}

fn find_caddy_binary() -> Option<PathBuf> {
    let local = local_bin_dir().join("caddy");
    if local.exists() {
        return Some(local);
    }
    let output = std::process::Command::new("which")
        .arg("caddy")
        .output()
        .ok()?;
    if output.status.success() {
        Some(PathBuf::from(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ))
    } else {
        None
    }
}

fn download_caddy() -> Result<PathBuf, String> {
    let caddy_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => return Err(format!("unsupported architecture: {other}")),
    };
    let caddy_os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => return Err(format!("unsupported os: {other}")),
    };

    eprintln!("fetching latest caddy version...");
    let output = std::process::Command::new("curl")
        .args([
            "-fsSLI",
            "-o",
            "/dev/null",
            "-w",
            "%{url_effective}",
            "https://github.com/caddyserver/caddy/releases/latest",
        ])
        .output()
        .map_err(|e| format!("curl failed: {e}"))?;

    let effective_url = String::from_utf8_lossy(&output.stdout);
    let tag = effective_url
        .trim()
        .rsplit('/')
        .next()
        .ok_or("could not determine latest caddy version")?
        .to_string();
    let version = tag.trim_start_matches('v');

    let filename = format!("caddy_{version}_{caddy_os}_{caddy_arch}.tar.gz");
    let url = format!("https://github.com/caddyserver/caddy/releases/download/{tag}/{filename}");

    let dest_dir = local_bin_dir();
    fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("cannot create {}: {e}", dest_dir.display()))?;
    let dest = dest_dir.join("caddy");

    eprintln!("downloading caddy {tag}...");
    let status = std::process::Command::new("sh")
        .args([
            "-c",
            &format!(
                "TMP=$(mktemp -d) && curl -fsSL '{}' | tar xz -C \"$TMP\" caddy && mv \"$TMP/caddy\" '{}' && chmod +x '{}' && rm -rf \"$TMP\"",
                url,
                dest.display(),
                dest.display()
            ),
        ])
        .status()
        .map_err(|e| format!("download failed: {e}"))?;

    if !status.success() {
        return Err("failed to download caddy".into());
    }

    eprintln!("installed caddy {tag} to {}", dest.display());
    Ok(dest)
}

fn caddy_reverse_proxy_block(domain: &str, bind: &str) -> String {
    format!("{domain} {{\n    reverse_proxy {bind}\n}}\n")
}

fn bind_port(bind: &str) -> u16 {
    bind.rsplit(':')
        .next()
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(7043)
}

fn write_caddyfile(data_root: &str, domain: &str, bind: &str) -> PathBuf {
    let caddyfile_path = PathBuf::from(data_root).join("Caddyfile");
    let content = caddy_reverse_proxy_block(domain, bind);
    fs::write(&caddyfile_path, content).unwrap_or_else(|err| {
        eprintln!("error: cannot write {}: {err}", caddyfile_path.display());
        std::process::exit(1);
    });
    println!("wrote {}", caddyfile_path.display());
    caddyfile_path
}

fn prompt_domain() -> String {
    if !atty::is(atty::Stream::Stdin) {
        eprintln!("error: --domain is required when stdin is not a terminal");
        eprintln!("usage: lore-server install --domain yourdomain.com");
        std::process::exit(1);
    }
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
        eprint!("Domain name (e.g. lore.example.com): ");
        io::stderr().flush().ok();
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            eprintln!("aborted");
            std::process::exit(1);
        }
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            eprintln!("domain cannot be empty");
            continue;
        }
        if !trimmed.contains('.') {
            eprintln!("that doesn't look like a domain name — try again");
            continue;
        }
        return trimmed;
    }
}

// --- self-update ---

async fn maybe_update_server(data_root: &PathBuf) -> lore_core::Result<()> {
    let update_config = AutoUpdateConfigStore::new(data_root.clone()).load()?;
    if !update_config.enabled {
        return Ok(());
    }
    let status_store = AutoUpdateStatusStore::new(data_root.clone());
    let executable_path = env::current_exe().map_err(lore_core::LoreError::Io)?;
    let client = reqwest::Client::new();
    match maybe_apply_self_update(
        &client,
        "lore-server",
        env!("CARGO_PKG_VERSION"),
        &update_config.github_repo,
        update_config.release_stream,
        &executable_path,
    )
    .await
    {
        Ok(outcome) => {
            let status = match outcome {
                lore_core::SelfUpdateOutcome::UpToDate(status) => status,
                lore_core::SelfUpdateOutcome::Updated(status) => {
                    status_store.save(&status)?;
                    if let Err(err) = relaunch_current_process(&executable_path) {
                        let detail = format!(
                            "{}; restart failed: {err}; leaving current process running",
                            status.detail
                        );
                        let failed_status = AutoUpdateStatus {
                            checked_at: time::OffsetDateTime::now_utc(),
                            current_version: status.current_version.clone(),
                            latest_version: status.latest_version.clone(),
                            detail,
                            applied: true,
                            ok: false,
                        };
                        status_store.save(&failed_status)?;
                        return Err(lore_core::LoreError::ExternalService(failed_status.detail));
                    }
                    return Ok(());
                }
            };
            status_store.save(&status)?;
        }
        Err(err) => {
            status_store.save(&AutoUpdateStatus {
                checked_at: time::OffsetDateTime::now_utc(),
                current_version: env!("CARGO_PKG_VERSION").to_string(),
                latest_version: None,
                detail: format!(
                    "auto-update failed against {} ({}) : {err}",
                    if update_config.github_repo.is_empty() {
                        DEFAULT_UPDATE_REPO
                    } else {
                        &update_config.github_repo
                    },
                    update_config.release_stream.as_str(),
                ),
                applied: false,
                ok: false,
            })?;
        }
    }
    Ok(())
}

fn relaunch_current_process(executable_path: &Path) -> std::result::Result<(), String> {
    if server_systemd_unit_exists() {
        match restart_server_via_systemd() {
            Ok(()) => std::process::exit(0),
            Err(err) => {
                eprintln!(
                    "warning: systemd restart failed after self-update: {err}; not falling back to unmanaged exec"
                );
                return Err(err.to_string());
            }
        }
    }
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let mut command = std::process::Command::new(executable_path);
    command.args(args);
    command.env(SELF_UPDATE_SKIP_ENV, "1");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = command.exec();
        Err(format!("failed to relaunch updated server: {err}"))
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = command.spawn() {
            return Err(format!("failed to relaunch updated server: {err}"));
        }
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_command_accepts_no_caddy_external_proxy_mode() {
        let cli = Cli::try_parse_from([
            "lore-server",
            "install",
            "--domain",
            "lore.armino.me",
            "--no-caddy",
        ])
        .expect("install --no-caddy should parse");

        match cli.command.expect("subcommand") {
            ServerCommand::Install { domain, no_caddy } => {
                assert_eq!(domain.as_deref(), Some("lore.armino.me"));
                assert!(no_caddy);
            }
            _ => panic!("expected install command"),
        }
    }

    #[test]
    fn external_proxy_caddy_snippet_points_at_configured_bind() {
        assert_eq!(
            caddy_reverse_proxy_block("lore.armino.me", "127.0.0.1:7043"),
            "lore.armino.me {\n    reverse_proxy 127.0.0.1:7043\n}\n"
        );
    }

    #[test]
    fn managed_caddy_unit_does_not_bind_proxy_lifetime_to_lore_server() {
        let unit = caddy_systemd_unit(
            "lore",
            Path::new("/home/lore/.local/bin/caddy"),
            Path::new("/home/lore/lore"),
        );
        assert!(unit.contains("After=network.target lore-server.service"));
        assert!(unit.contains("Wants=lore-server.service"));
        assert!(!unit.contains("BindsTo="));
    }

    #[test]
    fn bind_port_reads_trailing_port() {
        assert_eq!(bind_port("127.0.0.1:7043"), 7043);
        assert_eq!(bind_port("[::1]:8123"), 8123);
        assert_eq!(bind_port("bad"), 7043);
    }

    #[test]
    fn no_caddy_sudoers_rule_excludes_lore_caddy_restart() {
        let sudoers = restart_sudoers_content("lore", "/usr/bin/systemctl", false);
        assert!(sudoers.contains("/usr/bin/systemctl restart lore-server"));
        assert!(sudoers.contains("/usr/bin/systemctl start lore-server"));
        assert!(sudoers.contains("/usr/bin/systemctl daemon-reload"));
        assert!(!sudoers.contains("lore-caddy"));
    }

    #[test]
    fn managed_caddy_sudoers_rule_includes_lore_caddy_restart() {
        let sudoers = restart_sudoers_content("lore", "/usr/bin/systemctl", true);
        assert!(sudoers.contains("/usr/bin/systemctl restart lore-server"));
        assert!(sudoers.contains("/usr/bin/systemctl start lore-server"));
        assert!(sudoers.contains("/usr/bin/systemctl restart lore-caddy"));
        assert!(sudoers.contains("/usr/bin/systemctl start lore-caddy"));
        assert!(sudoers.contains("/usr/bin/systemctl daemon-reload"));
    }
}
