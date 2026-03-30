use clap::{Parser, Subcommand};
use lore_core::{
    AutoUpdateConfigStore, AutoUpdateStatus, AutoUpdateStatusStore, DEFAULT_UPDATE_REPO,
    FileBlockStore, LocalAuthStore, UserName, build_app, maybe_apply_self_update,
};
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

const SELF_UPDATE_SKIP_ENV: &str = "LORE_SKIP_SELF_UPDATE";
const SERVICE_NAME: &str = "lore-server";
const CADDY_SERVICE_NAME: &str = "lore-caddy";

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
    /// Install lore-server and Caddy HTTPS proxy as system daemons
    Install {
        /// Domain name for HTTPS (e.g. lore.example.com) — prompted if not given
        #[arg(long)]
        domain: Option<String>,
    },
    /// Remove lore-server and Caddy daemons
    Uninstall,
    /// Show daemon status
    Status,
    /// Update lore-server to the latest release
    Update,
    /// Remove all services and binaries but keep data (for a fresh reinstall)
    Clean,
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
        ServerCommand::Install { domain } => {
            ensure_data_dir(&data_root);
            prompt_initial_admin_if_needed(&data_root);
            let domain = domain.unwrap_or_else(|| prompt_domain());
            daemon_install(&data_root, &bind, &domain);
        }
        ServerCommand::Uninstall => daemon_uninstall(&data_root),
        ServerCommand::Status => daemon_status(&data_root),
        ServerCommand::Update => run_update(),
        ServerCommand::Clean => run_clean(&data_root),
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

    // Only prompt if we have a tty
    if !atty::is(atty::Stream::Stdin) {
        eprintln!("no admin account exists — visit the web UI to create one");
        return;
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

async fn run_server(data_root: String, bind: String) {
    let data_root_path = PathBuf::from(&data_root);

    if env::var_os(SELF_UPDATE_SKIP_ENV).is_none() {
        if let Err(err) = maybe_update_server(&data_root_path).await {
            eprintln!("warning: server self-update check failed: {err}");
        }
    }

    let store = FileBlockStore::new(data_root.clone());
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

fn daemon_install(data_root: &str, bind: &str, domain: &str) {
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

    // --- migrate from old user-level services if present ---
    migrate_user_services();

    // --- download caddy ---
    let caddy_path = match find_caddy_binary() {
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
    };

    // --- write Caddyfile (user-writable data dir) ---
    write_caddyfile(data_root, domain);
    let _ = fs::create_dir_all(data_root_abs.join("caddy-data"));
    let _ = fs::create_dir_all(data_root_abs.join("caddy-config"));

    // --- install system services (requires sudo) ---
    eprintln!();
    eprintln!("installing system services (requires sudo)...");

    let lore_unit = format!(
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
        data_dir = data_root_abs.display(),
    );

    let caddy_unit = format!(
        "\
[Unit]
Description=Caddy reverse proxy for Lore
After=network.target {SERVICE_NAME}.service
BindsTo={SERVICE_NAME}.service

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
        caddy = caddy_path.display(),
        caddyfile = data_root_abs.join("Caddyfile").display(),
        caddy_data = data_root_abs.join("caddy-data").display(),
        caddy_config = data_root_abs.join("caddy-config").display(),
    );

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

    if !sudo_write_file(&caddy_unit_path, &caddy_unit) {
        eprintln!("error: could not write {}", caddy_unit_path.display());
        std::process::exit(1);
    }
    println!("wrote {}", caddy_unit_path.display());

    sudo_systemctl(&["daemon-reload"]);

    if sudo_systemctl(&["enable", "--now", SERVICE_NAME]) {
        println!("lore-server started");
    } else {
        eprintln!("warning: could not start lore-server service");
    }

    if sudo_systemctl(&["enable", "--now", CADDY_SERVICE_NAME]) {
        println!("caddy started");
    } else {
        eprintln!("warning: could not start caddy service");
    }

    println!();
    println!("lore installed:");
    println!("  server:    http://{bind} (local only)");
    println!("  public:    https://{domain}");
    println!("  data:      {}", data_root_abs.display());
    println!();
    println!("useful commands:");
    println!("  lore-server status");
    println!("  lore-server uninstall");
    println!("  lore-server update");
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

fn write_caddyfile(data_root: &str, domain: &str) -> PathBuf {
    let caddyfile_path = PathBuf::from(data_root).join("Caddyfile");
    let content = format!("{domain} {{\n    reverse_proxy 127.0.0.1:7043\n}}\n");
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
        eprintln!("usage: lore-server caddy-install --domain yourdomain.com");
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
        &executable_path,
    )
    .await
    {
        Ok(outcome) => {
            let status = match outcome {
                lore_core::SelfUpdateOutcome::UpToDate(status) => status,
                lore_core::SelfUpdateOutcome::Updated(status) => {
                    status_store.save(&status)?;
                    relaunch_current_process(&executable_path);
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
                    "auto-update failed against {}: {err}",
                    if update_config.github_repo.is_empty() {
                        DEFAULT_UPDATE_REPO
                    } else {
                        &update_config.github_repo
                    }
                ),
                applied: false,
                ok: false,
            })?;
        }
    }
    Ok(())
}

fn relaunch_current_process(executable_path: &std::path::Path) {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let mut command = std::process::Command::new(executable_path);
    command.args(args);
    command.env(SELF_UPDATE_SKIP_ENV, "1");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = command.exec();
        eprintln!("warning: failed to relaunch updated server: {err}");
        std::process::exit(0);
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = command.spawn() {
            eprintln!("warning: failed to relaunch updated server: {err}");
        }
        std::process::exit(0);
    }
}
