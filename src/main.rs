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

#[derive(Parser)]
#[command(name = "lore-server")]
#[command(about = "Lore knowledge server")]
#[command(version)]
struct Cli {
    /// Data directory (default: ~/lore)
    #[arg(long, global = true)]
    data_dir: Option<String>,

    /// Bind address (default: 0.0.0.0:8080)
    #[arg(long, global = true)]
    bind: Option<String>,

    #[command(subcommand)]
    command: Option<ServerCommand>,
}

#[derive(Subcommand)]
enum ServerCommand {
    /// Start the server (default if no command given)
    Start,
    /// Install lore-server as a system daemon (systemd user service)
    #[command(name = "daemon-install")]
    DaemonInstall,
    /// Remove the lore-server daemon
    #[command(name = "daemon-uninstall")]
    DaemonUninstall,
    /// Show daemon status
    #[command(name = "daemon-status")]
    DaemonStatus,
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
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    match cli.command.unwrap_or(ServerCommand::Start) {
        ServerCommand::Start => {
            ensure_data_dir(&data_root);
            prompt_initial_admin_if_needed(&data_root);
            run_server(data_root, bind).await;
        }
        ServerCommand::DaemonInstall => {
            ensure_data_dir(&data_root);
            prompt_initial_admin_if_needed(&data_root);
            daemon_install(&data_root, &bind);
        }
        ServerCommand::DaemonUninstall => daemon_uninstall(),
        ServerCommand::DaemonStatus => daemon_status(),
    }
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

// --- daemon management (systemd user service) ---

fn systemd_unit_dir() -> PathBuf {
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("systemd").join("user")
    } else {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user")
    }
}

fn unit_file_path() -> PathBuf {
    systemd_unit_dir().join(format!("{SERVICE_NAME}.service"))
}

fn daemon_install(data_root: &str, bind: &str) {
    let exe = env::current_exe().unwrap_or_else(|err| {
        eprintln!("error: cannot determine executable path: {err}");
        std::process::exit(1);
    });

    let data_root_abs = fs::canonicalize(data_root).unwrap_or_else(|_| {
        // directory might not exist yet — resolve HOME part
        let p = PathBuf::from(data_root);
        if p.is_absolute() {
            p
        } else {
            env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(p)
        }
    });

    let unit_dir = systemd_unit_dir();
    if let Err(err) = fs::create_dir_all(&unit_dir) {
        eprintln!("error: cannot create {}: {err}", unit_dir.display());
        std::process::exit(1);
    }

    let unit_content = format!(
        "\
[Unit]
Description=Lore knowledge server
After=network.target

[Service]
Type=simple
ExecStart={exe} --data-dir {data_dir} --bind {bind} start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
",
        exe = exe.display(),
        data_dir = data_root_abs.display(),
        bind = bind,
    );

    let unit_path = unit_file_path();
    let mut f = fs::File::create(&unit_path).unwrap_or_else(|err| {
        eprintln!("error: cannot write {}: {err}", unit_path.display());
        std::process::exit(1);
    });
    f.write_all(unit_content.as_bytes()).unwrap_or_else(|err| {
        eprintln!("error: cannot write {}: {err}", unit_path.display());
        std::process::exit(1);
    });

    println!("wrote {}", unit_path.display());

    // reload and enable
    let reload = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    if let Ok(status) = reload {
        if !status.success() {
            eprintln!("warning: systemctl --user daemon-reload returned non-zero");
        }
    } else {
        eprintln!("warning: could not run systemctl --user daemon-reload");
    }

    let enable = std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", SERVICE_NAME])
        .status();
    match enable {
        Ok(status) if status.success() => {
            println!("daemon installed and started");
            println!("  data directory: {}", data_root_abs.display());
            println!("  bind address:   {bind}");
            println!();
            println!("useful commands:");
            println!("  systemctl --user status {SERVICE_NAME}");
            println!("  journalctl --user -u {SERVICE_NAME} -f");
            println!("  lore-server daemon-uninstall");
        }
        _ => {
            eprintln!("warning: could not enable the service via systemctl");
            eprintln!("you may need to run: systemctl --user enable --now {SERVICE_NAME}");
        }
    }
}

fn daemon_uninstall() {
    // stop and disable
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", SERVICE_NAME])
        .status();

    let unit_path = unit_file_path();
    if unit_path.exists() {
        if let Err(err) = fs::remove_file(&unit_path) {
            eprintln!("error: cannot remove {}: {err}", unit_path.display());
            std::process::exit(1);
        }
        println!("removed {}", unit_path.display());
    } else {
        println!("no daemon service file found");
    }

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    println!("daemon uninstalled");
}

fn daemon_status() {
    let unit_path = unit_file_path();
    if !unit_path.exists() {
        println!("daemon is not installed");
        println!("run: lore-server daemon-install");
        return;
    }

    let status = std::process::Command::new("systemctl")
        .args(["--user", "status", SERVICE_NAME])
        .status();

    match status {
        Ok(s) if !s.success() => {
            // systemctl status returns non-zero for inactive services,
            // but it still printed the output above
        }
        Err(err) => {
            eprintln!("error: could not run systemctl: {err}");
            std::process::exit(1);
        }
        _ => {}
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
