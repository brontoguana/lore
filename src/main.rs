use lore_core::{
    AutoUpdateConfigStore, AutoUpdateStatus, AutoUpdateStatusStore, DEFAULT_UPDATE_REPO,
    FileBlockStore, build_app, maybe_apply_self_update,
};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

const SELF_UPDATE_SKIP_ENV: &str = "LORE_SKIP_SELF_UPDATE";

#[tokio::main]
async fn main() {
    let data_root = env::var("LORE_DATA_ROOT").unwrap_or_else(|_| "./data".to_string());
    let bind = env::var("LORE_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let data_root_path = PathBuf::from(&data_root);

    if env::var_os(SELF_UPDATE_SKIP_ENV).is_none() {
        if let Err(err) = maybe_update_server(&data_root_path).await {
            eprintln!("warning: server self-update check failed: {err}");
        }
    }

    let store = FileBlockStore::new(data_root);
    let app = build_app(store);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|err| panic!("failed to bind {bind}: {err}"));

    let _addr: SocketAddr = listener.local_addr().expect("listener has local address");
    axum::serve(listener, app)
        .await
        .expect("server exited with error");
}

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
