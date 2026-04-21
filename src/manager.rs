use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use time::OffsetDateTime;

pub const MANAGER_DELAY_PREFIX: &str = "WAIT_FOR_SECONDS:";
pub const MAX_MANAGER_DELAY_SECONDS: u64 = 10 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerPromptStage {
    ReviewLatestOutput,
    RunPeriodicChecks,
    ValidatePeriodicChecks,
}

impl ManagerPromptStage {
    pub fn default_text(self) -> &'static str {
        match self {
            Self::ReviewLatestOutput => {
                "Review the agent's latest output and decide the next thing the agent should do. \
Respond as direct instructions to the agent. \
Do not ask the user for input. \
If the agent is waiting on a known long-running task, you may prefix your response with WAIT_FOR_SECONDS: <1-600> on the first line, then put the delayed instruction below it. \
If the agent is on track, briefly confirm that and tell it the next concrete step."
            }
            Self::RunPeriodicChecks => {
                "It's time for periodic checks. Ask the agent to verify the items listed above. \
Frame your message as direct instructions to the agent. \
If the checks are known to take a while, you may prefix your response with WAIT_FOR_SECONDS: <1-600> on the first line, then put the delayed instruction below it. \
Do not ask the user for input."
            }
            Self::ValidatePeriodicChecks => {
                "The agent just ran periodic checks. Validate the results. \
If anything looks wrong, flag it. Then tell the agent exactly what to do next. \
If the agent now needs to wait on a known long-running task, you may prefix your response with WAIT_FOR_SECONDS: <1-600> on the first line, then put the delayed instruction below it. \
Do not ask the user for input."
            }
        }
    }
}

pub fn extract_manager_delay_prefix(content: &str) -> (Option<u64>, String) {
    let trimmed = content.trim_start();
    let Some(first_line_end) = trimmed.find('\n') else {
        return parse_delay_line(trimmed, "");
    };
    let (first_line, rest) = trimmed.split_at(first_line_end);
    parse_delay_line(first_line, rest.trim_start_matches('\n'))
}

fn parse_delay_line(first_line: &str, rest: &str) -> (Option<u64>, String) {
    let Some(raw_delay) = first_line.strip_prefix(MANAGER_DELAY_PREFIX) else {
        return (
            None,
            first_line.to_string() + if rest.is_empty() { "" } else { "\n" } + rest,
        );
    };
    let Ok(delay_seconds) = raw_delay.trim().parse::<u64>() else {
        return (
            None,
            first_line.to_string() + if rest.is_empty() { "" } else { "\n" } + rest,
        );
    };
    if delay_seconds == 0 || delay_seconds > MAX_MANAGER_DELAY_SECONDS {
        return (
            None,
            first_line.to_string() + if rest.is_empty() { "" } else { "\n" } + rest,
        );
    }
    let delayed_message = rest.trim().to_string();
    if delayed_message.is_empty() {
        return (
            None,
            first_line.to_string() + if rest.is_empty() { "" } else { "\n" } + rest,
        );
    }
    (Some(delay_seconds), delayed_message)
}

pub fn describe_manager_delay(delay_seconds: u64) -> String {
    let minutes = delay_seconds / 60;
    let seconds = delay_seconds % 60;
    match (minutes, seconds) {
        (0, s) => format!("Pausing for {s}s before the next manager instruction"),
        (m, 0) => format!("Pausing for {m}m before the next manager instruction"),
        (m, s) => format!("Pausing for {m}m {s}s before the next manager instruction"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagerPromptOverride {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub text: String,
}

impl Default for ManagerPromptOverride {
    fn default() -> Self {
        Self {
            enabled: false,
            text: String::new(),
        }
    }
}

impl ManagerPromptOverride {
    pub fn resolved_text(&self, stage: ManagerPromptStage) -> String {
        if self.enabled {
            let trimmed = self.text.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        stage.default_text().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagerPromptConfig {
    #[serde(default)]
    pub review_latest_output: ManagerPromptOverride,
    #[serde(default)]
    pub run_periodic_checks: ManagerPromptOverride,
    #[serde(default)]
    pub validate_periodic_checks: ManagerPromptOverride,
    pub updated_at: OffsetDateTime,
}

impl Default for ManagerPromptConfig {
    fn default() -> Self {
        Self {
            review_latest_output: ManagerPromptOverride::default(),
            run_periodic_checks: ManagerPromptOverride::default(),
            validate_periodic_checks: ManagerPromptOverride::default(),
            updated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl ManagerPromptConfig {
    pub fn new(
        review_latest_output: ManagerPromptOverride,
        run_periodic_checks: ManagerPromptOverride,
        validate_periodic_checks: ManagerPromptOverride,
    ) -> Self {
        Self {
            review_latest_output,
            run_periodic_checks,
            validate_periodic_checks,
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn prompt_for_stage(&self, stage: ManagerPromptStage) -> String {
        match stage {
            ManagerPromptStage::ReviewLatestOutput => {
                self.review_latest_output.resolved_text(stage)
            }
            ManagerPromptStage::RunPeriodicChecks => self.run_periodic_checks.resolved_text(stage),
            ManagerPromptStage::ValidatePeriodicChecks => {
                self.validate_periodic_checks.resolved_text(stage)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagerPromptConfigStore {
    root: PathBuf,
}

impl ManagerPromptConfigStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load(&self) -> Result<ManagerPromptConfig> {
        let path = self.config_path();
        if path.exists() {
            return Ok(serde_json::from_slice(&fs::read(path)?)?);
        }
        Ok(ManagerPromptConfig::default())
    }

    pub fn save(&self, config: &ManagerPromptConfig) -> Result<()> {
        self.ensure_layout()?;
        write_json_atomic(self.config_path(), config)
    }

    fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    fn config_path(&self) -> PathBuf {
        self.config_dir().join("manager-prompts.json")
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(self.config_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.config_dir(), fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

fn write_json_atomic(path: PathBuf, value: &impl Serialize) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ManagerPromptConfig, ManagerPromptConfigStore, ManagerPromptOverride, ManagerPromptStage,
        describe_manager_delay, extract_manager_delay_prefix,
    };
    use tempfile::tempdir;

    #[test]
    fn manager_prompt_config_defaults_to_builtin_stage_text() {
        let config = ManagerPromptConfig::default();
        assert_eq!(
            config.prompt_for_stage(ManagerPromptStage::ReviewLatestOutput),
            ManagerPromptStage::ReviewLatestOutput.default_text()
        );
        assert_eq!(
            config.prompt_for_stage(ManagerPromptStage::RunPeriodicChecks),
            ManagerPromptStage::RunPeriodicChecks.default_text()
        );
        assert_eq!(
            config.prompt_for_stage(ManagerPromptStage::ValidatePeriodicChecks),
            ManagerPromptStage::ValidatePeriodicChecks.default_text()
        );
    }

    #[test]
    fn manager_prompt_config_uses_custom_text_only_when_enabled() {
        let config = ManagerPromptConfig::new(
            ManagerPromptOverride {
                enabled: true,
                text: "Custom review".into(),
            },
            ManagerPromptOverride {
                enabled: false,
                text: "Ignored periodic".into(),
            },
            ManagerPromptOverride {
                enabled: true,
                text: String::new(),
            },
        );

        assert_eq!(
            config.prompt_for_stage(ManagerPromptStage::ReviewLatestOutput),
            "Custom review"
        );
        assert_eq!(
            config.prompt_for_stage(ManagerPromptStage::RunPeriodicChecks),
            ManagerPromptStage::RunPeriodicChecks.default_text()
        );
        assert_eq!(
            config.prompt_for_stage(ManagerPromptStage::ValidatePeriodicChecks),
            ManagerPromptStage::ValidatePeriodicChecks.default_text()
        );
    }

    #[test]
    fn manager_prompt_config_store_round_trips() {
        let dir = tempdir().unwrap();
        let store = ManagerPromptConfigStore::new(dir.path());
        let config = ManagerPromptConfig::new(
            ManagerPromptOverride {
                enabled: true,
                text: "Custom review".into(),
            },
            ManagerPromptOverride::default(),
            ManagerPromptOverride {
                enabled: true,
                text: "Custom validate".into(),
            },
        );

        store.save(&config).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.review_latest_output.enabled, true);
        assert_eq!(loaded.review_latest_output.text, "Custom review");
        assert_eq!(loaded.run_periodic_checks.enabled, false);
        assert_eq!(
            loaded.prompt_for_stage(ManagerPromptStage::ValidatePeriodicChecks),
            "Custom validate"
        );
    }

    #[test]
    fn manager_delay_prefix_extracts_delay_and_message() {
        let (delay, message) = extract_manager_delay_prefix(
            "WAIT_FOR_SECONDS: 180\nWait for the build to finish, then check the logs.",
        );
        assert_eq!(delay, Some(180));
        assert_eq!(
            message,
            "Wait for the build to finish, then check the logs."
        );
    }

    #[test]
    fn manager_delay_prefix_ignores_invalid_delay() {
        let (delay, message) = extract_manager_delay_prefix("WAIT_FOR_SECONDS: 999\nToo long");
        assert_eq!(delay, None);
        assert_eq!(message, "WAIT_FOR_SECONDS: 999\nToo long");
    }

    #[test]
    fn manager_delay_status_is_human_readable() {
        assert_eq!(
            describe_manager_delay(45),
            "Pausing for 45s before the next manager instruction"
        );
        assert_eq!(
            describe_manager_delay(120),
            "Pausing for 2m before the next manager instruction"
        );
    }
}
