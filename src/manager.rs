use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use time::OffsetDateTime;

pub const MANAGER_DELAY_PREFIX: &str = "WAIT_FOR_SECONDS:";
pub const MAX_MANAGER_DELAY_SECONDS: u64 = 10 * 60;
pub const MANAGER_STOPPING_TOKEN: &str = "STOPPING_POINT";
pub const MANAGER_RED_FLAG_TOKEN: &str = "RED_FLAG_POINT";
pub const MANAGER_CONTINUE_TOKEN: &str = "CONTINUE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerControlKind {
    Continue,
    Wait(u64),
    StoppingPoint,
    RedFlag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedManagerResponse {
    pub control: ManagerControlKind,
    pub content: String,
}

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
Use the required first-line control state from the protocol above. \
If the agent is waiting on a known long-running task, use WAIT_FOR_SECONDS with the number of seconds to wait, then put the delayed instruction below it. \
If the agent is on track, briefly confirm that and tell it the next concrete step."
            }
            Self::RunPeriodicChecks => {
                "It's time for periodic checks. Ask the agent to verify the items listed above. \
Frame your message as direct instructions to the agent. \
Use the required first-line control state from the protocol above. \
If the checks are known to take a while, use WAIT_FOR_SECONDS with the number of seconds to wait, then put the delayed instruction below it. \
Do not ask the user for input."
            }
            Self::ValidatePeriodicChecks => {
                "The agent just ran periodic checks. Validate the results. \
If anything looks wrong, flag it. Then tell the agent exactly what to do next. \
Use the required first-line control state from the protocol above. \
If the agent now needs to wait on a known long-running task, use WAIT_FOR_SECONDS with the number of seconds to wait, then put the delayed instruction below it. \
Do not ask the user for input."
            }
        }
    }
}

pub fn parse_manager_control_response(content: &str) -> ParsedManagerResponse {
    let trimmed = content.trim_start();
    if trimmed.is_empty() {
        return ParsedManagerResponse {
            control: ManagerControlKind::Continue,
            content: String::new(),
        };
    }

    let (first_line, rest) = split_first_line(trimmed);
    let first_line = first_line.trim();
    let rest = rest.trim();

    if let Some(reason) = parse_signal_line(first_line, MANAGER_STOPPING_TOKEN) {
        return ParsedManagerResponse {
            control: ManagerControlKind::StoppingPoint,
            content: join_signal_reason_and_body(reason, rest),
        };
    }
    if let Some(reason) = parse_signal_line(first_line, MANAGER_RED_FLAG_TOKEN) {
        return ParsedManagerResponse {
            control: ManagerControlKind::RedFlag,
            content: join_signal_reason_and_body(reason, rest),
        };
    }
    if let Some(raw_delay) = first_line.strip_prefix(MANAGER_DELAY_PREFIX) {
        if let Ok(delay_seconds) = raw_delay.trim().parse::<u64>() {
            if delay_seconds > 0 && delay_seconds <= MAX_MANAGER_DELAY_SECONDS && !rest.is_empty() {
                return ParsedManagerResponse {
                    control: ManagerControlKind::Wait(delay_seconds),
                    content: rest.to_string(),
                };
            }
        }
    }
    if let Some(reason) = parse_signal_line(first_line, MANAGER_CONTINUE_TOKEN) {
        let content = join_signal_reason_and_body(reason, rest);
        return ParsedManagerResponse {
            control: ManagerControlKind::Continue,
            content: if content.is_empty() {
                trimmed.trim().to_string()
            } else {
                content
            },
        };
    }

    ParsedManagerResponse {
        control: ManagerControlKind::Continue,
        content: trimmed.trim().to_string(),
    }
}

pub fn manager_response_display_content(parsed: &ParsedManagerResponse) -> String {
    match parsed.control {
        ManagerControlKind::StoppingPoint => prefix_manager_signal("\u{2705}", &parsed.content),
        ManagerControlKind::RedFlag => prefix_manager_signal("\u{1f6a9}", &parsed.content),
        ManagerControlKind::Continue | ManagerControlKind::Wait(_) => parsed.content.clone(),
    }
}

pub fn manager_control_decision_label(control: ManagerControlKind) -> String {
    match control {
        ManagerControlKind::Continue => "Continue".to_string(),
        ManagerControlKind::Wait(delay_seconds) => format!("Wait {delay_seconds}s"),
        ManagerControlKind::StoppingPoint => "Stopping Point".to_string(),
        ManagerControlKind::RedFlag => "Red Flag".to_string(),
    }
}

pub fn extract_manager_delay_prefix(content: &str) -> (Option<u64>, String) {
    let parsed = parse_manager_control_response(content);
    match parsed.control {
        ManagerControlKind::Wait(delay_seconds) => (Some(delay_seconds), parsed.content),
        _ => (None, content.trim_start().trim().to_string()),
    }
}

fn split_first_line(content: &str) -> (&str, &str) {
    if let Some(first_line_end) = content.find('\n') {
        (
            content[..first_line_end].trim_end_matches('\r'),
            &content[first_line_end + 1..],
        )
    } else {
        (content.trim_end_matches('\r'), "")
    }
}

fn parse_signal_line<'a>(first_line: &'a str, token: &str) -> Option<&'a str> {
    if first_line == token {
        Some("")
    } else {
        first_line
            .strip_prefix(token)
            .and_then(|rest| rest.strip_prefix(':'))
            .map(str::trim)
    }
}

fn join_signal_reason_and_body(reason: &str, body: &str) -> String {
    match (reason.trim().is_empty(), body.trim().is_empty()) {
        (true, true) => String::new(),
        (true, false) => body.trim().to_string(),
        (false, true) => reason.trim().to_string(),
        (false, false) => format!("{}\n{}", reason.trim(), body.trim()),
    }
}

fn prefix_manager_signal(prefix: &str, content: &str) -> String {
    if content.trim().is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix} {}", content.trim())
    }
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
        ManagerControlKind, ManagerPromptConfig, ManagerPromptConfigStore, ManagerPromptOverride,
        ManagerPromptStage, describe_manager_delay, extract_manager_delay_prefix,
        manager_control_decision_label, manager_response_display_content,
        parse_manager_control_response,
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
    fn manager_control_response_parses_first_line_protocol() {
        let stop = parse_manager_control_response(
            "STOPPING_POINT: Release deployed\nReport the commit and health checks.",
        );
        assert_eq!(stop.control, ManagerControlKind::StoppingPoint);
        assert_eq!(
            stop.content,
            "Release deployed\nReport the commit and health checks."
        );
        assert_eq!(
            manager_response_display_content(&stop),
            "\u{2705} Release deployed\nReport the commit and health checks."
        );

        let red = parse_manager_control_response("RED_FLAG_POINT: Unrelated files changed");
        assert_eq!(red.control, ManagerControlKind::RedFlag);
        assert_eq!(
            manager_response_display_content(&red),
            "\u{1f6a9} Unrelated files changed"
        );

        let wait = parse_manager_control_response("WAIT_FOR_SECONDS: 90\nCheck the build result.");
        assert_eq!(wait.control, ManagerControlKind::Wait(90));
        assert_eq!(wait.content, "Check the build result.");

        let cont = parse_manager_control_response("CONTINUE\nRun the focused regression next.");
        assert_eq!(cont.control, ManagerControlKind::Continue);
        assert_eq!(cont.content, "Run the focused regression next.");

        assert_eq!(
            manager_control_decision_label(ManagerControlKind::Continue),
            "Continue"
        );
        assert_eq!(
            manager_control_decision_label(ManagerControlKind::Wait(90)),
            "Wait 90s"
        );
        assert_eq!(
            manager_control_decision_label(ManagerControlKind::StoppingPoint),
            "Stopping Point"
        );
        assert_eq!(
            manager_control_decision_label(ManagerControlKind::RedFlag),
            "Red Flag"
        );
    }

    #[test]
    fn manager_control_response_ignores_inline_control_words() {
        let parsed = parse_manager_control_response(
            "The agent mentioned STOPPING_POINT in prose, but should keep going.",
        );
        assert_eq!(parsed.control, ManagerControlKind::Continue);
        assert_eq!(
            parsed.content,
            "The agent mentioned STOPPING_POINT in prose, but should keep going."
        );
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
