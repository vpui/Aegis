#![forbid(unsafe_code)]

use std::{fs, path::Path};

use aegis_core::{ActionKind, ActionRequest, Decision, Evaluation};
use globset::Glob;
use serde::Deserialize;
use thiserror::Error;

/// A reviewable, file-backed Aegis policy.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub version: u32,
    pub default_action: Decision,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub effect: Decision,
    pub action: ActionKind,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("could not read policy at {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse policy: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("policy version must be greater than zero")]
    InvalidVersion,
    #[error("rule {rule_id} has an invalid pattern {pattern}: {source}")]
    InvalidPattern {
        rule_id: String,
        pattern: String,
        #[source]
        source: globset::Error,
    },
}

impl Policy {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml_str(&contents)
    }

    pub fn from_yaml_str(contents: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_yaml::from_str(contents)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn evaluate(&self, request: ActionRequest) -> Evaluation {
        for rule in &self.rules {
            if rule.matches(&request) {
                return Evaluation::new(
                    request,
                    rule.effect,
                    format!("matched policy rule {}", rule.id),
                    Some(rule.id.clone()),
                );
            }
        }

        Evaluation::new(
            request,
            self.default_action,
            "no policy rule matched; applied default action",
            None,
        )
    }

    fn validate(&self) -> Result<(), PolicyError> {
        if self.version == 0 {
            return Err(PolicyError::InvalidVersion);
        }

        for rule in &self.rules {
            for pattern in rule.patterns() {
                Glob::new(pattern).map_err(|source| PolicyError::InvalidPattern {
                    rule_id: rule.id.clone(),
                    pattern: pattern.clone(),
                    source,
                })?;
            }
        }

        Ok(())
    }
}

impl Rule {
    fn matches(&self, request: &ActionRequest) -> bool {
        if self.action != request.kind {
            return false;
        }

        let patterns = self.patterns();
        patterns.is_empty()
            || patterns
                .iter()
                .any(|pattern| pattern_matches(pattern, &request.target))
    }

    fn patterns(&self) -> &[String] {
        match self.action {
            ActionKind::FileRead | ActionKind::FileWrite => &self.paths,
            ActionKind::ProcessExecute => &self.commands,
            ActionKind::NetworkConnect => &self.domains,
            ActionKind::McpCall => &self.tools,
        }
    }
}

fn pattern_matches(pattern: &str, target: &str) -> bool {
    Glob::new(pattern)
        .expect("policy patterns are validated before evaluation")
        .compile_matcher()
        .is_match(target)
}

#[cfg(test)]
mod tests {
    use aegis_core::{ActionKind, ActionRequest, Decision};

    use super::Policy;

    const POLICY: &str = r#"
version: 1
default_action: ask
rules:
  - id: block-secrets
    effect: deny
    action: file.read
    paths: ["secrets/**", ".env"]
  - id: allow-source
    effect: allow
    action: file.read
    paths: ["src/**"]
"#;

    #[test]
    fn first_matching_rule_decides_the_outcome() {
        let policy = Policy::from_yaml_str(POLICY).expect("valid policy");
        let evaluation = policy.evaluate(ActionRequest::new(ActionKind::FileRead, "src/main.rs"));

        assert_eq!(evaluation.decision, Decision::Allow);
        assert_eq!(evaluation.matched_rule.as_deref(), Some("allow-source"));
    }

    #[test]
    fn prevents_sensitive_file_reads() {
        let policy = Policy::from_yaml_str(POLICY).expect("valid policy");
        let evaluation = policy.evaluate(ActionRequest::new(ActionKind::FileRead, "secrets/token"));

        assert_eq!(evaluation.decision, Decision::Deny);
    }

    #[test]
    fn rejects_invalid_globs_at_load_time() {
        let invalid = POLICY.replace("src/**", "[");
        assert!(Policy::from_yaml_str(&invalid).is_err());
    }
}
