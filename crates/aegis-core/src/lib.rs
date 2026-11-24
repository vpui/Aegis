#![forbid(unsafe_code)]

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// A capability requested by an AI agent or one of its connected tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionKind {
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "network.connect")]
    NetworkConnect,
    #[serde(rename = "process.execute")]
    ProcessExecute,
    #[serde(rename = "mcp.call")]
    McpCall,
}

impl ActionKind {
    pub const ALL: [Self; 5] = [
        Self::FileRead,
        Self::FileWrite,
        Self::NetworkConnect,
        Self::ProcessExecute,
        Self::McpCall,
    ];
}

impl fmt::Display for ActionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::NetworkConnect => "network.connect",
            Self::ProcessExecute => "process.execute",
            Self::McpCall => "mcp.call",
        };
        formatter.write_str(label)
    }
}

impl FromStr for ActionKind {
    type Err = ParseActionKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "file.read" => Ok(Self::FileRead),
            "file.write" => Ok(Self::FileWrite),
            "network.connect" => Ok(Self::NetworkConnect),
            "process.execute" => Ok(Self::ProcessExecute),
            "mcp.call" => Ok(Self::McpCall),
            _ => Err(ParseActionKindError(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseActionKindError(pub String);

impl fmt::Display for ParseActionKindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unsupported action kind: {}", self.0)
    }
}

impl std::error::Error for ParseActionKindError {}

/// Origin confidence of the data that caused the action request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Trusted,
    #[default]
    Untrusted,
    Mixed,
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
            Self::Mixed => "mixed",
        };
        formatter.write_str(label)
    }
}

impl FromStr for TrustLevel {
    type Err = ParseTrustLevelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "trusted" => Ok(Self::Trusted),
            "untrusted" => Ok(Self::Untrusted),
            "mixed" => Ok(Self::Mixed),
            _ => Err(ParseTrustLevelError(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTrustLevelError(pub String);

impl fmt::Display for ParseTrustLevelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported trust level: {}; use trusted, untrusted, or mixed",
            self.0
        )
    }
}

impl std::error::Error for ParseTrustLevelError {}

/// A normalized request that can be evaluated independently of a specific agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequest {
    pub kind: ActionKind,
    pub target: String,
    #[serde(default)]
    pub source: TrustLevel,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl ActionRequest {
    pub fn new(kind: ActionKind, target: impl Into<String>) -> Self {
        Self {
            kind,
            target: target.into(),
            source: TrustLevel::Untrusted,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_source(mut self, source: TrustLevel) -> Self {
        self.source = source;
        self
    }
}

/// A policy outcome. `Ask` requires an explicit human decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

impl fmt::Display for Decision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        };
        formatter.write_str(label)
    }
}

/// An explainable policy evaluation returned to the caller and audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub request: ActionRequest,
    pub decision: Decision,
    pub reason: String,
    pub matched_rule: Option<String>,
}

impl Evaluation {
    pub fn new(
        request: ActionRequest,
        decision: Decision,
        reason: impl Into<String>,
        matched_rule: Option<String>,
    ) -> Self {
        Self {
            request,
            decision,
            reason: reason.into(),
            matched_rule,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ActionKind, TrustLevel};
    use std::str::FromStr;

    #[test]
    fn parses_known_action_kind() {
        assert_eq!(
            ActionKind::from_str("mcp.call").expect("known action kind"),
            ActionKind::McpCall
        );
    }

    #[test]
    fn defaults_to_untrusted_data() {
        assert_eq!(TrustLevel::default(), TrustLevel::Untrusted);
    }
}
