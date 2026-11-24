#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use aegis_core::{ActionKind, ActionRequest, Evaluation, TrustLevel};
use aegis_policy::Policy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Minimal representation of a JSON-RPC message emitted by an MCP client.
#[derive(Debug, Deserialize)]
pub struct McpMessage {
    #[serde(default)]
    pub jsonrpc: Option<String>,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// An audit record emitted by the inspection mode. This is deliberately separate
/// from an upstream MCP response so a caller cannot confuse inspection with relay.
#[derive(Debug, Serialize)]
pub struct McpAuditRecord {
    pub method: String,
    pub evaluation: Evaluation,
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("could not parse MCP JSON-RPC message on line {line}: {source}")]
    Parse {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("could not serialize Aegis audit record: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Converts an MCP tool call into a normalized Aegis capability request.
/// Other JSON-RPC methods are intentionally ignored by this initial inspector.
pub fn classify(message: &McpMessage) -> Option<ActionRequest> {
    if message.method != "tools/call" {
        return None;
    }

    let tool = message
        .params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unnamed-tool");

    Some(ActionRequest::new(ActionKind::McpCall, tool).with_source(TrustLevel::Mixed))
}

/// Reads newline-delimited MCP JSON-RPC messages and writes newline-delimited,
/// explainable decisions. It does not forward calls to an MCP server.
pub fn inspect_jsonl<R: BufRead, W: Write>(
    reader: R,
    mut writer: W,
    policy: &Policy,
) -> Result<(), ProxyError> {
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let message: McpMessage =
            serde_json::from_str(&line).map_err(|source| ProxyError::Parse {
                line: index + 1,
                source,
            })?;

        if let Some(request) = classify(&message) {
            let audit = McpAuditRecord {
                method: message.method,
                evaluation: policy.evaluate(request),
            };
            serde_json::to_writer(&mut writer, &audit)?;
            writer.write_all(b"\n")?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use aegis_core::ActionKind;
    use aegis_policy::Policy;

    use super::{McpMessage, classify, inspect_jsonl};

    #[test]
    fn classifies_mcp_tool_calls() {
        let message: McpMessage = serde_json::from_str(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"github.create_issue"}}"#,
        )
        .expect("valid MCP message");

        let request = classify(&message).expect("tool call");
        assert_eq!(request.kind, ActionKind::McpCall);
        assert_eq!(request.target, "github.create_issue");
    }

    #[test]
    fn emits_an_audit_record_for_tool_calls() {
        let policy = Policy::from_yaml_str("version: 1\ndefault_action: deny\nrules: []\n")
            .expect("valid policy");
        let input = b"{\"method\":\"tools/call\",\"params\":{\"name\":\"git.push\"}}\n";
        let mut output = Vec::new();

        inspect_jsonl(&input[..], &mut output, &policy).expect("inspection succeeds");

        let record = String::from_utf8(output).expect("UTF-8 audit record");
        assert!(record.contains("deny"));
        assert!(record.contains("git.push"));
    }
}
