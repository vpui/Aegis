#![forbid(unsafe_code)]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader},
    path::PathBuf,
    str::FromStr,
};

use aegis_core::{ActionKind, ActionRequest, Evaluation, TrustLevel};
use aegis_policy::Policy;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

const DEFAULT_POLICY: &str = r#"version: 1
default_action: ask
rules:
  - id: deny-sensitive-paths
    effect: deny
    action: file.read
    paths: [".env", ".env.*", "secrets/**", "**/.ssh/**"]
  - id: confirm-network-egress
    effect: ask
    action: network.connect
  - id: confirm-mcp-calls
    effect: ask
    action: mcp.call
"#;

#[derive(Debug, Parser)]
#[command(
    name = "aegis",
    version,
    about = "Local policy firewall for AI coding agents"
)]
struct Cli {
    /// YAML policy applied to every command that evaluates requests.
    #[arg(short, long, global = true, default_value = "policies/default.yaml")]
    policy: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Evaluate one explicit capability request.
    Check {
        #[arg(long)]
        kind: String,
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "untrusted")]
        source: String,
        /// Emit a machine-readable JSON result.
        #[arg(long)]
        json: bool,
    },
    /// Evaluate newline-delimited ActionRequest JSON records from a file.
    Inspect {
        input: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Inspect newline-delimited MCP JSON-RPC tool calls from a file or standard input.
    McpInspect {
        /// Reads from standard input when omitted.
        #[arg(long)]
        input: Option<PathBuf>,
    },
    /// Open the decision browser for a JSONL request file or a built-in demo.
    Tui {
        #[arg(long)]
        input: Option<PathBuf>,
    },
    /// Write a conservative starter policy without overwriting an existing file.
    InitPolicy {
        #[arg(long, default_value = "policies/default.yaml")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::InitPolicy { output } => init_policy(output),
        command => {
            let policy = Policy::from_path(&cli.policy)
                .with_context(|| format!("could not load policy {}", cli.policy.display()))?;
            execute(command, &policy)
        }
    }
}

fn execute(command: Command, policy: &Policy) -> Result<()> {
    match command {
        Command::Check {
            kind,
            target,
            source,
            json,
        } => {
            let kind = ActionKind::from_str(&kind).context("invalid --kind value")?;
            let source = TrustLevel::from_str(&source).context("invalid --source value")?;
            let evaluation = policy.evaluate(ActionRequest::new(kind, target).with_source(source));
            print_evaluation(&evaluation, json)
        }
        Command::Inspect { input, json } => {
            for evaluation in inspect_requests(&input, policy)? {
                print_evaluation(&evaluation, json)?;
            }
            Ok(())
        }
        Command::McpInspect { input } => inspect_mcp(input, policy),
        Command::Tui { input } => {
            let evaluations = match input {
                Some(path) => inspect_requests(&path, policy)?,
                None => demo_evaluations(policy),
            };
            aegis_tui::run(evaluations).context("TUI stopped unexpectedly")
        }
        Command::InitPolicy { .. } => unreachable!("init policy is handled before loading policy"),
    }
}

fn inspect_requests(path: &PathBuf, policy: &Policy) -> Result<Vec<Evaluation>> {
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut evaluations = Vec::new();

    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.with_context(|| format!("could not read line {}", index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: ActionRequest = serde_json::from_str(&line)
            .with_context(|| format!("invalid JSON request on line {}", index + 1))?;
        evaluations.push(policy.evaluate(request));
    }

    Ok(evaluations)
}

fn inspect_mcp(input: Option<PathBuf>, policy: &Policy) -> Result<()> {
    let stdout = io::stdout();
    let writer = stdout.lock();

    match input {
        Some(path) => {
            let file =
                File::open(&path).with_context(|| format!("could not open {}", path.display()))?;
            aegis_mcp_proxy::inspect_jsonl(BufReader::new(file), writer, policy)?;
        }
        None => {
            let stdin = io::stdin();
            aegis_mcp_proxy::inspect_jsonl(BufReader::new(stdin.lock()), writer, policy)?;
        }
    }

    Ok(())
}

fn init_policy(output: PathBuf) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .with_context(|| format!("refusing to overwrite {}", output.display()))?;
    use std::io::Write;
    file.write_all(DEFAULT_POLICY.as_bytes())?;
    println!("Created {}", output.display());
    Ok(())
}

fn print_evaluation(evaluation: &Evaluation, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(evaluation)?);
    } else {
        let rule = evaluation.matched_rule.as_deref().unwrap_or("default");
        println!(
            "{:<5} {:<18} {}\n      source: {}; rule: {}; {}",
            evaluation.decision.to_string().to_uppercase(),
            evaluation.request.kind,
            evaluation.request.target,
            evaluation.request.source,
            rule,
            evaluation.reason,
        );
    }
    Ok(())
}

fn demo_evaluations(policy: &Policy) -> Vec<Evaluation> {
    [
        ActionRequest::new(ActionKind::FileRead, "src/auth.rs").with_source(TrustLevel::Trusted),
        ActionRequest::new(ActionKind::FileRead, ".env").with_source(TrustLevel::Untrusted),
        ActionRequest::new(ActionKind::NetworkConnect, "api.example.com")
            .with_source(TrustLevel::Mixed),
        ActionRequest::new(ActionKind::McpCall, "github.create_pull_request")
            .with_source(TrustLevel::Mixed),
    ]
    .into_iter()
    .map(|request| policy.evaluate(request))
    .collect()
}
