#![forbid(unsafe_code)]

use std::{io, time::Duration};

use aegis_core::{Decision, Evaluation};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

/// Runs the interactive decision browser. Press `q` to exit, or use arrows/
/// `j` and `k` to inspect a different record.
pub fn run(evaluations: Vec<Evaluation>) -> io::Result<()> {
    let mut terminal = enter_terminal()?;
    let result = run_loop(&mut terminal, evaluations);
    restore_terminal(&mut terminal)?;
    result
}

fn enter_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    evaluations: Vec<Evaluation>,
) -> io::Result<()> {
    let mut state = AppState::new(evaluations);

    loop {
        terminal.draw(|frame| render(frame, &mut state))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Down | KeyCode::Char('j') => state.next(),
                    KeyCode::Up | KeyCode::Char('k') => state.previous(),
                    _ => {}
                }
            }
        }
    }
}

struct AppState {
    evaluations: Vec<Evaluation>,
    selected: usize,
}

impl AppState {
    fn new(evaluations: Vec<Evaluation>) -> Self {
        Self {
            evaluations,
            selected: 0,
        }
    }

    fn next(&mut self) {
        if !self.evaluations.is_empty() {
            self.selected = (self.selected + 1) % self.evaluations.len();
        }
    }

    fn previous(&mut self) {
        if !self.evaluations.is_empty() {
            self.selected = if self.selected == 0 {
                self.evaluations.len() - 1
            } else {
                self.selected - 1
            };
        }
    }
}

fn render(frame: &mut ratatui::Frame<'_>, state: &mut AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" AEGIS ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw("  Local policy decisions for AI-agent actions"),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Agent firewall"),
        ),
        layout[0],
    );

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(layout[1]);

    let items = if state.evaluations.is_empty() {
        vec![ListItem::new("No actions to display")]
    } else {
        state
            .evaluations
            .iter()
            .map(|evaluation| {
                let label = format!("{:5}", evaluation.decision.to_string().to_uppercase());
                let text = format!(
                    "{label}  {}  {}",
                    evaluation.request.kind, evaluation.request.target
                );
                ListItem::new(text).style(Style::default().fg(decision_color(evaluation.decision)))
            })
            .collect()
    };

    let mut list_state = ListState::default();
    if !state.evaluations.is_empty() {
        list_state.select(Some(state.selected));
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Actions"))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        body[0],
        &mut list_state,
    );

    let detail = state
        .evaluations
        .get(state.selected)
        .map(render_detail)
        .unwrap_or_else(|| "Run `aegis inspect requests.jsonl` to load decisions.".to_owned());
    frame.render_widget(
        Paragraph::new(detail)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Decision detail"),
            )
            .wrap(Wrap { trim: true }),
        body[1],
    );

    frame.render_widget(
        Paragraph::new(" ↑/k previous   ↓/j next   q or Esc quit ")
            .block(Block::default().borders(Borders::ALL)),
        layout[2],
    );
}

fn render_detail(evaluation: &Evaluation) -> String {
    let rule = evaluation
        .matched_rule
        .as_deref()
        .unwrap_or("default action");
    format!(
        "Decision: {}\nAction: {}\nTarget: {}\nSource: {}\nRule: {}\n\n{}",
        evaluation.decision.to_string().to_uppercase(),
        evaluation.request.kind,
        evaluation.request.target,
        evaluation.request.source,
        rule,
        evaluation.reason,
    )
}

fn decision_color(decision: Decision) -> Color {
    match decision {
        Decision::Allow => Color::Green,
        Decision::Ask => Color::Yellow,
        Decision::Deny => Color::Red,
    }
}

#[cfg(test)]
mod tests {
    use aegis_core::{ActionKind, ActionRequest, Decision, Evaluation};

    use super::render_detail;

    #[test]
    fn renders_explainable_decision_details() {
        let evaluation = Evaluation::new(
            ActionRequest::new(ActionKind::FileRead, ".env"),
            Decision::Deny,
            "matched policy rule deny-secrets",
            Some("deny-secrets".to_owned()),
        );

        assert!(render_detail(&evaluation).contains("deny-secrets"));
    }
}
