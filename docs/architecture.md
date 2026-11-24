# Architecture

```text
agent / integration
        │ ActionRequest or MCP JSON-RPC
        ▼
  aegis-cli ─── loads ─── policy YAML
        │                     │
        ├── aegis-mcp-proxy ──┤
        ▼                     ▼
    aegis-core ◀──── aegis-policy
        │
        ▼
    aegis-tui or JSON output
```

`aegis-core` owns serializable, provider-neutral domain types. A request carries an
action kind, target, data trust level, and optional metadata. An evaluation always
contains the resulting decision, a human-readable reason, and the matching rule ID.

`aegis-policy` parses a YAML file once, validates every glob at load time, then
evaluates rules from top to bottom. First matching rule wins. This makes reviews
deterministic and prevents an ambiguous merge strategy from silently widening
access.

`aegis-mcp-proxy` currently inspects newline-delimited JSON-RPC messages. It turns
only `tools/call` into `mcp.call` requests, then emits an audit record. It does not
relay requests; a future relay must preserve this decision boundary.

`aegis-tui` displays existing evaluations and never executes actions. This avoids
giving the presentation layer security authority.
