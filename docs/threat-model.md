# Threat model

## Assets

- source code and local project files;
- credentials, tokens, private keys, and `.env` files;
- ability to send data to a network destination;
- ability to modify a repository or invoke local processes.

## Threats addressed by the MVP

| Threat | Aegis response |
| --- | --- |
| An agent asks to read a known secret path | A matching deny rule blocks the request. |
| Untrusted content leads to a write, network, process, or MCP action | A policy can require a human decision with `ask`. |
| A reviewer needs to understand a decision | Each evaluation contains the matching rule and reason. |
| A malformed policy pattern would weaken matching | Policy loading fails before evaluation begins. |

## Out of scope today

The MVP cannot force every agent to report every shell command, prevent an agent
from reading a file outside an external sandbox, or prove that data has not been
encoded before a network request. It also does not relay MCP traffic or manage
credentials. Production enforcement needs process isolation, restricted filesystem
mounts, a controlled network path, and agent-specific interception hooks.

The safest deployment grants each agent only the minimum filesystem, network, and
tool capabilities it needs for a single task.
