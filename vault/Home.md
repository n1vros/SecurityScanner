# STOscanner Vault — Home

Knowledge base for STOscanner. Start here; conventions are in [[README]].

## Areas

Notes are created as they are needed; the folders below are placeholders for
them.

| Area | Where | What goes there |
| --- | --- | --- |
| Architecture | `architecture.md` | components, data flow, scan pipeline |
| Decisions | `decisions/` | one note per decision and its trade-offs |
| Research | `research/` | platform APIs, takeover techniques, tooling |
| Operations | `operations/` | runbooks: scanning, credentials, incidents |

## Quick facts

- **Purpose** — continuous subdomain-takeover detection for bug bounty scopes
- **Entry point** — `main.py` (`daemon` | `web` | CLI)
- **Orchestrator** — `app/core/daemon.py` + `app/core/scheduler.py`
- **Stack** — Python 3.12, asyncio, FastAPI, SQLAlchemy async + PostgreSQL, Redis
- **State** — programs → scopes → subdomains → findings → notifications
- **Docs** — `AGENTS.md` (conventions), `README.md` (usage), `SPEC.md` (spec)

## Notes

Nothing here yet beyond the index. Add notes as you learn the system:

```text
vault/
├── Home.md
├── README.md
├── architecture.md
├── decisions/
├── research/
└── operations/
```

## Open questions

- Which discovery sources are highest-yield per platform?
- What is the right re-notification cadence to stay useful without alert spam?

## Decision log

| Date | Decision | Note |
| --- | --- | --- |
| — | Vault created as the project knowledge base | [[README]] |
