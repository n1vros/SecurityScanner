# Vault

Markdown knowledge vault for STOscanner — design notes, decisions, and research
that do not belong in code comments or `AGENTS.md`.

The folder is Obsidian-compatible: open `vault/` as a vault, or just read the
files in any editor. Every note is plain Markdown with `[[WikiLinks]]`, so links
keep working when files move.

## Conventions

- Start every note with a level-1 title, then a one-line summary.
- Link related notes with `[[Note name]]`; keep `[[Home]]` reachable from all of
  them.
- One topic per note; put open questions in a `## Open questions` section and
  resolved decisions in `## Decision` with the date and the reason.
- Record *why* a design exists, not just *what* it does — the code and
  `AGENTS.md` cover the what.
- Do not paste secrets, tokens, credentials, or third-party data that cannot be
  published.

## Layout

| Path | Contents |
| --- | --- |
| `Home.md` | Index of areas and notes (start here) |
| `architecture.md` | System architecture and data flow |
| `decisions/` | One note per significant decision |
| `research/` | Platform APIs, takeover techniques, background material |
| `operations/` | Runbooks for scanning, credentials and incident handling |

Empty folders are created as needed; there is no required file besides `Home.md`.
