---
name: comments
description: Keep code comments durable — explain intent, invariants and trade-offs, never bug-fix history, ticket IDs, changelogs, or restatements of the code.
whenToUse: Use when adding or reviewing comments/docstrings, when cleaning a codebase, or when a comment mentions a fix, a previous implementation, or repeats the next line.
metadata:
  version: "1"
  scope: project
---

# Comments

A comment is read months later by someone who never saw the change that
produced it. Write only what stays true: intent, constraints, invariants and
non-obvious trade-offs. Never use comments as a changelog.

## Remove

- Bug-fix narratives and labels: `FIX:`, `BUG-FIX #12`, `FIX-9`, `Fix 2`,
  `HOTFIX`, ticket/PR references, dated notes.
- History: "previously …", "the old code …", "was X, now Y", "this used to …",
  "changed from …", "regression", "reverted".
- Restatements of the next line: `# increment counter` above `counter += 1`,
  a `# loop over hosts` above an obvious `for host in hosts`.
- Duplicated comments: the same explanation pasted into several functions;
  keep one canonical explanation where the rule lives and reference the helper.
- Section banners that only repeat the function name or file name.
- Commented-out code (delete it; git keeps history).

## Keep

- Why something is done this way, especially when the obvious alternative is
  wrong (ordering, retries, double checks, why a value is capped).
- Invariants and safety rules: "must run after X", "never lower the confidence
  here", "this order matters".
- Security, legal and privacy constraints; scope boundaries.
- External quirks: provider API behaviour, wire formats, rate limits, odd HTTP
  responses.
- Thresholds and units that are not obvious from the value (`0.1 s = 10 q/s`).
- Public docstrings that describe the contract, arguments and failure modes.

## Rewriting a bug-derived comment

If a comment records a fix but the rule still matters, restate it in the present
tense and drop the story:

```python
# Bad: FIX #12: previously double timeouts counted as NXDOMAIN; now we require
# at least one explicit NXDOMAIN rcode.
# Good: A double timeout is not NXDOMAIN; require one explicit NXDOMAIN rcode.
```

If the rule is already enforced by code or covered in `AGENTS.md`/`PLAN.md`,
delete the comment instead of moving the story around.

## Workflow

1. Scan for chatter:

   ```bash
   grep -rniE "#.*\b(fix|bug|hotfix|previously|was:|used to|no longer|changed from|reverted|regression)\b" app/ --include="*.py"
   grep -rn "^[[:space:]]*#" app/ --include="*.py" | awk -F: 'length($3) < 45'
   ```

2. Read each hit in context. Classify it: **historical** (delete), **rule**
   (rewrite without the history), **redundant** (delete), or **useful**
   (leave unchanged).
3. Edit comments only — no behavioural change in the same commit.
4. Re-scan until only durable explanations remain.
5. Run the test suite and linter, then commit with a message that says the
   comments were cleaned, not what each one used to say.

## Boundaries

- Do not rewrite module docstrings that document architecture into one-liners;
  trim only their change-history sections.
- Do not delete a comment just because it is long: length is fine when it
  explains a real constraint.
- Documentation files (`PLAN.md`, `README.md`, `AGENTS.md`) may record decisions
  and history; this rule is about code comments.
