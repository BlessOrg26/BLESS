# Agent instructions — PersonalCodingAgent

Guidance for any AI/automation working inside `PersonalCodingAgent/`.

## Non-negotiable constraints

- **Local-only.** Never add cloud AI calls, telemetry, analytics, or network
  egress beyond the loopback Ollama connection. Keep `OLLAMA_NO_CLOUD=1`.
- **No publishing.** Do not publish, deploy, change repository visibility, or
  push to any external/personal GitHub. The draft PR on this project repo is the
  only review surface.
- **Privacy first.** Never read credentials, passwords, financial records, SSH/
  GPG/AWS material, or unrelated folders. Only operate on synthetic/disposable
  files in tests.
- **Honest wording.** Do not describe the tool as fully secure, production-ready,
  an OS sandbox, or as verified on macOS. Never claim a test passed without
  actually running it and pasting the real output.

## Safeguards you must preserve

All 13 controls in `SECURITY.md`. If you change behavior, update `SECURITY.md`,
`README.md`, `TASKS.md`, and `VERIFICATION.md`, and keep the tests green.

## Testing rules

- Tests must run **offline**. Ollama must stay **mocked** — no network, no model
  download, ever.
- Run both `python3 private_agent.py --self-test` and the unit suite before
  reporting results, and record actual output in `VERIFICATION.md`.

## Continuity

Keep `TASKS.md` (done / remaining / blockers) and `VERIFICATION.md` (commands +
real results + what's untested) up to date. Update both before stopping.
