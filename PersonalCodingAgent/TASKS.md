# TASKS — PersonalCodingAgent

Status as of the end of **Stage 1** (small, reviewable; stopping here for review).

## Completed

- `private_agent.py`: local-only terminal coding agent.
  - Local Ollama manager (`OLLAMA_NO_CLOUD=1`, loopback bind, own `ollama serve`).
  - Cloud/remote model-name rejection (incl. registry-host form like
    `ollama.com/library/x`).
  - Path hardening: traversal, absolute-outside, symlink, symlinked-parent,
    hard-link, oversized-file, and sensitive-keyword rejection.
  - Edit workflow: read → prompt (selected file only) → propose → unified diff →
    explicit per-file approval → stale-check (hash+mtime) → backup → write.
  - Malformed/empty proposal handling (dropped, never wipes the file).
  - Model output is never executed (write-only by construction).
  - `--self-test` (offline) and a CLI run mode.
- Unit tests (`tests/test_private_agent.py`), Ollama fully mocked, no network:
  model validation, path safety, symlink/hard-link/oversized, fingerprint/backup,
  approval gating (approve + reject), stale/duplicate rejection, malformed
  proposals, "never executed", "only selected file in prompt", code extraction,
  full request→proposal→diff→approval workflow, and Ollama env hardening.
- Docs: `README.md`, `SECURITY.md`, `AGENTS.md`, `.gitignore`.
- Continuity: `TASKS.md`, `VERIFICATION.md`.

## Safeguards added BEYOND the original 8-point spec

- **Hard-link rejection** (`st_nlink > 1`): a hard link shares an inode with
  another path that could be outside the project or sensitive; backing-up and
  replacing could affect that other path, so such files are refused.
- **Oversized-file rejection** (`MAX_FILE_BYTES`, default 1 MB): guards against
  huge inputs / accidental binaries entering the model context.
- **Malformed/empty-proposal handling**: an empty model reply is dropped rather
  than silently truncating the real file.
- **Symlinked-parent-directory rejection** (beyond just the leaf being a symlink).

## Remaining / not done (future stages — NOT started, awaiting review)

- Running against a real local Ollama model (needs a user machine + pulled model).
- Any macOS-specific verification (nothing here runs on the user's Mac).
- Multi-file / project-wide reasoning; streaming; multi-turn chat.
- A broader, content-based (not just keyword) secret detector.

## Blockers

- None blocking Stage 1. Real-model and macOS verification require the user's own
  machine and are intentionally out of scope for this environment.
