# PersonalCodingAgent — `private_agent.py`

A **personal, local-only** AI coding assistant for the terminal. It talks to a
**local Ollama model only**, reads **only the files you explicitly select**, and
**never applies a change without showing you a diff and asking first**.

> ⚠️ **Disclaimer — read this first.**
> This is a **hardened *starting* version** with safeguards. It is **NOT fully
> secure and NOT production-ready.** The protections here are application-level
> checks inside this Python program — they are **not an operating-system
> sandbox**. Treat all model output and file contents as **untrusted input**.
> No part of this project has been run or verified on your Mac in this
> environment, so **macOS compatibility is not verified here**. Review every
> proposed change and keep your own backups.

---

## What it actually does (capabilities)

- Launches its **own** `ollama serve` process bound to `127.0.0.1` with
  `OLLAMA_NO_CLOUD=1` (Ollama's documented cloud-disable setting) so inference
  stays local.
- Accepts a project directory and a repeatable `--file` list; **only those
  files** are ever placed into the model prompt.
- For each file: builds a prompt, asks the local model for updated contents,
  shows you a **unified diff**, and waits for **explicit per-file approval**.
- On approval: re-checks the file hasn't changed on disk, writes a
  **timestamped `.bak` backup**, then writes the new contents.
- Ships a `--self-test` and a full offline unit-test suite (Ollama is mocked).

## What it does NOT do (limitations — honest list)

- It is **not an OS sandbox**. A determined local process, or the Ollama server
  itself, is outside this program's control.
- It **never executes** model output — but that also means it does not run,
  compile, or verify the code it writes. **You** must test every change.
- The sensitive-file deny-list is **name/keyword based**. It catches common
  cases (e.g. `.env`, `credentials`, `id_rsa`, `financial`) but is **not
  exhaustive**; a differently-named secret file could still be selected.
- Edits are **single-file**: the model sees one file at a time with no
  cross-file project awareness.
- No streaming, no multi-turn conversation, no automatic model download.
- Not verified on macOS (or anywhere) against a real model in this environment.

## Security safeguards (enforced in code)

1. **Local inference, cloud disabled** — own `ollama serve`, `OLLAMA_NO_CLOUD=1`,
   loopback host only.
2. **Explicit context only** — just the `--file` paths enter the prompt.
3. **Path hardening** — rejects path traversal, symlinks (and symlinked parent
   dirs), hard-linked files, oversized files, and anything resolving outside the
   project.
4. **Per-file approval after the diff** — nothing is written without a `y`.
5. **Backups** — every file is copied to `NAME.<timestamp>.bak` before replace.
6. **Stale-file protection** — an edit is refused if the file's hash/mtime
   changed after it was read.
7. **No auto-execution** — model output is only ever written to disk, never run.
8. **Secret avoidance** — a keyword deny-list blocks credentials, passwords,
   financial files, SSH/AWS/GPG material, etc.

(3 and the hard-link / oversized-file checks go slightly beyond the original
spec; see `TASKS.md`.)

---

## Install & use (on your own machine)

This project **does not** download a model for you. Do that yourself, while
online, once:

1. **Install Ollama** separately by following the official instructions at
   <https://ollama.com>. (This repo does not bundle or install it.)
2. **Download a local model while online**, for example:
   ```bash
   ollama pull llama3:8b
   ```
3. **Find the exact local model name:**
   ```bash
   ollama list
   ```
   Use the name from the first column (for example `llama3:8b`).
4. **Run the agent** against a project you own, selecting only the files you
   want it to see:
   ```bash
   python3 private_agent.py \
     --project /path/to/your/project \
     --model llama3:8b \
     --file src/example.py \
     --file src/other.py \
     --instruction "Add type hints and a docstring"
   ```
   You will be shown a diff for each file and asked to approve it.

### Offline self-check (no model needed)

```bash
python3 private_agent.py --self-test
```

### Run the tests (no network, Ollama is mocked)

```bash
python3 -m unittest discover -s tests -v
# or, if you have pytest:
python3 -m pytest tests/ -q
```

## Requirements

- Python 3.9+ (standard library only; `pytest` is optional for tests).
- Ollama installed separately, with at least one local model pulled.

See `SECURITY.md` for the threat model and `VERIFICATION.md` for the exact
commands run here and their actual results.
