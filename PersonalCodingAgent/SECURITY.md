# Security notes — PersonalCodingAgent

**This is a hardened starting version, not a secure or production-ready product.**
The controls below are **application-level checks** inside `private_agent.py`.
They are **not an operating-system sandbox** and do not constrain other
processes, the Ollama server, or the OS itself.

## Threat model & assumptions

- **Trusted:** the person running the tool on their own machine, and the local
  machine's basic integrity.
- **Untrusted:** **all model output** and **all file contents** read from disk.
  Everything the model returns is treated as data to be shown/written, never as
  commands to run.
- **Out of scope:** OS-level isolation, network egress filtering beyond binding
  Ollama to loopback, protecting against a compromised Ollama binary, and
  side-channels. There is **no** guarantee of absolute security.

## Controls implemented

| # | Control | Where |
|---|---------|-------|
| 1 | Local Ollama only; `OLLAMA_NO_CLOUD=1`; loopback bind | `OllamaManager` |
| 2 | Only explicitly selected files enter the prompt | `EditSession.propose` / `build_edit_prompt` |
| 3 | Reject cloud/remote model names (incl. registry hosts) | `assert_local_model` |
| 4 | Reject path traversal & absolute paths outside project | `assert_safe_path` |
| 5 | Reject symlinks and symlinked parent directories | `assert_safe_path` |
| 6 | Reject hard-linked files (shared inode) | `assert_safe_path` |
| 7 | Reject oversized files (`MAX_FILE_BYTES`) | `assert_safe_path` |
| 8 | Keyword deny-list for secrets/financial/credentials | `assert_safe_path` / `_is_sensitive` |
| 9 | Per-file approval **after** the diff is shown | `EditSession.apply` |
| 10 | Timestamped backup before every overwrite | `backup_file` |
| 11 | Stale-file (hash + mtime) rejection | `Fingerprint` / `EditSession.apply` |
| 12 | Malformed/empty proposals are dropped, not written | `ProposedEdit.is_malformed` |
| 13 | Model output is never executed | by construction (write-only) |

## Known limitations

- The secret deny-list is **keyword-based** and not exhaustive.
- No integrity verification of the Ollama binary or models.
- No multi-file/project-wide reasoning; one file per prompt.
- Not verified on macOS or against a real model in this environment.

## Reporting

This is a personal tool. If you find a weakness, note it in `TASKS.md` under
blockers/remaining work before relying on the tool further.
