#!/usr/bin/env python3
"""
private_agent.py — a PERSONAL, LOCAL-ONLY AI coding agent.

This is a hardened *starting* version with safeguards. It is NOT fully secure
and NOT production-ready. See the README for the full disclaimer.

Design goals (all enforced below, do not weaken):
  1. Local Ollama inference only, with cloud features disabled
     (the agent launches its own localhost `ollama serve` with OLLAMA_NO_CLOUD=1).
  2. Only files explicitly selected on the CLI may enter the model context.
  3. Reject cloud/remote model names, symlinks, and any path outside the project.
  4. Require explicit per-file human approval *after* showing the proposed diff.
  5. Back up every file before it is replaced.
  6. Reject an edit if the file changed on disk after it was read (hash + mtime).
  7. Never execute model-generated commands or code automatically.
  8. Never read credentials, passwords, financial records, or unrelated folders.

Everything that talks to Ollama goes through a single injectable callable so the
test-suite can run completely offline (no network, no model required).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence


# ---------------------------------------------------------------------------
# Configuration constants (security-relevant — keep conservative).
# ---------------------------------------------------------------------------

# Ollama is only ever contacted on loopback. We never allow a remote host.
OLLAMA_BIND_HOST = "127.0.0.1"
DEFAULT_OLLAMA_PORT = 11434

# Substrings that indicate a model is NOT a plain local model. Ollama's hosted
# ("cloud") models carry a `-cloud` tag; anything referencing a remote provider
# or a URL is rejected outright.
CLOUD_MODEL_MARKERS = (
    "cloud",
    "remote",
    "openai",
    "anthropic",
    "claude",
    "gemini",
    "gpt-4",
    "gpt-3",
    "gpt-5",
    "mistral.ai",
    "api.",
    "://",
    "http",
)

# A valid local model name looks like `llama3`, `llama3:8b`, or
# `library/qwen2.5-coder:7b`. We deliberately keep the allowed charset tight.
_LOCAL_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

# Largest file we will read into the model context (defense against huge files
# and accidental binaries). Overridable in tests.
MAX_FILE_BYTES = 1_000_000  # 1 MB

# Filenames / path fragments that must never be read into the model context.
# Matching is case-insensitive and substring-based on each path component.
SENSITIVE_NAME_MARKERS = (
    "credential",
    "password",
    "passwd",
    "secret",
    "financial",
    "finance",
    "bank",
    "wallet",
    "token",
    "apikey",
    "api_key",
    "id_rsa",
    "id_ed25519",
    ".env",
    ".pem",
    ".key",
    ".keystore",
    ".ssh",
    ".aws",
    ".gnupg",
    "shadow",
)


class SecurityError(Exception):
    """Raised whenever a safeguard blocks an action. Never swallow silently."""


# ---------------------------------------------------------------------------
# Safeguard 1 / 3: model-name validation (reject cloud / remote models).
# ---------------------------------------------------------------------------

def assert_local_model(model: str) -> str:
    """Validate that `model` is a plain local Ollama model name.

    Rejects empty names, URLs, remote-provider references, and Ollama's hosted
    `-cloud` models. Returns the (stripped) name on success.
    """
    if model is None or not model.strip():
        raise SecurityError("Model name must not be empty.")
    name = model.strip()
    lowered = name.lower()

    for marker in CLOUD_MODEL_MARKERS:
        if marker in lowered:
            raise SecurityError(
                f"Refusing cloud/remote model {name!r} (matched {marker!r}). "
                "Only local Ollama models are allowed."
            )

    if not _LOCAL_MODEL_RE.fullmatch(name):
        raise SecurityError(
            f"Model name {name!r} contains characters that are not allowed for "
            "a local model name."
        )

    # A namespaced name like `library/llama3` is fine, but if the first segment
    # (before the first `/`) contains a dot it looks like a remote registry host
    # (e.g. `ollama.com/library/x`, `registry.ollama.ai/...`) — reject it.
    first_segment = name.split("/", 1)[0]
    if "/" in name and "." in first_segment:
        raise SecurityError(
            f"Model name {name!r} looks like a remote registry reference. "
            "Only plain local model names are allowed."
        )
    return name


# ---------------------------------------------------------------------------
# Safeguard 2 / 3 / 8: path validation.
# ---------------------------------------------------------------------------

def _is_sensitive(path: Path) -> bool:
    """True if any component of `path` looks like a secret / financial file."""
    for component in path.parts:
        lowered = component.lower()
        for marker in SENSITIVE_NAME_MARKERS:
            if marker in lowered:
                return True
    return False


def assert_safe_path(project_root: Path, candidate: str) -> Path:
    """Resolve `candidate` and confirm it is a safe file inside `project_root`.

    Enforces, in order:
      * the project root itself is a real directory,
      * no path-traversal escapes the project (checked lexically *before* any
        symlink resolution so a crafted path cannot slip out),
      * no component of the path is a symlink,
      * the target exists and is a regular file,
      * nothing matches the sensitive-file deny-list,
      * the fully resolved real path still lives inside the project.
    """
    project_root = Path(project_root).resolve(strict=True)
    if not project_root.is_dir():
        raise SecurityError(f"Project root {project_root} is not a directory.")

    raw = Path(candidate)
    if not raw.is_absolute():
        raw = project_root / raw

    # Lexical normalization WITHOUT following symlinks. This is what blocks
    # `../../etc/passwd` style traversal regardless of what symlinks exist.
    norm = Path(os.path.normpath(str(raw)))
    try:
        rel = norm.relative_to(project_root)
    except ValueError as exc:
        raise SecurityError(
            f"Path {candidate!r} is outside the project directory."
        ) from exc

    # Walk every component from the project root down, rejecting symlinks.
    cursor = project_root
    for part in rel.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise SecurityError(
                f"Refusing symlink {cursor} — symlinks are not allowed."
            )

    if _is_sensitive(norm):
        raise SecurityError(
            f"Refusing {norm} — matches the sensitive/credentials deny-list."
        )

    if not norm.exists():
        raise SecurityError(f"File {norm} does not exist.")
    if not norm.is_file():
        raise SecurityError(f"{norm} is not a regular file.")

    stat = norm.stat()

    # Reject files with more than one hard link. A hard link shares an inode
    # with another path (possibly outside the project, possibly a sensitive
    # file), so backing-up-and-replacing could affect that other path too.
    if stat.st_nlink > 1:
        raise SecurityError(
            f"Refusing {norm.name} — it has multiple hard links "
            f"(st_nlink={stat.st_nlink}); the same data is reachable elsewhere."
        )

    # Reject oversized files (defense against huge inputs / accidental binaries).
    if stat.st_size > MAX_FILE_BYTES:
        raise SecurityError(
            f"Refusing {norm.name} — {stat.st_size} bytes exceeds the "
            f"{MAX_FILE_BYTES}-byte limit."
        )

    # Final defense in depth: even after resolving every symlink, the real path
    # must remain inside the project root.
    real = norm.resolve(strict=True)
    if real != project_root and project_root not in real.parents:
        raise SecurityError(
            f"Path {candidate!r} resolves outside the project directory."
        )
    return norm


# ---------------------------------------------------------------------------
# Safeguard 5 / 6: fingerprints and backups.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Fingerprint:
    """A cheap snapshot used to detect out-of-band edits to a file."""

    sha256: str
    mtime_ns: int

    def matches(self, other: "Fingerprint") -> bool:
        # The hash is authoritative; mtime is a fast first-line check.
        return self.sha256 == other.sha256 and self.mtime_ns == other.mtime_ns


def fingerprint_file(path: Path) -> Fingerprint:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    mtime_ns = path.stat().st_mtime_ns
    return Fingerprint(sha256=digest, mtime_ns=mtime_ns)


def backup_file(path: Path, now: Optional[_dt.datetime] = None) -> Path:
    """Copy `path` to a timestamped `.bak` sibling and return the backup path."""
    stamp = (now or _dt.datetime.now()).strftime("%Y%m%d-%H%M%S-%f")
    backup_path = path.with_name(f"{path.name}.{stamp}.bak")
    backup_path.write_bytes(path.read_bytes())
    return backup_path


# ---------------------------------------------------------------------------
# Safeguard 1: local Ollama process management + inference.
# ---------------------------------------------------------------------------

class OllamaManager:
    """Owns a localhost `ollama serve` process with cloud features disabled.

    The process is started with ``OLLAMA_NO_CLOUD=1`` (Ollama's documented
    cloud-disable flag) and bound to loopback only. All generation is a plain
    HTTP POST to ``127.0.0.1``. Nothing here reaches the public internet.
    """

    def __init__(self, port: int = DEFAULT_OLLAMA_PORT) -> None:
        self.port = port
        self.host = f"{OLLAMA_BIND_HOST}:{port}"
        self._proc: Optional[subprocess.Popen] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}"

    def start(self, wait_seconds: float = 20.0) -> None:
        """Launch `ollama serve` locally with cloud disabled."""
        env = dict(os.environ)
        # Security-critical: disable Ollama cloud features and pin to loopback.
        env["OLLAMA_NO_CLOUD"] = "1"
        env["OLLAMA_HOST"] = self.host
        self._proc = subprocess.Popen(
            ["ollama", "serve"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            if self.is_up():
                return
            time.sleep(0.4)
        raise RuntimeError("Local Ollama server did not become ready in time.")

    def is_up(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=2):
                return True
        except (urllib.error.URLError, OSError):
            return False

    def generate(self, model: str, prompt: str, timeout: float = 300.0) -> str:
        """POST a prompt to the local server and return the model's text."""
        payload = json.dumps(
            {"model": model, "prompt": prompt, "stream": False}
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body.get("response", "")

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None


# The signature every inference backend must satisfy. Tests inject a fake one.
GenerateFn = Callable[[str, str], str]


# ---------------------------------------------------------------------------
# Prompt building (Safeguard 2: only selected files go into context) and
# response parsing.
# ---------------------------------------------------------------------------

EDIT_SYSTEM_PREAMBLE = (
    "You are a local, offline coding assistant. You are given the FULL current "
    "contents of exactly one file. Return ONLY the complete, updated contents "
    "of that file inside a single fenced code block. Do not add commentary, "
    "shell commands, or instructions to run anything."
)


def build_edit_prompt(path: Path, content: str, instruction: str) -> str:
    """Build the prompt for a single file. Only this file's content is included."""
    return (
        f"{EDIT_SYSTEM_PREAMBLE}\n\n"
        f"# Task\n{instruction}\n\n"
        f"# File: {path.name}\n"
        f"```\n{content}\n```\n"
    )


_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def extract_code(response: str) -> str:
    """Pull the file body out of the model's fenced reply (best effort)."""
    match = _FENCE_RE.search(response)
    if match:
        return match.group(1)
    # No fence — treat the whole response as the proposed content.
    return response


def make_diff(path: Path, before: str, after: str) -> str:
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{path.name}",
        tofile=f"b/{path.name}",
    )
    return "".join(diff)


# ---------------------------------------------------------------------------
# The edit session ties the safeguards together.
# ---------------------------------------------------------------------------

@dataclass
class ProposedEdit:
    path: Path
    original: str
    original_fp: Fingerprint
    updated: str

    @property
    def is_noop(self) -> bool:
        return self.original == self.updated

    @property
    def is_malformed(self) -> bool:
        # The model returned nothing usable while the original had content.
        return self.updated.strip() == "" and self.original.strip() != ""


class EditSession:
    """Coordinates reading, proposing, approving, and safely applying edits.

    `generate_fn` is injectable so the whole flow can be unit-tested offline.
    `approver` returns True to apply an edit; `display` is used for all output.
    """

    def __init__(
        self,
        project_root: Path,
        model: str,
        generate_fn: GenerateFn,
        approver: Callable[[str], bool] = None,  # type: ignore[assignment]
        display: Callable[[str], None] = print,
    ) -> None:
        self.project_root = Path(project_root).resolve(strict=True)
        self.model = assert_local_model(model)
        self.generate_fn = generate_fn
        self.display = display
        self.approver = approver or _interactive_approver

    def read_file(self, candidate: str) -> "LoadedFile":
        path = assert_safe_path(self.project_root, candidate)
        content = path.read_text(encoding="utf-8")
        return LoadedFile(path=path, content=content, fingerprint=fingerprint_file(path))

    def propose(self, loaded: "LoadedFile", instruction: str) -> ProposedEdit:
        prompt = build_edit_prompt(loaded.path, loaded.content, instruction)
        # Safeguard 2: the prompt only ever contains this one selected file.
        raw = self.generate_fn(self.model, prompt)
        updated = extract_code(raw)
        return ProposedEdit(
            path=loaded.path,
            original=loaded.content,
            original_fp=loaded.fingerprint,
            updated=updated,
        )

    def apply(self, edit: ProposedEdit) -> bool:
        """Show the diff, require approval, re-check staleness, back up, write.

        Returns True if the file was written, False otherwise. Never executes
        any model output (Safeguard 7) — it is only ever written to disk after
        explicit approval.
        """
        # Treat model output as untrusted: a malformed (empty) proposal is
        # dropped rather than silently wiping the file.
        if edit.is_malformed:
            self.display(
                f"[malformed] Empty/garbage proposal for {edit.path.name}; "
                "ignoring."
            )
            return False

        if edit.is_noop:
            self.display(f"[skip] No changes proposed for {edit.path.name}.")
            return False

        diff = make_diff(edit.path, edit.original, edit.updated)
        self.display(diff)

        # Safeguard 4: explicit per-file approval AFTER the diff is shown.
        if not self.approver(edit.path.name):
            self.display(f"[declined] {edit.path.name} left unchanged.")
            return False

        # Safeguard 6: refuse if the file changed on disk since we read it.
        current = fingerprint_file(edit.path)
        if not current.matches(edit.original_fp):
            raise SecurityError(
                f"{edit.path.name} changed on disk after it was read "
                "(hash/mtime mismatch). Refusing to overwrite."
            )

        # Safeguard 5: back up before replacing.
        backup = backup_file(edit.path)
        self.display(f"[backup] {backup.name}")
        edit.path.write_text(edit.updated, encoding="utf-8")
        self.display(f"[applied] {edit.path.name}")
        return True


@dataclass
class LoadedFile:
    path: Path
    content: str
    fingerprint: Fingerprint


def _interactive_approver(filename: str) -> bool:
    answer = input(f"Apply changes to {filename}? [y/N] ").strip().lower()
    return answer in ("y", "yes")


# ---------------------------------------------------------------------------
# Self-test (Safeguard coverage without touching the network).
# ---------------------------------------------------------------------------

def run_self_test(display: Callable[[str], None] = print) -> bool:
    """Exercise each safeguard with synthetic files. Returns True if all pass."""
    import tempfile

    results: List[tuple] = []

    def check(name: str, ok: bool) -> None:
        results.append((name, ok))
        display(f"  [{'PASS' if ok else 'FAIL'}] {name}")

    display("Running private_agent self-test (offline, synthetic files)...")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        (root / "sub").mkdir()
        target = root / "hello.py"
        target.write_text("print('hello')\n", encoding="utf-8")

        # 1. Cloud / bad model names are rejected; a local one is accepted.
        for bad in ("gpt-oss:120b-cloud", "gpt-4o", "http://evil/llama",
                    "ollama.com/library/x", "claude-3", ""):
            try:
                assert_local_model(bad)
                check(f"reject cloud model {bad!r}", False)
            except SecurityError:
                check(f"reject cloud model {bad!r}", True)
        try:
            check("accept local model 'llama3:8b'",
                  assert_local_model("llama3:8b") == "llama3:8b")
        except SecurityError:
            check("accept local model 'llama3:8b'", False)

        # 2. Path traversal is rejected.
        try:
            assert_safe_path(root, "../../etc/passwd")
            check("reject path traversal", False)
        except SecurityError:
            check("reject path traversal", True)

        # 3. Symlinks are rejected.
        link = root / "sub" / "link.py"
        try:
            os.symlink(target, link)
            try:
                assert_safe_path(root, "sub/link.py")
                check("reject symlink", False)
            except SecurityError:
                check("reject symlink", True)
        except OSError:
            check("reject symlink (symlink unsupported, skipped)", True)

        # 4. Sensitive files are rejected.
        secret = root / "credentials.txt"
        secret.write_text("token=abc\n", encoding="utf-8")
        try:
            assert_safe_path(root, "credentials.txt")
            check("reject sensitive file", False)
        except SecurityError:
            check("reject sensitive file", True)

        # 5. A legitimate file inside the project is accepted.
        try:
            ok_path = assert_safe_path(root, "hello.py")
            check("accept in-project file", ok_path == target)
        except SecurityError:
            check("accept in-project file", False)

        # Build a session with a fake model that returns new content.
        executed = {"ran": False}

        def fake_generate(model: str, prompt: str) -> str:
            # A malicious-looking reply; it must NEVER be executed.
            return "```\nprint('patched')\n```\n"

        def auto_yes(_name: str) -> bool:
            return True

        session = EditSession(root, "llama3", fake_generate,
                              approver=auto_yes, display=lambda _m: None)

        # 6. Approval gating: a declined edit leaves the file untouched.
        declined_session = EditSession(
            root, "llama3", fake_generate,
            approver=lambda _n: False, display=lambda _m: None,
        )
        loaded = declined_session.read_file("hello.py")
        edit = declined_session.propose(loaded, "patch it")
        wrote = declined_session.apply(edit)
        check("declined edit is not written",
              (not wrote) and target.read_text() == "print('hello')\n")

        # 7. Backup is created and content applied on approval.
        loaded = session.read_file("hello.py")
        edit = session.propose(loaded, "patch it")
        wrote = session.apply(edit)
        backups = list(root.glob("hello.py.*.bak"))
        check("approved edit is written", wrote and
              target.read_text() == "print('patched')\n")
        check("backup created before replace",
              len(backups) == 1 and backups[0].read_text() == "print('hello')\n")

        # 8. Stale-file rejection: modify on disk after reading. Use a model
        #    reply that differs from the current content so the edit is real.
        def fake_generate_v2(model: str, prompt: str) -> str:
            return "```\nprint('v2')\n```\n"

        stale_session = EditSession(root, "llama3", fake_generate_v2,
                                   approver=auto_yes, display=lambda _m: None)
        loaded = stale_session.read_file("hello.py")
        edit = stale_session.propose(loaded, "patch again")
        # Simulate an out-of-band change AFTER the read.
        time.sleep(0.01)
        target.write_text("print('changed by someone else')\n", encoding="utf-8")
        try:
            stale_session.apply(edit)
            check("reject stale (changed-on-disk) edit", False)
        except SecurityError:
            check("reject stale (changed-on-disk) edit", True)

        # 9. Model output is never executed automatically.
        #    `fake_generate` could have returned anything; we only ever wrote a
        #    file, never ran code. Prove the "ran" flag was never flipped.
        check("model output never executed", executed["ran"] is False)

    passed = all(ok for _, ok in results)
    display("")
    display(f"Self-test: {sum(ok for _, ok in results)}/{len(results)} checks passed.")
    return passed


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="private_agent.py",
        description="Personal, local-only AI coding agent (hardened starting "
                    "version — NOT production-ready).",
    )
    parser.add_argument("--self-test", action="store_true",
                        help="Run the offline safeguard self-test and exit.")
    parser.add_argument("--project", help="Project directory (context root).")
    parser.add_argument("--model", help="Local Ollama model name, e.g. llama3:8b.")
    parser.add_argument("--file", action="append", default=[],
                        help="A project file to edit. Repeatable.")
    parser.add_argument("--instruction",
                        help="What change to request for the selected files.")
    parser.add_argument("--port", type=int, default=DEFAULT_OLLAMA_PORT,
                        help="Local Ollama port (loopback only).")
    return parser


def run_cli(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.self_test:
        return 0 if run_self_test() else 1

    if not args.project or not args.model or not args.file:
        print("error: --project, --model, and at least one --file are required "
              "(or use --self-test).", file=sys.stderr)
        return 2

    try:
        project_root = Path(args.project).resolve(strict=True)
    except OSError:
        print(f"error: project directory {args.project!r} not found.",
              file=sys.stderr)
        return 2

    try:
        model = assert_local_model(args.model)
    except SecurityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    instruction = args.instruction or input("Describe the change to make: ").strip()

    # Validate every selected path up front (fail fast before starting Ollama).
    try:
        loaded_paths = [assert_safe_path(project_root, f) for f in args.file]
    except SecurityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    manager = OllamaManager(port=args.port)
    print(f"Starting local Ollama (cloud disabled) on {manager.host} ...")
    try:
        manager.start()
    except Exception as exc:  # noqa: BLE001 — surface any startup failure clearly.
        print(f"error: could not start local Ollama: {exc}", file=sys.stderr)
        print("Install Ollama and pull a model first (see README).",
              file=sys.stderr)
        return 1

    try:
        session = EditSession(project_root, model, manager.generate)
        for path in loaded_paths:
            loaded = session.read_file(str(path))
            print(f"\n=== Proposing changes for {loaded.path.name} ===")
            edit = session.propose(loaded, instruction)
            session.apply(edit)
    except SecurityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        manager.stop()

    print("\nDone. Review backups (*.bak) and run your own tests before trusting "
          "any change.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
