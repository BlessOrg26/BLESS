# VERIFICATION — PersonalCodingAgent

Exact commands run in the development environment (Linux, Python 3.12.3) and
their **actual** results. Ollama was **mocked** throughout — no network access
and no model were used. **Nothing was run on the user's Mac**, so macOS behavior
is **not** verified here.

## 1. Offline self-test

Command:
```bash
python3 private_agent.py --self-test
```

Actual output:
```
Running private_agent self-test (offline, synthetic files)...
  [PASS] reject cloud model 'gpt-oss:120b-cloud'
  [PASS] reject cloud model 'gpt-4o'
  [PASS] reject cloud model 'http://evil/llama'
  [PASS] reject cloud model 'ollama.com/library/x'
  [PASS] reject cloud model 'claude-3'
  [PASS] reject cloud model ''
  [PASS] accept local model 'llama3:8b'
  [PASS] reject path traversal
  [PASS] reject symlink
  [PASS] reject sensitive file
  [PASS] accept in-project file
  [PASS] declined edit is not written
  [PASS] approved edit is written
  [PASS] backup created before replace
  [PASS] reject stale (changed-on-disk) edit
  [PASS] model output never executed

Self-test: 16/16 checks passed.
```
Exit code: `0`.

## 2. Unit test suite (stdlib unittest)

Command:
```bash
python3 -m unittest discover -s tests -v
```

Actual result (summary):
```
Ran 31 tests in 0.061s

OK
```
All 31 tests reported `... ok`; exit code `0`.

Test classes exercised:
`CodeExtractionTests`, `EditSessionTests`, `FingerprintAndBackupTests`,
`FullWorkflowTests`, `HardLinkAndSizeTests`, `MalformedAndDuplicateTests`,
`ModelValidationTests`, `OllamaManagerTests`, `PathSafetyTests`, `SelfTestTests`.

## 3. Unit test suite (pytest)

Command:
```bash
python3 -m pytest tests/ -q
```

Actual output:
```
...............................                                          [100%]
31 passed in 0.10s
```
Exit code: `0`.

## What remains UNTESTED here (honest list)

- **Real Ollama inference.** All model calls were mocked; no real
  `ollama serve`, no real model, no real `/api/generate` round-trip was
  exercised.
- **macOS.** No command in this file was run on the user's Mac; macOS
  compatibility is unverified.
- **Live network behavior.** By design, nothing contacted the network, so the
  loopback HTTP client was not exercised against a running server.
- **Large real-world projects / binary files** beyond the synthetic fixtures.
