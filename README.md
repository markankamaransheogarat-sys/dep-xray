# dep-xray

**Behavioral AST diff analyzer for dependency updates.**

Every day, Dependabot and Renovate open PRs bumping 20–50 transitive dependencies in `Cargo.lock`, `package-lock.json`, or `pnpm-lock.yaml`. A standard `git diff` only shows version numbers and integrity hashes — nobody reads thousands of lines of upstream source code for every bump. That's how supply-chain attacks (`xz-utils`, malicious npm `postinstall` scripts, `.env` exfiltration in `build.rs`) slip through.

`dep-xray` fetches **only the changed packages**, diffs the **actual source code** between the old and new versions, and runs **Tree-sitter AST behavioral analysis** exclusively on the added/modified code (or the full source for newly added packages) — filtering out 99% of benign noise and surfacing dangerous capability changes.

---

## Features

- **Lockfile Diffing:** `Cargo.lock` (Rust), `package-lock.json` v1/v2/v3 (npm), and `pnpm-lock.yaml` v5/v6/v9 (pnpm).
- **Fast Parallel Fetching & Caching:** Concurrently fetches only updated/added tarballs from `crates.io` (`static.crates.io`) and `registry.npmjs.org`, reusing `~/.cargo/registry/cache` and a local disk cache.
- **Line-Accurate AST Analysis:** Uses `tree-sitter` (Rust, JavaScript, TypeScript, TSX) to inspect only newly added/changed AST nodes, ignoring comments and documentation files.
- **Rich Output Formats:** Terminal table with code snippets, GitHub PR Markdown comments (`--format markdown`), SARIF 2.1.0 (`--format sarif`) for GitHub Code Scanning, and JSON (`--format json`).
- **Memory-Safe:** Built with `#![forbid(unsafe_code)]`.

---

## Installation

```bash
cargo install --git https://github.com/markankamaransheogarat-sys/dep-xray
```

---

## Usage

### Local Git Diff

```bash
# Compare the last commit
dep-xray diff HEAD~1..HEAD

# Compare a PR branch against main and fail on HIGH or CRITICAL signals
dep-xray diff --base main --head HEAD --fail-on high

# Generate a Markdown PR comment
dep-xray diff main..HEAD --format markdown --output report.md

# Generate SARIF 2.1.0 for GitHub Security / Code Scanning
dep-xray diff main..HEAD --format sarif --output dep-xray.sarif
```

### Direct Lockfile Comparison (without Git)

```bash
dep-xray lockfiles old/Cargo.lock new/Cargo.lock --format terminal
```

---

## GitHub Action

Add `dep-xray` to any repository in 5 lines of YAML:

```yaml
name: Dependency Behavioral Audit
on: [pull_request]

jobs:
  dep-xray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: markankamaransheogarat-sys/dep-xray@main
        with:
          fail-on: high
          format: markdown
```

---

## Example Markdown PR Comment

```markdown
## dep-xray Behavioral Diff Report — **FAIL**

- **Packages analyzed:** 2
- **Capability signals:** 3
- **Total risk score:** 150

| Package | Ecosystem | Version | Risk Score | Max Severity | Signals |
| --- | --- | --- | ---: | --- | ---: |
| `evil-crate` | `cargo` | `0.1.0 -> 0.1.1` | 150 | **CRITICAL** | 3 |
| `benign-utils` | `cargo` | `1.2.0 -> 1.2.1` | 0 | **CLEAN** | 0 |

### Capability Signals

- **[CRITICAL]** `DX005` `Network client or socket usage` (`evil-crate@0.1.1:build.rs:4`): Uses HTTP client or raw TCP/UDP socket APIs.
- **[CRITICAL]** `DX008` `Environment variable read (std::env::var)` (`evil-crate@0.1.1:build.rs:5`): Reads runtime or build-time environment variables.
```

---

## Capability Detectors

| Rule ID | Category | Default Severity | What It Detects |
| --- | --- | --- | --- |
| `DX001` | Execution / Install Hook | `MEDIUM` | Added or modified `build.rs` compile-time script |
| `DX002` | Execution / Install Hook | `HIGH` / `CRITICAL` | Added/modified `preinstall`, `install`, `postinstall`, `prepare` in `package.json` |
| `DX003` | Execution / Install Hook | `HIGH` / `CRITICAL` | `std::process::Command` / `tokio::process::Command` in Rust (`CRITICAL` in `build.rs`) |
| `DX004` | Execution / Install Hook | `HIGH` | `child_process` (`exec`, `execSync`, `spawn`, `spawnSync`, `execFile`) in JS/TS |
| `DX005` | Network / Exfiltration | `HIGH` / `CRITICAL` | `reqwest`, `ureq`, `hyper`, `TcpStream`, `UdpSocket` in Rust (`CRITICAL` in `build.rs`) |
| `DX006` | Network / Exfiltration | `HIGH` | `fetch()`, `http.request`, `https.request`, `net.connect`, `WebSocket` in JS/TS |
| `DX007` | Network / Exfiltration | `MEDIUM` / `HIGH` | Hardcoded external URLs or raw IPv4 addresses in code string literals |
| `DX008` | Sensitive Read / Env | `MEDIUM` / `CRITICAL` | `std::env::var`, `env!()`, `process.env` (`CRITICAL` in `build.rs`) |
| `DX009` | Sensitive Read / Env | `CRITICAL` | References to `.ssh`, `.aws/credentials`, `.npmrc`, `.cargo/credentials`, `.env` |
| `DX010` | Unsafe / Dynamic Code | `HIGH` | New `unsafe { ... }` blocks, `unsafe fn`, or `std::mem::transmute` in Rust |
| `DX011` | Unsafe / Dynamic Code | `HIGH` / `CRITICAL` | `eval()`, `new Function()`, `WebAssembly.instantiate`, dynamic `require()` |
| `DX012` | Obfuscation / Entropy | `HIGH` | Long high-entropy base64/hex string literals in source code |
| `DX013` | Obfuscation / Entropy | `HIGH` / `CRITICAL` | `atob()` or `Buffer.from(..., 'base64'|'hex')` (`CRITICAL` near `eval`/`exec`) |
| `DX014` | Obfuscation / Entropy | `CRITICAL` | Invisible or bidirectional override Unicode characters (Trojan Source) |

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
