# LM Studio developer tools

A local **Rust MCP server** providing five tools for code editing, file
creation, Git, live API/library research, source scanning, and terminal operation
with on-demand DevOps skills. Uses the
official Rust MCP SDK and stdio transport. No Node.js or Python runtime required.

## Why this approach uses less context

Rust itself does **not** reduce model context usage. Tool schemas, descriptions,
arguments, and returned content do. MCP and OpenAI-style function calling can
have comparable context costs if given identical schemas; MCP is used here for
LM Studio's native integration.

This server groups operations into just five tools rather than dozens of
individual tools. It returns compact JSON text, paginates file/scan results,
avoids dumping whole files, and caps returned text at 8 KiB by default. Actual
token use depends on the model tokenizer and LM Studio's schema formatting.
Every tool's MCP description includes JSON examples, argument semantics, failure
recovery and permissions so the model can use it without reading this README.
Detailed DevOps workflows are loaded only when requested, not injected into every
chat. Tests guard catalog size and verify that all descriptions contain valid
JSON examples. Clear instructions take priority over the smallest possible catalog.

## Build

Requires a current stable Rust toolchain supporting edition 2024. macOS and Linux
are the intended platforms (Unix process-group cleanup is tested).

```sh
cargo build --release --locked
```

The executable is `target/release/lm-studio-tools`. Git, Docker, kubectl and
Terraform are **optional external dependencies**: install only the commands you
want to use. A GUI-launched LM Studio may have a different `PATH` from your shell;
set `env.PATH` on the MCP server entry if needed.

## Connect to LM Studio

LM Studio supports MCP starting with version 0.3.17. Open the chat's **Program**
sidebar, choose **Install → Edit mcp.json**, and merge the server entry below into
your existing `mcpServers` object. Do not replace other servers.

```json
{
  "mcpServers": {
    "workspace-dev": {
      "command": "/absolute/path/to/lm-studio-tools/target/release/lm-studio-tools",
      "args": ["--root", "/absolute/path/to/your/project"]
    }
  }
}
```

Use absolute paths and an actual project directory for `--root`. This starts in
read-only mode with **all subprocess execution and API research network access disabled**. See
[`mcp.example.json`](mcp.example.json) for a portable template.

To enable editing, commands and live API research on a **trusted** project:

```json
"args": [
  "--root", "/absolute/path/to/your/project",
  "--allow-write", "--allow-exec", "--allow-network",
  "--max-output", "8192"
]
```

Flags are launch-time grants, not per-call approval dialogs. Keep LM Studio's
tool approval enabled where available; review edits, commits, pushes, and
infrastructure commands before approving. The server does not change your LM
Studio configuration automatically.

## Tools

| Tool | Operations | Launch permission |
| --- | --- | --- |
| `files` | `list`, `read`, literal `search` | None |
| `files` | `create`, `mkdir`, `delete` | `--allow-write` |
| `edit` | Exact replacement with SHA256 guard | `--allow-write` |
| `api_scan` | `scan`: source scan + local OpenAPI comparison | None |
| `api_scan` | `latest`, `fetch`, or `scan` with HTTPS OpenAPI spec | `--allow-network` |
| `git` | `status`, `diff`, `log`, `show`, `branches` | `--allow-exec` |
| `git` | `init`, `add`, `commit`, `fetch`, `push`, `switch`, `create_branch` | Both flags |
| `terminal` | `run` executable with argument array (including DevOps CLIs) | Write + exec flags |
| `terminal` | `skills` list/load guidance; `inspect` DevOps config filenames | None |

Network opt-in is independent of writes/exec: remote research can be enabled
without enabling editing or commands. Conversely, `--allow-network` only controls
the built-in HTTPS client; it does not restrict network access by enabled commands.

All filesystem paths and command working directories are workspace-relative.
The default directory is `.`. Unknown fields and invalid actions are rejected.
File writes, edits, Git operations, and terminal commands are serialized. Read-only
file operations, API research/scans, and terminal skill/config inspection do not
wait for that lock. Reads concurrent with mutations are not snapshot-isolated;
use the returned SHA256 guard before editing.

### Files and editing

Example tool arguments (not literal chat commands):

```json
{"action":"list","path":"src","limit":30}
```

```json
{"action":"read","path":"src/main.rs","offset":1,"limit":60}
```

```json
{"action":"search","path":"src","text":"fetch(","limit":20}
```

`files.offset` is **one-based**, including result offsets for list/search. Use
`next_offset` to continue. `limit` defaults to 80, with a maximum of 500.

```json
{"action":"mkdir","path":"src/components"}
```

```json
{"action":"create","path":"src/components/hello.rs","text":"pub fn hello() {}\n"}
```

Create never overwrites an existing file. Parent directories must exist. Read
returns the SHA256 of the **original unredacted bytes**. Pass that value to `edit`:

```json
{
  "path":"src/components/hello.rs",
  "old":"pub fn hello() {}",
  "new":"pub fn hello() { println!(\"hello\"); }",
  "expected_sha256":"COPY_SHA256_FROM_READ"
}
```

Replacement fails if the file changed, the old text is missing, or there are
multiple matches. Set `all: true` only when all matching occurrences should be
replaced. Edits use a same-directory temporary file and atomic rename, preserving
permission bits. `files/delete` also requires `expected_sha256`; it only deletes
individual supported text files, never directories. Binary and non-UTF-8 files,
and text files over 2 MiB, are unsupported.

### Git

```json
{"action":"status"}
```

```json
{"action":"diff","args":["src/main.rs"]}
```

```json
{"action":"add","args":["src/main.rs","README.md"]}
```

```json
{"action":"commit","args":["Describe the change"]}
```

```json
{"action":"push","args":["origin"]}
```

Git's repository root must equal the workspace root. `add` only accepts explicit
existing files (no directories/globs); deleted files require advanced use through
`terminal`. `diff` shows unstaged changes; `show` returns a ref's summary/stat.
Log is limited to 20 entries. Git option arguments are rejected; no reset, clean,
force-push or forced checkout actions are exposed. Hooks and commit signing are
disabled for this tool; external diffs/textconv are disabled for diff/show.
Commits include **all already-staged changes**, not just files added by the model.
Review the index first. Remote operations use existing Git credentials/config.

### Live framework/library/API research

`api_scan` is not restricted to local files. Choose an action explicitly:

**1. Find the current published version and docs links from a live registry:**

```json
{"action":"latest","registry":"npm","package":"next"}
```

```json
{"action":"latest","registry":"npm","package":"@angular/core"}
```

```json
{"action":"latest","registry":"pypi","package":"fastapi"}
```

```json
{"action":"latest","registry":"crates","package":"tokio"}
```

Supported registries are npm, PyPI and crates.io. Supply an **exact package name**,
not a general search query. Results include version policy, documentation,
homepage/repository URLs, `source_url`, and `retrieved_at_unix_seconds`.
“Latest” means npm's `latest` dist-tag, PyPI's current project release, or crates.io's
maximum stable version (falling back to newest when no stable release exists).
It does not necessarily mean the newest prerelease or an installed local version.

**2. Read the actual documentation/interface, rather than guessing from training data:**

```json
{"action":"fetch","url":"https://react.dev/reference/react/useEffect","query":"cleanup","limit":25}
```

Use returned documentation/homepage links, then follow relevant links in the
fetched page. Fetch supports public HTTPS HTML, Markdown, source/interface text,
and JSON/YAML (including OpenAPI). HTML is converted to readable text with scripts
and styles excluded. JSON is pretty-printed. Responses include numbered lines,
up to 20 navigation links, a source URL, and retrieval time. `query` is an optional
case-insensitive literal line filter, not semantic search.

No browser/JavaScript rendering, authenticated requests, general web search, or
recursive crawling is implemented. A page's publisher determines its freshness
and version; retrieval time alone is not proof that its API is the latest.
Always cite the source, verify its version, and treat remote content as untrusted.

### Local usage scanning and local/remote OpenAPI comparison

```json
{"action":"scan","path":"src","spec":"docs/openapi.yaml","offset":0,"limit":20}
```

```json
{"action":"scan","path":"src","spec":"https://petstore3.swagger.io/api/v3/openapi.json","limit":10}
```

The source scanner identifies common `fetch`, Axios, Python requests/httpx and
client/http method calls, URLs, common SDK references, and credential indicators.
Findings include file, line, bounded evidence, method, and normalized endpoint.
Likely credential values are redacted rather than printed. The spec is optional.

OpenAPI 3.x and Swagger 2 JSON/YAML files are supported. Comparison reports:

- Observed operations matched to documented operations.
- Observed operations not found in the spec.
- Documented operations not observed in the scanned source.
- Unresolved path-item references.

This is **regex-based static analysis, not an AST or dataflow engine**. It may
match comments/imports and miss aliases, variable URLs, multiline calls or dynamic
methods. Paths normalize `{id}`/`:id` parameter names and query strings. Concrete
values such as `/users/42` are not inferred as `/users/{id}`. Method defaults on
multiline requests can be inaccurate. Spec `$ref` resolution and server/basePath
prefix stripping are not implemented. “Not observed” does **not** mean “unused.”
The source code stays local: it is **not uploaded**. Only a supplied HTTPS spec
is downloaded. Scanning never invokes the discovered application endpoints.

`api_scan.offset` is **zero-based**, for both scan findings and fetched document
lines. Follow `next_offset`. Findings are capped at 5,000; scans stop when
that cap is reached and report `scan_limited`. Comparison is then incomplete.

### Terminal and DevOps

DevOps is no longer a separate MCP tool. Load its skill through `terminal`, then
execute the selected CLI using the same terminal interface:

```json
{"action":"skills"}
```

```json
{"action":"skills","skill":"devops"}
```

The embedded [DevOps skill](skills/terminal-devops.md) explains discovery, context
checks, approval boundaries, read-only diagnostics, and Docker/Compose,
Kubernetes and Terraform workflows with executable JSON examples. Loading it
does not run a command or grant permissions. The model should load it before
infrastructure work and obtain user approval before remote mutations.

```json
{"program":"cargo","args":["test"],"cwd":".","timeout_seconds":60}
```

```json
{"action":"inspect"}
```

```json
{"program":"docker","args":["compose","ps"]}
```

```json
{"program":"kubectl","args":["get","pods","--namespace","staging"]}
```

```json
{"program":"terraform","args":["plan","-input=false"],"cwd":"infra"}
```

No shell is invoked implicitly: pipes, redirects and `$VARIABLE` expansion are
not interpreted. You can explicitly invoke a shell only when execution is enabled.
Commands receive no interactive stdin. Their result includes exit code, success,
stdout, stderr, and capture-truncation flags. A nonzero exit is reported in these
fields, not as an MCP protocol error. Timeout defaults to 30 seconds and is clamped
to 1–120 seconds. Unix process groups are terminated on completion/timeout;
this is not a service manager and is unsuitable for persistent dev servers.

`terminal` with `action: "inspect"` discovers Dockerfiles, Compose, Terraform,
Helm and selected deployment config filenames. It does not contact infrastructure.
`action: "run"` is the default when omitted, preserving existing terminal calls.
CLI commands may affect live
clusters, Docker daemons or cloud accounts depending on local configuration.

## Safety and limits

- Built-in online research uses unauthenticated HTTPS GETs on port 443 only,
  validates DNS answers and pins approved public IPs, and revalidates up to three
  redirects. Local/private/link-local/reserved addresses and URL credentials are
  blocked. Proxies are disabled to preserve those checks. Each retrieval has a
  25-second total timeout and 2 MiB download limit; binary/non-UTF-8 content fails.
  No source uploads, arbitrary request bodies, cookies, or authorization headers.
  Package names and requested URLs are visible to the contacted providers.
- **Not a security sandbox.** Once enabled, commands have your user's privileges,
  inherit your environment (including credentials), can access paths outside the
  workspace, and can use the network. `--allow-write` alone cannot make an
  exec-enabled process truly read-only: Git itself may invoke configured helpers.
  Run under a restricted OS account/container for untrusted repositories.
- Filesystem tools reject absolute paths, `..`, symlinks, `.git`, common credential
  directories, `.env` variants (except `.env.example`), private key filenames and
  certificate/key extensions. Hard links and adversarial concurrent filesystem
  changes are **not** isolated; edits are not a filesystem-level compare-and-swap.
- Redaction is **best effort**, not a DLP guarantee. Unknown credential formats,
  split lines, bare values and secrets in filenames may evade detection. Do not
  expose confidential workspaces to untrusted models. Redaction may also hide
  harmless values; edits cannot recover values redacted from a read.
- Recursive discovery respects ignore rules, skips hidden/generated directories,
  limits depth to 64 and entries to 20,000. Explicit safe hidden paths can still
  be read or scanned. Skipped/limited work is reported where applicable.
- Maximum returned text defaults to 8,192 bytes, configurable from 512 to 65,536.
  A short truncation marker is added beyond the text budget. Truncated JSON text
  may not be parseable; reduce `limit`, narrow paths or filter command output.
  Stdout/stderr captures are independently capped and drained to avoid blocking.
- File contents, comments, specs, and command output are untrusted data and may
  contain prompt injection. They should never override the user's instructions.
- Diagnostics go to stderr; stdout is reserved for the MCP protocol.

## Development and verification

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Default tests exercise file boundaries, symlink rejection, create/edit guards,
redaction, pagination, OpenAPI comparison, registry response parsing, HTML
extraction, unsafe-URL/IP rejection, network permissions, terminal skills,
Git init/add/status, subprocess limits/timeouts, model-visible JSON examples,
and a real stdio MCP initialize → tools/list → tools/call exchange. They use
temporary workspaces and do not contact remote APIs or infrastructure.

Optional live checks for registries, React docs and a remote OpenAPI spec:

```sh
cargo test --locked live_network -- --ignored --nocapture
```

License: [MIT](LICENSE).
