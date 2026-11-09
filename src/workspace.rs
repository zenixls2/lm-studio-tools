use std::{
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::LazyLock,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use ignore::WalkBuilder;
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncReadExt, process::Command};

use crate::{EditArgs, FileAction, FileArgs, GitAction, GitArgs, TerminalAction, TerminalArgs};

pub const MAX_FILE: u64 = 2 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 20_000;

pub struct Workspace {
    pub root: PathBuf,
    pub allow_write: bool,
    pub allow_exec: bool,
    pub allow_network: bool,
    pub max_output: usize,
}

// Best effort, deliberately conservative. Never return matching credential values.
static SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r#"(?i)(["']?(?:[a-z0-9_]*(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)[a-z0-9_]*|authorization)["']?\s*[:=]\s*)(?:["'][^"'\r\n]*["']|[^\s,;}]+)"#
).unwrap()
});
static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r"(?:\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b|(?i:Bearer)\s+[A-Za-z0-9._~+/-]+=*)"
).unwrap()
});
static URL_AUTH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(https?://)[^/\s:@]+:[^/\s@]+@").unwrap());
static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")
        .unwrap()
});

pub fn redact(text: &str) -> String {
    let text = PRIVATE_KEY.replace_all(text, |capture: &regex::Captures<'_>| {
        // Preserve line numbers when redacting before pagination/search.
        std::iter::repeat_n(
            "[REDACTED PRIVATE KEY]",
            capture[0].bytes().filter(|b| *b == b'\n').count() + 1,
        )
        .collect::<Vec<_>>()
        .join("\n")
    });
    let text = TOKEN.replace_all(&text, "[REDACTED]");
    let text = SECRET.replace_all(&text, "$1[REDACTED]");
    URL_AUTH.replace_all(&text, "${1}[REDACTED]@").into_owned()
}

pub fn redact_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = redact(text),
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        Value::Object(map) => {
            for (key, value) in map {
                let probe = format!("{key}=sentinel");
                if redact(&probe) != probe {
                    *value = Value::String("[REDACTED]".into());
                } else {
                    redact_value(value);
                }
            }
        }
        _ => (),
    }
}

pub fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.into();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n[truncated; narrow the request or paginate]",
        &text[..end]
    )
}

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn sensitive(path: &Path) -> bool {
    path.components().any(|part| {
        let s = part.as_os_str().to_string_lossy().to_ascii_lowercase();
        s == ".git"
            || s == ".ssh"
            || s == ".aws"
            || s == ".gnupg"
            || s == ".env"
            || s.starts_with(".env.") && !s.ends_with(".example")
            || s.ends_with(".pem")
            || s.ends_with(".key")
            || s.ends_with(".p12")
            || s == "credentials"
            || s == "id_rsa"
            || s == "id_ed25519"
    })
}

impl Workspace {
    pub fn new(
        root: PathBuf,
        allow_write: bool,
        allow_exec: bool,
        max_output: usize,
    ) -> Result<Self> {
        let root = root.canonicalize().context("workspace root must exist")?;
        ensure!(root.is_dir(), "workspace root must be a directory");
        Ok(Self {
            root,
            allow_write,
            allow_exec,
            allow_network: false,
            max_output,
        })
    }

    pub fn output(&self, text: &str) -> String {
        truncate(text, self.max_output)
    }

    pub fn write_allowed(&self) -> Result<()> {
        ensure!(
            self.allow_write,
            "writes disabled; launch server with --allow-write"
        );
        Ok(())
    }

    /// Reject traversal, symlinks (including internal ones), and special credential paths.
    /// Does not claim protection against concurrent filesystem changes by other processes.
    pub fn resolve(&self, path: &str) -> Result<PathBuf> {
        let relative = Path::new(path);
        ensure!(!relative.is_absolute(), "use workspace-relative paths");
        ensure!(!sensitive(relative), "sensitive paths are blocked");
        let mut result = self.root.clone();
        for part in relative.components() {
            match part {
                Component::CurDir => (),
                Component::Normal(name) => {
                    result.push(name);
                    match fs::symlink_metadata(&result) {
                        Ok(meta) => ensure!(!meta.file_type().is_symlink(), "symlinks are blocked"),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                        Err(error) => return Err(error.into()),
                    }
                }
                _ => bail!("path traversal is blocked"),
            }
        }
        Ok(result)
    }

    pub fn relative(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    }

    pub fn read_text(&self, path: &Path) -> Result<String> {
        let mut file = fs::File::open(path)?;
        let meta = file.metadata()?;
        ensure!(meta.is_file(), "not a regular file");
        ensure!(meta.len() <= MAX_FILE, "file exceeds 2 MiB limit");
        let mut bytes = Vec::new();
        (&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= MAX_FILE, "file exceeds 2 MiB limit");
        ensure!(!bytes.contains(&0), "binary file is not supported");
        String::from_utf8(bytes).context("file must be UTF-8")
    }

    /// Ignores VCS/ignore rules, hidden files, generated directories, symlinks and secrets.
    pub fn walk(&self, path: &Path) -> Result<(Vec<PathBuf>, bool)> {
        ensure!(path.exists(), "path does not exist");
        let mut paths = Vec::new();
        let mut limited = false;
        let walker = WalkBuilder::new(path)
            .follow_links(false)
            .require_git(false)
            .max_depth(Some(64))
            .filter_entry(|entry| {
                let p = entry.path();
                !sensitive(p)
                    && !entry.file_type().is_some_and(|t| t.is_symlink())
                    && !matches!(
                        entry.file_name().to_str(),
                        Some("node_modules" | "target" | "dist" | "build" | "vendor" | ".venv")
                    )
            })
            .build();
        for entry in walker {
            let entry = entry.context("cannot traverse workspace")?;
            if paths.len() >= MAX_ENTRIES {
                limited = true;
                break;
            }
            paths.push(entry.into_path());
        }
        paths.sort();
        Ok((paths, limited))
    }

    pub fn files(&self, args: FileArgs) -> Result<Value> {
        let path = self.resolve(&args.path)?;
        let limit = args.limit.unwrap_or(80).clamp(1, 500);
        let offset = args.offset.unwrap_or(1).max(1) - 1;
        match args.action {
            FileAction::List => {
                let (paths, scan_limited) = self.walk(&path)?;
                let entries: Vec<_> = paths.iter().skip(offset).take(limit).map(|p| json!({
                    "path": self.relative(p), "type": if p.is_dir() { "directory" } else { "file" }
                })).collect();
                Ok(
                    json!({"entries": entries, "total": paths.len(), "scan_limited": scan_limited,
                    "next_offset": (offset.saturating_add(limit) < paths.len()).then_some(offset.saturating_add(limit).saturating_add(1))}),
                )
            }
            FileAction::Read => {
                let text = self.read_text(&path)?;
                let safe_text = redact(&text);
                let lines: Vec<_> = safe_text
                    .lines()
                    .enumerate()
                    .skip(offset)
                    .take(limit)
                    .map(|(i, line)| format!("{}: {}", i + 1, line))
                    .collect();
                let total = text.lines().count();
                Ok(
                    json!({"path": args.path, "sha256": hash(text.as_bytes()), "lines": lines,
                    "total_lines": total, "next_offset": (offset.saturating_add(limit) < total).then_some(offset.saturating_add(limit).saturating_add(1))}),
                )
            }
            FileAction::Search => {
                let query = args.text.context("text is required for literal search")?;
                ensure!(!query.is_empty(), "search text must not be empty");
                let (paths, scan_limited) = self.walk(&path)?;
                let mut hits = Vec::new();
                let mut total = 0usize;
                let mut skipped = 0;
                for path in paths.iter().filter(|p| p.is_file()) {
                    let Ok(text) = self.read_text(path) else {
                        skipped += 1;
                        continue;
                    };
                    let safe_text = redact(&text);
                    for (i, (line, safe_line)) in text.lines().zip(safe_text.lines()).enumerate() {
                        if line.contains(&query) {
                            if total >= offset && hits.len() < limit {
                                hits.push(json!({"path": self.relative(path), "line": i+1, "text": truncate(safe_line, 500)}));
                            }
                            total += 1;
                        }
                    }
                }
                Ok(
                    json!({"matches": hits, "total": total, "scan_limited": scan_limited, "skipped_files": skipped,
                    "next_offset": (offset.saturating_add(limit) < total).then_some(offset.saturating_add(limit).saturating_add(1))}),
                )
            }
            FileAction::Create => {
                self.write_allowed()?;
                let text = args.text.context("text is required for create")?;
                ensure!(text.len() as u64 <= MAX_FILE, "content exceeds 2 MiB limit");
                let parent = path.parent().context("no parent directory")?;
                ensure!(parent.is_dir(), "parent must exist; use mkdir first");
                let mut temp = tempfile::NamedTempFile::new_in(parent)?;
                temp.write_all(text.as_bytes())?;
                temp.as_file().sync_all()?;
                temp.persist_noclobber(&path)
                    .context("create failed; never overwrites existing paths")?;
                Ok(json!({"created": args.path, "sha256": hash(text.as_bytes())}))
            }
            FileAction::Mkdir => {
                self.write_allowed()?;
                fs::create_dir_all(path)?;
                Ok(json!({"created_directory": args.path}))
            }
            FileAction::Delete => {
                self.write_allowed()?;
                let text = self.read_text(&path)?;
                ensure!(
                    Some(hash(text.as_bytes())) == args.expected_sha256,
                    "expected_sha256 required and must match"
                );
                fs::remove_file(path)?;
                Ok(json!({"deleted": args.path}))
            }
        }
    }

    pub fn edit(&self, args: EditArgs) -> Result<Value> {
        self.write_allowed()?;
        ensure!(
            !args.old.is_empty(),
            "old must not be empty; use files/create for new files"
        );
        let path = self.resolve(&args.path)?;
        let text = self.read_text(&path)?;
        ensure!(
            hash(text.as_bytes()) == args.expected_sha256,
            "stale edit: SHA256 mismatch; read the file again"
        );
        let count = text.matches(&args.old).count();
        ensure!(count > 0, "old text was not found");
        ensure!(
            count == 1 || args.all,
            "old text occurs {count} times; narrow it or set all=true"
        );
        let updated = text.replace(&args.old, &args.new);
        ensure!(
            updated.len() as u64 <= MAX_FILE,
            "result exceeds 2 MiB limit"
        );
        let mut temp = tempfile::NamedTempFile::new_in(path.parent().context("no parent")?)?;
        temp.as_file()
            .set_permissions(fs::metadata(&path)?.permissions())?;
        temp.write_all(updated.as_bytes())?;
        temp.as_file().sync_all()?;
        // Catch external changes between the initial read and replacement.
        ensure!(
            hash(self.read_text(&path)?.as_bytes()) == args.expected_sha256,
            "file changed during edit"
        );
        temp.persist(&path)?;
        Ok(json!({"edited": args.path, "replacements": count, "sha256": hash(updated.as_bytes())}))
    }

    pub async fn terminal(&self, args: TerminalArgs) -> Result<Value> {
        match args.action {
            TerminalAction::Skills => {
                ensure!(
                    args.program.is_none() && args.args.is_empty(),
                    "skills does not execute commands; omit program/args"
                );
                return match args.skill.as_deref() {
                    None => Ok(
                        json!({"skills": [{"name": "devops", "description": "Safe Docker/Compose/Kubernetes/Terraform workflows", "load_example": {"action": "skills", "skill": "devops"}}]}),
                    ),
                    Some("devops") => Ok(
                        json!({"skill": "devops", "instructions": include_str!("../skills/terminal-devops.md")}),
                    ),
                    Some(_) => bail!(
                        "unknown skill; use terminal with action=skills to list available skills"
                    ),
                };
            }
            TerminalAction::Inspect => {
                ensure!(
                    args.program.is_none() && args.args.is_empty() && args.skill.is_none(),
                    "inspect accepts cwd only; omit program/args/skill"
                );
                return self.inspect_devops(&args.cwd);
            }
            TerminalAction::Run => ensure!(
                args.skill.is_none(),
                "load skills separately with action=skills, then run the chosen command"
            ),
        }
        self.write_allowed()?;
        let program = args.program.context(
            "run requires program, e.g. {\"program\":\"docker\",\"args\":[\"compose\",\"ps\"]}",
        )?;
        self.run(&program, &args.args, &args.cwd, args.timeout_seconds)
            .await
    }

    pub async fn git(&self, args: GitArgs) -> Result<Value> {
        let mut command: Vec<String> = vec![
            "--no-pager",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let mutating = !matches!(
            args.action,
            GitAction::Status
                | GitAction::Diff
                | GitAction::Log
                | GitAction::Show
                | GitAction::Branches
        );
        if mutating {
            self.write_allowed()?;
        }
        let extra = args.args;
        ensure!(
            extra.iter().all(|a| !a.starts_with('-')),
            "option arguments are not accepted by git tool; use terminal for advanced operations"
        );
        match args.action {
            GitAction::Status => {
                ensure!(extra.is_empty(), "status takes no args");
                command.extend(strings(&["status", "--short", "--branch"]));
            }
            GitAction::Diff => {
                for path in &extra {
                    self.resolve(path)?;
                }
                command.extend(strings(&["diff", "--no-ext-diff", "--no-textconv", "--"]));
                command.extend(extra);
            }
            GitAction::Log => {
                ensure!(extra.is_empty(), "log takes no args");
                command.extend(strings(&["log", "-20", "--oneline", "--decorate"]));
            }
            GitAction::Show => {
                ensure!(extra.len() <= 1, "show takes at most one ref");
                command.extend(strings(&[
                    "show",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--stat",
                ]));
                command.extend(extra);
            }
            GitAction::Branches => {
                ensure!(extra.is_empty(), "branches takes no args");
                command.extend(strings(&["branch", "--list"]));
            }
            GitAction::Init => {
                ensure!(extra.is_empty(), "init takes no args");
                command.push("init".into());
            }
            GitAction::Add => {
                ensure!(!extra.is_empty(), "add requires explicit paths");
                // Forbid directory/pathspec adds which could inadvertently stage secrets.
                for path in &extra {
                    ensure!(
                        self.resolve(path)?.is_file(),
                        "add only accepts explicit existing regular file paths"
                    );
                }
                command.extend(strings(&["--literal-pathspecs", "add", "--"]));
                command.extend(extra);
            }
            GitAction::Commit => {
                ensure!(extra.len() == 1, "commit requires one message");
                command.extend(strings(&["-c", "commit.gpgsign=false", "commit", "-m"]));
                command.extend(extra);
            }
            GitAction::Fetch | GitAction::Push => {
                ensure!(
                    extra.len() <= 1,
                    "fetch/push accept at most one remote name"
                );
                ensure!(
                    extra.iter().all(|a| a
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c))),
                    "use a configured remote name, not a URL"
                );
                command.push(
                    if matches!(args.action, GitAction::Fetch) {
                        "fetch"
                    } else {
                        "push"
                    }
                    .into(),
                );
                command.extend(extra);
            }
            GitAction::Switch | GitAction::CreateBranch => {
                ensure!(extra.len() == 1, "requires one branch name");
                command.push("switch".into());
                if matches!(args.action, GitAction::CreateBranch) {
                    command.push("-c".into());
                }
                command.extend(extra);
            }
        }
        // Do not accidentally operate on a parent repository outside the workspace.
        if !matches!(args.action, GitAction::Init) {
            let top = self
                .run(
                    "git",
                    &strings(&["rev-parse", "--show-toplevel"]),
                    ".",
                    Some(10),
                )
                .await?;
            ensure!(top["exit_code"] == 0, "workspace is not a Git repository");
            let root = top["stdout"].as_str().context("missing git root")?.trim();
            ensure!(
                Path::new(root).canonicalize()? == self.root,
                "Git repository root must equal workspace root"
            );
        }
        self.run("git", &command, ".", Some(60)).await
    }

    fn inspect_devops(&self, cwd: &str) -> Result<Value> {
        let path = self.resolve(cwd)?;
        let (paths, scan_limited) = self.walk(&path)?;
        let configs: Vec<_> = paths
            .iter()
            .filter(|p| p.is_file())
            .filter(|p| {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                name.starts_with("Dockerfile")
                    || name.starts_with("docker-compose")
                    || name.starts_with("compose.")
                    || name.ends_with(".tf")
                    || name == "Chart.yaml"
                    || name == "Jenkinsfile"
                    || name == "skaffold.yaml"
                    || name == "kustomization.yaml"
            })
            .map(|p| self.relative(p))
            .collect();
        Ok(json!({"configs": configs, "scan_limited": scan_limited,
                "note": "Filename discovery only. Use files/read; hidden CI directories require explicit paths."}))
    }

    pub async fn run(
        &self,
        program: &str,
        args: &[String],
        cwd: &str,
        seconds: Option<u64>,
    ) -> Result<Value> {
        ensure!(
            self.allow_exec,
            "execution disabled; launch server with --allow-exec"
        );
        ensure!(!program.is_empty(), "program is required");
        let cwd = self.resolve(cwd)?;
        ensure!(cwd.is_dir(), "cwd must be a directory");
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_PAGER", "cat")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("NO_COLOR", "1");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("could not launch {program}"))?;
        let pid = child.id();
        let group = ProcessGroup(pid);
        let stdout = child.stdout.take().context("stdout missing")?;
        let stderr = child.stderr.take().context("stderr missing")?;
        let cap = self.max_output;
        let out_task = tokio::spawn(capture(stdout, cap));
        let err_task = tokio::spawn(capture(stderr, cap));
        let timeout = Duration::from_secs(seconds.unwrap_or(30).clamp(1, 120));
        let result = tokio::time::timeout(timeout, async {
            let status = child.wait().await?;
            let out = out_task.await??;
            let err = err_task.await??;
            Ok::<_, anyhow::Error>((status, out, err))
        })
        .await;
        // Kill surviving descendants as well, including on successful parent exit.
        drop(group);
        match result {
            Ok(result) => {
                let (status, (out, out_truncated), (err, err_truncated)) = result?;
                Ok(
                    json!({"exit_code": status.code(), "success": status.success(),
                    "stdout": String::from_utf8_lossy(&out), "stderr": String::from_utf8_lossy(&err),
                    "stdout_truncated": out_truncated, "stderr_truncated": err_truncated}),
                )
            }
            Err(_) => {
                let _ = child.kill().await;
                bail!(
                    "command timed out after {} seconds; process group terminated (no output returned)",
                    timeout.as_secs()
                );
            }
        }
    }
}

struct ProcessGroup(Option<u32>);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.0 {
            // Child was started in a new process group with its PID as group ID.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
}

async fn capture(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut result = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut truncated = false;
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        let keep = n.min(cap.saturating_sub(result.len()));
        result.extend_from_slice(&buffer[..keep]);
        truncated |= keep < n;
    }
    Ok((result, truncated))
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(write: bool, exec: bool) -> (tempfile::TempDir, Workspace) {
        let dir = tempfile::tempdir().unwrap();
        let ws = Workspace::new(dir.path().into(), write, exec, 8192).unwrap();
        (dir, ws)
    }

    fn file(action: FileAction, path: &str, text: Option<&str>) -> FileArgs {
        FileArgs {
            action,
            path: path.into(),
            text: text.map(String::from),
            offset: None,
            limit: None,
            expected_sha256: None,
        }
    }

    #[test]
    fn blocks_traversal_and_secrets() {
        let (_dir, ws) = workspace(false, false);
        for path in [
            "../outside",
            "/etc/passwd",
            "src/../../outside",
            ".env",
            ".env.local",
            ".ssh/id_rsa",
            "cert.key",
            ".git/config",
        ] {
            assert!(ws.resolve(path).is_err(), "{path}");
        }
        assert!(ws.resolve(".env.example").is_ok());
        assert!(ws.resolve("src/lib.rs").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn blocks_symlinks() {
        use std::os::unix::fs::symlink;
        let (dir, ws) = workspace(true, false);
        symlink("/etc", dir.path().join("escape")).unwrap();
        assert!(ws.resolve("escape/passwd").is_err());
        assert!(
            ws.files(file(FileAction::Create, "escape/new", Some("x")))
                .is_err()
        );
    }

    #[test]
    fn read_only_is_default_and_create_never_clobbers() {
        let (_dir, ws) = workspace(false, false);
        assert!(
            ws.files(file(FileAction::Create, "new.txt", Some("hello")))
                .is_err()
        );
        let (dir, ws) = workspace(true, false);
        assert!(
            ws.files(file(FileAction::Create, "new.txt", Some("hello")))
                .is_ok()
        );
        assert!(
            ws.files(file(FileAction::Create, "new.txt", Some("oops")))
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("new.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn edit_hash_and_ambiguity_guards() {
        let (dir, ws) = workspace(true, false);
        fs::write(dir.path().join("code.rs"), "hello hello").unwrap();
        let mut args = EditArgs {
            path: "code.rs".into(),
            old: "hello".into(),
            new: "world".into(),
            expected_sha256: "stale".into(),
            all: false,
        };
        assert!(ws.edit(args).is_err());
        args = EditArgs {
            path: "code.rs".into(),
            old: "hello".into(),
            new: "world".into(),
            expected_sha256: hash(b"hello hello"),
            all: false,
        };
        assert!(ws.edit(args).is_err());
        let result = ws
            .edit(EditArgs {
                path: "code.rs".into(),
                old: "hello".into(),
                new: "world".into(),
                expected_sha256: hash(b"hello hello"),
                all: true,
            })
            .unwrap();
        assert_eq!(result["replacements"], 2);
        assert_eq!(
            fs::read_to_string(dir.path().join("code.rs")).unwrap(),
            "world world"
        );
    }

    #[test]
    fn ignores_generated_files_and_paginates() {
        let (dir, ws) = workspace(false, false);
        fs::create_dir(dir.path().join("target")).unwrap();
        fs::write(dir.path().join("target/artifact.rs"), "needle").unwrap();
        fs::write(dir.path().join(".env"), "needle").unwrap();
        fs::write(dir.path().join("source.rs"), "needle\nneedle\nneedle").unwrap();
        let mut args = file(FileAction::Search, ".", Some("needle"));
        args.limit = Some(1);
        let result = ws.files(args).unwrap();
        assert_eq!(result["total"], 3);
        assert_eq!(result["next_offset"], 2);
        assert_eq!(result["matches"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn redacts_nested_values_and_multiline_keys() {
        let mut value = json!({"lines": ["const api_key = 'secret-value';", "Authorization: Bearer abcdefgh"], "password": "hidden", "data": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"});
        redact_value(&mut value);
        let text = value.to_string();
        for secret in ["secret-value", "abcdefgh", "hidden", "abc\\n"] {
            assert!(!text.contains(secret), "{text}");
        }
        assert!(text.contains("REDACTED"));
        assert_eq!(
            redact("https://user:pass@example.com"),
            "https://[REDACTED]@example.com"
        );
    }

    #[test]
    fn file_pagination_is_one_based_without_gaps_or_duplicates() {
        let (dir, ws) = workspace(false, false);
        fs::write(
            dir.path().join("source.rs"),
            "needle one\nneedle two\nneedle three\n",
        )
        .unwrap();
        for action in [FileAction::List, FileAction::Read, FileAction::Search] {
            let (name, key) = match action {
                FileAction::List => ("list", "entries"),
                FileAction::Read => ("read", "lines"),
                FileAction::Search => ("search", "matches"),
                _ => unreachable!(),
            };
            let path = if name == "list" { "." } else { "source.rs" };
            let request = |offset, limit| {
                serde_json::from_value(json!({
                    "action": name, "path": path, "text": "needle",
                    "offset": offset, "limit": limit
                }))
                .unwrap()
            };
            let full = ws.files(request(1, 500)).unwrap();
            let mut collected = Vec::new();
            let mut offset = 1;
            loop {
                let page = ws.files(request(offset, 1)).unwrap();
                collected.extend(page[key].as_array().unwrap().iter().cloned());
                let Some(next) = page["next_offset"].as_u64() else {
                    break;
                };
                assert_eq!(next, offset + 1, "{name}");
                offset = next;
            }
            assert_eq!(json!(collected), full[key], "{name}");
            assert_eq!(
                ws.files(request(0, 1)).unwrap()[key],
                ws.files(request(1, 1)).unwrap()[key]
            );
            let past_end = ws.files(request(usize::MAX as u64, 1)).unwrap();
            assert_eq!(past_end[key], json!([]));
            assert!(past_end["next_offset"].is_null());
        }
    }

    #[test]
    fn truncation_is_utf8_safe() {
        assert!(truncate("你好世界", 4).starts_with("你\n[truncated"));
    }

    #[test]
    fn paginated_reads_and_search_hide_private_key_body() {
        let (dir, ws) = workspace(false, false);
        let text = "before\n-----BEGIN PRIVATE KEY-----\nkey-body-should-not-leak\n-----END PRIVATE KEY-----\nafter\n";
        fs::write(dir.path().join("embedded.rs"), text).unwrap();
        let mut args = file(FileAction::Read, "embedded.rs", None);
        args.offset = Some(3);
        args.limit = Some(1);
        let result = ws.files(args).unwrap();
        assert_eq!(result["sha256"], hash(text.as_bytes()));
        assert_eq!(result["lines"][0], "3: [REDACTED PRIVATE KEY]");
        let result = ws
            .files(file(FileAction::Search, ".", Some("key-body")))
            .unwrap();
        assert!(!result.to_string().contains("key-body"));
        assert_eq!(result["matches"][0]["line"], 3);
    }

    #[test]
    fn delete_requires_matching_hash() {
        let (dir, ws) = workspace(true, false);
        fs::write(dir.path().join("delete.txt"), "hello").unwrap();
        assert!(
            ws.files(file(FileAction::Delete, "delete.txt", None))
                .is_err()
        );
        let mut args = file(FileAction::Delete, "delete.txt", None);
        args.expected_sha256 = Some(hash(b"hello"));
        assert!(ws.files(args).is_ok());
        assert!(!dir.path().join("delete.txt").exists());
    }

    #[tokio::test]
    async fn devops_inspection_does_not_need_execution() {
        let (dir, ws) = workspace(false, false);
        fs::write(dir.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        let result = ws
            .terminal(TerminalArgs {
                action: TerminalAction::Inspect,
                skill: None,
                program: None,
                args: vec![],
                cwd: ".".into(),
                timeout_seconds: None,
            })
            .await
            .unwrap();
        assert_eq!(result["configs"][0], "Dockerfile");
        assert!(
            ws.terminal(TerminalArgs {
                action: TerminalAction::Run,
                skill: None,
                program: Some("docker".into()),
                args: vec!["ps".into()],
                cwd: ".".into(),
                timeout_seconds: None
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn commands_need_both_permissions() {
        let (_dir, ws) = workspace(false, true);
        assert!(
            ws.terminal(TerminalArgs {
                action: TerminalAction::Run,
                skill: None,
                program: Some("echo".into()),
                args: vec![],
                cwd: ".".into(),
                timeout_seconds: None
            })
            .await
            .is_err()
        );
        let (_dir, ws) = workspace(true, false);
        assert!(ws.run("echo", &[], ".", None).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn commands_capture_exit_bound_output_and_timeout() {
        let (_dir, ws) = workspace(true, true);
        let result = ws
            .run(
                "sh",
                &strings(&["-c", "echo hello; echo problem >&2; exit 7"]),
                ".",
                None,
            )
            .await
            .unwrap();
        assert_eq!(result["exit_code"], 7);
        assert_eq!(result["stdout"], "hello\n");
        assert_eq!(result["stderr"], "problem\n");
        let result = ws
            .run(
                "sh",
                &strings(&["-c", "head -c 20000 /dev/zero"]),
                ".",
                None,
            )
            .await
            .unwrap();
        assert_eq!(result["stdout"].as_str().unwrap().len(), 8192);
        assert_eq!(result["stdout_truncated"], true);
        let start = std::time::Instant::now();
        assert!(
            ws.run("sh", &strings(&["-c", "sleep 30 & wait"]), ".", Some(1))
                .await
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn git_lifecycle_and_option_rejection() {
        let (dir, ws) = workspace(true, true);
        assert!(
            ws.git(GitArgs {
                action: GitAction::Init,
                args: vec![]
            })
            .await
            .unwrap()["success"]
                .as_bool()
                .unwrap()
        );
        fs::write(dir.path().join("new.rs"), "fn main() {}\n").unwrap();
        let added = ws
            .git(GitArgs {
                action: GitAction::Add,
                args: vec!["new.rs".into()],
            })
            .await
            .unwrap();
        assert_eq!(added["success"], true, "{added}");
        let status = ws
            .git(GitArgs {
                action: GitAction::Status,
                args: vec![],
            })
            .await
            .unwrap();
        assert!(status["stdout"].as_str().unwrap().contains("new.rs"));
        assert!(
            ws.git(GitArgs {
                action: GitAction::Push,
                args: vec!["--force".into()]
            })
            .await
            .is_err()
        );
        assert!(
            ws.git(GitArgs {
                action: GitAction::Add,
                args: vec![".".into()]
            })
            .await
            .is_err()
        );
    }
}
