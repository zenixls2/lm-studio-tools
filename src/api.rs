use std::{collections::BTreeSet, path::Path, sync::LazyLock};

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde_json::{Value, json};

use crate::{
    ApiAction, ApiArgs, remote,
    workspace::{Workspace, redact, truncate},
};

static URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"https?://[^\s"'`<>\\)]+"#).unwrap());
static REQUEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r#"(?i)\b(fetch|axios(?:\.(?:get|post|put|patch|delete|head|options))?|requests\.(?:get|post|put|patch|delete|head|options)|(?:client|http|httpx|session)\.(?:get|post|put|patch|delete|head|options))\s*\(\s*["'`]([^"'`\r\n]+)["'`]"#
).unwrap()
});
static SDK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r"(?i)\b(?:openai|anthropic|stripe|boto3|supabase|firebase|octokit|s3|bedrock|dynamodb)\b|\b(?:client|sdk)\.[a-zA-Z_][a-zA-Z_0-9.]*\s*\("
).unwrap()
});
static METHOD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bmethod\s*[:=]\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']"#).unwrap()
});
static PARAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{[^/{}]+\}|:[A-Za-z_][A-Za-z0-9_]*").unwrap());

const METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];
const MAX_FINDINGS: usize = 5000;

fn source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some(
            "rs" | "py"
                | "js"
                | "jsx"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "go"
                | "java"
                | "kt"
                | "swift"
                | "rb"
                | "php"
                | "cs"
                | "c"
                | "cpp"
                | "h"
                | "sh"
                | "json"
                | "yaml"
                | "yml"
                | "toml"
        )
    )
}

fn endpoint_path(raw: &str) -> String {
    let path = if let Some((_, rest)) = raw.split_once("://") {
        rest.find('/').map(|i| &rest[i..]).unwrap_or("/")
    } else {
        raw
    };
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let normalized = PARAM.replace_all(path, "{}");
    let normalized = normalized.trim_end_matches('/');
    if normalized.is_empty() {
        "/".into()
    } else {
        normalized.into()
    }
}

fn request_method(call: &str, line: &str) -> String {
    let suffix = call.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if METHODS.contains(&suffix.as_str()) {
        return suffix.to_uppercase();
    }
    METHOD
        .captures(line)
        .map(|c| c[1].to_uppercase())
        .unwrap_or_else(|| {
            if call.eq_ignore_ascii_case("fetch") {
                "GET".into()
            } else {
                "UNKNOWN".into()
            }
        })
}

pub async fn run(ws: &Workspace, args: ApiArgs) -> Result<Value> {
    match args.action {
        ApiAction::Latest => {
            ensure!(
                args.url.is_none() && args.spec.is_none() && args.query.is_none(),
                "latest accepts registry and package; use fetch for URLs"
            );
            remote::latest(ws, &args).await
        }
        ApiAction::Fetch => {
            ensure!(
                args.registry.is_none() && args.package.is_none() && args.spec.is_none(),
                "fetch accepts url/query/offset/limit; use latest for package versions"
            );
            remote::fetch(ws, &args).await
        }
        ApiAction::Scan => {
            ensure!(
                args.registry.is_none()
                    && args.package.is_none()
                    && args.url.is_none()
                    && args.query.is_none(),
                "scan accepts path/spec/offset/limit; use latest or fetch for remote research"
            );
            if let Some(spec) = args.spec.as_deref().filter(|s| s.starts_with("https://")) {
                let doc = remote::get(ws, spec).await?;
                let mut value = scan_with_spec(ws, args, Some(&doc.body))?;
                value["comparison"]["source_url"] = json!(doc.url);
                value["comparison"]["retrieved_at_unix_seconds"] = json!(doc.retrieved);
                Ok(value)
            } else {
                scan(ws, args)
            }
        }
    }
}

pub fn scan(ws: &Workspace, args: ApiArgs) -> Result<Value> {
    scan_with_spec(ws, args, None)
}

fn scan_with_spec(ws: &Workspace, args: ApiArgs, remote_spec: Option<&str>) -> Result<Value> {
    let path = ws.resolve(&args.path)?;
    let (paths, walk_limited) = ws.walk(&path)?;
    let mut findings = Vec::new();
    let mut endpoints = BTreeSet::<(String, String)>::new();
    let mut files_scanned = 0;
    let mut files_skipped = 0;
    let mut finding_limited = false;
    'files: for path in paths.iter().filter(|p| p.is_file() && source(p)) {
        let Ok(text) = ws.read_text(path) else {
            files_skipped += 1;
            continue;
        };
        files_scanned += 1;
        for (index, line) in text.lines().enumerate() {
            let mut kinds = Vec::new();
            let mut calls = Vec::new();
            for capture in REQUEST.captures_iter(line) {
                let method = request_method(&capture[1], line);
                let raw = &capture[2];
                let path = endpoint_path(raw);
                if raw.starts_with('/') || raw.starts_with("http://") || raw.starts_with("https://")
                {
                    endpoints.insert((method.clone(), path.clone()));
                }
                calls.push(
                    json!({"method": method, "target": redact(raw), "normalized_path": path}),
                );
            }
            if !calls.is_empty() {
                kinds.push("http_call");
            }
            let urls: Vec<_> = URL
                .find_iter(line)
                .take(10)
                .map(|m| redact(m.as_str()))
                .collect();
            if !urls.is_empty() {
                kinds.push("url");
            }
            if SDK.is_match(line) {
                kinds.push("sdk_reference");
            }
            if redact(line) != line {
                kinds.push("credential_indicator");
            }
            if !kinds.is_empty() {
                if findings.len() >= MAX_FINDINGS {
                    finding_limited = true;
                    break 'files;
                }
                findings.push(json!({"path": ws.relative(path), "line": index+1,
                    "kinds": kinds, "calls": calls, "urls": urls,
                    "evidence": truncate(&redact(line.trim()), 300)}));
            }
        }
    }
    let comparison = args
        .spec
        .map(|spec| {
            if let Some(text) = remote_spec {
                compare_text(&spec, text, &endpoints)
            } else {
                ensure!(
                    !spec.contains("://"),
                    "remote spec must use public HTTPS and --allow-network"
                );
                let text = ws.read_text(&ws.resolve(&spec)?)?;
                compare_text(&spec, &text, &endpoints)
            }
        })
        .transpose()?;
    let limit = args.limit.unwrap_or(80).clamp(1, 500);
    let total = findings.len();
    let page: Vec<_> = findings.into_iter().skip(args.offset).take(limit).collect();
    Ok(
        json!({"findings": page, "total_findings": total, "files_scanned": files_scanned,
        "files_skipped": files_skipped, "scan_limited": walk_limited || finding_limited,
        "next_offset": (args.offset.saturating_add(limit) < total).then_some(args.offset.saturating_add(limit)),
        "comparison": comparison,
        "limitations": "Heuristic, not AST/dataflow analysis. Comments, config URLs and imports may be false positives. Dynamic/multiline requests, aliases and variable URLs may be missed. Comparison matches normalized path+method only; not proof of unused APIs."}),
    )
}

fn compare_text(spec: &str, text: &str, observed: &BTreeSet<(String, String)>) -> Result<Value> {
    // YAML parser accepts JSON too; URL suffixes and query strings need not indicate format.
    let doc: Value = serde_yaml::from_str(text)?;
    ensure!(
        doc.get("openapi")
            .and_then(Value::as_str)
            .is_some_and(|v| v.starts_with("3."))
            || doc.get("swagger").and_then(Value::as_str) == Some("2.0"),
        "expected OpenAPI 3.x or Swagger 2.0"
    );
    let paths = doc["paths"]
        .as_object()
        .context("spec must contain a paths object")?;
    let mut documented = BTreeSet::new();
    let mut unresolved = Vec::new();
    for (path, item) in paths {
        if item.get("$ref").is_some() {
            unresolved.push(path.clone());
        }
        if let Some(item) = item.as_object() {
            for method in METHODS {
                if item.get(*method).is_some() {
                    documented.insert((method.to_uppercase(), endpoint_path(path)));
                }
            }
        }
    }
    let known: Vec<_> = observed.intersection(&documented).map(operation).collect();
    let missing: Vec<_> = observed.difference(&documented).map(operation).collect();
    let unobserved: Vec<_> = documented.difference(observed).map(operation).collect();
    Ok(
        json!({"spec": spec, "documented_operations": documented.len(), "matched": known,
        "observed_not_documented": missing, "documented_not_observed": unobserved,
        "unresolved_path_refs": unresolved,
        "limitations": "No $ref resolution, server/basePath prefix stripping, or cross-file/dynamic call resolution. UNKNOWN methods are not treated as exact matches. Source scan truncation also limits comparison."}),
    )
}

fn operation((method, path): &(String, String)) -> Value {
    json!({"method": method, "path": path})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn normalizes_paths() {
        assert_eq!(
            endpoint_path("https://example.com/users/{userId}/?x=1"),
            "/users/{}"
        );
        assert_eq!(endpoint_path("/users/:id"), "/users/{}");
    }

    #[test]
    fn scans_and_compares_openapi() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(
            root.path().join("client.ts"),
            "fetch('/users/42');\naxios.post('/users', {});\nconst api_key = 'super-secret-value';",
        )?;
        fs::write(
            root.path().join("openapi.yaml"),
            "openapi: 3.0.3\npaths:\n  /users:\n    post: {}\n    get: {}\n",
        )?;
        let ws = Workspace::new(root.path().into(), false, false, 8192)?;
        let result = scan(
            &ws,
            ApiArgs {
                path: ".".into(),
                spec: Some("openapi.yaml".into()),
                offset: 0,
                limit: None,
                ..Default::default()
            },
        )?;
        assert_eq!(result["comparison"]["matched"][0]["method"], "POST");
        assert_eq!(
            result["comparison"]["documented_not_observed"][0]["method"],
            "GET"
        );
        assert!(!result.to_string().contains("super-secret-value"));
        Ok(())
    }

    #[test]
    fn compares_json_spec_without_filename_extension() -> Result<()> {
        let observed = BTreeSet::from([("GET".into(), "/users/{}".into())]);
        let value = compare_text(
            "https://example.com/schema?format=json",
            r#"{"swagger":"2.0","paths":{"/users/{id}":{"get":{}}}}"#,
            &observed,
        )?;
        assert_eq!(value["matched"][0]["path"], "/users/{}");
        Ok(())
    }

    #[test]
    fn scan_pagination_is_zero_based_without_gaps_or_duplicates() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(
            root.path().join("client.ts"),
            "fetch('/one');\nfetch('/two');\nfetch('/three');\n",
        )?;
        let ws = Workspace::new(root.path().into(), false, false, 8192)?;
        let page = |offset, limit| {
            scan(
                &ws,
                ApiArgs {
                    path: ".".into(),
                    offset,
                    limit: Some(limit),
                    ..Default::default()
                },
            )
        };
        let full = page(0, 500)?;
        let mut collected = Vec::new();
        let mut offset = 0;
        loop {
            let result = page(offset, 1)?;
            collected.extend(result["findings"].as_array().unwrap().iter().cloned());
            let Some(next) = result["next_offset"].as_u64() else {
                break;
            };
            assert_eq!(next as usize, offset + 1);
            offset = next as usize;
        }
        assert_eq!(collected.len(), 3);
        assert_eq!(json!(collected), full["findings"]);
        let past_end = page(usize::MAX, 1)?;
        assert_eq!(past_end["findings"], json!([]));
        assert!(past_end["next_offset"].is_null());
        Ok(())
    }
}
