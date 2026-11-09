use std::{process::Stdio, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

#[tokio::test]
async fn mcp_initialize_catalog_and_calls() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("hello.txt"), "hello\n")?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_lm-studio-tools"))
        .args(["--root", root.path().to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"integration-test","version":"1"}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files","arguments":{"action":"read","path":"hello.txt"}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"files","arguments":{"action":"create","path":"no.txt","text":"no"}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"terminal","arguments":{"program":"echo"}}}),
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"terminal","arguments":{"action":"skills","skill":"devops"}}}),
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"api_scan","arguments":{"action":"latest","registry":"npm","package":"next"}}}),
        json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"terminal","arguments":{"action":"inspect"}}}),
    ];
    for (i, request) in requests.iter().enumerate() {
        stdin.write_all(format!("{request}\n").as_bytes()).await?;
        stdin.flush().await?;
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await??
            .unwrap();
        let response: Value = serde_json::from_str(&line)?;
        assert_eq!(response["id"], request["id"]);
        assert!(response.get("error").is_none(), "{response}");
        match i {
            0 => {
                assert!(response["result"]["capabilities"]["tools"].is_object());
                stdin
                    .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
                    .await?;
            }
            1 => {
                let tools = response["result"]["tools"].as_array().unwrap();
                assert_eq!(tools.len(), 5);
                assert!(!tools.iter().any(|t| t["name"] == "devops"));
                for tool in tools {
                    let description = tool["description"].as_str().unwrap();
                    assert!(
                        description.contains("Example") || description.contains("example"),
                        "missing usage examples: {}",
                        tool["name"]
                    );
                    let mut rest = description;
                    let mut example_count = 0;
                    while let Some(start) = rest.find('{') {
                        let mut stream =
                            serde_json::Deserializer::from_str(&rest[start..]).into_iter::<Value>();
                        let example = stream
                            .next()
                            .unwrap()
                            .expect("tool description example must be valid JSON");
                        assert!(example.is_object());
                        example_count += 1;
                        rest = &rest[start + stream.byte_offset()..];
                    }
                    assert!(
                        example_count > 0,
                        "missing JSON example for {}",
                        tool["name"]
                    );
                }
                let catalog_bytes = serde_json::to_vec(tools)?.len();
                eprintln!("MCP tool catalog: {catalog_bytes} bytes (five documented tools)");
                assert!(
                    catalog_bytes < 20_000,
                    "catalog grew to {catalog_bytes} bytes"
                );
            }
            2 => {
                assert_ne!(response["result"]["isError"], true);
                assert!(line.contains("sha256"));
            }
            5 => {
                assert_ne!(response["result"]["isError"], true);
                assert!(line.contains("Terraform"));
            }
            6 => {
                assert_eq!(response["result"]["isError"], true);
                assert!(line.contains("--allow-network"));
            }
            7 => assert_ne!(response["result"]["isError"], true),
            _ => assert_eq!(response["result"]["isError"], true),
        }
    }
    child.kill().await?;
    Ok(())
}
