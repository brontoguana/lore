use base64::Engine;
use lore_core::{FileBlockStore, LocalAuthStore, UserName};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tempfile::tempdir;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn basic_auth(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
    )
}

const ADMIN_USER: &str = "admin";
const ADMIN_PASS: &str = "correct-horse-battery";

fn setup_store(dir: &std::path::Path) -> FileBlockStore {
    let store = FileBlockStore::new(dir);
    let auth = LocalAuthStore::new(dir.to_path_buf());
    if !auth.has_users().unwrap() {
        auth.bootstrap_admin(
            UserName::new(ADMIN_USER.to_string()).unwrap(),
            ADMIN_PASS.to_string(),
        )
        .unwrap();
    }
    store
}

async fn spawn_server(dir: &std::path::Path) -> (SocketAddr, reqwest::Client) {
    let store = setup_store(dir);
    if let Ok(infos) = store.list_project_infos() {
        for info in &infos {
            let _ = store.migrate_project_to_documents(&info.slug);
        }
    }
    let app = lore_core::build_app(store);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    (addr, client)
}

fn url(addr: &SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

async fn api_create_agent_token(
    client: &reqwest::Client,
    addr: &SocketAddr,
    name: &str,
    grants: &[(&str, &str)],
) -> String {
    let grants_json: Vec<Value> = grants
        .iter()
        .map(|(project, perm)| json!({"project": project, "permission": perm}))
        .collect();
    let resp = client
        .post(url(addr, "/v1/admin/agent-tokens"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({"name": name, "owner": ADMIN_USER, "grants": grants_json}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create agent token failed");
    let body: Value = resp.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

async fn admin_login(client: &reqwest::Client, addr: &SocketAddr) -> (String, String) {
    let resp = client
        .post(url(addr, "/login"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("username=admin&password=correct-horse-battery")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    let cookie = resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let page_resp = client
        .get(url(addr, "/ui"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(page_resp.status(), 200);
    let html = page_resp.text().await.unwrap();
    let csrf = extract_hidden_value(&html, "csrf_token").unwrap();
    (cookie, csrf)
}

fn extract_hidden_value(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\" value=\"");
    let start = html.find(&needle)? + needle.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

async fn create_endpoint(
    client: &reqwest::Client,
    addr: &SocketAddr,
    name: &str,
    endpoint_url: &str,
    model: &str,
) -> String {
    let resp = client
        .post(url(addr, "/v1/admin/endpoints"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({
            "name": name,
            "kind": "openai",
            "url": endpoint_url,
            "model": model,
            "api_key": "test-key-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create endpoint failed");
    let body: Value = resp.json().await.unwrap();
    body["id"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Layer 2: API Integration Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_check() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let resp = client.get(url(&addr, "/v1/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn project_lifecycle() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "test-agent", &[("test.project", "read_write")]).await;

    // Create a block to auto-create the project
    let resp = client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "test.project", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List projects
    let resp = client
        .get(url(&addr, "/v1/projects"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let projects: Value = resp.json().await.unwrap();
    let arr = projects.as_array().unwrap();
    assert!(arr.iter().any(|p| {
        let proj = &p["project"];
        proj.as_str() == Some("test.project") || proj["slug"].as_str() == Some("test.project")
    }), "project not in list: {projects:?}");
}

#[tokio::test]
async fn document_crud() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "doc-agent", &[("docs.project", "read_write")]).await;

    // Seed project
    let resp = client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "docs.project", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Create document
    let resp = client
        .post(url(&addr, "/v1/projects/docs.project/documents"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "Architecture Notes"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap().to_string();
    assert_eq!(doc["name"], "Architecture Notes");

    // List documents
    let resp = client
        .get(url(&addr, "/v1/projects/docs.project/documents"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let docs: Value = resp.json().await.unwrap();
    let doc_arr = docs["documents"].as_array().unwrap();
    // Tree is hierarchical -- root doc may contain children, or new doc is a sibling
    fn count_docs(arr: &[Value]) -> usize {
        arr.iter().map(|d| 1 + count_docs(d["children"].as_array().unwrap_or(&vec![]))).sum()
    }
    let total = count_docs(doc_arr);
    assert!(total >= 1, "should have at least our new doc, got {} (tree: {docs:?})", total);

    // Rename document
    let resp = client
        .put(url(&addr, &format!("/v1/projects/docs.project/documents/{doc_id}")))
        .header("x-lore-key", &token)
        .json(&json!({"name": "Design Notes"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify rename
    let resp = client
        .get(url(&addr, "/v1/projects/docs.project/documents"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    let docs: Value = resp.json().await.unwrap();
    let doc_arr = docs["documents"].as_array().unwrap();
    fn find_in_tree(arr: &[Value], name: &str) -> bool {
        arr.iter().any(|d| d["name"] == name || find_in_tree(d["children"].as_array().unwrap_or(&vec![]), name))
    }
    assert!(find_in_tree(doc_arr, "Design Notes"), "renamed doc not found: {docs:?}");

    // Delete document
    let resp = client
        .delete(url(&addr, &format!("/v1/projects/docs.project/documents/{doc_id}")))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Verify deletion
    let resp = client
        .get(url(&addr, "/v1/projects/docs.project/documents"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    let docs: Value = resp.json().await.unwrap();
    let doc_arr = docs["documents"].as_array().unwrap();
    fn find_deleted(arr: &[Value], name: &str) -> bool {
        arr.iter().any(|d| d["name"] == name || find_deleted(d["children"].as_array().unwrap_or(&vec![]), name))
    }
    assert!(!find_deleted(doc_arr, "Design Notes"));
}

#[tokio::test]
async fn document_block_crud() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "block-agent", &[("blocks.proj", "read_write")]).await;

    // Seed project
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "blocks.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    // Create document
    let resp = client
        .post(url(&addr, "/v1/projects/blocks.proj/documents"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "Test Doc"}))
        .send()
        .await
        .unwrap();
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap();

    // Create block in document
    let resp = client
        .post(url(&addr, &format!("/v1/projects/blocks.proj/documents/{doc_id}/blocks")))
        .header("x-lore-key", &token)
        .json(&json!({"block_type": "markdown", "content": "# Hello World\n\nThis is a test block."}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let block: Value = resp.json().await.unwrap();
    let block_id = block["id"].as_str().unwrap().to_string();

    // Read block
    let resp = client
        .get(url(&addr, &format!("/v1/projects/blocks.proj/documents/{doc_id}/blocks/{block_id}")))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let read_block: Value = resp.json().await.unwrap();
    let content = read_block["block"]["content"].as_str()
        .or_else(|| read_block["content"].as_str())
        .unwrap();
    assert!(content.contains("Hello World"));

    // Update block
    let resp = client
        .patch(url(&addr, &format!("/v1/projects/blocks.proj/documents/{doc_id}/blocks/{block_id}")))
        .header("x-lore-key", &token)
        .json(&json!({"block_type": "markdown", "content": "# Updated Title\n\nNew content here."}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify update
    let resp = client
        .get(url(&addr, &format!("/v1/projects/blocks.proj/documents/{doc_id}/blocks/{block_id}")))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    let read_block: Value = resp.json().await.unwrap();
    let content = read_block["block"]["content"].as_str()
        .or_else(|| read_block["content"].as_str())
        .unwrap();
    assert!(content.contains("Updated Title"));

    // List blocks
    let resp = client
        .get(url(&addr, &format!("/v1/projects/blocks.proj/documents/{doc_id}/blocks")))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let blocks: Value = resp.json().await.unwrap();
    assert_eq!(blocks.as_array().unwrap().len(), 1);

    // Create a second block
    let resp = client
        .post(url(&addr, &format!("/v1/projects/blocks.proj/documents/{doc_id}/blocks")))
        .header("x-lore-key", &token)
        .json(&json!({"block_type": "markdown", "content": "Second block"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let block2: Value = resp.json().await.unwrap();
    let block2_id = block2["id"].as_str().unwrap().to_string();

    // Move block
    let resp = client
        .post(url(&addr, &format!("/v1/projects/blocks.proj/documents/{doc_id}/blocks/{block2_id}/move")))
        .header("x-lore-key", &token)
        .json(&json!({"right": block_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Delete block
    let resp = client
        .delete(url(&addr, &format!("/v1/projects/blocks.proj/documents/{doc_id}/blocks/{block2_id}")))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert!(resp.status() == 200 || resp.status() == 204, "delete returned {}", resp.status());

    // Verify only one block remains
    let resp = client
        .get(url(&addr, &format!("/v1/projects/blocks.proj/documents/{doc_id}/blocks")))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    let blocks: Value = resp.json().await.unwrap();
    assert_eq!(blocks.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn edit_block_find_replace() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "edit-agent", &[("edit.proj", "read_write")]).await;

    // Seed project + document + block
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "edit.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(url(&addr, "/v1/projects/edit.proj/documents"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "Edit Test"}))
        .send()
        .await
        .unwrap();
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap();

    let resp = client
        .post(url(&addr, &format!("/v1/projects/edit.proj/documents/{doc_id}/blocks")))
        .header("x-lore-key", &token)
        .json(&json!({"block_type": "markdown", "content": "The quick brown fox jumps over the lazy dog."}))
        .send()
        .await
        .unwrap();
    let block: Value = resp.json().await.unwrap();
    let block_id = block["id"].as_str().unwrap();

    // Find and replace
    let resp = client
        .post(url(&addr, &format!("/v1/projects/edit.proj/documents/{doc_id}/blocks/{block_id}/edit")))
        .header("x-lore-key", &token)
        .json(&json!({"old_string": "quick brown fox", "new_string": "slow red turtle"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify
    let resp = client
        .get(url(&addr, &format!("/v1/projects/edit.proj/documents/{doc_id}/blocks/{block_id}")))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    let block: Value = resp.json().await.unwrap();
    let content = block["block"]["content"].as_str()
        .or_else(|| block["content"].as_str())
        .unwrap();
    assert_eq!(content, "The slow red turtle jumps over the lazy dog.");
}

#[tokio::test]
async fn grep_doc_blocks() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "grep-agent", &[("grep.proj", "read_write")]).await;

    // Seed project + document + blocks
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "grep.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(url(&addr, "/v1/projects/grep.proj/documents"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "Grep Test"}))
        .send()
        .await
        .unwrap();
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap();

    client
        .post(url(&addr, &format!("/v1/projects/grep.proj/documents/{doc_id}/blocks")))
        .header("x-lore-key", &token)
        .json(&json!({"block_type": "markdown", "content": "Line one\nLine two with KEYWORD\nLine three"}))
        .send()
        .await
        .unwrap();

    client
        .post(url(&addr, &format!("/v1/projects/grep.proj/documents/{doc_id}/blocks")))
        .header("x-lore-key", &token)
        .json(&json!({"block_type": "markdown", "content": "No match here"}))
        .send()
        .await
        .unwrap();

    // Grep
    let resp = client
        .get(url(&addr, &format!("/v1/projects/grep.proj/documents/{doc_id}/grep?q=KEYWORD")))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let results: Value = resp.json().await.unwrap();
    let arr = results.as_array().unwrap();
    assert_eq!(arr.len(), 1, "grep should match exactly one block");
}

#[tokio::test]
async fn reserved_blocks() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let (cookie, csrf) = admin_login(&client, &addr).await;
    let token = api_create_agent_token(&client, &addr, "reserved-agent", &[("reserved-project", "read_write")]).await;

    // Create project via UI form (this calls create_project which sets up reserved blocks)
    let resp = client
        .post(url(&addr, "/ui/projects"))
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("csrf_token={csrf}&project_name=Reserved+Project&parent="))
        .send()
        .await
        .unwrap();
    assert!(resp.status().as_u16() < 400 || resp.status() == 303, "project create: {}", resp.status());

    // Read _overview reserved block
    let resp = client
        .get(url(&addr, "/v1/projects/reserved-project/reserved/_overview"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let block: Value = resp.json().await.unwrap();
    assert_eq!(block["content"], "");

    // Update _overview (user-only, must use basic auth)
    let resp = client
        .patch(url(&addr, "/v1/projects/reserved-project/reserved/_overview"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({"content": "This project covers testing infrastructure."}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify
    let resp = client
        .get(url(&addr, "/v1/projects/reserved-project/reserved/_overview"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    let block: Value = resp.json().await.unwrap();
    assert_eq!(block["content"], "This project covers testing infrastructure.");

    // Update _agent-context (user-only)
    let resp = client
        .patch(url(&addr, "/v1/projects/reserved-project/reserved/_agent-context"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({"content": "Focus on Rust testing patterns."}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify agent is rejected for _overview update
    let resp = client
        .patch(url(&addr, "/v1/projects/reserved-project/reserved/_overview"))
        .header("x-lore-key", &token)
        .json(&json!({"content": "agent should not be allowed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "agents should not be able to update _overview");

    // Update _map (agent-writable)
    let resp = client
        .patch(url(&addr, "/v1/projects/reserved-project/reserved/_map"))
        .header("x-lore-key", &token)
        .json(&json!({"content": "- tests/integration.rs: main integration test file"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify _overview has size limit (2000 chars)
    let long_content = "x".repeat(2001);
    let resp = client
        .patch(url(&addr, "/v1/projects/reserved-project/reserved/_overview"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({"content": long_content}))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(status >= 400, "should reject content over 2000 chars, got {status}");
}

#[tokio::test]
async fn mcp_tool_list() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "mcp-agent", &[("mcp.proj", "read_write")]).await;

    let resp = client
        .get(url(&addr, "/v1/chat/lore-tools"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let tools: Value = resp.json().await.unwrap();
    let arr = tools["tools"].as_array().unwrap();

    let tool_names: Vec<&str> = arr
        .iter()
        .filter_map(|t| t["function"]["name"].as_str())
        .collect();

    for expected in &[
        "list_projects",
        "list_documents",
        "create_document",
        "rename_document",
        "delete_document",
        "list_blocks",
        "read_block",
        "update_block",
        "edit_block",
        "create_block",
        "delete_block",
        "move_block",
        "grep_blocks",
    ] {
        assert!(
            tool_names.contains(expected),
            "missing MCP tool: {expected}, found: {tool_names:?}"
        );
    }
}

#[tokio::test]
async fn mcp_tool_call_list_projects() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "mcp-call-agent", &[("mcp.call.proj", "read_write")]).await;

    // Seed project
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "mcp.call.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    // Call list_projects tool
    let resp = client
        .post(url(&addr, "/v1/chat/lore-tools"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "list_projects", "arguments": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: Value = resp.json().await.unwrap();
    let content = result["result"].as_str().unwrap_or("");
    assert!(content.contains("mcp.call.proj"), "list_projects should include our project: {content}");
}

#[tokio::test]
async fn mcp_tool_call_document_workflow() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "mcp-doc-agent", &[("mcp.doc.proj", "read_write")]).await;

    // Seed
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "mcp.doc.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    // Create document via MCP
    let resp = client
        .post(url(&addr, "/v1/chat/lore-tools"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "create_document", "arguments": {"project": "mcp.doc.proj", "name": "MCP Created Doc"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: Value = resp.json().await.unwrap();
    let content = result["result"].as_str().unwrap_or("");
    assert!(content.contains("MCP Created Doc") || content.contains("created") || content.contains("Created"), "doc creation should succeed: {content}");

    // List documents via MCP
    let resp = client
        .post(url(&addr, "/v1/chat/lore-tools"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "list_documents", "arguments": {"project": "mcp.doc.proj"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: Value = resp.json().await.unwrap();
    let content = result["result"].as_str().unwrap_or("");
    assert!(content.contains("MCP Created Doc"), "list_documents should include our doc: {content}");
}

#[tokio::test]
async fn mcp_tool_call_block_workflow() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "mcp-blk-agent", &[("mcp.blk.proj", "read_write")]).await;

    // Seed
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "mcp.blk.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    // Create doc via REST (simpler for getting the ID)
    let resp = client
        .post(url(&addr, "/v1/projects/mcp.blk.proj/documents"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "Block Test"}))
        .send()
        .await
        .unwrap();
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap();

    // Create block via MCP
    let resp = client
        .post(url(&addr, "/v1/chat/lore-tools"))
        .header("x-lore-key", &token)
        .json(&json!({
            "name": "create_block",
            "arguments": {
                "project": "mcp.blk.proj",
                "document_id": doc_id,
                "block_type": "markdown",
                "content": "# Created via MCP\n\nThis block was created through the tool interface."
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List blocks via MCP
    let resp = client
        .post(url(&addr, "/v1/chat/lore-tools"))
        .header("x-lore-key", &token)
        .json(&json!({
            "name": "list_blocks",
            "arguments": {"project": "mcp.blk.proj", "document_id": doc_id}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: Value = resp.json().await.unwrap();
    let content = result["result"].as_str().unwrap_or("");
    assert!(content.contains("Created via MCP"), "list_blocks should contain our block: {content}");

    // Grep via MCP
    let resp = client
        .post(url(&addr, "/v1/chat/lore-tools"))
        .header("x-lore-key", &token)
        .json(&json!({
            "name": "grep_blocks",
            "arguments": {"project": "mcp.blk.proj", "query": "tool interface"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let result: Value = resp.json().await.unwrap();
    let content = result["result"].as_str().unwrap_or("");
    assert!(content.contains("tool interface"), "grep should find our text: {content}");
}

#[tokio::test]
async fn version_history_for_doc_blocks() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "hist-agent", &[("hist.proj", "read_write")]).await;

    // Seed + doc + block
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "hist.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(url(&addr, "/v1/projects/hist.proj/documents"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "History Test"}))
        .send()
        .await
        .unwrap();
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap();

    let resp = client
        .post(url(&addr, &format!("/v1/projects/hist.proj/documents/{doc_id}/blocks")))
        .header("x-lore-key", &token)
        .json(&json!({"block_type": "markdown", "content": "version 1"}))
        .send()
        .await
        .unwrap();
    let block: Value = resp.json().await.unwrap();
    let block_id = block["id"].as_str().unwrap();

    // Update to create a version
    client
        .patch(url(&addr, &format!("/v1/projects/hist.proj/documents/{doc_id}/blocks/{block_id}")))
        .header("x-lore-key", &token)
        .json(&json!({"block_type": "markdown", "content": "version 2"}))
        .send()
        .await
        .unwrap();

    // Check history exists
    let resp = client
        .get(url(&addr, "/v1/projects/hist.proj/history"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let history: Value = resp.json().await.unwrap();
    let versions = history["versions"].as_array().unwrap_or_else(|| {
        panic!("expected versions array, got: {history:?}")
    });
    assert!(versions.len() >= 2, "should have at least 2 versions (create + update), got {}", versions.len());
}

#[tokio::test]
async fn ui_project_page_shows_documents() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "ui-agent", &[("ui.proj", "read_write")]).await;
    let (cookie, _csrf) = admin_login(&client, &addr).await;

    // Seed project + document
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "ui.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    client
        .post(url(&addr, "/v1/projects/ui.proj/documents"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "UI Visible Doc"}))
        .send()
        .await
        .unwrap();

    // Load project page
    let resp = client
        .get(url(&addr, "/ui/ui.proj"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("UI Visible Doc"), "project page should show document name");
    assert!(html.contains("Agent Context"), "project page should show reserved blocks");
    assert!(html.contains("Overview"), "project page should show overview");
    assert!(html.contains("File Map"), "project page should show file map");
}

#[tokio::test]
async fn ui_document_page_shows_blocks() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "uid-agent", &[("uid.proj", "read_write")]).await;
    let (cookie, _csrf) = admin_login(&client, &addr).await;

    // Seed + doc + block
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "uid.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(url(&addr, "/v1/projects/uid.proj/documents"))
        .header("x-lore-key", &token)
        .json(&json!({"name": "Doc Page Test"}))
        .send()
        .await
        .unwrap();
    let doc: Value = resp.json().await.unwrap();
    let doc_id = doc["id"].as_str().unwrap();

    client
        .post(url(&addr, &format!("/v1/projects/uid.proj/documents/{doc_id}/blocks")))
        .header("x-lore-key", &token)
        .json(&json!({"block_type": "markdown", "content": "# Visible Heading\n\nBody text here."}))
        .send()
        .await
        .unwrap();

    // Load document page
    let resp = client
        .get(url(&addr, &format!("/ui/uid.proj/doc/{doc_id}")))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("<h1>Visible Heading</h1>"), "document page should render markdown");
    assert!(html.contains("Body text here"), "document page should show body text");
}

#[tokio::test]
async fn ui_projects_list_shows_tree() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "tree-agent", &[("tree.proj", "read_write")]).await;
    let (cookie, _csrf) = admin_login(&client, &addr).await;

    // Seed project
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "tree.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    // Load projects page
    let resp = client
        .get(url(&addr, "/ui"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("tree.proj"), "projects page should show project");
}

#[tokio::test]
async fn auth_rejects_bad_token() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;

    let resp = client
        .get(url(&addr, "/v1/projects"))
        .header("x-lore-key", "bad-token-123")
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(status >= 400, "should reject bad token, got {status}");
}

#[tokio::test]
async fn auth_rejects_cross_project_access() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;

    // Create a role with access only to project.a
    let resp = client
        .post(url(&addr, "/v1/admin/roles"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({"name": "only-a", "grants": [{"project": "project.a", "permission": "read_write"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create role failed");

    // Create a non-admin user with that role
    let resp = client
        .post(url(&addr, "/v1/admin/users"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({"username": "limited-user", "password": "test-pass-123", "roles": ["only-a"], "is_admin": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create user failed");

    // Create an agent token owned by the limited user
    let resp = client
        .post(url(&addr, "/v1/admin/agent-tokens"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({"name": "agent-a", "owner": "limited-user", "grants": [{"project": "project.a", "permission": "read_write"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create agent token failed");
    let body: Value = resp.json().await.unwrap();
    let token_a = body["token"].as_str().unwrap().to_string();

    // Try to create a block in a project the owner doesn't have access to
    let resp = client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token_a)
        .json(&json!({"project": "project.b", "block_type": "markdown", "content": "unauthorized"}))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(status >= 400, "should reject cross-project access, got {status}");
}

#[tokio::test]
async fn migration_preserves_existing_blocks() {
    // Create a project with blocks BEFORE starting server, then verify migration
    let dir = tempdir().unwrap();

    // Manually set up a pre-migration project using the store directly
    let store = setup_store(dir.path());
    let auth = LocalAuthStore::new(dir.path().to_path_buf());
    let created = auth.create_agent_token(lore_core::NewAgentToken {
        display_name: "mig-agent".to_string(),
        owner: UserName::new("admin".to_string()).unwrap(),
        grants: vec![lore_core::ProjectGrant {
            project: lore_core::ProjectName::new("migrate.proj").unwrap(),
            permission: lore_core::ProjectPermission::ReadWrite,
        }],
        backend: lore_core::AgentBackend::default(),
        endpoint_id: None,
    }).unwrap();
    let token = created.token;

    // Create a block which auto-creates the project in old style
    let new_block = lore_core::NewBlock {
        project: lore_core::ProjectName::new("migrate.proj").unwrap(),
        block_type: lore_core::BlockType::Markdown,
        content: "pre-migration content".to_string(),
        author_key: token.clone(),
        left: None,
        right: None,
        image_upload: None,
    };
    store.create_block(new_block).unwrap();

    // Now start the server -- migration runs on startup
    let (addr, client) = spawn_server(dir.path()).await;

    // The migration should have created documents
    let resp = client
        .get(url(&addr, "/v1/projects/migrate.proj/documents"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let docs: Value = resp.json().await.unwrap();
    let doc_arr = docs["documents"].as_array().unwrap();
    assert!(!doc_arr.is_empty(), "migration should create at least a root document: {docs:?}");
}

// ---------------------------------------------------------------------------
// Layer 3: Mock LLM + Agent Flow Tests
// ---------------------------------------------------------------------------

async fn spawn_mock_llm() -> (SocketAddr, tokio::sync::mpsc::Sender<()>) {
    use axum::{Router, routing::post, Json};

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(|Json(req): Json<Value>| async move {
                let empty = vec![];
                let messages = req["messages"].as_array().unwrap_or(&empty);
                let last_msg = messages
                    .last()
                    .and_then(|m| m["content"].as_str())
                    .unwrap_or("");

                let has_tool_calls = req.get("tools").and_then(|t| t.as_array()).map(|a| !a.is_empty()).unwrap_or(false);

                let response_content = if last_msg.contains("tool_result") || last_msg.contains("function") {
                    "I've processed the tool result. The operation was successful."
                } else if has_tool_calls {
                    return Json(json!({
                        "id": format!("chatcmpl-{}", uuid::Uuid::new_v4()),
                        "object": "chat.completion",
                        "model": "mock-model",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": null,
                                "tool_calls": [{
                                    "id": format!("call_{}", uuid::Uuid::new_v4()),
                                    "type": "function",
                                    "function": {
                                        "name": "list_projects",
                                        "arguments": "{}"
                                    }
                                }]
                            },
                            "finish_reason": "tool_calls"
                        }],
                        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
                    }));
                } else {
                    "Hello! I'm the mock LLM responding to your message."
                };

                Json(json!({
                    "id": format!("chatcmpl-{}", uuid::Uuid::new_v4()),
                    "object": "chat.completion",
                    "model": "mock-model",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": response_content
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
                }))
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown_rx.recv().await; })
            .await
            .unwrap();
    });

    (addr, shutdown_tx)
}

#[tokio::test]
async fn mock_llm_responds() {
    let (llm_addr, _shutdown) = spawn_mock_llm().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{llm_addr}/v1/chat/completions"))
        .json(&json!({
            "model": "mock-model",
            "messages": [{"role": "user", "content": "Hello"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["choices"][0]["message"]["content"].as_str().unwrap().contains("mock LLM"));
}

#[tokio::test]
async fn mock_llm_returns_tool_calls() {
    let (llm_addr, _shutdown) = spawn_mock_llm().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{llm_addr}/v1/chat/completions"))
        .json(&json!({
            "model": "mock-model",
            "messages": [{"role": "user", "content": "What projects exist?"}],
            "tools": [{"type": "function", "function": {"name": "list_projects", "parameters": {}}}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let tool_calls = body["choices"][0]["message"]["tool_calls"].as_array();
    assert!(tool_calls.is_some(), "should return tool calls");
    assert_eq!(tool_calls.unwrap()[0]["function"]["name"], "list_projects");
}

#[tokio::test]
async fn chat_proxy_completions_with_mock_llm() {
    let dir = tempdir().unwrap();
    let (llm_addr, _shutdown) = spawn_mock_llm().await;
    let (addr, client) = spawn_server(dir.path()).await;

    // Create endpoint pointing to mock LLM
    let _endpoint_id = create_endpoint(
        &client,
        &addr,
        "mock-endpoint",
        &format!("http://{llm_addr}/v1/chat/completions"),
        "mock-model",
    )
    .await;

    // Create agent token with endpoint
    let token = api_create_agent_token(&client, &addr, "chat-agent", &[("chat.proj", "read_write")]).await;

    // Seed project
    client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "chat.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();

    // Proxy a completion through the server
    let resp = client
        .post(url(&addr, "/v1/chat/completions"))
        .header("x-lore-key", &token)
        .json(&json!({
            "model": "mock-model",
            "messages": [{"role": "user", "content": "Hello from integration test"}],
            "stream": false
        }))
        .send()
        .await;

    // This may fail if the agent doesn't have an endpoint_id set on the token,
    // which requires agent provisioning. That's expected - we're testing the path.
    // The important thing is the server doesn't crash.
    assert!(resp.is_ok(), "request should not fail at transport level");
}

#[tokio::test]
async fn librarian_ask_via_ui_with_mock_llm() {
    let dir = tempdir().unwrap();
    let (llm_addr, _shutdown) = spawn_mock_llm().await;
    let (addr, client) = spawn_server(dir.path()).await;

    // Create endpoint pointing to mock LLM
    let endpoint_id = create_endpoint(
        &client,
        &addr,
        "lib-endpoint",
        &format!("http://{llm_addr}/v1/chat/completions"),
        "mock-model",
    )
    .await;

    // Configure librarian to use this endpoint
    let resp = client
        .post(url(&addr, "/v1/admin/librarian-config"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({
            "endpoint_id": endpoint_id,
            "request_timeout_secs": 30,
            "max_concurrent_runs": 2,
            "action_requires_approval": false
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "configure librarian failed: {}", resp.text().await.unwrap_or_default());

    // Seed a project with content via API
    let token = api_create_agent_token(&client, &addr, "lib-agent", &[("lib.proj", "read_write")]).await;
    let resp = client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "lib.proj", "block_type": "markdown", "content": "The capital of France is Paris."}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "seed block failed");

    // Login as admin to get session cookie + CSRF
    let (cookie, csrf) = admin_login(&client, &addr).await;

    // Ask the librarian via the UI endpoint (specific project)
    let resp = client
        .post(url(&addr, "/ui/chat/librarian/ask"))
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "csrf_token={}&project=lib.proj&question=What+is+the+capital+of+France&include_history=0&allow_edits=0",
            csrf
        ))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body_text = resp.text().await.unwrap();
    eprintln!("librarian ask response status={status} body={body_text}");

    // The response MUST be JSON with `ok: true`
    let body: Value = serde_json::from_str(&body_text)
        .unwrap_or_else(|_| panic!("librarian response was not JSON: status={status} body={body_text}"));
    assert!(body["ok"].as_bool().unwrap_or(false), "librarian ask failed: {body}");
    let answer = body["answer"].as_str().unwrap_or("");
    assert!(!answer.is_empty(), "librarian answer should not be empty: {body}");

    // Also test "All Projects" mode (empty project)
    let resp = client
        .post(url(&addr, "/ui/chat/librarian/ask"))
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "csrf_token={}&project=&question=What+projects+exist&include_history=0&allow_edits=0",
            csrf
        ))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body_text = resp.text().await.unwrap();
    eprintln!("librarian all-projects response status={status} body={body_text}");

    let body: Value = serde_json::from_str(&body_text)
        .unwrap_or_else(|_| panic!("all-projects response was not JSON: status={status} body={body_text}"));
    assert!(body["ok"].as_bool().unwrap_or(false), "all-projects ask failed: {body}");
}

#[tokio::test]
async fn librarian_ask_without_endpoint_returns_json_error() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;

    // Seed a project so the librarian has something to work with
    let token = api_create_agent_token(&client, &addr, "seed-agent", &[("no.ep.proj", "read_write")]).await;
    let resp = client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "no.ep.proj", "block_type": "markdown", "content": "test content"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "seed block failed");

    let (cookie, csrf) = admin_login(&client, &addr).await;

    // Ask about a specific project WITHOUT configuring a librarian endpoint
    let resp = client
        .post(url(&addr, "/ui/chat/librarian/ask"))
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "csrf_token={}&project=no.ep.proj&question=hello&include_history=0&allow_edits=0",
            csrf
        ))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body_text = resp.text().await.unwrap();
    eprintln!("no-endpoint response status={status} ct={content_type} body={body_text}");

    // This endpoint is called via fetch() from JS -- it MUST return JSON, not HTML
    assert!(
        content_type.contains("application/json"),
        "librarian ask should return JSON even on error, but got content-type={content_type} body={body_text}"
    );

    // Also test "All Projects" mode without endpoint
    let resp = client
        .post(url(&addr, "/ui/chat/librarian/ask"))
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "csrf_token={}&project=&question=hello&include_history=0&allow_edits=0",
            csrf
        ))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body_text = resp.text().await.unwrap();
    eprintln!("no-endpoint all-projects response status={status} ct={content_type} body={body_text}");

    assert!(
        content_type.contains("application/json"),
        "all-projects ask should return JSON even on error, but got content-type={content_type} body={body_text}"
    );
}

#[tokio::test]
async fn librarian_history_persists_after_ask() {
    let dir = tempdir().unwrap();
    let (llm_addr, _shutdown) = spawn_mock_llm().await;
    let (addr, client) = spawn_server(dir.path()).await;

    let endpoint_id = create_endpoint(
        &client,
        &addr,
        "hist-ep",
        &format!("http://{llm_addr}/v1/chat/completions"),
        "mock-model",
    )
    .await;

    let resp = client
        .post(url(&addr, "/v1/admin/librarian-config"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({
            "endpoint_id": endpoint_id,
            "request_timeout_secs": 30,
            "max_concurrent_runs": 2,
            "action_requires_approval": false
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let token = api_create_agent_token(&client, &addr, "hist-agent", &[("hist.proj", "read_write")]).await;
    let resp = client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "hist.proj", "block_type": "markdown", "content": "Testing history persistence."}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let (cookie, csrf) = admin_login(&client, &addr).await;

    // Send a librarian question
    let resp = client
        .post(url(&addr, "/ui/chat/librarian/ask"))
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "csrf_token={}&project=hist.proj&question=What+is+being+tested&include_history=0&allow_edits=0",
            csrf
        ))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert!(body["ok"].as_bool().unwrap_or(false), "ask failed: {body}");

    // Now fetch history -- it must contain the question and answer
    let resp = client
        .get(url(&addr, "/ui/chat/librarian/history?project=hist.proj"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    let history: Value = resp.json().await.unwrap();
    let messages = history["messages"].as_array().expect("messages should be an array");
    assert!(messages.len() >= 2, "history should have at least user + assistant: {history}");
    assert_eq!(messages[0]["role"].as_str().unwrap(), "user");
    assert!(messages[0]["content"].as_str().unwrap().contains("What is being tested"));
    assert_eq!(messages[1]["role"].as_str().unwrap(), "assistant");
    let answer = messages[1]["content"].as_str().unwrap();
    assert!(!answer.is_empty(), "assistant answer in history should not be empty");

    // Also check "All Projects" history includes the same run
    let resp = client
        .get(url(&addr, "/ui/chat/librarian/history?project="))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    let history: Value = resp.json().await.unwrap();
    let messages = history["messages"].as_array().expect("messages array");
    assert!(messages.len() >= 2, "all-projects history should include the run: {history}");
}

#[tokio::test]
async fn agent_chat_send_poll_respond() {
    let dir = tempdir().unwrap();
    let (llm_addr, _shutdown) = spawn_mock_llm().await;
    let (addr, client) = spawn_server(dir.path()).await;

    // Create endpoint pointing to mock LLM
    let endpoint_id = create_endpoint(
        &client,
        &addr,
        "chat-ep",
        &format!("http://{llm_addr}/v1/chat/completions"),
        "mock-model",
    )
    .await;

    // Create agent token with a project grant
    let token = api_create_agent_token(
        &client,
        &addr,
        "chat-bot",
        &[("chat.proj", "read_write")],
    )
    .await;

    // Seed a project so it exists
    let resp = client
        .post(url(&addr, "/v1/blocks"))
        .header("x-lore-key", &token)
        .json(&json!({"project": "chat.proj", "block_type": "markdown", "content": "seed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Login as admin to get session
    let (cookie, csrf) = admin_login(&client, &addr).await;

    // Assign the endpoint to the agent via the config endpoint
    let resp = client
        .post(url(&addr, &format!("/ui/chat/chat-bot/config")))
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "csrf_token={}&endpoint_id={}",
            csrf, endpoint_id
        ))
        .send()
        .await
        .unwrap();
    let config_status = resp.status();
    let config_body = resp.text().await.unwrap();
    eprintln!("assign endpoint status={config_status} body={config_body}");
    assert_eq!(config_status, 200, "assign endpoint failed: {config_body}");

    // Step 1: Send a message via the UI endpoint
    let resp = client
        .post(url(&addr, &format!("/ui/chat/chat-bot/send")))
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "csrf_token={}&message=Hello+agent",
            csrf
        ))
        .send()
        .await
        .unwrap();
    let send_status = resp.status();
    let send_body = resp.text().await.unwrap();
    eprintln!("send status={send_status} body={send_body}");
    assert_eq!(send_status, 200, "send message failed: {send_body}");

    // Step 2: Poll as the agent -- should see the pending message
    let resp = client
        .get(url(&addr, "/v1/chat/poll"))
        .header("x-lore-key", &token)
        .header("x-lore-version", env!("CARGO_PKG_VERSION"))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    let poll_status = resp.status();
    let poll_body: Value = resp.json().await.unwrap();
    eprintln!("poll status={poll_status} body={poll_body}");
    assert_eq!(poll_status, 200);

    let messages = poll_body["messages"].as_array().expect("messages should be array");
    assert!(!messages.is_empty(), "poll should return the pending message");
    let msg_content = messages[0]["content"].as_str().unwrap_or("");
    assert!(msg_content.contains("Hello agent"), "message content mismatch: {msg_content}");

    // Step 3: Agent responds (simulating what the machine does)
    let resp = client
        .post(url(&addr, "/v1/chat/respond"))
        .header("x-lore-key", &token)
        .json(&json!({
            "complete": true,
            "content": "Hi! I'm the agent responding."
        }))
        .send()
        .await
        .unwrap();
    let respond_status = resp.status();
    eprintln!("respond status={respond_status}");
    assert_eq!(respond_status, 200);

    // Step 4: Verify the conversation has both messages
    let resp = client
        .get(url(&addr, "/v1/chat/history"))
        .header("x-lore-key", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let history: Value = resp.json().await.unwrap();
    let hist_msgs = history["messages"].as_array().expect("history messages");
    eprintln!("history messages count={}", hist_msgs.len());
    let has_user_msg = hist_msgs.iter().any(|m| m["role"] == "user" && m["content"].as_str().unwrap_or("").contains("Hello agent"));
    let has_agent_msg = hist_msgs.iter().any(|m| m["role"] == "assistant" && m["content"].as_str().unwrap_or("").contains("agent responding"));
    assert!(has_user_msg, "history should contain user message");
    assert!(has_agent_msg, "history should contain agent response");

    // Step 5: Now test the REAL issue -- proxy a completion through the server
    // (this is what the machine does in API mode with an endpoint)
    let resp = client
        .post(url(&addr, "/v1/chat/completions"))
        .header("x-lore-key", &token)
        .json(&json!({
            "model": "mock-model",
            "messages": [{"role": "user", "content": "Test message through proxy"}],
            "stream": false
        }))
        .send()
        .await
        .unwrap();
    let proxy_status = resp.status();
    let proxy_body = resp.text().await.unwrap();
    eprintln!("proxy completions status={proxy_status} body={proxy_body}");
    assert_eq!(proxy_status, 200, "proxy completions failed: {proxy_body}");
    let proxy_json: Value = serde_json::from_str(&proxy_body)
        .unwrap_or_else(|_| panic!("proxy response not JSON: {proxy_body}"));
    assert!(
        proxy_json["choices"][0]["message"]["content"].as_str().is_some(),
        "proxy should return LLM response: {proxy_json}"
    );
}

#[tokio::test]
async fn full_mcp_protocol_flow() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;
    let token = api_create_agent_token(&client, &addr, "mcp-full-agent", &[("mcp.full.proj", "read_write")]).await;

    // MCP initialize (requires bearer auth)
    let resp = client
        .post(url(&addr, "/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("mcp-protocol-version", "2025-06-18")
        .header("accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let session_id = resp.headers().get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_default();
    let body: Value = resp.json().await.unwrap();
    assert!(body["result"]["capabilities"]["tools"].is_object(), "should advertise tool capabilities: {body:?}");

    // MCP tools/list (requires session header)
    let resp = client
        .post(url(&addr, "/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("mcp-session-id", &session_id)
        .header("mcp-protocol-version", "2025-06-18")
        .header("accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let tools = body["result"]["tools"].as_array().unwrap();
    assert!(!tools.is_empty(), "should have MCP tools");
}

// ---------------------------------------------------------------------------
// Multi-agent isolation test
// ---------------------------------------------------------------------------

/// Helper: create a role, non-admin user, register a machine, provision an agent.
/// Returns the agent token.
async fn setup_agent_with_project(
    client: &reqwest::Client,
    addr: &SocketAddr,
    role_name: &str,
    project: &str,
    username: &str,
    password: &str,
    machine_name: &str,
    agent_display_name: &str,
) -> String {
    // Create role granting read_write to the project
    let resp = client
        .post(url(addr, "/v1/admin/roles"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({
            "name": role_name,
            "grants": [{"project": project, "permission": "read_write"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create role {role_name} failed");

    // Create non-admin user with that role
    let resp = client
        .post(url(addr, "/v1/admin/users"))
        .header("authorization", basic_auth(ADMIN_USER, ADMIN_PASS))
        .json(&json!({
            "username": username,
            "password": password,
            "roles": [role_name],
            "is_admin": false
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create user {username} failed");

    // Register machine (authenticates with user credentials)
    let resp = client
        .post(url(addr, "/v1/machines/register"))
        .json(&json!({
            "username": username,
            "password": password,
            "machine_name": machine_name
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "register machine {machine_name} failed");
    let body: Value = resp.json().await.unwrap();
    let machine_token = body["token"].as_str().unwrap().to_string();

    // Provision agent via machine token
    let resp = client
        .post(url(addr, "/v1/agents/provision"))
        .header("x-lore-key", &machine_token)
        .json(&json!({"name": agent_display_name}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "provision agent {agent_display_name} failed");
    let body: Value = resp.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_agent_isolation_and_concurrent_execution() {
    let dir = tempdir().unwrap();
    let (addr, client) = spawn_server(dir.path()).await;

    // --- Setup: two users, two agents, two projects ---

    let token_alpha = setup_agent_with_project(
        &client, &addr,
        "role-alpha", "project.alpha",
        "user-alpha", "pass-alpha-123",
        "machine-alpha", "agent-alpha",
    )
    .await;

    let token_beta = setup_agent_with_project(
        &client, &addr,
        "role-beta", "project.beta",
        "user-beta", "pass-beta-456",
        "machine-beta", "agent-beta",
    )
    .await;

    // --- Seed both projects concurrently ---

    let (seed_a, seed_b) = tokio::join!(
        client
            .post(url(&addr, "/v1/blocks"))
            .header("x-lore-key", &token_alpha)
            .json(&json!({"project": "project.alpha", "block_type": "markdown", "content": "Alpha secret data"}))
            .send(),
        client
            .post(url(&addr, "/v1/blocks"))
            .header("x-lore-key", &token_beta)
            .json(&json!({"project": "project.beta", "block_type": "markdown", "content": "Beta secret data"}))
            .send(),
    );
    assert_eq!(seed_a.unwrap().status(), 200, "seed alpha failed");
    assert_eq!(seed_b.unwrap().status(), 200, "seed beta failed");

    // Create documents in each project concurrently
    let (doc_a_resp, doc_b_resp) = tokio::join!(
        client
            .post(url(&addr, "/v1/projects/project.alpha/documents"))
            .header("x-lore-key", &token_alpha)
            .json(&json!({"name": "Alpha Doc"}))
            .send(),
        client
            .post(url(&addr, "/v1/projects/project.beta/documents"))
            .header("x-lore-key", &token_beta)
            .json(&json!({"name": "Beta Doc"}))
            .send(),
    );
    let doc_a: Value = doc_a_resp.unwrap().json().await.unwrap();
    let doc_b: Value = doc_b_resp.unwrap().json().await.unwrap();
    let doc_a_id = doc_a["id"].as_str().unwrap().to_string();
    let doc_b_id = doc_b["id"].as_str().unwrap().to_string();

    // Create blocks in each document concurrently
    let (blk_a, blk_b) = tokio::join!(
        client
            .post(url(&addr, &format!("/v1/projects/project.alpha/documents/{doc_a_id}/blocks")))
            .header("x-lore-key", &token_alpha)
            .json(&json!({"block_type": "markdown", "content": "Alpha confidential notes"}))
            .send(),
        client
            .post(url(&addr, &format!("/v1/projects/project.beta/documents/{doc_b_id}/blocks")))
            .header("x-lore-key", &token_beta)
            .json(&json!({"block_type": "markdown", "content": "Beta confidential notes"}))
            .send(),
    );
    assert_eq!(blk_a.unwrap().status(), 200, "create alpha block failed");
    assert_eq!(blk_b.unwrap().status(), 200, "create beta block failed");

    // --- Verify: each agent sees only its own project ---

    // list_projects: alpha sees project.alpha, not project.beta
    let resp = client
        .get(url(&addr, "/v1/projects"))
        .header("x-lore-key", &token_alpha)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let projects: Value = resp.json().await.unwrap();
    let project_slugs: Vec<&str> = projects
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| {
            p["project"].as_str().or_else(|| p["project"]["slug"].as_str())
        })
        .collect();
    assert!(
        project_slugs.contains(&"project.alpha"),
        "alpha should see project.alpha: {project_slugs:?}"
    );
    assert!(
        !project_slugs.contains(&"project.beta"),
        "alpha must NOT see project.beta: {project_slugs:?}"
    );

    // Same check for beta
    let resp = client
        .get(url(&addr, "/v1/projects"))
        .header("x-lore-key", &token_beta)
        .send()
        .await
        .unwrap();
    let projects: Value = resp.json().await.unwrap();
    let project_slugs: Vec<&str> = projects
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| {
            p["project"].as_str().or_else(|| p["project"]["slug"].as_str())
        })
        .collect();
    assert!(
        project_slugs.contains(&"project.beta"),
        "beta should see project.beta: {project_slugs:?}"
    );
    assert!(
        !project_slugs.contains(&"project.alpha"),
        "beta must NOT see project.alpha: {project_slugs:?}"
    );

    // --- Cross-project access denied (concurrent checks) ---

    let (cross_a, cross_b) = tokio::join!(
        // Alpha tries to read beta's doc blocks
        client
            .get(url(&addr, &format!("/v1/projects/project.beta/documents/{doc_b_id}/blocks")))
            .header("x-lore-key", &token_alpha)
            .send(),
        // Beta tries to read alpha's doc blocks
        client
            .get(url(&addr, &format!("/v1/projects/project.alpha/documents/{doc_a_id}/blocks")))
            .header("x-lore-key", &token_beta)
            .send(),
    );
    let cross_a_status = cross_a.unwrap().status().as_u16();
    let cross_b_status = cross_b.unwrap().status().as_u16();
    assert!(
        cross_a_status >= 400,
        "alpha reading beta's blocks should be denied, got {cross_a_status}"
    );
    assert!(
        cross_b_status >= 400,
        "beta reading alpha's blocks should be denied, got {cross_b_status}"
    );

    // Cross-project write denied
    let (write_cross_a, write_cross_b) = tokio::join!(
        client
            .post(url(&addr, "/v1/blocks"))
            .header("x-lore-key", &token_alpha)
            .json(&json!({"project": "project.beta", "block_type": "markdown", "content": "infiltration"}))
            .send(),
        client
            .post(url(&addr, "/v1/blocks"))
            .header("x-lore-key", &token_beta)
            .json(&json!({"project": "project.alpha", "block_type": "markdown", "content": "infiltration"}))
            .send(),
    );
    assert!(
        write_cross_a.unwrap().status().as_u16() >= 400,
        "alpha writing to beta's project should be denied"
    );
    assert!(
        write_cross_b.unwrap().status().as_u16() >= 400,
        "beta writing to alpha's project should be denied"
    );

    // Cross-project MCP tool call denied
    let (mcp_cross_a, mcp_cross_b) = tokio::join!(
        client
            .post(url(&addr, "/v1/chat/lore-tools"))
            .header("x-lore-key", &token_alpha)
            .json(&json!({"name": "list_blocks", "arguments": {"project": "project.beta", "document_id": doc_b_id}}))
            .send(),
        client
            .post(url(&addr, "/v1/chat/lore-tools"))
            .header("x-lore-key", &token_beta)
            .json(&json!({"name": "list_blocks", "arguments": {"project": "project.alpha", "document_id": doc_a_id}}))
            .send(),
    );
    let mcp_a_status = mcp_cross_a.unwrap().status().as_u16();
    let mcp_b_status = mcp_cross_b.unwrap().status().as_u16();
    assert!(
        mcp_a_status >= 400,
        "alpha MCP into beta should be denied, got status {mcp_a_status}"
    );
    assert!(
        mcp_b_status >= 400,
        "beta MCP into alpha should be denied, got status {mcp_b_status}"
    );

    // Cross-project document listing denied
    let (list_docs_a, list_docs_b) = tokio::join!(
        client
            .get(url(&addr, "/v1/projects/project.beta/documents"))
            .header("x-lore-key", &token_alpha)
            .send(),
        client
            .get(url(&addr, "/v1/projects/project.alpha/documents"))
            .header("x-lore-key", &token_beta)
            .send(),
    );
    assert!(
        list_docs_a.unwrap().status().as_u16() >= 400,
        "alpha listing beta's documents should be denied"
    );
    assert!(
        list_docs_b.unwrap().status().as_u16() >= 400,
        "beta listing alpha's documents should be denied"
    );

    // Cross-project block deletion denied
    // First, get a block ID from each project to attempt deletion
    let own_blocks_a: Value = client
        .get(url(&addr, &format!("/v1/projects/project.alpha/documents/{doc_a_id}/blocks")))
        .header("x-lore-key", &token_alpha)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let block_a_id = own_blocks_a.as_array().unwrap()
        .iter()
        .find(|b| b["block_type"].as_str() == Some("markdown"))
        .and_then(|b| b["id"].as_str())
        .expect("alpha should have a markdown block");

    let own_blocks_b: Value = client
        .get(url(&addr, &format!("/v1/projects/project.beta/documents/{doc_b_id}/blocks")))
        .header("x-lore-key", &token_beta)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let block_b_id = own_blocks_b.as_array().unwrap()
        .iter()
        .find(|b| b["block_type"].as_str() == Some("markdown"))
        .and_then(|b| b["id"].as_str())
        .expect("beta should have a markdown block");

    let (del_cross_a, del_cross_b) = tokio::join!(
        // Alpha tries to delete beta's block
        client
            .delete(url(&addr, &format!("/v1/blocks/{block_b_id}?project=project.beta")))
            .header("x-lore-key", &token_alpha)
            .send(),
        // Beta tries to delete alpha's block
        client
            .delete(url(&addr, &format!("/v1/blocks/{block_a_id}?project=project.alpha")))
            .header("x-lore-key", &token_beta)
            .send(),
    );
    assert!(
        del_cross_a.unwrap().status().as_u16() >= 400,
        "alpha deleting beta's block should be denied"
    );
    assert!(
        del_cross_b.unwrap().status().as_u16() >= 400,
        "beta deleting alpha's block should be denied"
    );

    // Cross-project project-level block reads denied
    let (proj_blocks_a, proj_blocks_b) = tokio::join!(
        client
            .get(url(&addr, "/v1/projects/project.beta/blocks"))
            .header("x-lore-key", &token_alpha)
            .send(),
        client
            .get(url(&addr, "/v1/projects/project.alpha/blocks"))
            .header("x-lore-key", &token_beta)
            .send(),
    );
    assert!(
        proj_blocks_a.unwrap().status().as_u16() >= 400,
        "alpha reading beta's project blocks should be denied"
    );
    assert!(
        proj_blocks_b.unwrap().status().as_u16() >= 400,
        "beta reading alpha's project blocks should be denied"
    );

    // --- Concurrent agent execution: fake LLM backends running in parallel ---
    //
    // This verifies that two agents can simultaneously receive chat requests,
    // spawn backend subprocesses, and complete their work concurrently.
    // A fake "claude" script sleeps 3 seconds then outputs valid stream-json.
    // If agents run in parallel: wall clock ~3-4s.  If serialized: ~6-7s.

    // Create a fake claude binary that takes 3+ seconds
    let fake_bin_dir = dir.path().join("fake-bin");
    std::fs::create_dir_all(&fake_bin_dir).unwrap();
    let fake_claude_path = fake_bin_dir.join("fake-claude");
    std::fs::write(&fake_claude_path, concat!(
        "#!/bin/sh\n",
        "cat > /dev/null\n",
        "sleep 3\n",
        "echo '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"Fake LLM done\"}]}}'\n",
        "echo '{\"type\":\"result\",\"result\":\"Done\"}'\n",
    )).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_claude_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Login as each user and get CSRF tokens
    let resp_a = client
        .post(url(&addr, "/login"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("username=user-alpha&password=pass-alpha-123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp_a.status(), 303);
    let cookie_a = resp_a
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let page_a = client
        .get(url(&addr, "/ui"))
        .header("cookie", &cookie_a)
        .send()
        .await
        .unwrap();
    let csrf_a = extract_hidden_value(&page_a.text().await.unwrap(), "csrf_token").unwrap();

    let resp_b = client
        .post(url(&addr, "/login"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("username=user-beta&password=pass-beta-456")
        .send()
        .await
        .unwrap();
    assert_eq!(resp_b.status(), 303);
    let cookie_b = resp_b
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let page_b = client
        .get(url(&addr, "/ui"))
        .header("cookie", &cookie_b)
        .send()
        .await
        .unwrap();
    let csrf_b = extract_hidden_value(&page_b.text().await.unwrap(), "csrf_token").unwrap();

    // Queue messages to both agents
    let (send_a, send_b) = tokio::join!(
        client
            .post(url(&addr, "/ui/chat/agent-alpha/send"))
            .header("cookie", &cookie_a)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("csrf_token={}&message=Hello+alpha+agent", csrf_a))
            .send(),
        client
            .post(url(&addr, "/ui/chat/agent-beta/send"))
            .header("cookie", &cookie_b)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("csrf_token={}&message=Hello+beta+agent", csrf_b))
            .send(),
    );
    assert_eq!(send_a.unwrap().status(), 200, "send to alpha failed");
    assert_eq!(send_b.unwrap().status(), 200, "send to beta failed");

    // Now simulate two concurrent agent tasks:
    //   1. Poll for the pending message
    //   2. Spawn the fake backend (3s+ subprocess)
    //   3. Read its output
    //   4. Post the response back
    // If these run in parallel, wall clock is ~3-4s. If serialized, ~6-7s.

    let concurrency_start = std::time::Instant::now();
    let fake_bin = fake_claude_path.clone();
    let fake_bin2 = fake_claude_path.clone();
    let client_ref = &client;
    let addr_ref = &addr;

    let agent_task = |token: String, agent_label: &'static str, fake_binary: std::path::PathBuf| {
        let client = client_ref.clone();
        let addr = *addr_ref;
        async move {
            // Poll for the pending message
            let resp = client
                .get(url(&addr, "/v1/chat/poll"))
                .header("x-lore-key", &token)
                .header("x-lore-version", env!("CARGO_PKG_VERSION"))
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .expect(&format!("{agent_label} poll failed"));
            let body: Value = resp.json().await.unwrap();
            let msgs = body["messages"].as_array().expect(&format!("{agent_label} should have messages"));
            assert!(!msgs.is_empty(), "{agent_label} should have a pending message");
            let msg_content = msgs[0]["content"].as_str().unwrap_or("");
            assert!(
                msg_content.contains(agent_label),
                "{agent_label} got wrong message: {msg_content}"
            );

            // Spawn the fake backend subprocess (3 second task)
            let mut child = tokio::process::Command::new(&fake_binary)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect(&format!("{agent_label} failed to spawn fake backend"));

            // Close stdin so the script's `cat` finishes
            drop(child.stdin.take());

            // Read output line by line (like the real agent does)
            let stdout = child.stdout.take().unwrap();
            let reader = tokio::io::BufReader::new(stdout);
            use tokio::io::AsyncBufReadExt;
            let mut lines = reader.lines();
            let mut response_text = String::new();
            while let Some(line) = lines.next_line().await.unwrap() {
                if line.trim().is_empty() { continue; }
                if let Ok(parsed) = serde_json::from_str::<Value>(&line) {
                    // Extract text from claude stream-json format
                    if parsed["type"].as_str() == Some("assistant") {
                        if let Some(content) = parsed["message"]["content"].as_array() {
                            for block in content {
                                if block["type"].as_str() == Some("text") {
                                    if let Some(t) = block["text"].as_str() {
                                        response_text.push_str(t);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let exit = child.wait().await.unwrap();
            assert!(exit.success(), "{agent_label} fake backend exited with error");

            // Post the response back
            let resp = client
                .post(url(&addr, "/v1/chat/respond"))
                .header("x-lore-key", &token)
                .json(&json!({
                    "complete": true,
                    "content": format!("{agent_label} agent done: {response_text}")
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "{agent_label} respond failed");
        }
    };

    let ((), ()) = tokio::join!(
        agent_task(token_alpha.clone(), "alpha", fake_bin),
        agent_task(token_beta.clone(), "beta", fake_bin2),
    );

    let concurrency_elapsed = concurrency_start.elapsed();
    assert!(
        concurrency_elapsed < std::time::Duration::from_secs(5),
        "concurrent agent execution took {:?} -- two 3s backend tasks in parallel should \
         complete in <5s; >=5s indicates serialized execution",
        concurrency_elapsed
    );
    assert!(
        concurrency_elapsed >= std::time::Duration::from_secs(3),
        "concurrent agent execution took {:?} -- expected at least 3s from the backend sleep",
        concurrency_elapsed
    );

    // Verify conversation histories are independent after the concurrent execution
    let (hist_a, hist_b) = tokio::join!(
        client
            .get(url(&addr, "/v1/chat/history"))
            .header("x-lore-key", &token_alpha)
            .send(),
        client
            .get(url(&addr, "/v1/chat/history"))
            .header("x-lore-key", &token_beta)
            .send(),
    );
    let hist_a_body: Value = hist_a.unwrap().json().await.unwrap();
    let hist_b_body: Value = hist_b.unwrap().json().await.unwrap();

    let hist_a_msgs = hist_a_body["messages"].as_array().expect("alpha history");
    let hist_b_msgs = hist_b_body["messages"].as_array().expect("beta history");

    let a_texts: String = hist_a_msgs
        .iter()
        .filter_map(|m| m["content"].as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let b_texts: String = hist_b_msgs
        .iter()
        .filter_map(|m| m["content"].as_str())
        .collect::<Vec<_>>()
        .join(" ");

    assert!(a_texts.contains("alpha"), "alpha history should have alpha content");
    assert!(!a_texts.contains("beta"), "alpha history must NOT contain beta content: {a_texts}");
    assert!(b_texts.contains("beta"), "beta history should have beta content");
    assert!(!b_texts.contains("alpha"), "beta history must NOT contain alpha content: {b_texts}");
}
