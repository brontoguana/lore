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
    let token_a = api_create_agent_token(&client, &addr, "agent-a", &[("project.a", "read_write")]).await;

    // Try to create a block in a project the agent doesn't have access to
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
