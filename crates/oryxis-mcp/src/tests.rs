#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use serde_json::{json, Value};
    use tempfile::NamedTempFile;

    use oryxis_core::models::connection::Connection;
    use oryxis_core::models::group::Group;
    use oryxis_core::models::key::{KeyAlgorithm, SshKey};
    use oryxis_vault::VaultStore;

    use crate::handlers::{dial_signature, reuse_signature};
    use crate::server::Server;
    use crate::stdio;
    use crate::tools::tool_definitions;

    /// A cancel handle nobody will ever pull.
    fn no_cancel() -> tokio::sync::watch::Receiver<bool> {
        let (tx, rx) = tokio::sync::watch::channel(false);
        std::mem::forget(tx);
        rx
    }

    fn test_vault() -> VaultStore {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let mut vault = VaultStore::open(&path).unwrap();
        vault.set_master_password("test").unwrap();
        let _ = vault.set_setting("mcp_server_enabled", "true");
        vault
    }

    #[test]
    fn tool_definitions_has_five_tools() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 5);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"list_hosts"));
        assert!(names.contains(&"get_host"));
        assert!(names.contains(&"ssh_execute"));
        assert!(names.contains(&"list_groups"));
        assert!(names.contains(&"list_keys"));
    }

    #[tokio::test]
    async fn initialize_returns_server_info() {
        let server = Server::new(test_vault());
        let resp = server.handle_request("initialize", json!(1), None, no_cancel()).await;
        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "oryxis-mcp");
        assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
        // No requested version in params: answer with the latest supported.
        assert_eq!(result["protocolVersion"], "2025-06-18");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn initialize_echoes_supported_requested_version() {
        let server = Server::new(test_vault());
        for requested in ["2024-11-05", "2025-03-26", "2025-06-18"] {
            let params = json!({
                "protocolVersion": requested,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            });
            let resp = server.handle_request("initialize", json!(1), Some(&params), no_cancel()).await;
            let result = resp.result.unwrap();
            assert_eq!(result["protocolVersion"], requested);
        }
    }

    #[tokio::test]
    async fn initialize_unknown_version_falls_back_to_latest() {
        let server = Server::new(test_vault());
        let params = json!({
            "protocolVersion": "2099-01-01",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        });
        let resp = server.handle_request("initialize", json!(1), Some(&params), no_cancel()).await;
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2025-06-18");
    }

    #[tokio::test]
    async fn ping_returns_empty_result() {
        let server = Server::new(test_vault());
        let resp = server.handle_request("ping", json!(11), None, no_cancel()).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result, json!({}));
    }

    #[tokio::test]
    async fn tools_list_returns_all_tools() {
        let server = Server::new(test_vault());
        let resp = server.handle_request("tools/list", json!(2), None, no_cancel()).await;
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 5);
    }

    #[tokio::test]
    async fn list_hosts_empty_vault() {
        let server = Server::new(test_vault());
        let resp = server.handle_request(
            "tools/call",
            json!(3),
            Some(&json!({"name": "list_hosts", "arguments": {}})),
            no_cancel(),
        )
        .await;
        let result = resp.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let hosts: Vec<Value> = serde_json::from_str(text).unwrap();
        assert!(hosts.is_empty());
    }

    #[tokio::test]
    async fn list_hosts_returns_mcp_enabled_only() {
        let server = Server::new(test_vault());

        let mut c1 = Connection::new("enabled-host", "10.0.0.1");
        c1.mcp_enabled = true;
        server.vault().save_connection(&c1, None).unwrap();

        let mut c2 = Connection::new("disabled-host", "10.0.0.2");
        c2.mcp_enabled = false;
        server.vault().save_connection(&c2, None).unwrap();

        let resp = server.handle_request(
            "tools/call",
            json!(4),
            Some(&json!({"name": "list_hosts", "arguments": {}})),
            no_cancel(),
        )
        .await;
        let result = resp.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let hosts: Vec<Value> = serde_json::from_str(text).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["label"], "enabled-host");
    }

    #[tokio::test]
    async fn get_host_returns_details() {
        let server = Server::new(test_vault());
        let conn = Connection::new("my-server", "192.168.1.100");
        server.vault().save_connection(&conn, None).unwrap();

        let resp = server.handle_request(
            "tools/call",
            json!(5),
            Some(&json!({"name": "get_host", "arguments": {"id": conn.id.to_string()}})),
            no_cancel(),
        )
        .await;
        let result = resp.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let host: Value = serde_json::from_str(text).unwrap();
        assert_eq!(host["label"], "my-server");
        assert_eq!(host["hostname"], "192.168.1.100");
        assert_eq!(host["port"], 22);
    }

    #[tokio::test]
    async fn get_host_not_found() {
        let server = Server::new(test_vault());
        let resp = server.handle_request(
            "tools/call",
            json!(6),
            Some(&json!({"name": "get_host", "arguments": {"id": "00000000-0000-0000-0000-000000000000"}})),
            no_cancel(),
        )
        .await;
        let result = resp.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
    }

    #[tokio::test]
    async fn list_groups_works() {
        let server = Server::new(test_vault());
        let g = Group::new("Production");
        server.vault().save_group(&g).unwrap();

        let resp = server.handle_request(
            "tools/call",
            json!(7),
            Some(&json!({"name": "list_groups", "arguments": {}})),
            no_cancel(),
        )
        .await;
        let result = resp.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let groups: Vec<Value> = serde_json::from_str(text).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["label"], "Production");
    }

    #[tokio::test]
    async fn list_keys_no_private_data() {
        let server = Server::new(test_vault());
        let key = SshKey::new("my-key", KeyAlgorithm::Ed25519);
        server.vault().save_key(&key, Some("PRIVATE_KEY_DATA")).unwrap();

        let resp = server.handle_request(
            "tools/call",
            json!(8),
            Some(&json!({"name": "list_keys", "arguments": {}})),
            no_cancel(),
        )
        .await;
        let result = resp.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        // Verify no private key data leaked
        assert!(!text.contains("PRIVATE_KEY_DATA"));
        let keys: Vec<Value> = serde_json::from_str(text).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["label"], "my-key");
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let server = Server::new(test_vault());
        let resp = server.handle_request("nonexistent/method", json!(9), None, no_cancel()).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn unknown_tool_returns_error() {
        let server = Server::new(test_vault());
        let resp = server.handle_request(
            "tools/call",
            json!(10),
            Some(&json!({"name": "nonexistent_tool", "arguments": {}})),
            no_cancel(),
        )
        .await;
        let result = resp.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
    }

    #[tokio::test]
    async fn mcp_disabled_rejects_calls() {
        let server = Server::new(test_vault());
        let _ = server.vault().set_setting("mcp_server_enabled", "false");

        let resp = server.handle_request(
            "tools/call",
            json!(11),
            Some(&json!({"name": "list_hosts", "arguments": {}})),
            no_cancel(),
        )
        .await;
        let result = resp.result.unwrap();
        assert!(result["isError"].as_bool().unwrap_or(false));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("disabled"));
    }

    #[tokio::test]
    async fn list_hosts_filter_by_tag() {
        let server = Server::new(test_vault());

        let mut c1 = Connection::new("web", "10.0.0.1");
        c1.tags = vec!["production".into()];
        server.vault().save_connection(&c1, None).unwrap();

        let mut c2 = Connection::new("db", "10.0.0.2");
        c2.tags = vec!["staging".into()];
        server.vault().save_connection(&c2, None).unwrap();

        let resp = server.handle_request(
            "tools/call",
            json!(12),
            Some(&json!({"name": "list_hosts", "arguments": {"tag": "production"}})),
            no_cancel(),
        )
        .await;
        let result = resp.result.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let hosts: Vec<Value> = serde_json::from_str(text).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["label"], "web");
    }

    #[test]
    fn dial_signature_ignores_recency_and_detection() {
        let mut a = Connection::new("web", "10.0.0.1");
        let before = dial_signature(&a);
        // The two narrow updates the app makes on every connect.
        a.last_used = Some(chrono::Utc::now());
        a.detected_os = Some("linux".into());
        a.updated_at = chrono::Utc::now();
        a.notes = Some("edited".into());
        assert_eq!(dial_signature(&a), before);
    }

    #[test]
    fn dial_signature_follows_the_dial_fields() {
        let base = Connection::new("web", "10.0.0.1");
        let before = dial_signature(&base);

        let mut moved = base.clone();
        moved.hostname = "10.0.0.2".into();
        assert_ne!(dial_signature(&moved), before);

        let mut reported = base.clone();
        reported.port = 2222;
        assert_ne!(dial_signature(&reported), before);

        let mut renamed = base.clone();
        renamed.username = Some("deploy".into());
        assert_ne!(dial_signature(&renamed), before);

        let mut rekeyed = base.clone();
        rekeyed.key_id = Some(uuid::Uuid::new_v4());
        assert_ne!(dial_signature(&rekeyed), before);

        let mut hopped = base.clone();
        hopped.jump_chain = vec![uuid::Uuid::new_v4()];
        assert_ne!(dial_signature(&hopped), before);
    }

    fn pin(host: &str, port: u16, key_type: &str, fingerprint: &str) -> oryxis_core::models::KnownHost {
        let now = chrono::Utc::now();
        oryxis_core::models::KnownHost {
            id: uuid::Uuid::new_v4(),
            hostname: host.into(),
            port,
            key_type: key_type.into(),
            fingerprint: fingerprint.into(),
            first_seen: now,
            last_seen: now,
            updated_at: now,
        }
    }

    /// Withdrawing trust from a route stops the pool reusing a
    /// connection dialled under it: removing or replacing the host's
    /// pin, or revoking its command proxy. An unrelated pin does not.
    #[test]
    fn reuse_signature_follows_the_trust_the_dial_needed() {
        use oryxis_core::models::connection::{proxy_command_fingerprint, ProxyConfig, ProxyType};
        use std::collections::HashSet;

        let conn = Connection::new("web", "10.0.0.1");
        let pins = vec![pin("10.0.0.1", 22, "ssh-ed25519", "SHA256:aaa")];
        let none = HashSet::new();
        let before = reuse_signature(&conn, &[], &pins, &none);

        let mut other = pins.clone();
        other.push(pin("10.0.0.9", 22, "ssh-ed25519", "SHA256:zzz"));
        assert_eq!(reuse_signature(&conn, &[], &other, &none), before);

        assert_ne!(reuse_signature(&conn, &[], &[], &none), before, "pin removed");
        let changed = vec![pin("10.0.0.1", 22, "ssh-ed25519", "SHA256:bbb")];
        assert_ne!(reuse_signature(&conn, &[], &changed, &none), before, "pin replaced");

        let line = "ssh -W %h:%p bastion";
        let mut proxied = conn.clone();
        proxied.proxy = Some(ProxyConfig {
            proxy_type: ProxyType::Command(line.into()),
            host: String::new(),
            port: 0,
            username: None,
            password: None,
        });
        let trusted: HashSet<String> = [proxy_command_fingerprint(line)].into();
        assert_ne!(
            reuse_signature(&proxied, &[], &pins, &trusted),
            reuse_signature(&proxied, &[], &pins, &none),
            "revoking the command proxy"
        );
    }

    /// A pin withdrawn from a bastion of the jump chain withdraws the
    /// route too; a pin of a host that is not on the route does not.
    #[test]
    fn reuse_signature_follows_the_pins_of_every_hop() {
        use std::collections::HashSet;

        let conn = Connection::new("db", "10.0.0.1");
        let hops = [("bastion.example", 22u16)];
        let none = HashSet::new();
        let pins = vec![
            pin("10.0.0.1", 22, "ssh-ed25519", "SHA256:aaa"),
            pin("bastion.example", 22, "ssh-ed25519", "SHA256:bbb"),
        ];
        let before = reuse_signature(&conn, &hops, &pins, &none);
        let mut unrelated = pins.clone();
        unrelated.push(pin("elsewhere", 22, "ssh-ed25519", "SHA256:zzz"));
        assert_eq!(reuse_signature(&conn, &hops, &unrelated, &none), before);
        let bastion_gone = vec![pin("10.0.0.1", 22, "ssh-ed25519", "SHA256:aaa")];
        assert_ne!(
            reuse_signature(&conn, &hops, &bastion_gone, &none),
            before,
            "bastion pin removed"
        );
        let bastion_changed = vec![
            pin("10.0.0.1", 22, "ssh-ed25519", "SHA256:aaa"),
            pin("bastion.example", 22, "ssh-ed25519", "SHA256:ccc"),
        ];
        assert_ne!(
            reuse_signature(&conn, &hops, &bastion_changed, &none),
            before,
            "bastion pin replaced"
        );
    }

    async fn send(w: &mut tokio::io::DuplexStream, v: Value) {
        use tokio::io::AsyncWriteExt;
        w.write_all(format!("{}\n", v).as_bytes()).await.unwrap();
    }

    async fn next_json(
        lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::io::DuplexStream>>,
        within: std::time::Duration,
    ) -> Option<Value> {
        match tokio::time::timeout(within, lines.next_line()).await {
            Ok(Ok(Some(line))) => Some(serde_json::from_str(&line).unwrap()),
            Ok(_) => panic!("output closed"),
            Err(_) => None,
        }
    }

    /// The property the loop exists for: a tool call stuck in its dial
    /// leaves the pipe free. A `ping` sent behind it answers at once, a
    /// cancel for it is honoured (no response ever goes out for that
    /// id), and the loop keeps serving afterwards.
    #[tokio::test]
    async fn a_dial_in_flight_does_not_block_the_loop_and_a_cancel_silences_it() {
        use std::sync::Arc;
        use tokio::io::AsyncBufReadExt;

        let server = Server::new(test_vault());
        // Listening but never speaking: the TCP handshake completes and
        // the dial then waits on an SSH banner that never comes.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut conn = Connection::new("silent", "127.0.0.1");
        conn.port = port;
        conn.mcp_enabled = true;
        server.vault().save_connection(&conn, None).unwrap();

        let (mut client_w, server_r) = tokio::io::duplex(1 << 16);
        let (server_w, client_r) = tokio::io::duplex(1 << 16);
        let loop_task = tokio::spawn(stdio::serve(Arc::clone(&server), server_r, server_w));
        let mut lines = tokio::io::BufReader::new(client_r).lines();

        send(
            &mut client_w,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "ssh_execute", "arguments": {
                    "id": conn.id.to_string(), "command": "echo hello"
                }}
            }),
        )
        .await;
        send(&mut client_w, json!({"jsonrpc": "2.0", "id": 2, "method": "ping"})).await;

        let pong = next_json(&mut lines, std::time::Duration::from_secs(3))
            .await
            .expect("ping answered while a dial is in flight");
        assert_eq!(pong["id"], 2);
        assert_eq!(pong["result"], json!({}));

        send(
            &mut client_w,
            json!({
                "jsonrpc": "2.0", "method": "notifications/cancelled",
                "params": {"requestId": 1, "reason": "user gave up"}
            }),
        )
        .await;
        // Nothing for the cancelled call, in either direction.
        assert!(
            next_json(&mut lines, std::time::Duration::from_secs(2)).await.is_none(),
            "a cancelled request must not be answered"
        );

        send(&mut client_w, json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})).await;
        let listed = next_json(&mut lines, std::time::Duration::from_secs(3))
            .await
            .expect("the loop keeps serving after a cancel");
        assert_eq!(listed["id"], 3);
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 5);

        // A line that is not JSON gets the parse error, and nothing else
        // is disturbed by it.
        use tokio::io::AsyncWriteExt;
        client_w.write_all(b"not json\n").await.unwrap();
        let parse = next_json(&mut lines, std::time::Duration::from_secs(3))
            .await
            .expect("parse errors are answered");
        assert_eq!(parse["error"]["code"], -32700);

        drop(client_w);
        tokio::time::timeout(std::time::Duration::from_secs(5), loop_task)
            .await
            .expect("the loop ends when its input closes")
            .unwrap();
        drop(listener);
    }
    /// A client that writes and closes its end at once still reads the
    /// answers: EOF flushes the writer instead of aborting it.
    #[tokio::test]
    async fn answers_queued_at_eof_still_go_out() {
        use std::sync::Arc;
        use tokio::io::AsyncBufReadExt;

        let server = Server::new(test_vault());
        let (mut client_w, server_r) = tokio::io::duplex(1 << 16);
        let (server_w, client_r) = tokio::io::duplex(1 << 16);
        let loop_task = tokio::spawn(stdio::serve(Arc::clone(&server), server_r, server_w));
        send(&mut client_w, json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})).await;
        send(&mut client_w, json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).await;
        drop(client_w);
        tokio::time::timeout(std::time::Duration::from_secs(5), loop_task)
            .await
            .expect("the loop ends when its input closes")
            .unwrap();
        let mut lines = tokio::io::BufReader::new(client_r).lines();
        let mut ids = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            let v: Value = serde_json::from_str(&line).unwrap();
            ids.push(v["id"].as_i64().unwrap());
        }
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
    }
}
