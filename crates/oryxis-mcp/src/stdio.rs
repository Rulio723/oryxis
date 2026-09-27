//! The JSON-RPC loop over a line-delimited byte stream (stdio in
//! production, an in-memory duplex in tests).
//!
//! Requests run CONCURRENTLY, one task each, and the loop goes straight
//! back to reading. That is the property everything else here rests on:
//! a `ping` or a second tool call is answered while an `ssh_execute` is
//! still dialling, and a `notifications/cancelled` for that call is
//! read the moment it arrives rather than after the dial ends. A
//! sequential loop would hold every later line in the pipe for the
//! length of the slowest call, and the client at the other end, which
//! has a budget per call, would read that silence as a dead server.
//!
//! Responses therefore go out in completion order, which JSON-RPC
//! allows (the id is what matches them). One writer task serialises the
//! lines so two responses can never interleave on the pipe.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch};

use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::server::Server;

/// The requests still running, by the JSON id the client will name in
/// a cancel. The sequence number tells a request's own entry from a
/// later one that reused the same id, so finishing never removes a
/// stranger's cancel handle.
#[derive(Default)]
struct InFlight {
    next_seq: u64,
    entries: HashMap<String, (u64, watch::Sender<bool>)>,
}

type Shared = Arc<Mutex<InFlight>>;

/// Serve requests read from `reader` until it reaches EOF, writing
/// responses to `writer`. Returns once the input is closed; requests
/// still running at that point are abandoned with the process.
pub async fn serve<R, W>(server: Arc<Server>, reader: R, writer: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (out_tx, out_rx) = mpsc::unbounded_channel::<String>();
    let writer_task = tokio::spawn(write_lines(writer, out_rx));
    let in_flight: Shared = Arc::default();

    let mut lines = BufReader::new(reader).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(e) => {
                tracing::info!(error = %e, "input closed");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                tracing::info!(error = %e, "parse error");
                let err = JsonRpcResponse::error(Value::Null, -32700, format!("Parse error: {}", e));
                let _ = out_tx.send(serde_json::to_string(&err).unwrap_or_default());
                continue;
            }
        };

        // The one notification with a meaning here: the client withdrew
        // a request. Checked before the generic drop below.
        if request.method == "notifications/cancelled" {
            cancel_request(&in_flight, request.params.as_ref());
            continue;
        }

        // Per JSON-RPC 2.0 a request without an `id` is a notification and
        // MUST NOT receive a response. MCP also reserves "notifications/*"
        // method names for notifications. Silently drop both.
        let Some(id) = request.id.clone() else {
            continue;
        };
        if request.method.starts_with("notifications/") {
            continue;
        }

        let key = id.to_string();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        // Registered under the lock the finishing task will take to
        // unregister, so a request that completes at once cannot
        // remove itself before it was ever inserted.
        let mut map = lock_or_recover(&in_flight);
        let seq = map.next_seq;
        map.next_seq += 1;
        if map.entries.insert(key.clone(), (seq, cancel_tx)).is_some() {
            // JSON-RPC forbids reusing an id while it is in flight; a
            // client that does so can now only cancel the newer one.
            tracing::debug!(id = %key, "request id reused while the first is still running");
        }
        tokio::spawn(run_request(
            Arc::clone(&server),
            request,
            id,
            key,
            seq,
            cancel_rx,
            Arc::clone(&in_flight),
            out_tx.clone(),
        ));
        drop(map);
    }

    // Input gone. Close what we hold on the hosts before the process
    // ends, then let the writer flush what is queued: a client that
    // half-closes its end right after writing (`echo ... | oryxis-mcp`,
    // a test harness) still reads the answers. The writer ends when the
    // last sender does; a request still running holds one, hence the
    // bound.
    server.shutdown().await;
    drop(out_tx);
    if tokio::time::timeout(DRAIN_TIMEOUT, writer_task).await.is_err() {
        tracing::info!("input closed with requests still running; their answers are dropped");
    }
}

/// How long the writer may keep flushing after the input closed.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[allow(clippy::too_many_arguments)]
async fn run_request(
    server: Arc<Server>,
    request: JsonRpcRequest,
    id: Value,
    key: String,
    seq: u64,
    cancel_rx: watch::Receiver<bool>,
    in_flight: Shared,
    out_tx: mpsc::UnboundedSender<String>,
) {
    let started = Instant::now();
    let tool = request
        .params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    tracing::info!(id = %key, method = %request.method, tool = %tool, "request");

    let response = server
        .handle_request(&request.method, id, request.params.as_ref(), cancel_rx.clone())
        .await;

    {
        let mut map = lock_or_recover(&in_flight);
        if map.entries.get(&key).map(|(s, _)| *s) == Some(seq) {
            map.entries.remove(&key);
        }
    }

    let elapsed_ms = started.elapsed().as_millis();
    if *cancel_rx.borrow() {
        // A cancelled request gets no response (the client stopped
        // waiting for one, and the spec says not to send it).
        tracing::info!(id = %key, method = %request.method, elapsed_ms, "cancelled, no response");
        return;
    }
    tracing::info!(
        id = %key,
        method = %request.method,
        tool = %tool,
        elapsed_ms,
        outcome = %outcome(&response),
        "response"
    );
    let _ = out_tx.send(serde_json::to_string(&response).unwrap_or_default());
}

/// `notifications/cancelled { requestId, reason }`: flip the cancel
/// flag of the named request, if it is still running.
fn cancel_request(in_flight: &Shared, params: Option<&Value>) {
    let Some(request_id) = params.and_then(|p| p.get("requestId")) else {
        tracing::info!("cancel without requestId ignored");
        return;
    };
    let key = request_id.to_string();
    let reason = params
        .and_then(|p| p.get("reason"))
        .and_then(|v| v.as_str())
        .map(|r| truncate(r, 120))
        .unwrap_or_default();
    let map = lock_or_recover(in_flight);
    match map.entries.get(&key) {
        Some((_, tx)) => {
            tracing::info!(id = %key, reason = %reason, "cancel");
            let _ = tx.send(true);
        }
        None => tracing::info!(id = %key, reason = %reason, "cancel for a request not in flight"),
    }
}

/// One line per response, flushed each: the client parses by newline
/// and a partial line held in a buffer is a response it never sees.
async fn write_lines<W: AsyncWrite + Unpin>(mut writer: W, mut rx: mpsc::UnboundedReceiver<String>) {
    while let Some(line) = rx.recv().await {
        if writer.write_all(line.as_bytes()).await.is_err()
            || writer.write_all(b"\n").await.is_err()
            || writer.flush().await.is_err()
        {
            tracing::info!("output closed");
            return;
        }
    }
}

/// A one-word account of a response for the log: the JSON-RPC error,
/// a tool answer flagged `isError` (with the start of its text, which
/// is this server's own message, never host output), or `ok`.
fn outcome(response: &JsonRpcResponse) -> String {
    if let Some(err) = &response.error {
        return format!("error {} {}", err.code, truncate(&err.message, 200));
    }
    let Some(result) = &response.result else {
        return "ok".into();
    };
    if result.get("isError").and_then(|v| v.as_bool()) == Some(true) {
        let text = result
            .get("content")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        return format!("tool error: {}", truncate(text, 200));
    }
    "ok".into()
}

fn truncate(s: &str, max: usize) -> String {
    let one_line: String = s.lines().next().unwrap_or("").to_string();
    match one_line.char_indices().nth(max) {
        Some((idx, _)) => format!("{}...", &one_line[..idx]),
        None => one_line,
    }
}

fn lock_or_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    }
}
