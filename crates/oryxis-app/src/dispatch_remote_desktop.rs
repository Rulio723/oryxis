//! RDP/VNC-over-SSH launcher. A one-click card action that opens a `-L`
//! tunnel through the host's SSH connection to its RDP/VNC service and
//! spawns the OS-native client at the local end.
//!
//! The tunnel (`ForwardSession`) is a MANAGED forward stored on the app.
//! It is NOT tied to the client's process (`open rdp://`, single-instance
//! Remmina and mstsc can return immediately, so process-exit teardown
//! would kill the tunnel before the desktop connects). Instead it
//! self-closes once it has served a connection and then goes idle (the
//! desktop client disconnected): the engine's ephemeral forward runs an
//! idle watcher (`spawn_autoclose_local_forward_task`), and when it fires
//! the stream below emits `RemoteDesktopClientClosed` so the app drops its
//! bookkeeping entry. Vault lock / app close clear the map outright.
//!
//! First-time hosts prompt for host-key verification exactly like a normal
//! connect: the launch wires the same `SshHostKeyVerify` modal bridge the
//! terminal connect uses, so a host that isn't in `known_hosts` yet no
//! longer fails outright (the old behaviour, which forced you to open a
//! terminal to the host first to trust its key).
//!
//! The client spawn is a fire-and-forget leaf with no automated coverage
//! (no headless RDP/VNC client exists); it needs manual QA. The command
//! RESOLUTION (`crate::remote_desktop::resolve_command`) is a pure,
//! unit-tested function.

#![allow(clippy::result_large_err)]

use std::sync::Arc;

use iced::Task;
use oryxis_core::models::Connection;
use oryxis_ssh::SshEngine;

use crate::app::{SshMessage, RemoteDesktopMessage, Message, Oryxis};
use crate::remote_desktop::{program_on_path, resolve_command};

impl Oryxis {
    pub(crate) fn handle_remote_desktop(
        &mut self,
        message: RemoteDesktopMessage,
    ) -> Task<Message> {
        match message {
            RemoteDesktopMessage::RemoteDesktopReady(conn_id, seq, res) => {
                match res {
                    Ok((session, port)) => {
                        // Replace any prior tunnel for this host. The old
                        // entry holds the sole strong `Arc`, so dropping it
                        // here fires its cancellation (and its own stream
                        // emits a now-stale `ClientClosed` we ignore by seq).
                        self.remote_desktop_forwards
                            .insert(conn_id, (seq, session));
                        self.set_toast(
                            crate::i18n::t("remote_desktop_opening")
                                .replace("{port}", &port.to_string()),
                        );
                    }
                    Err(e) => self.set_toast(e),
                }
                Task::none()
            }
            RemoteDesktopMessage::RemoteDesktopClientClosed(conn_id, seq) => {
                // The tunnel closed on its own. Drop the entry only if it is
                // still the one this stream owns: a superseded launch (Stop +
                // relaunch) must not evict the newer tunnel.
                if self
                    .remote_desktop_forwards
                    .get(&conn_id)
                    .is_some_and(|(s, _)| *s == seq)
                {
                    self.remote_desktop_forwards.remove(&conn_id);
                }
                Task::none()
            }
            RemoteDesktopMessage::StopRemoteDesktop(conn_id) => {
                if let Some((_, session)) = self.remote_desktop_forwards.remove(&conn_id) {
                    return Task::perform(
                        async move { session.cancel().await },
                        |_| Message::NoOp,
                    );
                }
                Task::none()
            }
        }
    }

    /// Launch the remote desktop for a `RemoteDesktop` host: tunnel to the
    /// desktop endpoint (`conn.hostname:conn.port`) through its gateway SSH
    /// host when `rd_gateway_id` is set (prompting for the gateway's host
    /// key if unknown), or connect directly when it isn't, then spawn the
    /// OS-native client. The desktop login (`conn.username`) prefills the
    /// client; it is NOT the gateway's SSH credential.
    pub(crate) fn launch_remote_desktop(&mut self, conn: Connection) -> Task<Message> {
        self.card_context_menu = None;
        self.overlay = None;
        // A remote-desktop launch never shows the connect-progress screen,
        // so clear it: the gateway's host-key modal only renders while
        // `connecting.is_none()`, and a lingering flag from elsewhere would
        // hide the prompt and hang the bridge waiting for an answer.
        self.connecting = None;
        use oryxis_core::models::connection::ConnectionProtocol;
        if conn.protocol != ConnectionProtocol::RemoteDesktop {
            return Task::none();
        }

        let kind = conn.rd_kind;
        let desktop_host = conn.hostname.clone();
        let desktop_port = conn.port;
        // The desktop login prefills the client (FreeRDP `/u:`). Empty ->
        // the client prompts for it.
        let rd_username = conn.username.clone().filter(|u| !u.trim().is_empty());

        // Resolve the gateway SSH host to tunnel through. A missing / non-SSH
        // id degrades to a direct connection with a warning (never an error),
        // mirroring `resolve_proxy`'s dangling-identity handling.
        let gateway = resolve_rd_gateway(conn.rd_gateway_id, &self.connections).cloned();
        if conn.rd_gateway_id.is_some() && gateway.is_none() {
            tracing::warn!(
                "remote-desktop gateway {:?} missing or not SSH; connecting directly",
                conn.rd_gateway_id
            );
        }

        // Direct connection (no SSH gateway): point the client straight at
        // the desktop endpoint, no tunnel, no managed forward.
        let Some(mut gw) = gateway else {
            return match resolve_command(
                kind,
                std::env::consts::OS,
                &desktop_host,
                desktop_port,
                rd_username.as_deref(),
                &program_on_path,
            ) {
                Ok(cmd) => match std::process::Command::new(&cmd.program)
                    .args(&cmd.args)
                    .spawn()
                {
                    Ok(_child) => {
                        self.set_toast(
                            crate::i18n::t("remote_desktop_opening")
                                .replace("{port}", &desktop_port.to_string()),
                        );
                        Task::none()
                    }
                    Err(e) => {
                        self.set_toast(format!("{}: {e}", cmd.program));
                        Task::none()
                    }
                },
                Err(no) => {
                    self.set_toast(format!(
                        "{} ({})",
                        crate::i18n::t("remote_desktop_no_client"),
                        no.looked_for.join(", ")
                    ));
                    Task::none()
                }
            };
        };

        // Gateway path: resolve the GATEWAY's SSH credentials for the tunnel
        // (distinct from the desktop login above). Same working copy every
        // connect path dials: group inheritance (D4) plus the effective
        // proxy, so the gateway authenticates like a tab to it would.
        self.apply_group_inheritance(&mut gw);
        let (password, private_key, certificate) = self.resolve_credentials(&gw);
        // Agent-auth pin (B3), same rule as the tab connect.
        let pinned_agent = self.pinned_agent_public(&gw);
        let totp_secret = self
            .vault
            .as_ref()
            .and_then(|v| v.get_connection_totp_secret(&gw.id).ok().flatten());
        let resolver = self.make_jump_resolver(&mut gw);
        let host_key_check = self.make_host_key_check();
        let keepalive = self.effective_keepalive(&gw);
        // The tunnel socket goes to the GATEWAY, so its preference rules.
        let address_family = gw.address_family;
        let rekey_limit_mb = gw.rekey_limit_mb;
        let username = rd_username;
        let conn_id = conn.id;
        let target_host = desktop_host;
        let target_port = desktop_port;
        let algo_ciphers = gw.ciphers.clone();
        let algo_kex = gw.kex.clone();
        let algo_macs = gw.macs.clone();
        let algo_host_keys = gw.host_key_algorithms.clone();

        // Launch generation, so a stale result / self-close from a
        // superseded launch can't clobber a newer tunnel for this host.
        self.remote_desktop_seq += 1;
        let seq = self.remote_desktop_seq;

        // Host-key + keyboard-interactive bridges: the engine asks over
        // `hk_ask` / `kbi_ask`, the stream surfaces the shared modals, and
        // the answers come back on the response channels the existing
        // `SshHostKey*` / `SshKbi*` handlers already drive. This inherits
        // the documented single-response-channel limitation (fine here: a
        // launch is a foreground, one-at-a-time user action).
        let (hk_ask_tx, mut hk_ask_rx) = tokio::sync::mpsc::channel::<(
            oryxis_ssh::HostKeyQuery,
            tokio::sync::oneshot::Sender<bool>,
        )>(1);
        let (hk_resp_tx, mut hk_resp_rx) = tokio::sync::mpsc::channel::<bool>(1);
        self.host_key_response_tx = Some(hk_resp_tx);

        let (kbi_ask_tx, mut kbi_ask_rx) = tokio::sync::mpsc::channel::<(
            oryxis_ssh::KbiQuery,
            tokio::sync::oneshot::Sender<Option<Vec<String>>>,
        )>(1);
        let (kbi_resp_tx, mut kbi_resp_rx) =
            tokio::sync::mpsc::channel::<Option<Vec<String>>>(1);
        self.kbi_response_tx = Some(kbi_resp_tx);

        // Command-proxy approval for the gateway host's own dial, same
        // bridge shape and the same one-at-a-time caveat.
        let (pc_ask_tx, mut pc_ask_rx) = tokio::sync::mpsc::channel::<(
            oryxis_ssh::ProxyCommandQuery,
            tokio::sync::oneshot::Sender<bool>,
        )>(1);
        let (pc_resp_tx, mut pc_resp_rx) = tokio::sync::mpsc::channel::<bool>(1);
        self.proxy_command_response_tx = Some(pc_resp_tx);

        let stream = iced::stream::channel::<Message>(
            8,
            move |mut sender: iced::futures::channel::mpsc::Sender<Message>| async move {
                use iced::futures::SinkExt;

                let engine = SshEngine::new()
                    .with_host_key_check(host_key_check)
                    .with_host_key_ask(hk_ask_tx)
                    .with_proxy_command_ask(pc_ask_tx)
                    .with_kbi_ask(kbi_ask_tx)
                    .with_totp_secret(totp_secret.as_deref())
                    .with_password_prompt_labels(
                        crate::i18n::t("auth_password_prompt_title").to_string(),
                        crate::i18n::t("password").to_string(),
                    )
                    // Launched by the user from the host: a touch may be
                    // asked for.
                    .with_security_key_prompts(crate::connect_methods::security_key_prompts(None))
                    .with_keepalive(keepalive)
                    .with_address_family(address_family)
                    .with_rekey_limit_mb(rekey_limit_mb)
                    .with_pinned_agent_key(pinned_agent.as_deref())
                    .with_strict_host_key(true)
                    .with_algorithm_overrides(
                        algo_ciphers,
                        algo_kex,
                        algo_macs,
                        algo_host_keys,
                    );

                let mut hk_sender = sender.clone();
                let _hk_bridge = tokio::spawn(async move {
                    while let Some((query, resp_tx)) = hk_ask_rx.recv().await {
                        let _ = hk_sender.send(Message::Ssh(SshMessage::SshHostKeyVerify(query))).await;
                        let accepted = hk_resp_rx.recv().await.unwrap_or(false);
                        let _ = resp_tx.send(accepted);
                    }
                });

                let mut kbi_sender = sender.clone();
                let _kbi_bridge = tokio::spawn(async move {
                    while let Some((query, resp_tx)) = kbi_ask_rx.recv().await {
                        let _ = kbi_sender.send(Message::Ssh(SshMessage::SshKbiPrompt(None, query))).await;
                        let answers = kbi_resp_rx.recv().await.unwrap_or(None);
                        let _ = resp_tx.send(answers);
                    }
                });

                let mut pc_sender = sender.clone();
                let _pc_bridge = tokio::spawn(async move {
                    while let Some((query, resp_tx)) = pc_ask_rx.recv().await {
                        let _ = pc_sender
                            .send(Message::Ssh(SshMessage::SshProxyCommandVerify(
                                Box::new(query),
                                crate::state::ProxyConsentMode::Ask,
                            )))
                            .await;
                        let approved = pc_resp_rx.recv().await.unwrap_or(false);
                        let _ = resp_tx.send(approved);
                    }
                });

                let outcome: Result<(Arc<oryxis_ssh::ForwardSession>, u16), String> = async {
                    let (session, port) = engine
                        .connect_local_forward_ephemeral(
                            &gw,
                            password.as_deref(),
                            private_key
                                .as_deref()
                                .map(|pem| oryxis_ssh::KeyMaterial::new(pem, certificate.as_deref())),
                            &target_host,
                            target_port,
                            resolver.as_ref(),
                        )
                        .await
                        .map_err(|e| {
                            format!("{}: {e}", crate::i18n::t("remote_desktop_tunnel_failed"))
                        })?;

                    // The tunnel is up; point a client at its local end.
                    match resolve_command(
                        kind,
                        std::env::consts::OS,
                        "127.0.0.1",
                        port,
                        username.as_deref(),
                        &program_on_path,
                    ) {
                        Ok(cmd) => match std::process::Command::new(&cmd.program)
                            .args(&cmd.args)
                            .spawn()
                        {
                            Ok(_child) => Ok((Arc::new(session), port)),
                            Err(e) => {
                                // Client found but failed to launch: drop the
                                // tunnel so it doesn't linger unusable.
                                session.cancel().await;
                                Err(format!("{}: {e}", cmd.program))
                            }
                        },
                        Err(no) => {
                            session.cancel().await;
                            Err(format!(
                                "{} ({})",
                                crate::i18n::t("remote_desktop_no_client"),
                                no.looked_for.join(", ")
                            ))
                        }
                    }
                }
                .await;

                match outcome {
                    Ok((session, port)) => {
                        // Watch for the tunnel closing (idle auto-close, owner
                        // Stop, or drop) BEFORE handing the sole `Arc` to the
                        // app, so we can tell it to drop the entry. The watch
                        // receiver does not keep the `ForwardSession` alive.
                        let mut closed = session.subscribe_cancel();
                        let _ = sender
                            .send(Message::RemoteDesktop(RemoteDesktopMessage::RemoteDesktopReady(conn_id, seq, Ok((session, port)))))
                            .await;
                        let _ = closed.wait_for(|&c| c).await;
                        let _ = sender
                            .send(Message::RemoteDesktop(RemoteDesktopMessage::RemoteDesktopClientClosed(conn_id, seq)))
                            .await;
                    }
                    Err(msg) => {
                        let _ = sender
                            .send(Message::RemoteDesktop(RemoteDesktopMessage::RemoteDesktopReady(conn_id, seq, Err(msg))))
                            .await;
                    }
                }
            },
        );

        Task::stream(stream)
    }
}

/// Resolve a remote-desktop gateway id to the SSH host it names. A missing
/// id, or one that names a non-existent or non-SSH host, resolves to `None`
/// (a direct connection) rather than an error, so deleting the gateway host
/// silently degrades to direct instead of breaking the desktop host. Pure
/// so the dangling-gateway fallback is unit-tested without a live client.
fn resolve_rd_gateway(
    gateway_id: Option<uuid::Uuid>,
    connections: &[Connection],
) -> Option<&Connection> {
    let gid = gateway_id?;
    connections.iter().find(|c| {
        c.id == gid
            && c.protocol == oryxis_core::models::connection::ConnectionProtocol::Ssh
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_rd_gateway;
    use oryxis_core::models::connection::ConnectionProtocol;
    use oryxis_core::models::Connection;

    #[test]
    fn none_id_is_direct() {
        let conns = vec![Connection::new("a", "h")];
        assert!(resolve_rd_gateway(None, &conns).is_none());
    }

    #[test]
    fn resolves_an_ssh_host() {
        let gw = Connection::new("gw", "bastion");
        let id = gw.id;
        let conns = vec![gw];
        assert_eq!(resolve_rd_gateway(Some(id), &conns).map(|c| c.id), Some(id));
    }

    #[test]
    fn dangling_id_degrades_to_direct() {
        let conns = vec![Connection::new("a", "h")];
        assert!(resolve_rd_gateway(Some(uuid::Uuid::new_v4()), &conns).is_none());
    }

    #[test]
    fn non_ssh_gateway_is_rejected() {
        // A gateway that is itself Telnet/Serial/RemoteDesktop can't tunnel;
        // it must degrade to direct, not be dialled as an SSH host.
        let mut gw = Connection::new("gw", "bastion");
        gw.protocol = ConnectionProtocol::Telnet;
        let id = gw.id;
        let conns = vec![gw];
        assert!(resolve_rd_gateway(Some(id), &conns).is_none());
    }
}
