use super::*;

pub(crate) struct ClientHandler {
    pub(crate) hostname: String,
    pub(crate) port: u16,
    pub(crate) host_key_check: Option<HostKeyCheckCallback>,
    pub(crate) host_key_ask_tx: Option<HostKeyAskSender>,
    /// Mirrors `SshEngine::agent_forwarding`. The handler uses it as a
    /// gate on `server_channel_open_agent_forward`, without an opt-in,
    /// inbound forward channels are rejected even if the server tries
    /// to open one.
    pub(crate) agent_forwarding: bool,
    /// Resolved local X11 endpoint, mirroring `SshEngine::x11`. Doubles
    /// as the gate on `server_channel_open_x11`: `None` means we never
    /// sent an `x11-req`, so an inbound X11 channel is unsolicited.
    pub(crate) x11: Option<std::sync::Arc<crate::x11::X11Forwarding>>,
    /// Cancellation for in-flight X11 bridges. Never fired explicitly:
    /// the bridges observe the sender being DROPPED along with this
    /// handler, which is exactly session teardown.
    pub(crate) x11_cancel: tokio::sync::watch::Sender<bool>,
    /// When there is no UI ask channel (e.g. a port forward auto-started
    /// at boot, before any terminal exists), an unknown host key is
    /// *rejected* rather than blindly TOFU-accepted. Lets a backgrounded
    /// forward fail to off instead of silently trusting a new key.
    pub(crate) strict_host_key: bool,
    /// For forward connections only: the routing table that delivers
    /// inbound `forwarded-tcpip` channels (the server side of `-R` rules)
    /// to the drain of the rule that requested that bind. Several `-R`
    /// rules can share one connection, so the handler routes by the
    /// (address, port) the server reports. When `None`, the handler drops
    /// such channels (we never asked for them).
    pub(crate) remote_routes: Option<RemoteRouteMap>,
    /// Where pre-auth banners (RFC 4252 §5.4: legal notices, MFA
    /// instructions) go so the UI can show them. `None` (headless
    /// callers: port forwards, MCP) logs and drops them.
    pub(crate) banner_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    /// The clock of the dial that built this handler. The host-key
    /// prompt is answered by a person, and the connect timeout counts
    /// network time only, so the wait for that answer stops it (see
    /// `dial_clock`). `None` outside a dial.
    pub(crate) dial_clock: Option<super::dial_clock::DialClock>,
}

impl ClientHandler {
    /// Test-only constructor: a handler that trusts any server key (no
    /// callback, non-strict) so the in-process harness in `sftp_harness`
    /// can build a `Handle<ClientHandler>` over a duplex stream. Fields
    /// are private to this module, so the harness can't build one itself.
    #[cfg(test)]
    pub(crate) fn test_accept_all() -> Self {
        ClientHandler {
            hostname: "harness".into(),
            port: 22,
            host_key_check: None,
            host_key_ask_tx: None,
            agent_forwarding: false,
            x11: None,
            x11_cancel: tokio::sync::watch::channel(false).0,
            strict_host_key: false,
            remote_routes: None,
            banner_tx: None,
            dial_clock: None,
        }
    }
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // RFC 4252 §5.4: "usually meant to be shown to the user" (legal
        // notices, MFA instructions). Forward to the UI when a sink is
        // set; never fail the connect over a banner.
        if let Some(tx) = &self.banner_tx {
            let _ = tx.send(banner.to_string());
        } else {
            tracing::info!("SSH banner from {}:{}: {}", self.hostname, self.port, banner.trim_end());
        }
        Ok(())
    }

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let key_type = key.algorithm().to_string();
        let fingerprint = key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256).to_string();

        tracing::info!(
            "Server key for {}:{}, {} {}",
            self.hostname, self.port, key_type, fingerprint
        );

        let status = if let Some(ref cb) = self.host_key_check {
            cb(&self.hostname, self.port, &key_type, &fingerprint)
        } else {
            HostKeyStatus::Unknown
        };

        match status {
            HostKeyStatus::Known => Ok(true),
            HostKeyStatus::Changed { .. } | HostKeyStatus::Unknown => {
                // Ask the UI
                if let Some(ref tx) = self.host_key_ask_tx {
                    let query = HostKeyQuery {
                        hostname: self.hostname.clone(),
                        port: self.port,
                        key_type,
                        fingerprint,
                        status,
                    };
                    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                    // A person is reading a fingerprint: the network
                    // timeout stops until they answer.
                    let _hold = self
                        .dial_clock
                        .as_ref()
                        .map(|c| c.hold(super::dial_clock::HoldKind::Human));
                    if tx.send((query, resp_tx)).await.is_err() {
                        return Ok(false);
                    }
                    Ok(resp_rx.await.unwrap_or(false))
                } else if self.strict_host_key {
                    // No UI channel and strict: reject both changed and
                    // unknown so a backgrounded forward never TOFU-trusts.
                    Ok(false)
                } else {
                    // No UI channel, reject changed, accept unknown (legacy fallback)
                    Ok(matches!(status, HostKeyStatus::Unknown))
                }
            }
        }
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if !self.agent_forwarding {
            // Server is trying to open a forward channel we never asked
            // for. Decline it at the protocol level instead of letting
            // the channel die on drop.
            reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
            tracing::warn!(
                "rejecting unsolicited agent-forward channel from {}:{}",
                self.hostname,
                self.port
            );
            return Ok(());
        }
        // Confirm the open before the bridge starts pumping bytes.
        reply.accept().await;
        tokio::spawn(async move {
            if let Err(e) = bridge_agent_channel(channel).await {
                tracing::warn!("agent-forward bridge ended: {e}");
            }
        });
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        originator_address: &str,
        originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // One channel per X client the user launches on the remote host.
        match &self.x11 {
            Some(cfg) => {
                reply.accept().await;
                cfg.spawn_bridge(channel, self.x11_cancel.subscribe());
            }
            None => {
                // We never sent an `x11-req`, so nothing legitimate can
                // be opening this.
                reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
                tracing::warn!(
                    "rejecting unsolicited X11 channel from {}:{} ({}:{})",
                    self.hostname,
                    self.port,
                    originator_address,
                    originator_port
                );
            }
        }
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // Inbound channel for a remote (`-R`) forward. Route it to the
        // drain of the rule that owns this bind; several rules can share
        // one connection, so the (address, port) the server reports picks
        // the drain. No routing table = we never requested a remote
        // forward; no route = no rule owns that bind. Decline both.
        let sink = self.remote_routes.as_ref().and_then(|routes| {
            route_lookup(
                &lock_routes(routes),
                connected_address,
                connected_port as u16,
            )
        });
        match sink {
            Some(sink) => {
                // Confirm before the handoff: the drain task reads the
                // channel as soon as it arrives.
                reply.accept().await;
                if sink.send(channel).is_err() {
                    tracing::warn!("forwarded-tcpip drain gone, dropping channel");
                }
            }
            None => {
                reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
                tracing::warn!(
                    "rejecting unsolicited forwarded-tcpip channel for {}:{}",
                    connected_address,
                    connected_port
                );
            }
        }
        Ok(())
    }
}
