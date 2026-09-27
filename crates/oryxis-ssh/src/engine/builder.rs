use super::*;

impl SshEngine {
    pub fn new() -> Self {
        Self {
            host_key_check: None,
            host_key_ask_tx: None,
            kbi_ask_tx: None,
            // Fail-closed default: an engine nobody wired a consent
            // channel into refuses command proxies outright.
            proxy_cmd_ask_tx: None,
            pw_prompt_title: None,
            pw_prompt_label: None,
            totp: None,
            keepalive_interval: None,
            rekey_limit_mb: None,
            address_family: AddressFamily::Auto,
            connect_timeout: std::time::Duration::from_secs(15),
            // Matches OpenSSH sshd's default LoginGraceTime (120s): the
            // server, not the client, sets the real ceiling on how long
            // auth may take, so a shorter client budget would cut off
            // legitimate slow auth (confirm-gated agents, hardware-key
            // touch, 2FA) before the server ever would. The per-agent-
            // candidate dial timeout still bounds the agent sweep, so a
            // wedged agent can't consume this whole window.
            auth_timeout: std::time::Duration::from_secs(120),
            session_timeout: std::time::Duration::from_secs(10),
            agent_forwarding: false,
            x11: None,
            env_vars: Vec::new(),
            encoding: None,
            terminal_type: None,
            algo_ciphers: None,
            algo_kex: None,
            algo_macs: None,
            algo_host_keys: None,
            strict_host_key: false,
            auto_interactive_fallback: false,
            remote_routes: None,
            banner_tx: None,
            pinned_agent_key: None,
        }
    }

    /// Pin the agent identity to prefer (B3): the OpenSSH public line of
    /// the vault key this connection references. A matching agent
    /// identity is offered first during agent auth; the try-all fallback
    /// stays. An unparseable line logs a warning and disables the pin
    /// rather than failing the connect (mirrors `with_totp_secret`).
    pub fn with_pinned_agent_key(mut self, public_line: Option<&str>) -> Self {
        self.pinned_agent_key = public_line.and_then(|line| {
            match russh::keys::PublicKey::from_openssh(line.trim()) {
                Ok(k) => Some(k),
                Err(e) => {
                    tracing::warn!("pinned agent key unusable, ignoring: {e}");
                    None
                }
            }
        });
        self
    }

    /// Pin per-host SSH algorithm overrides. Each `None` keeps russh's
    /// safe default for that category; `Some(list)` forces exactly those
    /// wire names (in order). Used to reach legacy servers that only offer
    /// cbc / sha1 / dh-group1.
    pub fn with_algorithm_overrides(
        mut self,
        ciphers: Option<Vec<String>>,
        kex: Option<Vec<String>>,
        macs: Option<Vec<String>>,
        host_keys: Option<Vec<String>>,
    ) -> Self {
        self.algo_ciphers = ciphers.filter(|v| !v.is_empty());
        self.algo_kex = kex.filter(|v| !v.is_empty());
        self.algo_macs = macs.filter(|v| !v.is_empty());
        self.algo_host_keys = host_keys.filter(|v| !v.is_empty());
        self
    }

    /// Build the russh `Preferred` algorithm set, starting from the safe
    /// default and overriding only the pinned categories. When every
    /// override is `None` the result is byte-identical to the default, so
    /// the secure negotiation is untouched unless the user opts in.
    pub(crate) fn build_preferred(&self) -> russh::Preferred {
        use std::borrow::Cow;
        let mut p = russh::Preferred::DEFAULT;
        if let Some(list) = &self.algo_ciphers {
            let names: Vec<russh::cipher::Name> = list
                .iter()
                .filter_map(|s| russh::cipher::Name::try_from(s.as_str()).ok())
                .collect();
            if !names.is_empty() {
                p.cipher = Cow::Owned(names);
            }
        }
        if let Some(list) = &self.algo_kex {
            let names: Vec<russh::kex::Name> = list
                .iter()
                .filter_map(|s| russh::kex::Name::try_from(s.as_str()).ok())
                .collect();
            if !names.is_empty() {
                p.kex = Cow::Owned(names);
            }
        }
        if let Some(list) = &self.algo_macs {
            let names: Vec<russh::mac::Name> = list
                .iter()
                .filter_map(|s| russh::mac::Name::try_from(s.as_str()).ok())
                .collect();
            if !names.is_empty() {
                p.mac = Cow::Owned(names);
            }
        }
        if let Some(list) = &self.algo_host_keys {
            let algos: Vec<russh::keys::ssh_key::Algorithm> = list
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !algos.is_empty() {
                p.key = Cow::Owned(algos);
            }
        }
        p
    }

    /// Reject unknown/changed host keys instead of TOFU-accepting when no
    /// UI ask channel is set. Used for port forwards auto-started at boot,
    /// where there is no terminal to surface a host-key prompt.
    /// Route pre-auth banners (RFC 4252 §5.4) to the UI. Without a sink
    /// they are logged and dropped (headless callers).
    pub fn with_banner_sink(
        mut self,
        tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Self {
        self.banner_tx = Some(tx);
        self
    }

    pub fn with_strict_host_key(mut self, enabled: bool) -> Self {
        self.strict_host_key = enabled;
        self
    }

    /// Quick-connect auth mode: let `AuthMethod::Auto` fall back to the
    /// interactive prompt (keyboard-interactive modal, then a single
    /// prompted password) once every silent method has failed. Needs a
    /// `with_kbi_ask` channel to have any effect.
    pub fn with_auto_interactive_fallback(mut self, enabled: bool) -> Self {
        self.auto_interactive_fallback = enabled;
        self
    }

    /// Set per-host environment variables to send (via `set_env`) before
    /// the shell starts on the next session opened on this engine.
    pub fn with_env_vars(mut self, vars: Vec<(String, String)>) -> Self {
        self.env_vars = vars;
        self
    }

    /// Enable X11 forwarding for the next session opened on this engine.
    ///
    /// The local display is resolved HERE, not per channel, so the fake
    /// cookie announced to the remote is the exact one the bridge later
    /// verifies. A missing local display disables forwarding with a
    /// warning instead of failing the connect: the same saved host may
    /// also be opened from a headless machine, and losing the shell over
    /// an unavailable GUI feature would be the wrong trade.
    pub fn with_x11_forwarding(mut self, enabled: bool) -> Self {
        self.x11 = if enabled {
            match crate::x11::X11Forwarding::resolve() {
                Some(f) => {
                    tracing::info!("X11 forwarding enabled, local display {}", f.describe());
                    Some(Arc::new(f))
                }
                None => {
                    tracing::warn!(
                        "X11 forwarding requested but no local display was found \
                         (set DISPLAY, or start an X server); continuing without it"
                    );
                    None
                }
            }
        } else {
            None
        };
        self
    }

    /// Set the per-host character encoding. `None` / `"UTF-8"` leaves the
    /// byte stream untouched; any other label transcodes PTY data to and
    /// from UTF-8 for the terminal.
    pub fn with_encoding(mut self, encoding: Option<String>) -> Self {
        self.encoding = encoding;
        self
    }

    /// Override the `TERM` name requested for the PTY. `None` keeps the
    /// default `xterm-256color`.
    pub fn with_terminal_type(mut self, terminal_type: Option<String>) -> Self {
        self.terminal_type = terminal_type;
        self
    }

    /// Enable ssh-agent forwarding for the next session opened on this
    /// engine. The flag is propagated to the channel-open request and
    /// to the inbound forward-channel handler so we don't proxy
    /// channels we didn't ask for.
    pub fn with_agent_forwarding(mut self, enabled: bool) -> Self {
        self.agent_forwarding = enabled;
        self
    }

    /// Override the TCP/SSH-handshake timeout (default 15s).
    pub fn with_connect_timeout(mut self, t: std::time::Duration) -> Self {
        self.connect_timeout = t;
        self
    }

    /// Override the authentication-phase timeout (default 120s).
    pub fn with_auth_timeout(mut self, t: std::time::Duration) -> Self {
        self.auth_timeout = t;
        self
    }

    /// Override the session/SFTP-channel-open timeout (default 10s).
    /// Applies to PTY session open, SFTP subsystem open, and sibling
    /// channel opens for the parallel transfer pool.
    pub fn with_session_timeout(mut self, t: std::time::Duration) -> Self {
        self.session_timeout = t;
        self
    }

    /// Set a sync callback that checks known hosts and returns the status.
    pub fn with_host_key_check(mut self, cb: HostKeyCheckCallback) -> Self {
        self.host_key_check = Some(cb);
        self
    }

    /// Set a channel for asking the UI to verify unknown/changed host keys.
    pub fn with_host_key_ask(mut self, tx: HostKeyAskSender) -> Self {
        self.host_key_ask_tx = Some(tx);
        self
    }

    /// Set a channel for surfacing keyboard-interactive prompts to the UI.
    /// Only meaningful for `AuthMethod::Interactive`; without it, interactive
    /// auth falls back to answering every prompt with the stored password.
    pub fn with_kbi_ask(mut self, tx: KbiAskSender) -> Self {
        self.kbi_ask_tx = Some(tx);
        self
    }

    /// Set a channel for asking the UI to approve a command proxy before
    /// it is spawned.
    ///
    /// Wire it on paths where a person is present to answer. Leave it
    /// unset for anything that dials on its own (boot-time auto-start
    /// forwards, the MCP server): those refuse instead, which is the
    /// right answer when the route may have arrived from a sync peer
    /// and nobody is watching.
    pub fn with_proxy_command_ask(mut self, tx: ProxyCommandAskSender) -> Self {
        self.proxy_cmd_ask_tx = Some(tx);
        self
    }

    /// Provide localized labels for the `AuthMethod::PasswordPrompt` modal
    /// (`title` = dialog heading, `label` = the password field caption).
    /// The engine renders these into the synthetic prompt it sends over
    /// `kbi_ask_tx`; without this call it falls back to plain English.
    pub fn with_password_prompt_labels(mut self, title: String, label: String) -> Self {
        self.pw_prompt_title = Some(title);
        self.pw_prompt_label = Some(label);
        self
    }

    /// Provide the connection's stored TOTP secret (raw vault value, a
    /// bare Base32 secret or an otpauth:// URI) for keyboard-interactive
    /// autofill. An unparseable value logs a warning and disables the
    /// autofill rather than failing the connect, the manual modal still
    /// works.
    pub fn with_totp_secret(mut self, secret: Option<&str>) -> Self {
        self.totp = secret.and_then(|s| match oryxis_core::totp::Totp::parse(s) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!("stored TOTP secret unusable, autofill disabled: {e}");
                None
            }
        });
        self
    }

    /// This engine as it authenticates a JUMP HOST: identical, except that
    /// the keyboard-interactive TOTP autofill answers with the hop's own
    /// secret (`None` = no autofill), never the target's. Offering the
    /// target's 30 s code to a bastion would hand a live second factor to
    /// a machine that is not the one it protects.
    pub(crate) fn for_hop(&self, hop_totp_secret: Option<&str>) -> Self {
        self.clone().with_totp_secret(hop_totp_secret)
    }

    /// Configure the client-side keepalive interval (zero / `None` disables).
    pub fn with_keepalive(mut self, interval: Option<std::time::Duration>) -> Self {
        self.keepalive_interval = interval.filter(|d| !d.is_zero());
        self
    }

    /// Configure the outbound address-family preference (per-host
    /// `Connection.address_family`).
    pub fn with_address_family(mut self, family: AddressFamily) -> Self {
        self.address_family = family;
        self
    }

    /// Per-host SSH rekey threshold in MB (C5). `None` / `Some(0)` keeps
    /// russh's 1 GB default.
    pub fn with_rekey_limit_mb(mut self, mb: Option<u32>) -> Self {
        self.rekey_limit_mb = mb.filter(|&m| m > 0);
        self
    }

    pub(crate) fn make_config(&self) -> Arc<client::Config> {
        // Per-host rekey limit: MB -> bytes, clamped to russh's 1 GiB cap
        // (`Limits::new` asserts <= 1<<30, a nonce-reuse guard). Applied to
        // both the write and read thresholds; the time limit keeps russh's
        // default. `None` leaves the whole `Limits::default()`.
        let limits = self.rekey_limit_mb.map(|mb| {
            let bytes = (mb as usize).saturating_mul(1 << 20).min(1 << 30);
            let default = russh::Limits::default();
            russh::Limits::new(bytes, bytes, default.rekey_time_limit)
        });
        Arc::new(client::Config {
            keepalive_interval: self.keepalive_interval,
            limits: limits.unwrap_or_default(),
            preferred: self.build_preferred(),
            // Every path below hands russh a pre-dialed stream, but keep
            // the config honest for any future `client::connect` caller.
            nodelay: true,
            ..client::Config::default()
        })
    }

    /// Resolve `addr` (`host:port`), keep the addresses `family` allows,
    /// and dial them in order until one connects. The resulting socket
    /// gets TCP_NODELAY: SSH multiplexes keystrokes and window updates
    /// on one stream, so Nagle's algorithm only adds latency (PuTTY has
    /// defaulted it on for interactive sessions for two decades). Used
    /// by the direct dial, the proxy dial and the first jump hop, the
    /// places a real socket leaves this machine. `family` is explicit
    /// because the first jump hop honors the BASTION's preference, not
    /// the target's.
    pub(crate) async fn dial_tcp(
        &self,
        addr: &str,
        family: AddressFamily,
    ) -> Result<TcpStream, SshError> {
        let resolved: Vec<std::net::SocketAddr> = tokio::net::lookup_host(addr)
            .await
            .map_err(|e| SshError::ConnectionFailed(format!("resolve {addr}: {e}")))?
            .collect();
        let candidates = oryxis_core::net::filter_addrs(&resolved, family);
        if candidates.is_empty() {
            return Err(SshError::ConnectionFailed(if resolved.is_empty() {
                format!("{addr}: name resolved to no addresses")
            } else {
                // Honest failure over silently ignoring the preference:
                // the host resolves, just not in the requested family.
                format!("{addr}: resolves to no {family} address")
            }));
        }
        let mut last_err: Option<std::io::Error> = None;
        for candidate in candidates {
            match TcpStream::connect(candidate).await {
                Ok(stream) => {
                    if let Err(e) = stream.set_nodelay(true) {
                        tracing::warn!("set_nodelay({candidate}) failed: {e}");
                    }
                    return Ok(stream);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(SshError::ConnectionFailed(format!(
            "{addr}: {}",
            last_err.expect("candidates was non-empty")
        )))
    }

    pub(crate) fn make_handler(&self, hostname: &str, port: u16) -> ClientHandler {
        ClientHandler {
            hostname: hostname.into(),
            port,
            host_key_check: self.host_key_check.clone(),
            host_key_ask_tx: self.host_key_ask_tx.clone(),
            agent_forwarding: self.agent_forwarding,
            x11: self.x11.clone(),
            // Held by the handler: dropping it (i.e. tearing the session
            // down) cancels every X11 bridge still pumping, so a closed
            // tab can't leave a live socket to the local X server.
            x11_cancel: tokio::sync::watch::channel(false).0,
            strict_host_key: self.strict_host_key,
            remote_routes: self.remote_routes.clone(),
            banner_tx: self.banner_tx.clone(),
        }
    }

}
