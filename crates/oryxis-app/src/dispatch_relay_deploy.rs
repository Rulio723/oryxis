//! `impl Oryxis` for "Install the relay on one of your hosts" (Settings >
//! Sync, the relay wizard's second level, E3): the SSH round trips
//! around the pure plan in `relay_deploy.rs`.
//!
//! The flow is two tasks with a consent between them:
//!
//! 1. **Probe.** Connect unattended (strict host key, approvals
//!    snapshot: `prepare_unattended_dial`), run [`PROBE_COMMAND`], fetch
//!    the relay manifest, download the binary for the HOST's arch and
//!    run both plugin gates on it here, then render the [`DeployPlan`].
//!    Read-only on the host. The session is parked in state.
//! 2. **Consent.** `Modal::RelayDeployConfirm` shows the plan's script
//!    verbatim. Cancel is the default row; nothing below runs until the
//!    user clicks Run.
//! 3. **Run.** Sweep the stale staging dirs earlier runs of this login
//!    user left behind (an ABORTED run stops before its own cleanup, and
//!    its dir holds the step scripts, the token-file writer included:
//!    `stale_staging_sweep_command`, unprivileged, our name shape only,
//!    older than any live run), then upload the binary and the step
//!    scripts into a fresh 0700 staging dir over SFTP, check the
//!    binary's SHA-256 on the host,
//!    run each step (`sudo -n sh <file>` or bare root, each bounded by
//!    `STEP_TIMEOUT`), remove the staging dir, GET `/healthz` on the
//!    PUBLIC endpoint from this device (retried with backoff up to
//!    `HEALTH_DEADLINE`, since a fresh certificate takes a while), and
//!    only then adopt the endpoint the way the level-1 test does.
//!
//! Both tasks are abortable and the handle lives on the form
//! (`RelayDeployForm::task`, abort-on-drop): the doors that end a deploy
//! (closing the section or the wizard card, the manual lock) STOP it,
//! and while one runs every input the plan was built from is disabled,
//! so nothing on screen can change under it.
//!
//! Every log line is masked at the source ([`mask_token`]) before it
//! becomes a message payload: `Message` derives `Debug`, so anything
//! that reaches a message can reach the debug log.

use std::sync::Arc;

use iced::Task;
use sha2::{Digest, Sha256};

use crate::app::{Message, Oryxis, SyncMessage};
use crate::i18n::t;
use crate::plugins::download::VerifiedBytes;
use crate::relay_deploy::{
    self, mask_token, DeployPlan, HostProbe, Privilege, RelayDeployStep, PROBE_COMMAND,
};

/// What a successful probe hands back: the host's answer, the parked
/// session, the verified bytes and the plan rendered from all of it.
///
/// `Debug` is written by hand so the binary never prints: the message
/// carrying this derives `Debug`, and ten megabytes in a log line is
/// not a log line.
#[derive(Clone)]
pub(crate) struct ProbeOutcome {
    pub probe: HostProbe,
    pub session: oryxis_ssh::SftpClient,
    pub verified: Arc<VerifiedBytes>,
    pub plan: DeployPlan,
    /// Plain HTTP to a host reached through a jump chain: the address
    /// the app dialled through the bastion may not be one the internet
    /// (or this device, directly) can reach, so the card says so before
    /// the run rather than after a failed health check.
    pub via_jump: bool,
}

impl std::fmt::Debug for ProbeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeOutcome")
            .field("probe", &self.probe)
            .field("asset", &self.plan.asset.name)
            .field("bytes", &self.verified.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Why a probe stopped, as DATA: each arm is its own sentence in the
/// active language, and the ones that carry a value show it.
#[derive(Debug, Clone)]
pub(crate) enum ProbeFailure {
    /// The dial itself failed (the engine's own message). The unattended
    /// dial asks nothing, so an unknown host key is refused here; the
    /// flag says whether every host on the route already has a key on
    /// file, which is what decides whether the host-key hint is the way
    /// out or a red herring (a wrong password is not fixed by opening a
    /// terminal tab).
    Dial { error: String, host_key_on_file: bool },
    /// Connected, but the probe command could not run or did not finish
    /// in time.
    Probe(String),
    /// The probe ran and printed something that is not its answer;
    /// carries what the host printed.
    Unreadable(String),
    /// `uname -s` was not Linux; carries what it was.
    NotLinux(String),
    /// Linux, but an arch the release does not build; carries `uname -m`.
    NoAsset(String),
    NoSystemd,
    /// TLS via Caddy was asked for and the host has no `caddy`.
    NoCaddy,
    /// The manifest carries no signed release for the host's platform
    /// (or no `relay.json` has been published yet).
    NoRelease,
    /// Offline mode refused the manifest fetch.
    Offline,
    /// Anything else on the download / verify side.
    Download(String),
}

/// How much of an unreadable probe answer the card quotes.
const UNREADABLE_QUOTE: usize = 200;

impl ProbeFailure {
    /// The line the card shows, plus the way out on a line of its own
    /// where there is one. Two widgets rather than one sentence, because
    /// the first half is the engine's text (machine-dependent) and the
    /// second is ours (what a test, and a reader, can hold on to).
    pub(crate) fn describe(&self) -> (String, Option<String>) {
        match self {
            Self::Dial { error, host_key_on_file } => (
                error.clone(),
                (!host_key_on_file).then(|| t("relay_deploy_hostkey_hint").to_string()),
            ),
            Self::Probe(e) => (e.clone(), None),
            Self::Unreadable(out) => {
                let quoted: String = out.chars().take(UNREADABLE_QUOTE).collect();
                let quoted = if quoted.is_empty() { "-".to_string() } else { quoted };
                (t("relay_deploy_probe_unreadable").replace("{output}", &quoted), None)
            }
            Self::NotLinux(os) => (t("relay_deploy_not_linux").replace("{os}", os), None),
            Self::NoAsset(arch) => (t("relay_deploy_no_asset").replace("{arch}", arch), None),
            Self::NoSystemd => (t("relay_deploy_not_systemd").to_string(), None),
            Self::NoCaddy => (t("relay_deploy_no_caddy").to_string(), None),
            Self::NoRelease => (t("relay_deploy_no_release").to_string(), None),
            Self::Offline => (t("relay_deploy_offline").to_string(), None),
            Self::Download(e) => (e.clone(), None),
        }
    }
}

/// The card's line for a command the host did not finish in time.
fn timeout_line(secs: u64) -> String {
    t("relay_deploy_log_step_timeout").replace("{secs}", &secs.to_string())
}

impl Oryxis {
    /// The deploy arms of `SyncMessage`. `Err(m)` only for a variant
    /// listed under the wrong group in `handle_sync`.
    pub(crate) fn handle_relay_deploy(
        &mut self,
        message: SyncMessage,
    ) -> Result<Task<Message>, SyncMessage> {
        let task = match message {
            SyncMessage::DeployToggle => {
                let d = &mut self.sync.relay_deploy;
                d.open = !d.open;
                if d.open {
                    if d.port.trim().is_empty() {
                        d.port = relay_deploy::DEFAULT_PORT.to_string();
                    }
                    // The deploy writes the wizard's token into the
                    // service; make sure there is one to write.
                    if self.sync.relay_wizard.token.is_empty() {
                        self.sync.relay_wizard.token = crate::dispatch_sync::fresh_relay_token();
                    }
                } else {
                    // Closing the section drops the parked session and
                    // STOPS a probe or run in flight: a connection nobody
                    // can see must not outlive the surface that opened
                    // it, and neither may commands running on it.
                    d.reset_probe();
                }
                Task::none()
            }
            SyncMessage::DeployHostPickerOpen => {
                // The host is baked into the plan; while a probe or run
                // is in flight it cannot change (the trigger is disabled
                // too, this is the keyboard's door).
                if !self.sync.relay_deploy.busy {
                    self.sync.relay_deploy.picker_open = true;
                    self.sync.relay_deploy.picker_search.clear();
                }
                Task::none()
            }
            SyncMessage::DeployHostPickerClose => {
                self.sync.relay_deploy.picker_open = false;
                self.sync.relay_deploy.picker_search.clear();
                Task::none()
            }
            SyncMessage::DeployHostPickerSearch(v) => {
                self.sync.relay_deploy.picker_search = v;
                Task::none()
            }
            SyncMessage::DeployHostChanged(id) => {
                let d = &mut self.sync.relay_deploy;
                d.picker_open = false;
                d.picker_search.clear();
                if !d.busy && d.host_id != Some(id) {
                    d.host_id = Some(id);
                    // A probe describes ONE host; a plan built for
                    // another one must not be runnable here.
                    d.reset_probe();
                    d.result = None;
                    d.result_hint = None;
                    d.log.clear();
                }
                Task::none()
            }
            SyncMessage::DeployPortChanged(v) => {
                let d = &mut self.sync.relay_deploy;
                // Disabled while busy; refused here as well, because an
                // edit invalidates the plan a run is executing.
                if !d.busy {
                    d.port = v;
                    // The plan bakes the port into the unit and the
                    // health check, so an edit invalidates it like a
                    // domain edit invalidates the level-1 probe.
                    d.reset_probe();
                    d.result = None;
                    d.result_hint = None;
                }
                Task::none()
            }
            SyncMessage::DeployCaddyToggled => {
                let d = &mut self.sync.relay_deploy;
                if !d.busy {
                    d.use_caddy = !d.use_caddy;
                    d.reset_probe();
                    d.result = None;
                    d.result_hint = None;
                }
                Task::none()
            }
            SyncMessage::DeployProbe => self.start_relay_deploy_probe(),
            SyncMessage::DeployProbed(seq, outcome) => {
                let d = &mut self.sync.relay_deploy;
                if seq != d.seq {
                    // A probe the user abandoned (host changed, section
                    // closed): its session drops with the payload.
                    return Ok(Task::none());
                }
                d.busy = false;
                d.step = None;
                // Finished: the handle has nothing left to stop.
                d.task = None;
                match outcome {
                    Ok(o) => {
                        let o = *o;
                        let mut lines = vec![
                            t("relay_deploy_probe_ok")
                                .replace("{os}", &format!("{} {}", o.probe.os, o.probe.machine))
                                .replace("{user}", &o.probe.user),
                            t("relay_deploy_asset_line")
                                .replace("{name}", &o.plan.asset.name)
                                .replace("{version}", &o.plan.asset.version),
                        ];
                        if o.probe.already_installed() {
                            lines.push(t("relay_deploy_existing").to_string());
                        }
                        match o.probe.privilege {
                            Privilege::Root => {}
                            Privilege::Sudo => lines.push(t("relay_deploy_via_sudo").to_string()),
                            Privilege::None => lines.push(t("relay_deploy_need_sudo").to_string()),
                        }
                        if o.via_jump {
                            lines.push(
                                t("relay_deploy_jump_warning")
                                    .replace("{url}", &o.plan.public_url),
                            );
                        }
                        d.log.extend(lines);
                        d.probe = Some(o.probe);
                        d.session = Some(o.session);
                        d.verified = Some(o.verified);
                        d.plan = Some(o.plan);
                        d.result = None;
                        d.result_hint = None;
                    }
                    Err(e) => {
                        let (line, hint) = e.describe();
                        d.result = Some(Err(line));
                        d.result_hint = hint;
                    }
                }
                Task::none()
            }
            SyncMessage::DeployReview => {
                let d = &mut self.sync.relay_deploy;
                // The modal only opens over a plan that can RUN: with
                // neither root nor sudo the card offers the copy instead.
                let runnable = d
                    .probe
                    .as_ref()
                    .is_some_and(|p| p.privilege != Privilege::None)
                    && d.plan.is_some()
                    && d.session.is_some()
                    && !d.busy;
                if runnable {
                    d.confirm_open = true;
                }
                Task::none()
            }
            SyncMessage::DeployConfirmCancel => {
                self.sync.relay_deploy.confirm_open = false;
                Task::none()
            }
            SyncMessage::DeployRun => self.start_relay_deploy_run(),
            SyncMessage::DeployProgress(seq, step, line) => {
                let d = &mut self.sync.relay_deploy;
                if seq != d.seq {
                    return Ok(Task::none());
                }
                d.step = Some(step);
                match line {
                    Ok(l) => d.log.push(l),
                    Err(l) => d.log.push(format!("\u{2717} {l}")),
                }
                Task::none()
            }
            SyncMessage::DeployFinished(seq, result) => {
                let d = &mut self.sync.relay_deploy;
                if seq != d.seq {
                    return Ok(Task::none());
                }
                d.busy = false;
                d.step = None;
                d.task = None;
                // The run spent the session either way: a success has
                // nothing more to ask the host, a failure reconnects on
                // the next probe so a dropped link is not reused.
                d.session = None;
                d.verified = None;
                let adopt = match &result {
                    Ok(url) => d.plan.as_ref().map(|p| (url.clone(), p.token.clone())),
                    Err(_) => None,
                };
                d.result = Some(result);
                if let Some((url, token)) = adopt {
                    // Adopt what RAN, never the live form: the plan's
                    // token and the plan's URL, the level-1 rule.
                    self.sync.signaling_url = url.clone();
                    self.sync.signaling_token = token.clone();
                    if let Some(vault) = &self.vault {
                        let _ = vault.set_setting("sync_signaling_url", &url);
                        let _ = vault.set_setting("sync_signaling_token", &token);
                    }
                    self.sync.relay_wizard.result = Some(Ok(()));
                    if self.sync.engine_running {
                        self.stop_sync_engine();
                        return Ok(self.start_sync_engine());
                    }
                }
                Task::none()
            }
            m => return Err(m),
        };
        Ok(task)
    }

    /// Validate the form, connect, probe, download + verify, render the
    /// plan. Precondition failures land in the card's result line and
    /// return `Task::none()`.
    fn start_relay_deploy_probe(&mut self) -> Task<Message> {
        if self.sync.relay_deploy.busy {
            return Task::none();
        }
        // Credentials need the master key, same gate as a sync round.
        if !self.sync_round_allowed() {
            return Task::none();
        }
        let Some(host_id) = self.sync.relay_deploy.host_id else {
            self.sync.relay_deploy.result = Some(Err(t("relay_deploy_no_host").to_string()));
            return Task::none();
        };
        let Some(mut conn) = self.connections.iter().find(|c| c.id == host_id).cloned() else {
            self.sync.relay_deploy.result = Some(Err(t("relay_deploy_no_host").to_string()));
            return Task::none();
        };
        let Some(port) = self.sync.relay_deploy.port() else {
            self.sync.relay_deploy.result = Some(Err(t("relay_deploy_bad_port").to_string()));
            return Task::none();
        };
        let use_caddy = self.sync.relay_deploy.use_caddy;
        // TLS needs the wizard's domain: that is the site Caddy serves
        // and the URL this device adopts. Both go into a root script, so
        // their SHAPE is checked here, before anything is dialled.
        let tls = if use_caddy {
            let w = &self.sync.relay_wizard;
            match relay_deploy::tls_endpoint(&w.domain, &w.port) {
                Ok(ep) => Some(ep),
                Err(e) => {
                    self.sync.relay_deploy.result = Some(Err(t(e.label_key()).to_string()));
                    self.sync.relay_deploy.result_hint = None;
                    return Task::none();
                }
            }
        } else {
            None
        };
        if self.sync.relay_wizard.token.is_empty() {
            self.sync.relay_wizard.token = crate::dispatch_sync::fresh_relay_token();
        }
        let token = self.sync.relay_wizard.token.clone();

        // Same working copy every connect path dials: group inheritance
        // (D4) and the effective proxy.
        self.apply_group_inheritance(&mut conn);
        let host_label = conn.label.clone();
        let (public_url, listen_v6) = match &tls {
            Some(ep) => (ep.base_url.clone(), false),
            None => match relay_deploy::http_endpoint(&conn.hostname, port) {
                Some(pair) => pair,
                None => {
                    self.sync.relay_deploy.result =
                        Some(Err(t("relay_deploy_bad_host_address").to_string()));
                    self.sync.relay_deploy.result_hint = None;
                    return Task::none();
                }
            },
        };
        let via_jump = tls.is_none() && !conn.jump_chain.is_empty();
        let host_key_on_file = self.route_host_keys_on_file(&conn);
        let dial = self.prepare_unattended_dial(conn);

        let d = &mut self.sync.relay_deploy;
        d.reset_probe();
        d.busy = true;
        d.result = None;
        d.result_hint = None;
        d.log.clear();
        d.step = Some(RelayDeployStep::Probe);
        let seq = d.seq;
        let staging = relay_deploy::fresh_staging_dir();

        // A stream rather than a single `perform`: the probe has two
        // waits a person can see (the SSH connect, then a ~10 MB
        // download), and the progress line names which one is running.
        let stream = iced::stream::channel::<Message>(
            16,
            move |mut tx: iced::futures::channel::mpsc::Sender<Message>| async move {
                use iced::futures::SinkExt as _;
                let outcome = async {
                    let client = dial
                        .open_sftp()
                        .await
                        .map_err(|error| ProbeFailure::Dial { error, host_key_on_file })?;
                    let (code, out, err) = client
                        .exec_timeout(PROBE_COMMAND, relay_deploy::PROBE_TIMEOUT)
                        .await
                        .map_err(|e| match e {
                            oryxis_ssh::SshError::ExecTimeout(secs) => {
                                ProbeFailure::Probe(timeout_line(secs))
                            }
                            other => ProbeFailure::Probe(other.to_string()),
                        })?;
                    let probe = relay_deploy::parse_probe(&out).map_err(|printed| {
                        let printed = if printed.is_empty() { err.trim().to_string() } else { printed };
                        ProbeFailure::Unreadable(if printed.is_empty() {
                            format!("exit {code}")
                        } else {
                            printed
                        })
                    })?;
                    let (os, arch) = match probe.asset_target() {
                        Some(t) => t,
                        None if probe.os != "Linux" => {
                            return Err(ProbeFailure::NotLinux(probe.os.clone()));
                        }
                        None => return Err(ProbeFailure::NoAsset(probe.machine.clone())),
                    };
                    if !probe.systemd {
                        return Err(ProbeFailure::NoSystemd);
                    }
                    if tls.is_some() && !probe.caddy {
                        return Err(ProbeFailure::NoCaddy);
                    }
                    let _ = tx
                        .send(Message::Sync(SyncMessage::DeployProgress(
                            seq,
                            RelayDeployStep::Download,
                            Ok(format!("{os}/{arch}")),
                        )))
                        .await;
                    // Download + both gates HERE, before a byte heads for
                    // the host: what the consent names is what was
                    // verified.
                    let verified = crate::plugins::download::fetch_verified_for(
                        relay_deploy::PROVIDER_ID,
                        os,
                        arch,
                        |_, _| {},
                    )
                    .await
                    .map_err(|e| match e {
                        crate::plugins::PluginError::Offline => ProbeFailure::Offline,
                        // No `relay.json` anywhere yet (the catalog file
                        // is written by the first `relay-v*` tag that runs
                        // the signing workflow) reads as "not published",
                        // not as a broken download.
                        e if crate::plugins::download::is_no_manifest_release(&e) => {
                            ProbeFailure::NoRelease
                        }
                        other => ProbeFailure::Download(other.to_string()),
                    })?
                    .ok_or(ProbeFailure::NoRelease)?;
                    let name = verified
                        .binary
                        .url
                        .rsplit('/')
                        .next()
                        .unwrap_or("oryxis-relay")
                        .to_string();
                    let plan = DeployPlan {
                        host_label,
                        user: probe.user.clone(),
                        privilege: probe.privilege,
                        http_client: probe.http_client,
                        sha256sum: probe.sha256sum,
                        asset: relay_deploy::AssetRef {
                            version: verified.version.clone(),
                            name,
                            sha256: verified.binary.sha256.to_ascii_lowercase(),
                            size: verified.binary.size,
                        },
                        token,
                        port,
                        tls_site: tls.map(|ep| ep.site),
                        staging,
                        public_url,
                        listen_v6,
                    };
                    Ok(Box::new(ProbeOutcome {
                        probe,
                        session: client,
                        verified: Arc::new(verified),
                        plan,
                        via_jump,
                    }))
                }
                .await;
                let _ = tx
                    .send(Message::Sync(SyncMessage::DeployProbed(seq, outcome)))
                    .await;
            },
        );
        let (task, handle) = Task::stream(stream).abortable();
        self.sync.relay_deploy.task = Some(handle.abort_on_drop());
        task
    }

    /// Whether every host the probe dials (the target and each hop of
    /// its expanded jump route) already has a key on file. The unattended
    /// dial refuses an unknown key, so this is what tells a refusal that
    /// "connect once from a tab" fixes apart from one it does not.
    fn route_host_keys_on_file(&self, conn: &oryxis_core::models::connection::Connection) -> bool {
        let known = |host: &str, port: u16| {
            self.known_hosts.iter().any(|k| k.hostname == host && k.port == port)
        };
        let mut route = conn.clone();
        self.expand_jump_chain(&mut route);
        known(&conn.hostname, conn.port)
            && route.jump_chain.iter().all(|id| {
                self.connections
                    .iter()
                    .find(|c| c.id == *id)
                    .is_some_and(|hop| known(&hop.hostname, hop.port))
            })
    }

    /// Upload and run the reviewed plan on the parked session, streaming
    /// one message per log line, then verify the public endpoint from
    /// here and report. The plan and the session are the PROBE's: the
    /// form is not re-read.
    fn start_relay_deploy_run(&mut self) -> Task<Message> {
        let d = &mut self.sync.relay_deploy;
        if d.busy || !d.confirm_open {
            return Task::none();
        }
        let (Some(plan), Some(client), Some(verified)) =
            (d.plan.clone(), d.session.clone(), d.verified.clone())
        else {
            d.confirm_open = false;
            return Task::none();
        };
        if plan.privilege == Privilege::None {
            d.confirm_open = false;
            return Task::none();
        }
        d.confirm_open = false;
        d.busy = true;
        d.result = None;
        d.result_hint = None;
        d.step = Some(RelayDeployStep::Upload);
        let seq = d.seq;

        let stream = iced::stream::channel::<Message>(
            64,
            move |mut tx: iced::futures::channel::mpsc::Sender<Message>| async move {
                use iced::futures::SinkExt as _;
                let token = plan.token.clone();
                let mut say = |step: RelayDeployStep, line: Result<String, String>| {
                    let line = match line {
                        Ok(l) => Ok(mask_token(&l, &token)),
                        Err(l) => Err(mask_token(&l, &token)),
                    };
                    let mut tx = tx.clone();
                    async move {
                        let _ = tx
                            .send(Message::Sync(SyncMessage::DeployProgress(seq, step, line)))
                            .await;
                    }
                };
                let outcome = run_plan(&client, &plan, &verified, &mut say).await;
                let _ = tx
                    .send(Message::Sync(SyncMessage::DeployFinished(seq, outcome)))
                    .await;
            },
        );
        // Abortable for the same reason as the probe, with more at stake:
        // these are root commands on a remote host, and the doors that
        // stop a run (closing the section, the manual lock) must stop
        // it, not merely stop listening to it. A step cut mid-way leaves
        // the host where that step left it; every script is idempotent,
        // so the next run converges.
        let (task, handle) = Task::stream(stream).abortable();
        self.sync.relay_deploy.task = Some(handle.abort_on_drop());
        task
    }
}

/// Every step on the host, then the public health check. `say` takes a
/// step and a line; an `Err` line is the step's failure and the run
/// stops after cleaning up. The returned `Err` is the summary line for
/// the card.
async fn run_plan<F, Fut>(
    client: &oryxis_ssh::SftpClient,
    plan: &DeployPlan,
    verified: &VerifiedBytes,
    say: &mut F,
) -> Result<String, String>
where
    F: FnMut(RelayDeployStep, Result<String, String>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let step_failed = |step: RelayDeployStep| {
        t("relay_deploy_failed").replace("{step}", t(step.label_key()))
    };

    // Upload: a 0700 staging dir, the binary, the step scripts. The dir
    // is created first and on its own: if that fails, there is nothing
    // of ours to clean up, and a path we did not create (a leftover, a
    // name some other user took in /tmp) must never be `rm -rf`ed.
    let staging = &plan.staging;
    let bin_path = format!("{staging}/oryxis-relay");
    say(
        RelayDeployStep::Upload,
        Ok(t("relay_deploy_log_upload")
            .replace("{name}", &plan.asset.name)
            .replace("{path}", &bin_path)
            .replace("{bytes}", &verified.bytes.len().to_string())),
    )
    .await;
    // Leftovers of earlier runs of this login user first (an aborted run
    // never reaches its own cleanup), never this run's dir and never one
    // a concurrent run could still own. Best effort, bounded, ignored.
    let _ = client
        .exec_timeout(
            &relay_deploy::stale_staging_sweep_command(staging),
            relay_deploy::PROBE_TIMEOUT,
        )
        .await;
    if let Err(e) = client.create_dir(staging).await {
        say(RelayDeployStep::Upload, Err(e.to_string())).await;
        return Err(step_failed(RelayDeployStep::Upload));
    }
    let upload = async {
        client.chmod(staging, 0o700).await.map_err(|e| e.to_string())?;
        client
            .write_file(&bin_path, &verified.bytes)
            .await
            .map_err(|e| e.to_string())?;
        for script in plan.scripts() {
            client
                .write_file(&format!("{staging}/{}", script.file), script.body.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok::<(), String>(())
    };
    if let Err(e) = upload.await {
        say(RelayDeployStep::Upload, Err(e)).await;
        cleanup(client, staging).await;
        return Err(step_failed(RelayDeployStep::Upload));
    }

    // Transfer integrity: the host's own digest when it has sha256sum,
    // else the bytes read back and hashed here. Either way the file
    // that gets installed is proven to be the file that was verified.
    let remote_digest = if plan.sha256sum {
        match client
            .exec_timeout(&format!("sha256sum {bin_path}"), relay_deploy::STEP_TIMEOUT)
            .await
        {
            Ok((0, out, _)) => out.split_whitespace().next().unwrap_or_default().to_ascii_lowercase(),
            Ok((code, _, err)) => {
                say(
                    RelayDeployStep::Upload,
                    Err(t("relay_deploy_log_hash_failed")
                        .replace("{code}", &code.to_string())
                        .replace("{error}", err.trim())),
                )
                .await;
                cleanup(client, staging).await;
                return Err(step_failed(RelayDeployStep::Upload));
            }
            Err(e) => {
                say(RelayDeployStep::Upload, Err(exec_error_line(e))).await;
                cleanup(client, staging).await;
                return Err(step_failed(RelayDeployStep::Upload));
            }
        }
    } else {
        match client.read_file(&bin_path).await {
            Ok(bytes) => to_hex(&Sha256::digest(&bytes)),
            Err(e) => {
                say(RelayDeployStep::Upload, Err(e.to_string())).await;
                cleanup(client, staging).await;
                return Err(step_failed(RelayDeployStep::Upload));
            }
        }
    };
    if remote_digest != plan.asset.sha256 {
        say(
            RelayDeployStep::Upload,
            Err(t("relay_deploy_log_hash_mismatch")
                .replace("{remote}", &remote_digest)
                .replace("{expected}", &plan.asset.sha256)),
        )
        .await;
        cleanup(client, staging).await;
        return Err(step_failed(RelayDeployStep::Upload));
    }
    say(
        RelayDeployStep::Upload,
        Ok(t("relay_deploy_log_hash_ok").replace("{sha}", &plan.asset.sha256)),
    )
    .await;

    // The steps, each its own file, each its own exit code, each its own
    // time bound: a hung step fails the run instead of holding the card.
    for script in plan.scripts() {
        let command = plan.run_command(&script);
        say(script.step, Ok(format!("$ {command}"))).await;
        match client.exec_timeout(&command, relay_deploy::STEP_TIMEOUT).await {
            Ok((code, out, err)) => {
                for line in out.lines().chain(err.lines()) {
                    if !line.trim().is_empty() {
                        say(script.step, Ok(line.to_string())).await;
                    }
                }
                if code != 0 {
                    say(
                        script.step,
                        Err(t("relay_deploy_log_exit").replace("{code}", &code.to_string())),
                    )
                    .await;
                    cleanup(client, staging).await;
                    return Err(step_failed(script.step));
                }
            }
            Err(e) => {
                say(script.step, Err(exec_error_line(e))).await;
                cleanup(client, staging).await;
                return Err(step_failed(script.step));
            }
        }
    }
    cleanup(client, staging).await;

    // The verdict that matters: can THIS device reach the endpoint it
    // is about to adopt. Same probe the level-1 Test button runs,
    // retried with backoff: the first request routinely lands before
    // Caddy holds its certificate, and one attempt would call a working
    // deploy a failure.
    say(
        RelayDeployStep::Health,
        Ok(format!("GET {}/healthz", plan.public_url)),
    )
    .await;
    let started = std::time::Instant::now();
    let mut wait = HEALTH_FIRST_WAIT;
    loop {
        match crate::dispatch_sync::probe_relay_health(plan.public_url.clone()).await {
            Ok(()) => break,
            Err(e) => {
                if started.elapsed() + wait > relay_deploy::HEALTH_DEADLINE {
                    say(RelayDeployStep::Health, Err(e)).await;
                    return Err(step_failed(RelayDeployStep::Health));
                }
                say(
                    RelayDeployStep::Health,
                    Ok(t("relay_deploy_log_health_retry")
                        .replace("{error}", &e)
                        .replace("{secs}", &wait.as_secs().to_string())),
                )
                .await;
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(HEALTH_MAX_WAIT);
            }
        }
    }
    say(RelayDeployStep::Adopt, Ok(plan.public_url.clone())).await;
    Ok(plan.public_url.clone())
}

/// First pause between two public health checks, doubled per retry.
const HEALTH_FIRST_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
/// Longest pause between two public health checks.
const HEALTH_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// The log line for an exec that failed to complete: the timeout in the
/// active language (it may still be running there, which is the part a
/// reader must know), anything else as the engine words it.
fn exec_error_line(e: oryxis_ssh::SshError) -> String {
    match e {
        oryxis_ssh::SshError::ExecTimeout(secs) => timeout_line(secs),
        other => other.to_string(),
    }
}

/// Best effort: the staging dir is the login user's, so this needs no
/// privilege, and a failure here changes nothing about the install.
async fn cleanup(client: &oryxis_ssh::SftpClient, staging: &str) {
    let _ = client.remove_dir_recursive(staging).await;
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
