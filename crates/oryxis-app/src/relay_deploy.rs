//! The pure half of "Install the relay on one of your hosts" (Settings >
//! Sync, the relay wizard's second level): what the probe asks a host,
//! how its answer is read, the exact scripts a deploy runs there, and
//! the masking that keeps the relay token out of every log line.
//!
//! Nothing here touches a network or a file. The SSH round trips live in
//! `dispatch_relay_deploy.rs`; this module exists so that the script the
//! consent modal SHOWS and the script the host RUNS are the same string,
//! tested as one, and so the systemd unit the wizard offers for copying
//! and the one the deploy writes come from a single renderer.
//!
//! Two decisions worth stating once:
//!
//! - **The scripts run as files, not as a quoted line.** Each step is
//!   uploaded to a staging directory and started with `sh <file>`, so a
//!   heredoc, a quote or a `$` inside the unit file never has to
//!   survive a second shell. What the modal shows is byte for byte what
//!   the host executes.
//! - **The token goes in a root-only env file, never in the unit.** A
//!   unit under `/etc/systemd/system` is world-readable; the wizard's
//!   copy-paste artifact still inlines the token because a single file
//!   is what a person pasting by hand wants, and the deploy writes
//!   `EnvironmentFile=` instead. One renderer, two spellings
//!   ([`UnitToken`]), so the two units cannot drift in anything else.

/// Catalog id of the relay's manifest (`plugins/relay.json`).
pub(crate) const PROVIDER_ID: &str = "relay";
/// Where the binary lands on the host.
pub(crate) const REMOTE_BIN: &str = "/usr/local/bin/oryxis-relay";
/// The systemd unit the deploy writes.
pub(crate) const UNIT_PATH: &str = "/etc/systemd/system/oryxis-relay.service";
/// Root-only directory holding the token env file.
pub(crate) const ENV_DIR: &str = "/etc/oryxis-relay";
/// The `EnvironmentFile` carrying `ORYXIS_RELAY_TOKEN`, mode 0600.
pub(crate) const ENV_FILE: &str = "/etc/oryxis-relay/env";
/// Caddy's default configuration path on every packaged install.
pub(crate) const CADDYFILE: &str = "/etc/caddy/Caddyfile";
/// The unprivileged system account the service runs as.
pub(crate) const SERVICE_USER: &str = "oryxis";
/// Default relay port, the one every artifact of the level-1 wizard
/// has always used.
pub(crate) const DEFAULT_PORT: u16 = 8080;
/// The Caddyfile the deploy copies aside before touching it, and puts
/// back when the result does not validate or does not load. Left on the
/// host afterwards: it is the configuration as it was before the last
/// deploy, which is what a person undoing it by hand wants.
pub(crate) const CADDYFILE_BACKUP: &str = "/etc/caddy/Caddyfile.oryxis-backup";
/// First line of the block the deploy owns in the Caddyfile.
pub(crate) const CADDY_BEGIN: &str = "# oryxis-relay begin";
/// Last line of the block the deploy owns in the Caddyfile.
pub(crate) const CADDY_END: &str = "# oryxis-relay end";
/// How long the probe command may run. It only reads: a host taking
/// longer than this is hung on something (a wedged `systemctl`, a DNS
/// stall in `sudo`), not busy.
pub(crate) const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// How long one deploy step may run on the host. Generous (a slow disk
/// installing ten megabytes, a `systemctl restart` waiting on a unit's
/// stop timeout), but bounded, so a hung step fails the run instead of
/// holding the card busy forever.
pub(crate) const STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
/// How long the public health check keeps retrying. The first request
/// often lands before Caddy has its certificate (ACME takes a few to a
/// few tens of seconds), so one attempt would report a working deploy
/// as failed.
pub(crate) const HEALTH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);
/// What replaces the token in every log line.
pub(crate) const TOKEN_MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

/// One `sh` line the probe runs on the host, unprivileged. Every answer
/// is a `key=value` line so [`parse_probe`] never depends on the order
/// or on stderr; a missing key reads as the conservative default.
///
/// `sudo -n true` is the passwordless-sudo test: `-n` refuses to prompt,
/// so a host that would ask for a password answers non-zero and is
/// reported as having no privilege rather than hanging the exec.
pub(crate) const PROBE_COMMAND: &str = concat!(
    "printf 'uname=%s\\n' \"$(uname -sm 2>/dev/null)\"; ",
    "if [ -d /run/systemd/system ]; then echo systemd=1; else echo systemd=0; fi; ",
    "if [ \"$(id -u)\" = 0 ]; then echo priv=root; ",
    "elif sudo -n true 2>/dev/null; then echo priv=sudo; else echo priv=none; fi; ",
    "printf 'user=%s\\n' \"$(id -un 2>/dev/null)\"; ",
    "if command -v caddy >/dev/null 2>&1; then echo caddy=1; else echo caddy=0; fi; ",
    "if command -v curl >/dev/null 2>&1; then echo curl=1; else echo curl=0; fi; ",
    "if command -v wget >/dev/null 2>&1; then echo wget=1; else echo wget=0; fi; ",
    "if command -v sha256sum >/dev/null 2>&1; then echo sha256sum=1; else echo sha256sum=0; fi; ",
    "if [ -f ", "/etc/systemd/system/oryxis-relay.service", " ]; then echo unit=1; else echo unit=0; fi; ",
    "printf 'existing=%s\\n' \"$(systemctl is-active oryxis-relay 2>/dev/null || true)\"",
);

/// How the deploy may run privileged commands on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Privilege {
    /// The login user is uid 0: commands run bare.
    Root,
    /// `sudo -n true` succeeded: commands run under `sudo -n`.
    Sudo,
    /// Neither. The script can still be shown and copied, never run.
    None,
}

/// Which HTTP client the in-band health check can use on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpClient {
    Curl,
    Wget,
    /// Neither: the local check is skipped and reported as skipped, and
    /// the out-of-band probe from the app is the only verdict.
    None,
}

/// What the probe learned about the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostProbe {
    /// `uname -s`, verbatim (`Linux`).
    pub os: String,
    /// `uname -m`, verbatim (`x86_64`, `aarch64`).
    pub machine: String,
    pub systemd: bool,
    pub privilege: Privilege,
    /// The login user, for the consent text ("runs as root" / "as
    /// deploy via sudo").
    pub user: String,
    pub caddy: bool,
    pub http_client: HttpClient,
    pub sha256sum: bool,
    /// Whether the unit file the deploy writes already exists on the
    /// host. Reported so a re-run says "already installed, will be
    /// updated" instead of looking like a first install. A file test,
    /// not `systemctl is-active`: that one prints `inactive` for a unit
    /// that does not exist at all.
    pub unit_present: bool,
    /// `systemctl is-active oryxis-relay` on the host (`active`,
    /// `inactive`, `failed`), for the same line.
    pub existing_unit: String,
}

impl HostProbe {
    /// The manifest `(os, arch)` pair for this host, `None` when no
    /// relay asset can exist for it (not Linux, or an arch the release
    /// does not build).
    pub(crate) fn asset_target(&self) -> Option<(&'static str, &'static str)> {
        if self.os != "Linux" {
            return None;
        }
        let arch = match self.machine.as_str() {
            "x86_64" | "amd64" => "x86_64",
            "aarch64" | "arm64" => "aarch64",
            _ => return None,
        };
        Some(("linux", arch))
    }

    /// Whether the unit already exists on the host (any state).
    pub(crate) fn already_installed(&self) -> bool {
        self.unit_present
    }
}

/// Read the probe's stdout. Unknown keys are ignored, a missing key
/// takes the conservative default (no systemd, no privilege, no tools),
/// and only `uname` is required: without it nothing else is worth
/// deciding. The error carries what the host printed instead, trimmed,
/// for the caller to word.
pub(crate) fn parse_probe(stdout: &str) -> Result<HostProbe, String> {
    let mut os = None;
    let mut machine = None;
    let mut systemd = false;
    let mut privilege = Privilege::None;
    let mut user = String::new();
    let mut caddy = false;
    let mut curl = false;
    let mut wget = false;
    let mut sha256sum = false;
    let mut unit_present = false;
    let mut existing_unit = String::new();
    for line in stdout.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key {
            "uname" => {
                let mut parts = value.split_whitespace();
                os = parts.next().map(str::to_string);
                machine = parts.next().map(str::to_string);
            }
            "systemd" => systemd = value == "1",
            "priv" => {
                privilege = match value {
                    "root" => Privilege::Root,
                    "sudo" => Privilege::Sudo,
                    _ => Privilege::None,
                }
            }
            "user" => user = value.to_string(),
            "caddy" => caddy = value == "1",
            "curl" => curl = value == "1",
            "wget" => wget = value == "1",
            "sha256sum" => sha256sum = value == "1",
            "unit" => unit_present = value == "1",
            "existing" => existing_unit = value.to_string(),
            _ => {}
        }
    }
    let (Some(os), Some(machine)) = (os, machine) else {
        return Err(stdout.trim().to_string());
    };
    Ok(HostProbe {
        os,
        machine,
        systemd,
        privilege,
        user,
        caddy,
        http_client: if curl {
            HttpClient::Curl
        } else if wget {
            HttpClient::Wget
        } else {
            HttpClient::None
        },
        sha256sum,
        unit_present,
        existing_unit,
    })
}

/// Where the unit reads its token from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnitToken<'a> {
    /// `Environment=ORYXIS_RELAY_TOKEN=<token>` inline. The wizard's
    /// copy-paste artifact: one file to paste, at the cost of a
    /// world-readable unit.
    Inline(&'a str),
    /// `EnvironmentFile=<path>`, the deploy's spelling: the token lives
    /// in a root-only file.
    File(&'a str),
}

/// The systemd unit, the single renderer behind both the wizard's
/// systemd artifact and the deployed service.
///
/// `bind` is `127.0.0.1` when a reverse proxy on the same host fronts
/// the relay (TLS via Caddy) and `0.0.0.0` when the relay itself is what
/// the internet reaches. The hardening lines are safe for a process
/// that only listens and holds queues in memory: it never writes to
/// disk, so `ProtectSystem=strict` costs it nothing.
pub(crate) fn systemd_unit(port: u16, bind: &str, token: UnitToken<'_>) -> String {
    let token_line = match token {
        UnitToken::Inline(token) => format!("Environment=ORYXIS_RELAY_TOKEN={token}"),
        UnitToken::File(path) => format!("EnvironmentFile={path}"),
    };
    format!(
        "[Unit]\n\
         Description=Oryxis sync relay\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={SERVICE_USER}\n\
         ExecStart={REMOTE_BIN} --port {port} --bind {bind}\n\
         {token_line}\n\
         Restart=always\n\
         RestartSec=5\n\
         NoNewPrivileges=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// The Caddy site block that terminates TLS in front of the relay on
/// the same host. `site` is the Caddyfile site address (`relay.example.com`,
/// or `relay.example.com:8443` for a non-default public port).
pub(crate) fn caddy_site(site: &str, port: u16) -> String {
    format!("{site} {{\n    reverse_proxy 127.0.0.1:{port}\n}}\n")
}

/// The `awk` program the Caddy step rewrites the Caddyfile with: every
/// line outside the managed block survives, the block itself (between
/// [`CADDY_BEGIN`] and [`CADDY_END`]) is dropped so the step can append
/// the current one, and blank lines are carried only when something
/// follows them, so a re-run does not grow the file by one blank line
/// per deploy. Single-quoted in the script, so it holds no `'`.
///
/// It also drops the UN-fenced block the first generator appended (a
/// nightly-only shape, before the fence existed): exactly
/// `<site> {` / `reverse_proxy 127.0.0.1:<port>` / `}` for THIS deploy's
/// site, passed in as the awk variable `site`. Left in place it would
/// define the site twice beside the fenced block, `caddy validate`
/// would refuse, and the deploy could never converge without a manual
/// edit. Any other shape, or another site, is the user's and passes
/// through; a partial match is printed back as it was.
pub(crate) const CADDY_STRIP_AWK: &str = "\
function out(line) {
    if (line ~ /^[[:space:]]*$/) { blank++; return }
    while (blank > 0) { print \"\"; blank-- }
    print line
}
function flush() { if (held >= 1) out(h1); if (held >= 2) out(h2); held = 0 }
skip { if ($0 == \"# oryxis-relay end\") skip = 0; next }
held == 1 {
    if ($0 ~ /^[[:space:]]*reverse_proxy 127[.]0[.]0[.]1:[0-9]+[[:space:]]*$/) { h2 = $0; held = 2; next }
    flush()
}
held == 2 {
    if ($0 ~ /^[[:space:]]*[}][[:space:]]*$/) { held = 0; blank = 0; next }
    flush()
}
tolower($0) == tolower(site \" {\") { flush(); h1 = $0; held = 1; next }
/^# oryxis-relay begin$/ { flush(); skip = 1; blank = 0; next }
/^# oryxis-relay end$/ { next }
{ out($0) }
END { flush() }
";

/// The one thing the health check on the host needs to know: how to
/// GET a URL with a short timeout.
fn http_get_command(client: HttpClient, url: &str) -> Option<String> {
    match client {
        HttpClient::Curl => Some(format!("curl -fsS -m 3 {url} >/dev/null 2>&1")),
        HttpClient::Wget => Some(format!("wget -q -T 3 -t 1 -O /dev/null {url} >/dev/null 2>&1")),
        HttpClient::None => None,
    }
}

/// The relay release the deploy installs, as the manifest describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssetRef {
    /// Manifest version (`0.1.1`).
    pub version: String,
    /// Asset file name (`oryxis-relay-linux-x86_64`).
    pub name: String,
    /// Lowercase hex SHA-256 from the manifest.
    pub sha256: String,
    pub size: u64,
}

/// Everything a deploy needs decided, with nothing left to resolve at
/// run time. Built once from the probe and the form, shown in the
/// consent modal, then executed as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeployPlan {
    /// The vault host's label, for the consent text.
    pub host_label: String,
    /// Login user on the host, for the consent text.
    pub user: String,
    pub privilege: Privilege,
    pub http_client: HttpClient,
    pub sha256sum: bool,
    pub asset: AssetRef,
    pub token: String,
    /// The port the relay binds.
    pub port: u16,
    /// `Some(site)` when Caddy on the host terminates TLS for `site`;
    /// `None` is plain HTTP straight to the relay.
    pub tls_site: Option<String>,
    /// Staging directory on the host (`/tmp/oryxis-relay-<random>`),
    /// created 0700 by the uploader and removed at the end.
    pub staging: String,
    /// The endpoint the app adopts once both health checks pass.
    pub public_url: String,
    /// Plain HTTP to a host whose address is an IPv6 literal: the relay
    /// has to listen on the IPv6 wildcard, since `0.0.0.0` never
    /// answers the address the URL names.
    pub listen_v6: bool,
}

/// The steps a deploy reports, in order. `Probe` and `Download` happen
/// before the consent; the consent is asked before `Upload`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayDeployStep {
    Probe,
    Download,
    Upload,
    Install,
    Service,
    Caddy,
    Health,
    Adopt,
}

impl RelayDeployStep {
    /// The i18n key of the step's label.
    pub(crate) fn label_key(self) -> &'static str {
        match self {
            Self::Probe => "relay_deploy_step_probe",
            Self::Download => "relay_deploy_step_download",
            Self::Upload => "relay_deploy_step_upload",
            Self::Install => "relay_deploy_step_install",
            Self::Service => "relay_deploy_step_service",
            Self::Caddy => "relay_deploy_step_caddy",
            Self::Health => "relay_deploy_step_health",
            Self::Adopt => "relay_deploy_step_adopt",
        }
    }
}

/// One script the host runs, uploaded as a file into the staging dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StepScript {
    pub step: RelayDeployStep,
    /// File name inside the staging dir (`20-install.sh`).
    pub file: String,
    /// Whether it runs under the probed privilege (`sudo -n` / bare
    /// root) or as the login user.
    pub privileged: bool,
    pub body: String,
}

impl DeployPlan {
    /// The bind address the unit gets: loopback behind Caddy, every
    /// interface when the relay is what the internet reaches (the IPv6
    /// wildcard, dual stack on Linux, when the host is an IPv6 literal).
    pub(crate) fn bind(&self) -> &'static str {
        if self.tls_site.is_some() {
            "127.0.0.1"
        } else if self.listen_v6 {
            "[::]"
        } else {
            "0.0.0.0"
        }
    }

    /// The scripts, in execution order. Every one is idempotent, so a
    /// re-run after a partial failure converges: the user exists or is
    /// created, the binary is (re)installed, the unit is rewritten and
    /// the service RESTARTED rather than merely enabled, so a new token
    /// or port takes effect on a second run.
    ///
    /// The Caddy step owns exactly one block of the Caddyfile, fenced by
    /// [`CADDY_BEGIN`] / [`CADDY_END`], and REPLACES it on every run, so
    /// a re-run with another relay port repoints the proxy instead of
    /// leaving the old block in charge. It never leaves Caddy worse off
    /// than it found it: the file is copied to [`CADDYFILE_BACKUP`]
    /// first, the result must pass `caddy validate`, and a reload is
    /// all it asks of a running Caddy (a restart with a broken file
    /// would take every other site on the host down with it). Any
    /// failure puts the backup back and fails the step. A site the user
    /// already defined by hand outside the block makes the validation
    /// fail as an ambiguous site, which is reported, never merged.
    pub(crate) fn scripts(&self) -> Vec<StepScript> {
        let mut out = Vec::new();
        let staging = &self.staging;

        out.push(StepScript {
            step: RelayDeployStep::Install,
            file: "20-install.sh".into(),
            privileged: true,
            body: format!(
                "set -eu\n\
                 id {SERVICE_USER} >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false {SERVICE_USER}\n\
                 install -m 0755 {staging}/oryxis-relay {REMOTE_BIN}\n"
            ),
        });

        let unit = systemd_unit(self.port, self.bind(), UnitToken::File(ENV_FILE));
        out.push(StepScript {
            step: RelayDeployStep::Service,
            file: "30-service.sh".into(),
            privileged: true,
            body: format!(
                "set -eu\n\
                 umask 077\n\
                 mkdir -p {ENV_DIR}\n\
                 cat > {ENV_FILE} <<'ORYXIS_EOF'\n\
                 ORYXIS_RELAY_TOKEN={token}\n\
                 ORYXIS_EOF\n\
                 chmod 0600 {ENV_FILE}\n\
                 cat > {UNIT_PATH} <<'ORYXIS_EOF'\n\
                 {unit}\
                 ORYXIS_EOF\n\
                 chmod 0644 {UNIT_PATH}\n\
                 systemctl daemon-reload\n\
                 systemctl enable oryxis-relay\n\
                 systemctl restart oryxis-relay\n",
                token = self.token,
            ),
        });

        if let Some(site) = &self.tls_site {
            let block = caddy_site(site, self.port);
            out.push(StepScript {
                step: RelayDeployStep::Caddy,
                file: "40-caddy.sh".into(),
                privileged: true,
                body: format!(
                    "set -eu\n\
                     restore() {{\n\
                     cat {CADDYFILE_BACKUP} > {CADDYFILE}\n\
                     rm -f {CADDYFILE}.oryxis-new\n\
                     echo \"$1; the previous Caddyfile was restored\" >&2\n\
                     exit 1\n\
                     }}\n\
                     [ -f {CADDYFILE} ] || : > {CADDYFILE}\n\
                     cp -p {CADDYFILE} {CADDYFILE_BACKUP}\n\
                     awk -v site='{site}' '{CADDY_STRIP_AWK}' {CADDYFILE_BACKUP} > {CADDYFILE}.oryxis-new\n\
                     printf '\\n%s\\n' '{CADDY_BEGIN}' >> {CADDYFILE}.oryxis-new\n\
                     cat >> {CADDYFILE}.oryxis-new <<'ORYXIS_EOF'\n\
                     {block}\
                     ORYXIS_EOF\n\
                     printf '%s\\n' '{CADDY_END}' >> {CADDYFILE}.oryxis-new\n\
                     cat {CADDYFILE}.oryxis-new > {CADDYFILE} || restore \"the Caddyfile could not be written\"\n\
                     rm -f {CADDYFILE}.oryxis-new\n\
                     if ! caddy validate --adapter caddyfile --config {CADDYFILE}; then\n\
                     restore \"caddy rejected the configuration (is {site} defined elsewhere in {CADDYFILE}?)\"\n\
                     fi\n\
                     if systemctl is-active --quiet caddy; then\n\
                     systemctl reload caddy || restore \"caddy did not reload the configuration\"\n\
                     else\n\
                     systemctl start caddy || restore \"caddy did not start with the configuration\"\n\
                     fi\n"
                ),
            });
        }

        let url = format!("http://127.0.0.1:{}/healthz", self.port);
        let body = match http_get_command(self.http_client, &url) {
            Some(get) => format!(
                "set -u\n\
                 i=0\n\
                 while [ $i -lt 15 ]; do\n\
                 if {get}; then echo \"relay answers on 127.0.0.1:{port}\"; exit 0; fi\n\
                 i=$((i+1)); sleep 1\n\
                 done\n\
                 echo \"relay did not answer on 127.0.0.1:{port}\" >&2\n\
                 systemctl status oryxis-relay --no-pager -l 2>&1 | head -n 25 >&2 || true\n\
                 exit 1\n",
                port = self.port,
            ),
            // Nothing on the host can GET a URL: say so on the record
            // and let the out-of-band probe from the app decide.
            None => "set -u\necho \"neither curl nor wget on this host: local health check skipped\"\nsleep 2\nexit 0\n".to_string(),
        };
        out.push(StepScript {
            step: RelayDeployStep::Health,
            file: "50-health.sh".into(),
            privileged: false,
            body,
        });

        out
    }

    /// The command that runs one uploaded step, with the privilege the
    /// probe found.
    pub(crate) fn run_command(&self, script: &StepScript) -> String {
        let path = format!("{}/{}", self.staging, script.file);
        match (script.privileged, self.privilege) {
            (true, Privilege::Sudo) => format!("sudo -n sh {path}"),
            _ => format!("sh {path}"),
        }
    }

    /// The text the consent modal shows: the upload the uploader will
    /// perform, then every step script verbatim with the command that
    /// starts it. This is the whole of what the host runs; the uploader
    /// does nothing but write these files and the binary.
    pub(crate) fn consent_script(&self) -> String {
        let mut s = String::new();
        // The housekeeping the run starts with is shown literally too:
        // it deletes on the host, and nothing runs there that this text
        // did not show first.
        s.push_str(&format!(
            "# housekeeping (unprivileged): stale staging dirs of earlier runs\n{}\n",
            stale_staging_sweep_command(&self.staging)
        ));
        s.push_str(&format!(
            "# upload (SFTP): mkdir 0700 {staging}\n\
             #   {staging}/oryxis-relay  <- {name} ({version}, sha256 {sha})\n",
            staging = self.staging,
            name = self.asset.name,
            version = self.asset.version,
            sha = self.asset.sha256,
        ));
        for script in self.scripts() {
            s.push_str(&format!("#   {}/{}\n", self.staging, script.file));
        }
        for script in self.scripts() {
            s.push_str(&format!("\n# ---- {} ----\n", self.run_command(&script)));
            s.push_str(&script.body);
        }
        s.push_str(&format!("\n# cleanup (SFTP): rm -r {}\n", self.staging));
        s
    }
}

/// Replace every occurrence of the token with [`TOKEN_MASK`]. Applied
/// where a line is PRODUCED, before it becomes a message payload: the
/// `Message` enum derives `Debug`, so anything reaching a message can
/// reach the debug log.
pub(crate) fn mask_token(text: &str, token: &str) -> String {
    if token.is_empty() {
        return text.to_string();
    }
    text.replace(token, TOKEN_MASK)
}

/// A fresh staging path: `/tmp/oryxis-relay-<8 hex>`. Random so two
/// deploys from two devices to one host cannot collide, and short
/// because it appears in every log line.
pub(crate) fn fresh_staging_dir() -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!("{STAGING_PREFIX}{}", &id[..8])
}

/// Every staging dir is `<this><8 hex>`, which is what lets a later run
/// recognise the ones an earlier run left behind.
pub(crate) const STAGING_PREFIX: &str = "/tmp/oryxis-relay-";

/// How old a leftover staging dir must be before a run sweeps it. Far
/// above the longest a run can hold one (the upload, then four steps of
/// at most `STEP_TIMEOUT` each), so a deploy another device is running
/// on the same host at the same moment is never swept from under it.
pub(crate) const STALE_STAGING_MINUTES: u32 = 120;

/// The command a run starts with: remove the staging dirs earlier runs
/// of THIS login user left behind (an aborted run stops before its own
/// cleanup, and the dir holds the step scripts, the one that writes the
/// token file included). Runs unprivileged, so it can only ever reach
/// the login user's own files, and matches only our exact name shape,
/// only dirs owned by that user, only past [`STALE_STAGING_MINUTES`].
/// `keep` (the dir this run is about to create) is excluded outright.
/// Best effort: a sweep that fails changes nothing about the install.
///
/// It runs at the start of a run rather than in the probe because the
/// probe is read-only on the host, and it is housekeeping of the same
/// class as the run's own `cleanup`, never a step of the install.
pub(crate) fn stale_staging_sweep_command(keep: &str) -> String {
    let dir = STAGING_PREFIX.rsplit_once('/').map(|(d, _)| d).unwrap_or("/tmp");
    let name = STAGING_PREFIX.rsplit_once('/').map(|(_, n)| n).unwrap_or(STAGING_PREFIX);
    let keep = keep.replace('\'', "'\\''");
    format!(
        "find {dir} -maxdepth 1 -type d -name '{name}????????' -user \"$(id -u)\" \
         -mmin +{STALE_STAGING_MINUTES} ! -path '{keep}' -exec rm -rf {{}} \\; 2>/dev/null; true"
    )
}

/// The Caddyfile site address for a public `https://` endpoint: the
/// bare domain when the public port is 443 (or unset), `domain:port`
/// otherwise. Mirrors `RelayWizardForm::base_url`.
pub(crate) fn caddy_site_address(domain: &str, public_port: &str) -> String {
    let port = public_port.trim();
    if port.is_empty() || port == "443" {
        domain.to_string()
    } else {
        format!("{domain}:{port}")
    }
}

/// Why the wizard's domain / public port cannot become a TLS endpoint.
/// Both values end up inside a script that runs as root, so they are
/// checked for SHAPE here rather than trusted because the consent
/// shows them: a typo would otherwise be caught by nothing before Caddy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointError {
    /// No domain typed.
    NoDomain,
    /// Neither a DNS name nor an IP literal.
    BadDomain,
    /// A public port that is not 1..=65535.
    BadPort,
}

impl EndpointError {
    /// The i18n key of the card's line for this error.
    pub(crate) fn label_key(self) -> &'static str {
        match self {
            Self::NoDomain => "relay_deploy_no_domain",
            Self::BadDomain => "relay_deploy_bad_domain",
            Self::BadPort => "relay_deploy_bad_public_port",
        }
    }
}

/// A validated public TLS endpoint: the Caddyfile site address and the
/// `https://` URL the app adopts, from the same normalized host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TlsEndpoint {
    pub site: String,
    pub base_url: String,
}

/// Validate the wizard's domain and public port and render the endpoint
/// they describe. The domain tolerates the scheme prefix and trailing
/// slash `RelayWizardForm::base_url` tolerates; an IPv6 literal (bare or
/// bracketed) is rendered bracketed in both forms.
pub(crate) fn tls_endpoint(domain: &str, public_port: &str) -> Result<TlsEndpoint, EndpointError> {
    let host = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    if host.is_empty() {
        return Err(EndpointError::NoDomain);
    }
    let host = url_host(host).ok_or(EndpointError::BadDomain)?;
    let port = public_port.trim();
    let port = if port.is_empty() {
        443
    } else {
        port.parse::<u16>().ok().filter(|p| *p != 0).ok_or(EndpointError::BadPort)?
    };
    let authority = if port == 443 { host } else { format!("{host}:{port}") };
    Ok(TlsEndpoint {
        base_url: format!("https://{authority}"),
        site: authority,
    })
}

/// `host` as it goes into a URL authority, or `None` when it is neither
/// a DNS name nor an IP literal. IPv6 comes back bracketed.
pub(crate) fn url_host(host: &str) -> Option<String> {
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(v6) = bare.parse::<std::net::Ipv6Addr>() {
        return Some(format!("[{v6}]"));
    }
    if bare.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(bare.to_string());
    }
    is_dns_name(bare).then(|| bare.trim_end_matches('.').to_ascii_lowercase())
}

/// Whether `name` is a DNS host name: dot-separated labels of ASCII
/// letters, digits and inner hyphens, 1..=63 bytes each, 253 in all
/// (one trailing dot allowed). IDNs are expected in their `xn--` form,
/// the spelling a certificate carries.
fn is_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// The `http://` endpoint of a relay reached directly on the host's own
/// address, and whether that address is an IPv6 literal (so the relay
/// must listen on the IPv6 wildcard). `None` when the host's address is
/// not something a URL can carry.
pub(crate) fn http_endpoint(hostname: &str, port: u16) -> Option<(String, bool)> {
    let hostname = hostname.trim();
    // A vault host's address was good enough to dial, so it is held to
    // what a URL authority can carry rather than to strict DNS rules:
    // an `/etc/hosts` name with an underscore is a real host here.
    let host = url_host(hostname).or_else(|| {
        (!hostname.is_empty()
            && hostname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
        .then(|| hostname.to_string())
    })?;
    let v6 = host.starts_with('[');
    Some((format!("http://{host}:{port}"), v6))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_staging_sweep_reaches_only_our_stale_dirs() {
        let cmd = super::stale_staging_sweep_command("/tmp/oryxis-relay-deadbeef");
        // Our exact name shape (8 hex chars), in /tmp only, owned by the
        // login user, and old enough that no live run can own it.
        assert!(cmd.starts_with("find /tmp -maxdepth 1 -type d -name 'oryxis-relay-????????'"));
        assert!(cmd.contains("-user \"$(id -u)\""));
        assert!(cmd.contains(&format!("-mmin +{}", super::STALE_STAGING_MINUTES)));
        // The run's own dir is never a candidate.
        assert!(cmd.contains("! -path '/tmp/oryxis-relay-deadbeef'"));
        // Best effort: never fails the run, never runs through sudo.
        assert!(cmd.ends_with("; true"));
        assert!(!cmd.contains("sudo"));
        assert!(super::fresh_staging_dir().starts_with(super::STAGING_PREFIX));
    }

    /// Run the sweep for real against a scratch tree standing in for
    /// /tmp: a stale dir of ours goes, a fresh one, a foreign name and
    /// the kept dir stay.
    #[cfg(unix)]
    #[test]
    fn the_staging_sweep_runs_as_rendered() {
        let root = std::env::temp_dir().join(format!("oryxis-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mk = |name: &str| {
            let p = root.join(name);
            std::fs::create_dir_all(&p).unwrap();
            p
        };
        let stale = mk("oryxis-relay-aaaaaaaa");
        let fresh = mk("oryxis-relay-bbbbbbbb");
        let kept = mk("oryxis-relay-cccccccc");
        let foreign = mk("oryxis-relay-notours-x");
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3 * 3600);
        for p in [&stale, &kept, &foreign] {
            std::fs::File::open(p).unwrap().set_modified(old).unwrap();
        }
        let cmd = super::stale_staging_sweep_command(&kept.to_string_lossy())
            .replacen("find /tmp ", &format!("find {} ", root.display()), 1);
        let status = std::process::Command::new("sh").arg("-c").arg(&cmd).status().unwrap();
        assert!(status.success());
        assert!(!stale.exists(), "a stale dir of ours is swept");
        assert!(fresh.exists(), "a dir a live run could own stays");
        assert!(kept.exists(), "the run's own dir stays");
        assert!(foreign.exists(), "another name shape stays");
        let _ = std::fs::remove_dir_all(&root);
    }

    use super::*;

    fn probe_output(priv_: &str) -> String {
        format!(
            "uname=Linux x86_64\nsystemd=1\npriv={priv_}\nuser=deploy\ncaddy=1\ncurl=1\nwget=0\nsha256sum=1\nunit=1\nexisting=active\n"
        )
    }

    fn plan(tls: bool, privilege: Privilege) -> DeployPlan {
        DeployPlan {
            host_label: "vps".into(),
            user: "deploy".into(),
            privilege,
            http_client: HttpClient::Curl,
            sha256sum: true,
            asset: AssetRef {
                version: "0.1.1".into(),
                name: "oryxis-relay-linux-x86_64".into(),
                sha256: "ab".repeat(32),
                size: 10,
            },
            token: "sekrit-token-value".into(),
            port: 8080,
            tls_site: tls.then(|| "relay.example.com".to_string()),
            staging: "/tmp/oryxis-relay-deadbeef".into(),
            public_url: if tls {
                "https://relay.example.com".into()
            } else {
                "http://vps.example.com:8080".into()
            },
            listen_v6: false,
        }
    }

    #[test]
    fn probe_parses_every_key_and_maps_the_asset() {
        let p = parse_probe(&probe_output("sudo")).unwrap();
        assert_eq!(p.os, "Linux");
        assert_eq!(p.machine, "x86_64");
        assert!(p.systemd);
        assert_eq!(p.privilege, Privilege::Sudo);
        assert_eq!(p.user, "deploy");
        assert!(p.caddy);
        assert_eq!(p.http_client, HttpClient::Curl);
        assert!(p.sha256sum);
        assert_eq!(p.existing_unit, "active");
        assert!(p.already_installed());
        assert_eq!(p.asset_target(), Some(("linux", "x86_64")));

        let root = parse_probe(&probe_output("root")).unwrap();
        assert_eq!(root.privilege, Privilege::Root);
        let none = parse_probe(&probe_output("none")).unwrap();
        assert_eq!(none.privilege, Privilege::None);
    }

    #[test]
    fn probe_defaults_are_conservative() {
        // Only uname present: no systemd, no privilege, no tools, no unit.
        let p = parse_probe("uname=Linux aarch64\n").unwrap();
        assert!(!p.systemd);
        assert_eq!(p.privilege, Privilege::None);
        assert_eq!(p.http_client, HttpClient::None);
        assert!(!p.sha256sum);
        assert!(!p.caddy);
        assert!(p.existing_unit.is_empty());
        assert!(!p.already_installed());
        assert_eq!(p.asset_target(), Some(("linux", "aarch64")));
        // `is-active` says `inactive` for a unit that does not exist;
        // only the file test answers "installed".
        let p = parse_probe("uname=Linux x86_64\nunit=0\nexisting=inactive\n").unwrap();
        assert!(!p.already_installed());
        // arm64 is the Debian spelling of aarch64.
        let p = parse_probe("uname=Linux arm64\n").unwrap();
        assert_eq!(p.asset_target(), Some(("linux", "aarch64")));
        // Not Linux, or an arch with no build: no asset.
        assert!(parse_probe("uname=Darwin arm64\n").unwrap().asset_target().is_none());
        assert!(parse_probe("uname=Linux riscv64\n").unwrap().asset_target().is_none());
        // wget is the fallback client when curl is absent.
        let p = parse_probe("uname=Linux x86_64\ncurl=0\nwget=1\n").unwrap();
        assert_eq!(p.http_client, HttpClient::Wget);
        // No uname at all is an error, not a guess.
        assert!(parse_probe("systemd=1\n").is_err());
    }

    #[test]
    fn unit_has_one_renderer_and_two_token_spellings() {
        let inline = systemd_unit(8080, "0.0.0.0", UnitToken::Inline("tok"));
        let file = systemd_unit(8080, "127.0.0.1", UnitToken::File(ENV_FILE));
        assert!(inline.contains("Environment=ORYXIS_RELAY_TOKEN=tok\n"));
        assert!(!inline.contains("EnvironmentFile"));
        assert!(file.contains(&format!("EnvironmentFile={ENV_FILE}\n")));
        assert!(!file.contains("tok"));
        assert!(inline.contains("ExecStart=/usr/local/bin/oryxis-relay --port 8080 --bind 0.0.0.0\n"));
        assert!(file.contains("ExecStart=/usr/local/bin/oryxis-relay --port 8080 --bind 127.0.0.1\n"));
        // Everything but the token line and the bind is identical.
        let strip = |s: &str| {
            s.lines()
                .filter(|l| !l.starts_with("Environment") && !l.starts_with("ExecStart"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(strip(&inline), strip(&file));
        assert!(inline.contains("User=oryxis\n"));
        assert!(inline.contains("ProtectSystem=strict\n"));
    }

    #[test]
    fn scripts_follow_the_probe() {
        // TLS via Caddy, sudo: four steps, bind loopback, sudo prefix on
        // the privileged ones and none on the health check.
        let p = plan(true, Privilege::Sudo);
        let scripts = p.scripts();
        let steps: Vec<_> = scripts.iter().map(|s| s.step).collect();
        assert_eq!(
            steps,
            vec![
                RelayDeployStep::Install,
                RelayDeployStep::Service,
                RelayDeployStep::Caddy,
                RelayDeployStep::Health
            ]
        );
        assert_eq!(p.run_command(&scripts[0]), "sudo -n sh /tmp/oryxis-relay-deadbeef/20-install.sh");
        assert_eq!(p.run_command(&scripts[3]), "sh /tmp/oryxis-relay-deadbeef/50-health.sh");
        assert!(scripts[1].body.contains("--bind 127.0.0.1"));
        assert!(scripts[1].body.contains("ORYXIS_RELAY_TOKEN=sekrit-token-value\n"));
        assert!(scripts[1].body.contains("systemctl restart oryxis-relay\n"));
        assert!(scripts[2].body.contains("relay.example.com {\n    reverse_proxy 127.0.0.1:8080\n}\n"));
        // The Caddy step owns a fenced block, validates before loading,
        // restores on failure and never restarts a running Caddy.
        let caddy = &scripts[2].body;
        assert!(caddy.contains(&format!("cp -p {CADDYFILE} {CADDYFILE_BACKUP}\n")));
        assert!(caddy.contains(CADDY_BEGIN) && caddy.contains(CADDY_END));
        assert!(caddy.contains(&format!("caddy validate --adapter caddyfile --config {CADDYFILE}")));
        assert!(caddy.contains("systemctl reload caddy || restore"));
        // A write that fails halfway (a full disk) puts the backup back
        // instead of leaving a truncated Caddyfile behind `set -e`.
        assert!(caddy.contains(&format!("cat {CADDYFILE}.oryxis-new > {CADDYFILE} || restore")));
        assert!(!caddy.contains("systemctl restart caddy"));
        assert!(caddy.contains(&format!("cat {CADDYFILE_BACKUP} > {CADDYFILE}\n")));
        assert!(scripts[3].body.contains("curl -fsS -m 3 http://127.0.0.1:8080/healthz"));
        // Every script that touches the shell starts strict.
        for s in &scripts[..3] {
            assert!(s.body.starts_with("set -eu\n"), "{}", s.file);
        }

        // Plain HTTP, root: no Caddy step, bind everywhere, no sudo.
        let p = plan(false, Privilege::Root);
        let scripts = p.scripts();
        assert_eq!(scripts.len(), 3);
        assert!(scripts.iter().all(|s| s.step != RelayDeployStep::Caddy));
        assert!(scripts[1].body.contains("--bind 0.0.0.0"));
        assert_eq!(p.run_command(&scripts[0]), "sh /tmp/oryxis-relay-deadbeef/20-install.sh");

        // No HTTP client on the host: the health step says so and passes.
        let mut p = plan(false, Privilege::Root);
        p.http_client = HttpClient::None;
        let health = p.scripts().into_iter().find(|s| s.step == RelayDeployStep::Health).unwrap();
        assert!(health.body.contains("skipped"));
        assert!(health.body.ends_with("exit 0\n"));
    }

    #[test]
    fn consent_script_is_every_step_verbatim() {
        let p = plan(true, Privilege::Sudo);
        let consent = p.consent_script();
        for script in p.scripts() {
            assert!(consent.contains(&script.body), "{} missing", script.file);
            assert!(consent.contains(&format!("# ---- {} ----", p.run_command(&script))));
        }
        assert!(consent.contains("oryxis-relay-linux-x86_64 (0.1.1, sha256 abab"));
        assert!(consent.contains("mkdir 0700 /tmp/oryxis-relay-deadbeef"));
        // The run's first remote command, the stale-staging sweep, is in
        // the text the user approved, byte for byte.
        assert!(consent.contains(&stale_staging_sweep_command(&p.staging)));
        assert!(consent.trim_end().ends_with("rm -r /tmp/oryxis-relay-deadbeef"));
    }

    #[test]
    fn mask_removes_the_token_everywhere() {
        let token = "sekrit-token-value";
        let p = plan(false, Privilege::Root);
        let masked = mask_token(&p.consent_script(), token);
        assert!(!masked.contains(token));
        assert!(masked.contains(&format!("ORYXIS_RELAY_TOKEN={TOKEN_MASK}")));
        let line = format!("cat: {token}: {token}");
        assert_eq!(mask_token(&line, token), format!("cat: {TOKEN_MASK}: {TOKEN_MASK}"));
        // An empty token masks nothing rather than everything.
        assert_eq!(mask_token("plain", ""), "plain");
    }

    #[test]
    fn staging_dir_is_random_and_short() {
        let a = fresh_staging_dir();
        let b = fresh_staging_dir();
        assert_ne!(a, b);
        assert!(a.starts_with("/tmp/oryxis-relay-"));
        assert_eq!(a.len(), "/tmp/oryxis-relay-".len() + 8);
    }

    #[test]
    fn caddy_site_address_mirrors_base_url() {
        assert_eq!(caddy_site_address("r.example.com", ""), "r.example.com");
        assert_eq!(caddy_site_address("r.example.com", "443"), "r.example.com");
        assert_eq!(caddy_site_address("r.example.com", " 8443 "), "r.example.com:8443");
    }

    #[test]
    fn strip_program_names_the_same_fence_the_script_writes() {
        assert!(CADDY_STRIP_AWK.contains(&format!("/^{CADDY_BEGIN}$/")));
        assert!(CADDY_STRIP_AWK.contains(&format!("/^{CADDY_END}$/")));
        // Single-quoted in the script: a quote inside would end it.
        assert!(!CADDY_STRIP_AWK.contains('\''));
    }

    /// Run the strip program the way the Caddy step does, on a real
    /// `awk`. Unix only: that is where the step runs.
    #[cfg(unix)]
    fn strip(input: &str) -> String {
        strip_for("relay.example.com", input)
    }

    #[cfg(unix)]
    fn strip_for(site: &str, input: &str) -> String {
        use std::io::Write as _;
        let mut child = std::process::Command::new("awk")
            .arg("-v")
            .arg(format!("site={site}"))
            .arg(CADDY_STRIP_AWK)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("awk");
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn a_rerun_replaces_the_managed_block_and_keeps_the_rest() {
        let site = caddy_site("relay.example.com", 8080);
        let first = format!(
            "example.com {{\n    root * /srv\n}}\n\n{CADDY_BEGIN}\n{site}{CADDY_END}\n"
        );
        // What the step appends after stripping, as the script does.
        let append = |base: &str, port: u16| {
            format!("{base}\n{CADDY_BEGIN}\n{}{CADDY_END}\n", caddy_site("relay.example.com", port))
        };
        let stripped = strip(&first);
        assert_eq!(stripped, "example.com {\n    root * /srv\n}\n");
        let second = append(&stripped, 9090);
        assert!(second.contains("reverse_proxy 127.0.0.1:9090"));
        assert!(!second.contains("reverse_proxy 127.0.0.1:8080"));
        // Converges: a third run on the second's output is identical,
        // no blank line gained per deploy.
        assert_eq!(append(&strip(&second), 9090), second);
        // A file with no managed block passes through untouched, minus
        // trailing blank lines.
        assert_eq!(strip("a {\n}\n\n\n"), "a {\n}\n");
    }

    /// A Caddyfile a nightly deploy wrote before the fence existed: the
    /// un-fenced block for THIS site goes (the fenced one replaces it),
    /// and the same shape for another site, or a block of this site the
    /// user edited, is theirs and stays.
    #[cfg(unix)]
    #[test]
    fn the_legacy_unfenced_block_of_this_site_is_replaced() {
        let legacy = format!(
            "example.com {{\n    root * /srv\n}}\n\n{}",
            caddy_site("relay.example.com", 8080)
        );
        assert_eq!(strip(&legacy), "example.com {\n    root * /srv\n}\n");
        // Case-insensitive, like the site address itself.
        assert_eq!(strip("Relay.Example.com {\n    reverse_proxy 127.0.0.1:1\n}\n"), "");
        // Another site of the same shape is not ours.
        let other = caddy_site("other.example.com", 8080);
        assert_eq!(strip(&other), other);
        // A block of this site with anything else inside is the user's,
        // printed back line for line.
        let edited = "relay.example.com {\n    reverse_proxy 127.0.0.1:8080\n    encode gzip\n}\n";
        assert_eq!(strip(edited), edited);
        let hand = "relay.example.com {\n    file_server\n}\n";
        assert_eq!(strip(hand), hand);
        // Legacy AND fenced together (a nightly deploy, then a fenced
        // re-run that could not converge): both go.
        let both = format!(
            "{}\n{CADDY_BEGIN}\n{}{CADDY_END}\n",
            caddy_site("relay.example.com", 8080),
            caddy_site("relay.example.com", 9090)
        );
        assert_eq!(strip(&both), "");
        // A port in the site address is part of the match.
        let with_port = caddy_site("relay.example.com:8443", 8080);
        assert_eq!(strip_for("relay.example.com:8443", &with_port), "");
        assert_eq!(strip(&with_port), with_port);
    }

    #[test]
    fn tls_endpoint_validates_domain_and_port() {
        let ep = tls_endpoint(" https://Relay.Example.com/ ", "").unwrap();
        assert_eq!(ep.site, "relay.example.com");
        assert_eq!(ep.base_url, "https://relay.example.com");
        let ep = tls_endpoint("relay.example.com", "8443").unwrap();
        assert_eq!(ep.site, "relay.example.com:8443");
        assert_eq!(ep.base_url, "https://relay.example.com:8443");
        assert_eq!(tls_endpoint("relay.example.com", "443").unwrap().site, "relay.example.com");
        let ep = tls_endpoint("2001:db8::1", "").unwrap();
        assert_eq!(ep.site, "[2001:db8::1]");
        assert_eq!(tls_endpoint("[2001:db8::1]", "8443").unwrap().base_url, "https://[2001:db8::1]:8443");
        assert_eq!(tls_endpoint("203.0.113.9", "").unwrap().site, "203.0.113.9");
        // Anything that would break out of the script or the site line.
        let long = "a".repeat(64);
        for bad in [
            "relay.example.com'; rm -rf /",
            "relay example.com",
            "-relay.example.com",
            "relay..example.com",
            "relay.example.com{",
            "a, relay.example.com",
            long.as_str(),
        ] {
            assert_eq!(tls_endpoint(bad, ""), Err(EndpointError::BadDomain), "{bad}");
        }
        assert_eq!(tls_endpoint("  ", ""), Err(EndpointError::NoDomain));
        for bad in ["abc", "0", "65536", "-1"] {
            assert_eq!(tls_endpoint("relay.example.com", bad), Err(EndpointError::BadPort), "{bad}");
        }
    }

    #[test]
    fn http_endpoint_brackets_ipv6_and_binds_it() {
        assert_eq!(http_endpoint("vps.example.com", 8080), Some(("http://vps.example.com:8080".into(), false)));
        assert_eq!(http_endpoint("my_box", 8080), Some(("http://my_box:8080".into(), false)));
        assert_eq!(http_endpoint("2001:db8::1", 8080), Some(("http://[2001:db8::1]:8080".into(), true)));
        assert_eq!(http_endpoint("[2001:db8::1]", 8080), Some(("http://[2001:db8::1]:8080".into(), true)));
        assert_eq!(http_endpoint("bad host", 8080), None);
        let mut p = plan(false, Privilege::Root);
        p.listen_v6 = true;
        assert_eq!(p.bind(), "[::]");
        assert!(p.scripts()[1].body.contains("--bind [::]"));
        // TLS always binds loopback, whatever the host's address.
        let mut p = plan(true, Privilege::Root);
        p.listen_v6 = true;
        assert_eq!(p.bind(), "127.0.0.1");
    }
}
