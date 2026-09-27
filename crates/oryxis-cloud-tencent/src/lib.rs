//! Tencent Cloud provider for Oryxis, driven entirely through the `tccli`
//! CLI (no native Tencent Cloud SDK).
//!
//! Discovery shells out to `tccli cvm DescribeInstances --output json` and
//! parses the JSON into the same `DiscoveredEc2` family the AWS provider
//! uses for individual-VM import; each CVM instance becomes an importable
//! `Connection` reached over plain SSH. The provider honours the
//! profile's optional CLI `profile` and `region`, mapping every failure
//! into a `CloudError`.
//!
//! `tccli` must be on PATH and already configured (`tccli configure`); a
//! missing binary surfaces as `CloudError::InvalidConfig` so the UI can
//! tell the user to install / configure it. TKE (managed Kubernetes) is
//! handled by fetching the cluster's kubeconfig through
//! `DescribeClusterKubeconfig`: unlike `gcloud` / `az` the CLI RETURNS the
//! credential rather than writing `~/.kube/config`, so the app stores it
//! in a file of its own and delegates to the Kubernetes provider.
//!
//! Two facts about `tccli` this crate is built on, both read off the
//! 3.x source rather than the docs: with `--output json` the body is the
//! API response's fields FLAT (`TotalCount`, `InstanceSet`, `RequestId`),
//! not wrapped in a `Response` envelope; and an API error is raised as
//! `[TencentCloudSDKException] code:<Code> message:<Message>` on stderr
//! with exit code 255, never as an exit-0 JSON body.

mod discover;
pub mod tke;

use async_trait::async_trait;
use serde::Deserialize;

use oryxis_cloud::{
    CloudError, CloudProfile, CloudProvider, CloudQuery, CloudResourceType, DiscoveredHost,
    DiscoveryResult, TransportKind,
};

/// Parsed `CloudProfile.config` for a Tencent Cloud account.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TencentConfig {
    /// `tccli` profile (`tccli configure --profile <name>`). `None`/empty
    /// = the CLI's default profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// Region (`ap-guangzhou`, `ap-singapore`, ...) to scope CVM / TKE
    /// discovery to. `None`/empty = the profile's configured region.
    #[serde(default)]
    pub region: Option<String>,
}

impl TencentConfig {
    /// Parse the profile's JSON `config`. A blank / malformed config is
    /// treated as "all defaults" (default profile, its region) rather
    /// than an error, so a half-filled profile still talks to the CLI.
    pub fn from_profile(profile: &CloudProfile) -> Self {
        if profile.config.trim().is_empty() {
            return Self::default();
        }
        serde_json::from_str(&profile.config).unwrap_or_default()
    }

    /// The configured region, blank treated as unset.
    pub(crate) fn region(&self) -> Option<&str> {
        self.region
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
}

/// Build the `tccli` argument list: the subcommand args, the
/// `--profile` / `--region` scopes from the config, and always
/// `--output json`, because the output format is a per-profile setting
/// (`tccli configure`) that defaults to `json` but can be `table` or
/// `text`, and a parser must not trust it. Pure + tested.
pub(crate) fn tccli_args(cfg: &TencentConfig, sub: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = sub.iter().map(|s| s.to_string()).collect();
    if let Some(p) = cfg
        .profile
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        args.push("--profile".to_string());
        args.push(p.to_string());
    }
    if let Some(r) = cfg.region() {
        args.push("--region".to_string());
        args.push(r.to_string());
    }
    args.push("--output".to_string());
    args.push("json".to_string());
    args
}

/// The `code:` and `message:` of a `[TencentCloudSDKException] code:X
/// message:Y requestId:Z` line, when stderr carries one.
fn sdk_exception(stderr: &str) -> Option<(String, String)> {
    let line = stderr
        .lines()
        .find(|l| l.contains("TencentCloudSDKException"))?;
    let after_code = line.split("code:").nth(1)?;
    let code = after_code.split_whitespace().next()?.to_string();
    let message = after_code
        .split("message:")
        .nth(1)
        .map(|m| {
            m.split(" requestId:")
                .next()
                .unwrap_or(m)
                .trim()
                .to_string()
        })
        .unwrap_or_default();
    Some((code, message))
}

/// Map a failed `tccli` invocation's stderr into the closest `CloudError`
/// variant so the UI can colour / phrase it sensibly. The usage banner
/// tccli prints above every error is dropped: only the exception line
/// (or, for a local failure, the last non-empty line) reaches the user.
pub(crate) fn classify_tccli_error(stderr: &str) -> CloudError {
    if let Some((code, message)) = sdk_exception(stderr) {
        let text = if message.is_empty() {
            code.clone()
        } else {
            format!("{code}: {message}")
        };
        let c = code.to_lowercase();
        return if c.starts_with("authfailure") || c.starts_with("unauthorizedoperation") {
            CloudError::Auth(text)
        } else if c.starts_with("invalidparameter")
            || c.starts_with("resourcenotfound")
            || c.starts_with("unsupportedregion")
            || c.starts_with("invalidregion")
            || c.starts_with("missingparameter")
        {
            CloudError::InvalidConfig(text)
        } else {
            // RequestLimitExceeded, InternalError, FailedOperation, ...
            CloudError::Upstream(text)
        };
    }
    let last = stderr
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("")
        .to_string();
    let s = last.to_lowercase();
    if s.contains("secretid is invalid") || s.contains("secretkey is invalid") {
        // No credential under this profile. tccli creates the profile
        // file on first mention, so an unknown `--profile` name lands
        // here too rather than as "unknown profile".
        CloudError::Auth(format!(
            "{last}. Run `tccli configure` (with `--profile <name>` for a named profile) first."
        ))
    } else if s.contains("max retries")
        || s.contains("connection")
        || s.contains("timed out")
        || s.contains("name or service not known")
        || s.contains("getaddrinfo")
        || s.contains("network is unreachable")
    {
        CloudError::Network(last)
    } else {
        CloudError::Upstream(last)
    }
}

/// `tccli` executable candidates. tccli is a Python entry point; pip
/// installs a `tccli.exe` shim on Windows, which `Command::new("tccli")`
/// resolves by itself, so unlike `gcloud.cmd` / `az.cmd` there is no
/// batch wrapper to name first. Kept as a list so the spawn loop reads
/// like the other CLI providers'.
const TCCLI_BINS: &[&str] = &["tccli"];

/// Upper bound on one `tccli` invocation. Every call is a single
/// read-only API request (a discovery page, a kubeconfig), so a CLI still
/// running after this is stuck on the network, and saying so beats a
/// spinner that only the plugin host's own deadline would ever end.
const CLI_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Run `tccli <sub...> --profile <p> --region <r> --output json` and
/// return stdout bytes on success. Every call this crate makes is
/// read-only, so a prompt-free failure is the worst case of a TTY-less
/// spawn.
pub(crate) async fn run_tccli(cfg: &TencentConfig, sub: &[&str]) -> Result<Vec<u8>, CloudError> {
    let args = tccli_args(cfg, sub);
    let mut output = None;
    for bin in TCCLI_BINS {
        let mut cmd = tokio::process::Command::new(bin);
        cmd.args(&args);
        // On Windows a console window would flash over the GUI on every
        // call. 0x08000000 = CREATE_NO_WINDOW suppresses it (same guard
        // the other CLI providers use).
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000);
        // The timeout drops the `output()` future, and a dropped child
        // would otherwise keep running (and keep its pipes) behind us.
        cmd.kill_on_drop(true);
        let run = tokio::time::timeout(CLI_TIMEOUT, cmd.output()).await;
        let Ok(run) = run else {
            return Err(CloudError::Network(format!(
                "tccli did not answer within {} s",
                CLI_TIMEOUT.as_secs()
            )));
        };
        match run {
            Ok(o) => {
                output = Some(o);
                break;
            }
            // Not on PATH under this name: try the next candidate.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(CloudError::Other(format!("failed to run tccli: {e}"))),
        }
    }
    let Some(output) = output else {
        // Every candidate was NotFound: the CLI is genuinely missing.
        return Err(CloudError::InvalidConfig(
            "tccli was not found on PATH. Install the Tencent Cloud CLI (`pip install tccli`) \
             and run `tccli configure` to use Tencent Cloud."
                .into(),
        ));
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let text = if stderr.trim().is_empty() {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            stderr.to_string()
        };
        return Err(classify_tccli_error(&text));
    }
    Ok(output.stdout)
}

/// Tencent Cloud provider. Stateless, every call re-derives config from
/// the profile and shells out to `tccli`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TencentProvider;

impl TencentProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CloudProvider for TencentProvider {
    fn id(&self) -> &'static str {
        "tencent"
    }

    async fn test_credentials(&self, profile: &CloudProfile) -> Result<(), CloudError> {
        let cfg = TencentConfig::from_profile(profile);
        // Validate the identity, not any one resource API. This provider
        // serves both CVM and TKE, so a CVM-specific probe would wrongly
        // fail a caller whose CAM policy only grants TKE. STS
        // `GetCallerIdentity` exercises the exact credential tccli uses
        // for discovery and fails cleanly (classified `Auth`) when the
        // profile has no key or the key is unknown. Per-API validity
        // surfaces later, at discovery.
        run_tccli(&cfg, &["sts", "GetCallerIdentity"]).await?;
        Ok(())
    }

    async fn discover(&self, profile: &CloudProfile) -> Result<DiscoveryResult, CloudError> {
        let cfg = TencentConfig::from_profile(profile);
        // CVM and TKE are independent services under one account: a CAM
        // policy can grant one without the other. Probe both, and let
        // each half contribute what it can. `discover_clusters` is
        // already best-effort (empty on any listing failure); mirror
        // that for CVM so a CVM-only failure does not hide the TKE
        // clusters the user CAN see.
        let cvm_result = discover::discover_instances(&cfg).await;
        let managed_clusters = tke::discover_clusters(&cfg).await.unwrap_or_default();
        let ec2 = match cvm_result {
            Ok(v) => v,
            // CVM failed. If TKE also produced nothing, the failure is
            // the real root cause (bad key / region) and must surface;
            // if TKE returned clusters, the account simply lacks CVM
            // read, so show what we have instead of failing the whole
            // discovery.
            Err(e) if managed_clusters.is_empty() => return Err(e),
            Err(_) => Vec::new(),
        };
        Ok(DiscoveryResult {
            ec2,
            ecs_services: Vec::new(),
            k8s_workloads: Vec::new(),
            gke_clusters: Vec::new(),
            aks_clusters: Vec::new(),
            managed_clusters,
        })
    }

    async fn resolve_query(
        &self,
        _profile: &CloudProfile,
        _query: &CloudQuery,
    ) -> Result<Vec<DiscoveredHost>, CloudError> {
        // CVM has no dynamic-group family (the AWS ECS / K8s-workload
        // analog); every instance imports as a standalone Connection.
        // TKE clusters are served through the Kubernetes provider.
        Err(CloudError::Unsupported("tencent resolve_query".into()))
    }

    fn supported_transports(&self, resource_type: CloudResourceType) -> Vec<TransportKind> {
        match resource_type {
            // CVM instances are reached over plain SSH (public or VPC
            // private IP). OrcaTerm / TAT channels are not offered.
            CloudResourceType::Ec2 => vec![TransportKind::Ssh],
        }
    }

    async fn cluster_kubeconfig(
        &self,
        profile: &CloudProfile,
        cluster_id: &str,
    ) -> Result<String, CloudError> {
        let cfg = TencentConfig::from_profile(profile);
        tke::kubeconfig(&cfg, cluster_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with(config: &str) -> CloudProfile {
        let mut p = CloudProfile::new("tencent", "tencent");
        p.auth_kind = "tccli".into();
        p.config = config.into();
        p
    }

    #[test]
    fn config_parses_profile_and_region_or_defaults() {
        let with = TencentConfig::from_profile(&profile_with(
            r#"{"profile":"work","region":"ap-guangzhou"}"#,
        ));
        assert_eq!(with.profile.as_deref(), Some("work"));
        assert_eq!(with.region(), Some("ap-guangzhou"));
        let blank = TencentConfig::from_profile(&profile_with(""));
        assert!(blank.profile.is_none() && blank.region.is_none());
        let bad = TencentConfig::from_profile(&profile_with("not json"));
        assert!(bad.profile.is_none() && bad.region.is_none());
    }

    #[test]
    fn tccli_args_always_force_json_and_scope_only_when_set() {
        let sub = &[
            "cvm",
            "DescribeInstances",
            "--Limit",
            "100",
            "--Offset",
            "0",
        ];
        assert_eq!(
            tccli_args(&TencentConfig::default(), sub),
            vec![
                "cvm",
                "DescribeInstances",
                "--Limit",
                "100",
                "--Offset",
                "0",
                "--output",
                "json"
            ]
        );
        let cfg = TencentConfig {
            profile: Some("work".into()),
            region: Some(" ap-singapore ".into()),
        };
        assert_eq!(
            tccli_args(&cfg, &["sts", "GetCallerIdentity"]),
            vec![
                "sts",
                "GetCallerIdentity",
                "--profile",
                "work",
                "--region",
                "ap-singapore",
                "--output",
                "json"
            ]
        );
    }

    /// The usage banner tccli prints above every failure.
    const BANNER: &str = "usage: tccli [options] <command> <subcommand> [<subcommand> ...] [parameters]\nTo tccli help text, you can run:\n\n  tccli help\n  tccli configure help\n  tccli service[cvm] help\n  tccli service[cvm] action[RunInstances] help\n\n";

    #[test]
    fn sdk_exceptions_are_classified_by_code_prefix() {
        let bad_key = format!(
            "{BANNER}[TencentCloudSDKException] code:AuthFailure.SecretIdNotFound message:SecretId不存在，请输入正确的密钥。 requestId:e4acb51e"
        );
        match classify_tccli_error(&bad_key) {
            CloudError::Auth(msg) => {
                assert_eq!(
                    msg,
                    "AuthFailure.SecretIdNotFound: SecretId不存在，请输入正确的密钥。"
                );
                // The banner and the request id stay out of the message.
                assert!(!msg.contains("usage:") && !msg.contains("requestId"));
            }
            other => panic!("expected Auth, got {other:?}"),
        }
        assert!(matches!(
            classify_tccli_error(
                "[TencentCloudSDKException] code:UnauthorizedOperation.CamNoAuth message:no permission requestId:1"
            ),
            CloudError::Auth(_)
        ));
        // A wrong region is rejected as an invalid `X-TC-Region` value.
        assert!(matches!(
            classify_tccli_error(
                "[TencentCloudSDKException] code:InvalidParameterValue message:参数 `X-TC-Region` 取值错误。 requestId:d326"
            ),
            CloudError::InvalidConfig(_)
        ));
        assert!(matches!(
            classify_tccli_error(
                "[TencentCloudSDKException] code:ResourceNotFound.ClusterNotFound message:cluster not found requestId:2"
            ),
            CloudError::InvalidConfig(_)
        ));
        assert!(matches!(
            classify_tccli_error(
                "[TencentCloudSDKException] code:RequestLimitExceeded message:slow down requestId:3"
            ),
            CloudError::Upstream(_)
        ));
    }

    #[test]
    fn local_failures_are_classified_from_the_last_line() {
        // No credential configured: tccli's own wording (exit 255).
        let none = format!("{BANNER}secretId is invalid");
        match classify_tccli_error(&none) {
            CloudError::Auth(msg) => assert!(msg.contains("tccli configure")),
            other => panic!("expected Auth, got {other:?}"),
        }
        assert!(matches!(
            classify_tccli_error(
                "HTTPSConnectionPool(host='cvm.tencentcloudapi.com', port=443): Max retries exceeded"
            ),
            CloudError::Network(_)
        ));
        assert!(matches!(
            classify_tccli_error("something else entirely"),
            CloudError::Upstream(_)
        ));
    }
}
