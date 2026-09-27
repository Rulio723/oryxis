//! Alibaba Cloud provider for Oryxis, driven entirely through the
//! `aliyun` CLI (no native Alibaba Cloud SDK).
//!
//! Discovery shells out to `aliyun ecs DescribeInstances` and parses the
//! OpenAPI JSON into the same `DiscoveredEc2` family the AWS provider
//! uses for individual-VM import; each ECS instance becomes an importable
//! `Connection` reached over plain SSH. The provider honours the
//! profile's optional CLI `profile` and `region`, mapping every failure
//! into a `CloudError`.
//!
//! `aliyun` must be on PATH and already configured (`aliyun configure`);
//! a missing binary surfaces as `CloudError::InvalidConfig` so the UI can
//! tell the user to install / configure it. ACK (managed Kubernetes) is
//! handled by fetching the cluster's kubeconfig through
//! `DescribeClusterUserKubeconfig`: unlike `gcloud` / `az` the CLI RETURNS
//! the credential rather than writing `~/.kube/config`, so the app stores
//! it in a file of its own and delegates to the Kubernetes provider.

pub mod ack;
mod discover;

use async_trait::async_trait;
use serde::Deserialize;

use oryxis_cloud::{
    CloudError, CloudProfile, CloudProvider, CloudQuery, CloudResourceType, DiscoveredHost,
    DiscoveryResult, TransportKind,
};

/// Parsed `CloudProfile.config` for an Alibaba Cloud account.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AliyunConfig {
    /// `aliyun` CLI profile (`aliyun configure --profile <name>`).
    /// `None`/empty = the CLI's default profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// Region id (`cn-hangzhou`, `ap-southeast-1`, ...) to scope ECS
    /// discovery to. `None`/empty = the profile's configured region.
    #[serde(default)]
    pub region: Option<String>,
}

impl AliyunConfig {
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

/// Build the `aliyun` argument list: the subcommand args followed by the
/// global `--profile` / `--region` flags from the config (the CLI takes
/// its global flags in any position; measured with `--cli-dry-run` on
/// 3.5.0). Pure + tested.
pub(crate) fn aliyun_args(cfg: &AliyunConfig, sub: &[&str]) -> Vec<String> {
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
    args
}

/// The error object `aliyun` 3.x prints to stderr on an API failure
/// (`{"message": ..., "error_code": "InvalidAccessKeyId.NotFound", ...}`,
/// exit code 2). Only the two fields we classify on are declared;
/// `recovery` and the rest are ignored.
#[derive(Debug, Deserialize)]
struct AliyunErrorJson {
    #[serde(default)]
    message: String,
    #[serde(default)]
    error_code: String,
}

/// Bucket an OpenAPI error code into a `CloudError` variant.
fn classify_code(code: &str, message: &str) -> CloudError {
    let text = if message.is_empty() {
        code.to_string()
    } else {
        format!("{code}: {message}")
    };
    let c = code.to_lowercase();
    if c.starts_with("invalidaccesskeyid")
        || c.starts_with("signaturedoesnotmatch")
        || c.starts_with("invalidsecuritytoken")
        || c.starts_with("securitytoken")
        || c.starts_with("forbidden")
        || c.contains("nopermission")
        || c.contains("unauthorized")
        || c.contains("expiredaccesskey")
    {
        CloudError::Auth(text)
    } else if c.starts_with("invalidregionid")
        || c.starts_with("invalidparameter")
        || c.starts_with("missingparameter")
        || c.starts_with("errorclusternotfound")
        || c.contains("notfound") && !c.starts_with("invalidaccesskeyid")
    {
        CloudError::InvalidConfig(text)
    } else {
        // Throttling, ServiceUnavailable, InternalError, ...: the
        // service's problem, retry later.
        CloudError::Upstream(text)
    }
}

/// Map a failed `aliyun` invocation's stderr into the closest
/// `CloudError` variant so the UI can colour / phrase it sensibly.
///
/// Two formats reach here. The 3.x CLI prints API errors as one JSON
/// object (`error_code` + `message`), while configuration failures
/// (`profile default is not configure yet`, exit 3) and older CLIs print
/// plain text (`ERROR: SDK.ServerError` / `ErrorCode: ...`). JSON is
/// tried first so the message shown is the API's own sentence rather
/// than the whole blob with its `recovery` object.
pub(crate) fn classify_aliyun_error(stderr: &str) -> CloudError {
    let trimmed = stderr.trim();
    if let Some(start) = trimmed.find('{')
        && let Ok(err) = serde_json::from_str::<AliyunErrorJson>(&trimmed[start..])
        && (!err.error_code.is_empty() || !err.message.is_empty())
    {
        if err.error_code.is_empty() {
            // A local error the CLI reports as JSON without a code: the
            // one seen in practice is `unknown endpoint for region ...`.
            return classify_text(&err.message);
        }
        return classify_code(&err.error_code, &err.message);
    }
    // Older CLIs: `ErrorCode: InvalidAccessKeyId.NotFound` on its own line.
    if let Some(code) = trimmed
        .lines()
        .find_map(|l| l.trim().strip_prefix("ErrorCode:"))
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        let message = trimmed
            .lines()
            .find_map(|l| l.trim().strip_prefix("Message:"))
            .map(str::trim)
            .unwrap_or("");
        return classify_code(code, message);
    }
    classify_text(trimmed)
}

/// Substring buckets for the plain-text messages.
fn classify_text(text: &str) -> CloudError {
    let s = text.to_lowercase();
    if s.contains("not configure yet")
        || s.contains("unknown profile")
        || s.contains("configuration failed")
        || s.contains("access key")
        || s.contains("accesskey")
        || s.contains("credential")
        || s.contains("signature")
        || s.contains("forbidden")
    {
        CloudError::Auth(text.to_string())
    } else if s.contains("unknown endpoint for region")
        || s.contains("invalidregionid")
        || s.contains("unknown region")
    {
        CloudError::InvalidConfig(text.to_string())
    } else if s.contains("timeout")
        || s.contains("timed out")
        || s.contains("connection")
        || s.contains("dial tcp")
        || s.contains("no such host")
        || s.contains("network is unreachable")
    {
        CloudError::Network(text.to_string())
    } else {
        CloudError::Upstream(text.to_string())
    }
}

/// `aliyun` CLI executable candidates. The CLI is a single Go binary on
/// every platform (`aliyun.exe` on Windows, which `Command::new("aliyun")`
/// resolves by itself), so unlike `gcloud.cmd` / `az.cmd` there is no
/// batch wrapper to name first. Kept as a list so the spawn loop reads
/// like the other CLI providers'.
const ALIYUN_BINS: &[&str] = &["aliyun"];

/// Upper bound on one `aliyun` invocation. Every call is a single
/// read-only API request (a discovery page, a kubeconfig), so a CLI still
/// running after this is stuck on the network, and saying so beats a
/// spinner that only the plugin host's own deadline would ever end.
const CLI_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Run `aliyun <sub...> --profile <p> --region <r>` and return stdout
/// bytes on success. Every call this crate makes is read-only, so a
/// prompt-free failure is the worst case of a TTY-less spawn.
pub(crate) async fn run_aliyun(cfg: &AliyunConfig, sub: &[&str]) -> Result<Vec<u8>, CloudError> {
    let args = aliyun_args(cfg, sub);
    let mut output = None;
    for bin in ALIYUN_BINS {
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
                "aliyun did not answer within {} s",
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
            Err(e) => return Err(CloudError::Other(format!("failed to run aliyun: {e}"))),
        }
    }
    let Some(output) = output else {
        // Every candidate was NotFound: the CLI is genuinely missing.
        return Err(CloudError::InvalidConfig(
            "aliyun was not found on PATH. Install the Alibaba Cloud CLI and run \
             `aliyun configure` to use Alibaba Cloud."
                .into(),
        ));
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        // A failure that printed nothing to stderr (seen on some local
        // errors) still has its account on stdout.
        let text = if stderr.trim().is_empty() {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            stderr.to_string()
        };
        return Err(classify_aliyun_error(&text));
    }
    // A zero exit with an empty body and a complaint on stderr is an
    // error the CLI failed to signal; reading it as "no instances" would
    // hide a wrong region behind an empty list.
    if output.stdout.iter().all(u8::is_ascii_whitespace) && !stderr.trim().is_empty() {
        return Err(classify_aliyun_error(&stderr));
    }
    Ok(output.stdout)
}

/// Alibaba Cloud provider. Stateless, every call re-derives config from
/// the profile and shells out to `aliyun`.
#[derive(Debug, Default, Clone, Copy)]
pub struct AliyunProvider;

impl AliyunProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CloudProvider for AliyunProvider {
    fn id(&self) -> &'static str {
        "aliyun"
    }

    async fn test_credentials(&self, profile: &CloudProfile) -> Result<(), CloudError> {
        let cfg = AliyunConfig::from_profile(profile);
        // Validate the identity, not any one resource API. This provider
        // serves both ECS and ACK, so an ECS-specific probe would wrongly
        // fail a caller whose RAM policy only grants ACK. STS
        // `GetCallerIdentity` works for every credential mode the CLI
        // supports (AK, STS token, RAM role, ECS RAM role) and fails
        // cleanly (classified `Auth`) when the profile is unconfigured
        // or its key is unknown. Per-API validity surfaces later, at
        // discovery.
        run_aliyun(&cfg, &["sts", "GetCallerIdentity"]).await?;
        Ok(())
    }

    async fn discover(&self, profile: &CloudProfile) -> Result<DiscoveryResult, CloudError> {
        let cfg = AliyunConfig::from_profile(profile);
        // ECS and ACK are independent services under one account: a RAM
        // policy can grant one without the other. Probe both, and let
        // each half contribute what it can. `discover_clusters` is
        // already best-effort (empty on any listing failure); mirror
        // that for ECS so an ECS-only failure does not hide the ACK
        // clusters the user CAN see.
        let ecs_result = discover::discover_instances(&cfg).await;
        let managed_clusters = ack::discover_clusters(&cfg).await.unwrap_or_default();
        let ec2 = match ecs_result {
            Ok(v) => v,
            // ECS failed. If ACK also produced nothing, the failure is
            // the real root cause (bad key / region) and must surface;
            // if ACK returned clusters, the account simply lacks ECS
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
        // ECS has no dynamic-group family (the AWS ECS / K8s-workload
        // analog); every instance imports as a standalone Connection.
        // ACK clusters are served through the Kubernetes provider.
        Err(CloudError::Unsupported("aliyun resolve_query".into()))
    }

    fn supported_transports(&self, resource_type: CloudResourceType) -> Vec<TransportKind> {
        match resource_type {
            // ECS instances are reached over plain SSH (public IP / EIP or
            // VPC private IP). Session Manager-style channels are not
            // offered.
            CloudResourceType::Ec2 => vec![TransportKind::Ssh],
        }
    }

    async fn cluster_kubeconfig(
        &self,
        profile: &CloudProfile,
        cluster_id: &str,
    ) -> Result<String, CloudError> {
        let cfg = AliyunConfig::from_profile(profile);
        ack::user_kubeconfig(&cfg, cluster_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with(config: &str) -> CloudProfile {
        let mut p = CloudProfile::new("aliyun", "aliyun");
        p.auth_kind = "aliyun_cli".into();
        p.config = config.into();
        p
    }

    #[test]
    fn config_parses_profile_and_region_or_defaults() {
        let with = AliyunConfig::from_profile(&profile_with(
            r#"{"profile":"work","region":"cn-hangzhou"}"#,
        ));
        assert_eq!(with.profile.as_deref(), Some("work"));
        assert_eq!(with.region(), Some("cn-hangzhou"));
        // Blank / malformed config yields all-defaults.
        let blank = AliyunConfig::from_profile(&profile_with(""));
        assert!(blank.profile.is_none() && blank.region.is_none());
        let bad = AliyunConfig::from_profile(&profile_with("not json"));
        assert!(bad.profile.is_none() && bad.region.is_none());
        // A whitespace-only region is treated as unset.
        let ws = AliyunConfig {
            profile: None,
            region: Some("  ".into()),
        };
        assert_eq!(ws.region(), None);
    }

    #[test]
    fn aliyun_args_appends_profile_and_region_only_when_set() {
        let sub = &["sts", "GetCallerIdentity"];
        assert_eq!(aliyun_args(&AliyunConfig::default(), sub), sub.to_vec());

        let cfg = AliyunConfig {
            profile: Some("work".into()),
            region: Some("cn-hangzhou".into()),
        };
        assert_eq!(
            aliyun_args(&cfg, sub),
            vec![
                "sts",
                "GetCallerIdentity",
                "--profile",
                "work",
                "--region",
                "cn-hangzhou"
            ]
        );

        let region_only = AliyunConfig {
            profile: Some(" ".into()),
            region: Some("ap-southeast-1".into()),
        };
        assert_eq!(
            aliyun_args(&region_only, sub),
            vec!["sts", "GetCallerIdentity", "--region", "ap-southeast-1"]
        );
    }

    #[test]
    fn json_errors_are_classified_by_code() {
        // Verbatim shape of aliyun 3.5.0's stderr on a bogus access key.
        let bad_key = r#"{"message":"Specified access key is not found.","error_code":"InvalidAccessKeyId.NotFound","status_code":404,"request_id":"01A0","recovery":{"action":"diagnose_error_code","command":"aliyun openapiexplorer ...","hint":"..."}}"#;
        match classify_aliyun_error(bad_key) {
            CloudError::Auth(msg) => {
                assert_eq!(
                    msg,
                    "InvalidAccessKeyId.NotFound: Specified access key is not found."
                );
                // The recovery blob stays out of what the UI shows.
                assert!(!msg.contains("openapiexplorer"));
            }
            other => panic!("expected Auth, got {other:?}"),
        }
        assert!(matches!(
            classify_aliyun_error(
                r#"{"message":"The request signature does not match.","error_code":"SignatureDoesNotMatch"}"#
            ),
            CloudError::Auth(_)
        ));
        assert!(matches!(
            classify_aliyun_error(
                r#"{"message":"You are not authorized.","error_code":"Forbidden.RAM"}"#
            ),
            CloudError::Auth(_)
        ));
        assert!(matches!(
            classify_aliyun_error(
                r#"{"message":"The specified RegionId does not exist.","error_code":"InvalidRegionId.NotFound"}"#
            ),
            CloudError::InvalidConfig(_)
        ));
        assert!(matches!(
            classify_aliyun_error(
                r#"{"message":"Request was denied due to request throttling.","error_code":"Throttling"}"#
            ),
            CloudError::Upstream(_)
        ));
        // A local error printed as JSON without a code (a region the CLI
        // has no endpoint for) is actionable configuration.
        assert!(matches!(
            classify_aliyun_error(
                r#"{"message":"unknown endpoint for region nowhere-1\n  you need to add --endpoint xxx.aliyuncs.com","recovery":{"action":"fix_endpoint_or_region"}}"#
            ),
            CloudError::InvalidConfig(_)
        ));
    }

    #[test]
    fn text_errors_are_classified_by_substring() {
        // Configuration failures print plain text (exit 3).
        assert!(matches!(
            classify_aliyun_error(
                "ERROR: profile default is not configure yet, run `aliyun configure --profile default` first\n\nConfiguration failed, use `aliyun configure` to configure it"
            ),
            CloudError::Auth(_)
        ));
        assert!(matches!(
            classify_aliyun_error("ERROR: unknown profile nope, run configure to check"),
            CloudError::Auth(_)
        ));
        // Older CLIs' multi-line server error.
        assert!(matches!(
            classify_aliyun_error(
                "ERROR: SDK.ServerError\nErrorCode: InvalidAccessKeyId.NotFound\nRecommend: ...\nRequestId: 1\nMessage: Specified access key is not found."
            ),
            CloudError::Auth(_)
        ));
        assert!(matches!(
            classify_aliyun_error("ERROR: dial tcp: lookup ecs.aliyuncs.com: no such host"),
            CloudError::Network(_)
        ));
        assert!(matches!(
            classify_aliyun_error("ERROR: something else entirely"),
            CloudError::Upstream(_)
        ));
    }
}
