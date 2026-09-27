//! TKE (Tencent Kubernetes Engine) primitives: list clusters and fetch a
//! cluster's kubeconfig, both via `tccli tke ...`.
//!
//! TKE is not a distinct transport in Oryxis: a cluster is reached the
//! same way any Kubernetes cluster is, through the `oryxis-cloud-k8s`
//! provider driving `kubectl`. The one Tencent-specific step is obtaining
//! a kubeconfig, and here it differs from GKE / AKS in kind:
//! `DescribeClusterKubeconfig` RETURNS the YAML (`{"Kubeconfig": ...}`)
//! instead of writing `~/.kube/config`, so the app stores it in a file
//! of its own. These stay pure CLI helpers so the app wiring composes
//! them without this crate owning how a cluster surfaces in the UI.

use serde::Deserialize;

use oryxis_cloud::{CloudError, DiscoveredManagedCluster};

use crate::{TencentConfig, run_tccli};

/// `DiscoveredManagedCluster::family` for TKE clusters.
pub const FAMILY: &str = "tke";

/// Page size for `DescribeClusters`; 100 is the API maximum.
const PAGE_SIZE: usize = 100;
/// Upper bound on pages per listing.
const MAX_PAGES: usize = 100;

/// One `DescribeClusters` response page (flat, no envelope).
#[derive(Debug, Deserialize)]
struct DescribeClusters {
    #[serde(rename = "TotalCount", default)]
    total_count: usize,
    #[serde(rename = "Clusters", default)]
    clusters: Vec<TkeCluster>,
}

/// One TKE cluster as the API emits it. Only the fields the UI needs are
/// declared.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TkeCluster {
    /// The handle `DescribeClusterKubeconfig` takes (`cls-abc12345`).
    #[serde(rename = "ClusterId")]
    pub cluster_id: String,
    #[serde(rename = "ClusterName", default)]
    pub cluster_name: String,
    /// `Running`, `Creating`, `Upgrading`, `Isolated`, ... as the API
    /// emits it.
    #[serde(rename = "ClusterStatus", default)]
    pub cluster_status: String,
    /// Kubernetes version (`1.30.0`).
    #[serde(rename = "ClusterVersion", default)]
    pub cluster_version: String,
    #[serde(rename = "ClusterNodeNum", default)]
    pub cluster_node_num: u32,
}

/// Parse a `DescribeClusters` page. Pure, so it is unit-tested against
/// fixture JSON.
fn parse_page(json: &[u8]) -> Result<DescribeClusters, CloudError> {
    serde_json::from_slice(json)
        .map_err(|e| CloudError::Other(format!("parsing tccli tke clusters JSON: {e}")))
}

/// List every TKE cluster in the configured region (or the profile's
/// default region). Managed and self-deployed clusters are both
/// clusters to `kubectl`, so no `ClusterType` filter is applied.
pub async fn list_clusters(cfg: &TencentConfig) -> Result<Vec<TkeCluster>, CloudError> {
    let mut out = Vec::new();
    let limit = PAGE_SIZE.to_string();
    for page in 0..MAX_PAGES {
        let offset = (page * PAGE_SIZE).to_string();
        let bytes = run_tccli(
            cfg,
            &[
                "tke",
                "DescribeClusters",
                "--Limit",
                &limit,
                "--Offset",
                &offset,
            ],
        )
        .await?;
        let page = parse_page(&bytes)?;
        let got = page.clusters.len();
        out.extend(page.clusters);
        if got == 0 || got < PAGE_SIZE || out.len() >= page.total_count {
            break;
        }
    }
    Ok(out)
}

/// Best-effort TKE discovery for the combined `discover()` pass: map
/// clusters onto the shared [`DiscoveredManagedCluster`] shape. TKE is
/// independent of CVM (a CAM policy may grant one but not the other), so
/// a listing failure yields an empty list rather than failing the whole
/// discovery, which would also hide the instances. The user simply sees
/// no TKE section.
pub async fn discover_clusters(
    cfg: &TencentConfig,
) -> Result<Vec<DiscoveredManagedCluster>, CloudError> {
    let clusters = match list_clusters(cfg).await {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };
    let region = cfg.region().unwrap_or_default().to_string();
    Ok(clusters
        .into_iter()
        .map(|c| to_managed(c, &region))
        .collect())
}

fn to_managed(c: TkeCluster, region: &str) -> DiscoveredManagedCluster {
    DiscoveredManagedCluster {
        family: FAMILY.to_string(),
        id: c.cluster_id,
        name: c.cluster_name,
        region: region.to_string(),
        status: c.cluster_status,
        version: c.cluster_version,
        node_count: c.cluster_node_num,
    }
}

/// The `DescribeClusterKubeconfig` response body.
#[derive(Debug, Deserialize)]
struct ClusterKubeconfig {
    #[serde(rename = "Kubeconfig", default)]
    kubeconfig: String,
}

/// Fetch a cluster's kubeconfig and return the YAML text. The PUBLIC API
/// server credential is requested (`IsExtranet=true`), because the
/// machine running Oryxis is normally outside the cluster's VPC. The API
/// does not fail when public access is off: it answers with a kubeconfig
/// whose `server` is a placeholder domain that resolves nowhere (its own
/// documentation says so), which is why the UI notes where the file
/// points instead of this crate guessing from an error.
pub async fn kubeconfig(cfg: &TencentConfig, cluster_id: &str) -> Result<String, CloudError> {
    check_cluster_id(cluster_id)?;
    let out = run_tccli(
        cfg,
        &[
            "tke",
            "DescribeClusterKubeconfig",
            "--ClusterId",
            cluster_id,
            "--IsExtranet",
            "true",
        ],
    )
    .await?;
    let body: ClusterKubeconfig = serde_json::from_slice(&out)
        .map_err(|e| CloudError::Other(format!("parsing tccli tke kubeconfig JSON: {e}")))?;
    if body.kubeconfig.trim().is_empty() {
        return Err(CloudError::Upstream(
            "the TKE API returned an empty kubeconfig".into(),
        ));
    }
    Ok(body.kubeconfig)
}

/// Refuse a cluster id the CLI could read as something other than the
/// VALUE of `--ClusterId`. The id arrives from the app, which got it from
/// a discovery page, i.e. from a remote API: one starting with `-` would
/// be parsed by `tccli` as a flag of its own, and an empty one would
/// shift the next argument into the value slot.
fn check_cluster_id(cluster_id: &str) -> Result<(), CloudError> {
    if cluster_id.trim().is_empty()
        || cluster_id.starts_with('-')
        || cluster_id.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(CloudError::InvalidConfig(format!(
            "refusing cluster id {cluster_id:?}: not a cluster id"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cluster_id_that_reads_as_a_flag_is_refused() {
        assert!(check_cluster_id("c3fb96524f9274b4495df0f12a6b50000").is_ok());
        assert!(check_cluster_id("cls-abc12345").is_ok());
        for bad in ["", " ", "--profile", "-x", "a b", "a\nb"] {
            assert!(check_cluster_id(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn parses_a_cluster_page() {
        let json = br#"{
          "TotalCount": 2,
          "Clusters": [
            {
              "ClusterId": "cls-abc12345",
              "ClusterName": "prod",
              "ClusterStatus": "Running",
              "ClusterVersion": "1.30.0",
              "ClusterNodeNum": 4,
              "ClusterType": "MANAGED_CLUSTER"
            },
            { "ClusterId": "cls-def67890", "ClusterName": "dev", "ClusterStatus": "Creating" }
          ],
          "RequestId": "x"
        }"#;
        let page = parse_page(json).unwrap();
        assert_eq!(page.total_count, 2);
        let m = to_managed(page.clusters[0].clone(), "ap-guangzhou");
        assert_eq!(m.family, "tke");
        assert_eq!(m.id, "cls-abc12345");
        assert_eq!(m.name, "prod");
        assert_eq!(m.region, "ap-guangzhou");
        assert_eq!(m.status, "Running");
        assert_eq!(m.version, "1.30.0");
        assert_eq!(m.node_count, 4);
        let d = to_managed(page.clusters[1].clone(), "");
        assert_eq!(d.node_count, 0);
        assert_eq!(d.version, "");
    }

    #[test]
    fn empty_cluster_page_is_ok() {
        let page = parse_page(br#"{"TotalCount":0,"Clusters":[],"RequestId":"x"}"#).unwrap();
        assert!(page.clusters.is_empty());
    }

    #[test]
    fn kubeconfig_body_carries_the_yaml() {
        let body: ClusterKubeconfig = serde_json::from_str(
            r#"{"Kubeconfig":"apiVersion: v1\nclusters:\n- cluster:\n    server: https://cls-abc12345.ccs.tencent-cloud.com\n","RequestId":"x"}"#,
        )
        .unwrap();
        assert!(body.kubeconfig.starts_with("apiVersion: v1"));
    }
}
