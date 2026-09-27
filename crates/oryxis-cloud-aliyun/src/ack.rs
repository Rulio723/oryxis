//! ACK (Container Service for Kubernetes) primitives: list clusters and
//! fetch a cluster's kubeconfig, both via `aliyun cs ...`.
//!
//! ACK is not a distinct transport in Oryxis: a cluster is reached the
//! same way any Kubernetes cluster is, through the `oryxis-cloud-k8s`
//! provider driving `kubectl`. The one Alibaba-specific step is obtaining
//! a kubeconfig, and here it differs from GKE / AKS in kind:
//! `DescribeClusterUserKubeconfig` RETURNS the YAML (`{"config": ...}`)
//! instead of writing `~/.kube/config`, so the app stores it in a file
//! of its own. These stay pure CLI helpers so the app wiring composes
//! them without this crate owning how a cluster surfaces in the UI.

use serde::Deserialize;

use oryxis_cloud::{CloudError, DiscoveredManagedCluster};

use crate::{AliyunConfig, run_aliyun};

/// `DiscoveredManagedCluster::family` for ACK clusters.
pub const FAMILY: &str = "ack";

/// Page size for `DescribeClustersV1`.
const PAGE_SIZE: u32 = 50;
/// Upper bound on pages per listing.
const MAX_PAGES: u32 = 100;

/// One `DescribeClustersV1` response page (`/api/v1/clusters`).
#[derive(Debug, Deserialize)]
struct ClustersV1 {
    #[serde(default)]
    clusters: Vec<AckCluster>,
    #[serde(default)]
    page_info: PageInfo,
}

#[derive(Debug, Default, Deserialize)]
struct PageInfo {
    #[serde(default)]
    page_number: u32,
    #[serde(default)]
    page_size: u32,
    #[serde(default)]
    total_count: u32,
}

/// One ACK cluster as the API emits it (snake_case keys). Only the fields
/// the UI needs are declared.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AckCluster {
    /// The handle `DescribeClusterUserKubeconfig` takes.
    pub cluster_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub region_id: String,
    /// `running`, `initial`, `failed`, ... lowercase as the API emits it.
    #[serde(default)]
    pub state: String,
    /// Node count.
    #[serde(default)]
    pub size: u32,
    /// Kubernetes version (`1.32.1-aliyun.1`).
    #[serde(default)]
    pub current_version: String,
}

/// Parse a `DescribeClustersV1` page. Pure, so it is unit-tested against
/// fixture JSON.
fn parse_page(json: &[u8]) -> Result<ClustersV1, CloudError> {
    serde_json::from_slice(json)
        .map_err(|e| CloudError::Other(format!("parsing aliyun cs clusters JSON: {e}")))
}

/// List every ACK cluster visible to the profile. Managed, dedicated,
/// serverless and edge clusters are all clusters to `kubectl`, so no
/// `cluster_type` filter is applied.
pub async fn list_clusters(cfg: &AliyunConfig) -> Result<Vec<AckCluster>, CloudError> {
    let mut out = Vec::new();
    let page_size = PAGE_SIZE.to_string();
    for page_number in 1..=MAX_PAGES {
        let page_number_s = page_number.to_string();
        let out_bytes = run_aliyun(
            cfg,
            &[
                "cs",
                "DescribeClustersV1",
                "--page_size",
                &page_size,
                "--page_number",
                &page_number_s,
            ],
        )
        .await?;
        let page = parse_page(&out_bytes)?;
        let got = page.clusters.len();
        out.extend(page.clusters);
        // Stop on the last page: past the total, or an empty / short page
        // when the API left `page_info` blank.
        let served =
            page.page_info.page_number.max(page_number) * page.page_info.page_size.max(PAGE_SIZE);
        if got == 0 || served >= page.page_info.total_count || got < PAGE_SIZE as usize {
            break;
        }
    }
    Ok(out)
}

/// Best-effort ACK discovery for the combined `discover()` pass: map
/// clusters onto the shared [`DiscoveredManagedCluster`] shape. ACK is
/// independent of ECS (a RAM policy may grant one but not the other), so
/// a listing failure yields an empty list rather than failing the whole
/// discovery, which would also hide the instances. The user simply sees
/// no ACK section.
pub async fn discover_clusters(
    cfg: &AliyunConfig,
) -> Result<Vec<DiscoveredManagedCluster>, CloudError> {
    let clusters = match list_clusters(cfg).await {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };
    Ok(clusters.into_iter().map(to_managed).collect())
}

fn to_managed(c: AckCluster) -> DiscoveredManagedCluster {
    DiscoveredManagedCluster {
        family: FAMILY.to_string(),
        id: c.cluster_id,
        name: c.name,
        region: c.region_id,
        status: c.state,
        version: c.current_version,
        node_count: c.size,
    }
}

/// The `DescribeClusterUserKubeconfig` response body.
#[derive(Debug, Deserialize)]
struct UserKubeconfig {
    #[serde(default)]
    config: String,
}

/// Fetch a cluster's kubeconfig and return the YAML text. The PUBLIC API
/// server credential is requested (`PrivateIpAddress=false`), because
/// the machine running Oryxis is normally outside the cluster's VPC.
/// What a cluster with no public endpoint answers has NOT been measured:
/// an API error reaches the UI as-is, and a kubeconfig naming only a
/// private address is flagged by the app (`servers_are_private`), so
/// both shapes end in a message rather than a file that silently cannot
/// connect. The credential is temporary (the response carries an
/// `expiration`), which is why the app offers to fetch it again.
pub async fn user_kubeconfig(cfg: &AliyunConfig, cluster_id: &str) -> Result<String, CloudError> {
    check_cluster_id(cluster_id)?;
    let out = run_aliyun(
        cfg,
        &[
            "cs",
            "DescribeClusterUserKubeconfig",
            "--ClusterId",
            cluster_id,
            "--PrivateIpAddress",
            "false",
        ],
    )
    .await?;
    let body: UserKubeconfig = serde_json::from_slice(&out)
        .map_err(|e| CloudError::Other(format!("parsing aliyun cs kubeconfig JSON: {e}")))?;
    if body.config.trim().is_empty() {
        return Err(CloudError::Upstream(
            "the ACK API returned an empty kubeconfig".into(),
        ));
    }
    Ok(body.config)
}

/// Refuse a cluster id the CLI could read as something other than the
/// VALUE of `--ClusterId`. The id arrives from the app, which got it from
/// a discovery page, i.e. from a remote API: one starting with `-` would
/// be parsed by `aliyun` as a flag of its own, and an empty one would
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
          "clusters": [
            {
              "cluster_id": "c3fb96524f9274b4495df0f12a6b50000",
              "name": "prod",
              "region_id": "cn-hangzhou",
              "state": "running",
              "size": 5,
              "current_version": "1.32.1-aliyun.1",
              "cluster_type": "ManagedKubernetes"
            },
            {
              "cluster_id": "c000",
              "name": "dev",
              "region_id": "cn-beijing",
              "state": "initial"
            }
          ],
          "page_info": { "page_number": 1, "page_size": 50, "total_count": 2 }
        }"#;
        let page = parse_page(json).unwrap();
        assert_eq!(page.page_info.total_count, 2);
        assert_eq!(page.clusters.len(), 2);
        let m = to_managed(page.clusters[0].clone());
        assert_eq!(m.family, "ack");
        assert_eq!(m.id, "c3fb96524f9274b4495df0f12a6b50000");
        assert_eq!(m.name, "prod");
        assert_eq!(m.region, "cn-hangzhou");
        assert_eq!(m.status, "running");
        assert_eq!(m.version, "1.32.1-aliyun.1");
        assert_eq!(m.node_count, 5);
        // Missing size / version default.
        let d = to_managed(page.clusters[1].clone());
        assert_eq!(d.node_count, 0);
        assert_eq!(d.version, "");
    }

    #[test]
    fn empty_cluster_page_is_ok() {
        let page = parse_page(br#"{"clusters":[],"page_info":{"total_count":0}}"#).unwrap();
        assert!(page.clusters.is_empty());
    }

    #[test]
    fn kubeconfig_body_carries_the_yaml() {
        let body: UserKubeconfig = serde_json::from_str(
            r#"{"config":"apiVersion: v1\nclusters:\n- cluster:\n    server: https://114.55.1.2:6443\n","expiration":"2027-03-10T09:56:17Z"}"#,
        )
        .unwrap();
        assert!(body.config.starts_with("apiVersion: v1"));
    }
}
