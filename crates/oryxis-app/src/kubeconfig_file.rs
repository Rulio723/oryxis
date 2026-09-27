//! Kubeconfig files the app keeps for managed clusters whose provider
//! RETURNS the credential instead of writing `~/.kube/config` (ACK on
//! Alibaba Cloud, TKE on Tencent Cloud; `DiscoveredManagedCluster`).
//!
//! Each cluster gets a file of its own under `~/.oryxis/kubeconfig/`,
//! and the Kubernetes account created for it points at that file
//! (`kubeconfig` in the k8s profile config), which the k8s provider and
//! the local `kubectl exec` path already honour. Merging into the user's
//! `~/.kube/config` was considered and rejected: it needs a YAML round
//! trip the workspace has no dependency for, and a bad merge corrupts
//! the one file every other tool on the machine reads. The cost is that
//! the user's own `kubectl` in a terminal does not see the cluster
//! unless they pass `--kubeconfig`; the file's path is what the account
//! shows.
//!
//! The file holds a credential, so it is written 0600 through a
//! temporary sibling and a rename, and removed with the account that
//! owned it. An account can also leave by SYNC (a peer deleted it), which
//! runs no UI arm, so `sweep_unreferenced` removes whatever file of ours
//! no Kubernetes account points at any more. Everything but the file
//! operations is pure and tested.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use uuid::Uuid;

/// Directory the per-cluster files live in.
pub(crate) fn dir() -> Option<PathBuf> {
    oryxis_core::paths::oryxis_dir().map(|d| d.join("kubeconfig"))
}

/// One normal path component out of a provider-supplied id: ASCII
/// letters, digits, `.`, `_` and `-`, never empty, never `.` / `..`,
/// never leading with `-`. Cluster ids arrive over the plugin boundary
/// from a remote API, so they are confined before they become part of a
/// path (the same traversal class the plugin cache confines a manifest
/// version to), and before they are handed back to a CLI as the value of
/// `--ClusterId`, where a leading `-` would read as a flag.
pub(crate) fn sanitize_component(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() || t == "." || t == ".." || t.starts_with('-') {
        return None;
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return None;
    }
    Some(t.to_string())
}

/// The file a cluster's kubeconfig is stored in, as fetched through one
/// cloud account: `<dir>/<family>-<cluster id>-<account id>.yaml`.
/// Deterministic, so the discovery view can tell an added cluster from a
/// new one without asking the provider, and a re-add overwrites in place.
///
/// The ACCOUNT is part of the name because the credential is the
/// account's, not the cluster's: two Alibaba Cloud accounts (two RAM
/// users with different RBAC) can see the same cluster, and keyed on the
/// cluster alone the second one's Add would read as a refresh and
/// silently replace the first account's credential with its own.
pub(crate) fn path_for(family: &str, account: Uuid, cluster_id: &str) -> Result<PathBuf, String> {
    let family = sanitize_component(family).ok_or_else(|| "invalid cluster family".to_string())?;
    let id = sanitize_component(cluster_id).ok_or_else(|| "invalid cluster id".to_string())?;
    let dir = dir().ok_or_else(|| "no home directory to store the kubeconfig in".to_string())?;
    Ok(dir.join(format!("{family}-{id}-{}.yaml", account.simple())))
}

/// The managed kubeconfig paths the given Kubernetes accounts point at
/// (`kubeconfig` in the profile config, under our directory only).
pub(crate) fn referenced_paths(profiles: &[oryxis_core::models::CloudProfile]) -> HashSet<PathBuf> {
    profiles
        .iter()
        .filter(|p| p.provider == "k8s")
        .filter_map(|p| serde_json::from_str::<serde_json::Value>(&p.config).ok())
        .filter_map(|v| v.get("kubeconfig")?.as_str().map(str::to_string))
        .filter(|path| is_managed_path(path))
        .map(PathBuf::from)
        .collect()
}

/// Remove every kubeconfig file of ours in `dir` that no account
/// references and that is not `in_flight` (an Add whose file is written
/// before the account that points at it exists). Returns what it removed.
///
/// Only visible `*.yaml` files are candidates: a `.<name>.tmp` sibling
/// belongs to a write still running, and anything else in the directory
/// is not something this module wrote. The caller must hand in the FULL
/// account list of an unlocked vault; an empty list from a vault that is
/// still locked would read as "nothing is referenced" and wipe them all.
pub(crate) fn sweep_unreferenced(
    dir: &Path,
    referenced: &HashSet<PathBuf>,
    in_flight: &HashSet<PathBuf>,
) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let visible_yaml = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| !n.starts_with('.'))
            && path.extension().and_then(|e| e.to_str()) == Some("yaml");
        if !visible_yaml || !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        if referenced.contains(&path) || in_flight.contains(&path) {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            removed.push(path);
        }
    }
    removed
}

/// True when `path` is one of ours, so deleting the Kubernetes account
/// that owns it may remove the file. Anything the user typed into a k8s
/// account by hand (`~/.kube/config`, a company file) is left alone.
pub(crate) fn is_managed_path(path: &str) -> bool {
    let Some(dir) = dir() else {
        return false;
    };
    let p = Path::new(path);
    p.parent() == Some(dir.as_path()) && p.extension().and_then(|e| e.to_str()) == Some("yaml")
}

/// The `current-context` a kubeconfig names, when it names one. A
/// line scan rather than a YAML parse: the files the cluster APIs hand
/// back are machine-generated block YAML with the key at column 0, and
/// the Kubernetes account works with a blank context anyway (the k8s
/// provider then uses the file's current-context), so a miss costs
/// nothing but the dup-check label.
pub(crate) fn current_context(yaml: &str) -> Option<String> {
    yaml.lines().find_map(|line| {
        let rest = line.strip_prefix("current-context:")?;
        let v = rest.trim().trim_matches(|c| c == '"' || c == '\'');
        (!v.is_empty()).then(|| v.to_string())
    })
}

/// True when every `server:` the kubeconfig names is a private address
/// (RFC 1918, CGNAT, link-local or loopback). Drives the note that such
/// a file only works from inside the cluster's VPC. Which shape a cluster
/// whose public endpoint is off gets back is provider-specific and, for
/// ACK, not measured (see `oryxis_cloud_aliyun::ack::user_kubeconfig`);
/// TKE documents a placeholder domain instead. Hostnames are not
/// resolved, so a private endpoint behind a DNS name reads as public
/// here.
pub(crate) fn servers_are_private(yaml: &str) -> bool {
    let mut seen = false;
    for line in yaml.lines() {
        let Some(rest) = line.trim_start().strip_prefix("server:") else {
            continue;
        };
        seen = true;
        if !is_private_server(rest.trim().trim_matches(|c| c == '"' || c == '\'')) {
            return false;
        }
    }
    seen
}

fn is_private_server(url: &str) -> bool {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let authority = without_scheme.split('/').next().unwrap_or("");
    // Strip a port, minding a bracketed IPv6 literal.
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority)
    };
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            // 100.64.0.0/10, the shared address space (RFC 6598): carrier
            // NAT, and what several clouds hand out inside a VPC.
            let cgnat = v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64;
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || cgnat
        }
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unique_local(),
        Err(_) => false,
    }
}

/// Write `contents` to `path` as a 0600 file: the directory is created,
/// the bytes land in a temporary sibling first and are renamed into
/// place, so a crash mid-write cannot leave a truncated credential
/// where a whole one used to be.
pub(crate) fn write_secret_file(path: &Path, contents: &str) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "kubeconfig path has no parent")
    })?;
    std::fs::create_dir_all(dir)?;
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "kubeconfig path has no name")
    })?;
    // Unique per WRITE, not per process: two fetches of the same cluster
    // in flight at once would otherwise share one temporary and interleave
    // their bytes, or have the second rename find the first one's gone.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{file_name}.{}.{seq}.tmp", std::process::id()));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        io::Write::write_all(&mut f, contents.as_bytes())?;
        io::Write::flush(&mut f)?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_confines_ids_to_one_path_component() {
        assert_eq!(
            sanitize_component("cls-abc12345").as_deref(),
            Some("cls-abc12345")
        );
        assert_eq!(
            sanitize_component(" c3fb96524f9274b4495df0f12a6b50000 ").as_deref(),
            Some("c3fb96524f9274b4495df0f12a6b50000")
        );
        for bad in [
            "", " ", ".", "..", "../x", "a/b", "a\\b", "a b", "c:d", "n\u{e9}", "-x", "--profile",
        ] {
            assert_eq!(sanitize_component(bad), None, "{bad:?} must be rejected");
        }
    }

    #[test]
    fn path_is_deterministic_and_named_after_family_id_and_account() {
        let acct = Uuid::parse_str("0f8e2c1a-7b3d-4e5f-9a6b-1c2d3e4f5a6b").unwrap();
        let a = path_for("tke", acct, "cls-abc12345").unwrap();
        let b = path_for("tke", acct, "cls-abc12345").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            a.file_name().unwrap().to_str().unwrap(),
            "tke-cls-abc12345-0f8e2c1a7b3d4e5f9a6b1c2d3e4f5a6b.yaml"
        );
        assert_eq!(a.parent().unwrap(), dir().unwrap());
        // Two accounts seeing one cluster keep two credentials.
        assert_ne!(a, path_for("tke", Uuid::new_v4(), "cls-abc12345").unwrap());
        assert!(path_for("ack", acct, "../etc").is_err());
        assert!(path_for("", acct, "x").is_err());
    }

    #[test]
    fn sweep_removes_only_unreferenced_visible_yaml() {
        let tmp = std::env::temp_dir().join(format!(
            "oryxis-kubeconfig-sweep-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let kept = tmp.join("ack-c1-a.yaml");
        let orphan = tmp.join("ack-c2-a.yaml");
        let flying = tmp.join("tke-c3-a.yaml");
        let temp_sibling = tmp.join(".ack-c4-a.yaml.1.0.tmp");
        let foreign = tmp.join("notes.txt");
        for p in [&kept, &orphan, &flying, &temp_sibling, &foreign] {
            std::fs::write(p, "x").unwrap();
        }
        let referenced: HashSet<PathBuf> = [kept.clone()].into_iter().collect();
        let in_flight: HashSet<PathBuf> = [flying.clone()].into_iter().collect();
        let removed = sweep_unreferenced(&tmp, &referenced, &in_flight);
        assert_eq!(removed, vec![orphan.clone()]);
        assert!(!orphan.exists());
        for p in [&kept, &flying, &temp_sibling, &foreign] {
            assert!(p.exists(), "{p:?} must survive");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn referenced_paths_reads_managed_k8s_accounts_only() {
        let ours = path_for("ack", Uuid::new_v4(), "c1").unwrap();
        let mut k8s = oryxis_core::models::CloudProfile::new("ACK: prod", "k8s");
        k8s.config = serde_json::json!({ "kubeconfig": ours }).to_string();
        let mut by_hand = oryxis_core::models::CloudProfile::new("mine", "k8s");
        by_hand.config = serde_json::json!({ "kubeconfig": "/home/u/.kube/config" }).to_string();
        let mut other = oryxis_core::models::CloudProfile::new("aws", "aws");
        other.config = serde_json::json!({ "kubeconfig": ours }).to_string();
        let set = referenced_paths(&[k8s, by_hand, other]);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&ours));
    }

    #[test]
    fn managed_path_is_only_our_directory() {
        let ours = path_for("ack", uuid::Uuid::nil(), "c123").unwrap();
        assert!(is_managed_path(ours.to_str().unwrap()));
        // A sibling directory with the same file name is not ours.
        let elsewhere = dir().unwrap().parent().unwrap().join("ack-c123.yaml");
        assert!(!is_managed_path(elsewhere.to_str().unwrap()));
        assert!(!is_managed_path("~/.kube/config"));
        assert!(!is_managed_path(""));
    }

    #[test]
    fn current_context_is_read_off_the_top_level_key() {
        let yaml = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://1.2.3.4:6443\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: \"cls-abc12345-admin\"\n  name: cls-abc12345-context-default\ncurrent-context: cls-abc12345-context-default\nkind: Config\n";
        assert_eq!(
            current_context(yaml).as_deref(),
            Some("cls-abc12345-context-default")
        );
        // Quoted value, and an indented `current-context:` inside a
        // nested map must not be mistaken for the top-level key.
        assert_eq!(
            current_context("kind: Config\ncurrent-context: 'kubernetes-admin-c1'\n").as_deref(),
            Some("kubernetes-admin-c1")
        );
        assert_eq!(
            current_context("preferences:\n  current-context: nope\n"),
            None
        );
        assert_eq!(current_context("current-context: \n"), None);
    }

    #[test]
    fn private_servers_are_recognized() {
        assert!(servers_are_private(
            "clusters:\n- cluster:\n    server: https://10.0.12.3:6443\n"
        ));
        assert!(servers_are_private(
            "clusters:\n- cluster:\n    server: \"https://192.168.1.10\"\n"
        ));
        assert!(!servers_are_private(
            "clusters:\n- cluster:\n    server: https://114.55.1.2:6443\n"
        ));
        // A domain is not resolved, so it reads as public.
        assert!(!servers_are_private(
            "clusters:\n- cluster:\n    server: https://cls-abc.ccs.tencent-cloud.com\n"
        ));
        // Mixed: one public server makes the file usable from outside.
        assert!(!servers_are_private(
            "- cluster:\n    server: https://10.0.0.1:6443\n- cluster:\n    server: https://8.8.8.8:6443\n"
        ));
        // No server at all: nothing to call private.
        assert!(!servers_are_private("kind: Config\n"));
        assert!(is_private_server("https://100.64.0.1:6443"));
        assert!(is_private_server("https://100.127.255.254"));
        assert!(!is_private_server("https://100.128.0.1:6443"));
        assert!(!is_private_server("https://100.63.255.255:6443"));
        assert!(is_private_server("https://[fd00::1]:6443"));
        assert!(!is_private_server("https://[2001:db8::1]:6443"));
    }

    #[test]
    fn secret_file_is_written_whole_and_private() {
        let tmp = std::env::temp_dir().join(format!(
            "oryxis-kubeconfig-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = tmp.join("nested").join("ack-c1.yaml");
        write_secret_file(&path, "kind: Config\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "kind: Config\n");
        // A second write replaces the content in place.
        write_secret_file(&path, "kind: Config\ncurrent-context: x\n").unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("current-context")
        );
        // No temporary sibling survives.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
