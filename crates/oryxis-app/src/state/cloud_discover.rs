//! The cloud discovery screen: what the probe found, what the user
//! ticked, and the defaults the import will apply.
//!
//! Worth a struct because the selection is long-lived: closing the
//! screen has to drop all of it together, and thirteen loose fields is
//! thirteen chances to leave a stale tick behind for the next profile.

use uuid::Uuid;

#[derive(Debug)]
pub(crate) struct CloudDiscoverUi {
    /// Discovery panel state, opened from a profile card or from the
    /// post-save flow. Carries the in-flight or completed result so
    /// the user picks resources without paying another API round-trip.
    pub(crate) visible: bool,
    pub(crate) profile_id: Option<Uuid>,
    pub(crate) state: crate::state::CloudDiscoverState,
    /// EC2 instance-ids currently checked in the discovery panel.
    pub(crate) selected_ec2: std::collections::HashSet<String>,
    /// ECS service identifiers checked in the discovery panel.
    /// Key format: `cluster/service/container` (the same triple a
    /// `CloudQuery::EcsTasks` carries), guarantees a stable id even
    /// when service or container names collide across clusters.
    pub(crate) selected_ecs: std::collections::HashSet<String>,
    /// Kubernetes workload identifiers checked in the discovery panel.
    /// Key format: `namespace/kind/name` (the workload identity the
    /// import looks back up to build a `K8sPods` dynamic group).
    pub(crate) selected_k8s: std::collections::HashSet<String>,
    /// Live filter for the discovery panel, matches against label,
    /// instance-id, hostname, IP. Lowercased substring match.
    pub(crate) filter: String,
    /// Section names currently collapsed in the discovery panel
    /// ("ec2" / "ecs" / "k8s"). Persisted only in memory, re-opens
    /// default to expanded.
    pub(crate) collapsed: std::collections::HashSet<String>,
    /// Default transport applied to every EC2 host imported in this
    /// discovery session. Lets the user pick "Instance Connect" once
    /// instead of editing 10 hosts after the fact. Stored at the
    /// `Oryxis` level (not on the `OverlayState`) so the choice
    /// survives discovery refreshes.
    pub(crate) default_transport: oryxis_core::models::cloud::TransportKind,
    /// Target group name for the next import. Empty string = no
    /// parent (drop at root). Otherwise the import flow finds a group
    /// with this label or creates it on the spot, so the user can
    /// type any name (existing or new) and have it materialised.
    /// Decoupled from the pick_list-based approach so typing a brand
    /// new folder name doesn't require a pre-existing entry.
    pub(crate) default_group_name: String,
    /// Whether the floating group picker overlay (inside the import
    /// confirmation modal) is open. Chevron toggles it; picking an
    /// entry or clicking the scrim closes it.
    pub(crate) default_group_picker_open: bool,
    /// Screen-space bounds of the Import-into combo row, populated
    /// by a `bounds_reporter` wrapper. Read by the toggle handler to
    /// anchor the picker overlay right under the chevron without
    /// guessing layout offsets.
    pub(crate) default_group_combo_bounds: crate::widgets::BoundsCell,
    /// Search text inside the group picker overlay. Independent of
    /// `cloud_discover_default_group_name` (the input box) so typing
    /// in the picker's filter doesn't overwrite the user's chosen
    /// folder name.
    pub(crate) default_group_picker_search: String,
    /// Managed-cluster kubeconfig files (`kubeconfig_file::path_for`)
    /// whose fetch is running. Disables that cluster's Add / Refresh
    /// button, refuses a second request for the same file, and keeps
    /// `sweep_unreferenced` off a file written before the account that
    /// will point at it exists. Deliberately NOT cleared with the screen:
    /// the task outlives the panel, and the completion is what ends it.
    pub(crate) managed_in_flight: std::collections::HashSet<std::path::PathBuf>,
}

impl Default for CloudDiscoverUi {
    fn default() -> Self {
        Self {
            visible: false,
            profile_id: None,
            state: crate::state::CloudDiscoverState::Idle,
            selected_ec2: std::collections::HashSet::new(),
            selected_ecs: std::collections::HashSet::new(),
            selected_k8s: std::collections::HashSet::new(),
            filter: String::new(),
            collapsed: std::collections::HashSet::new(),
            default_transport: oryxis_core::models::cloud::TransportKind::Ssh,
            default_group_name: String::new(),
            default_group_picker_open: false,
            default_group_combo_bounds: crate::widgets::new_bounds_cell(),
            default_group_picker_search: String::new(),
            managed_in_flight: std::collections::HashSet::new(),
        }
    }
}
