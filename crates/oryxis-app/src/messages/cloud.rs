//! Cloud accounts, discovery/import, dynamic groups and ECS/SSM/kubectl exec connects, wrapped by [`crate::messages::Message::Cloud`]. Handled by `Oryxis::handle_cloud`.

use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum CloudMessage {
    /// A cloud plugin PTY stream ended (session-manager-plugin /
    /// kubectl exited). Marks the tab disconnected, prints an in-pane
    /// notice and re-arms `pending_reopen` so selecting the tab again
    /// reconnects (the pane previously just went silently dead).
    PluginSessionEnded(Uuid),
    CloudSearchChanged(String),
    ShowCloudForm(Option<Uuid>),
    HideCloudForm,
    CloudFormLabelChanged(String),
    CloudFormProviderChanged(crate::state::CloudProviderChoice),
    CloudFormAuthKindChanged(crate::state::CloudAuthChoice),
    CloudFormAwsProfileNameChanged(String),
    CloudFormAwsRegionDraftChanged(String),
    /// Commit the current draft to the regions chip list. Supports
    /// comma or whitespace separated input so paste-multiple works.
    CloudFormAwsRegionAdd,
    CloudFormAwsRegionRemove(usize),
    CloudFormAwsAccessKeyIdChanged(String),
    CloudFormAwsAccessKeySecretChanged(super::Redacted),
    CloudFormAwsAccessKeySessionTokenChanged(super::Redacted),
    #[allow(dead_code)]
    CloudFormAwsAccessKeySecretToggleVisibility,
    CloudFormAwsSsoStartUrlChanged(String),
    CloudFormAwsSsoRegionChanged(String),
    CloudFormAwsSsoAccountIdChanged(String),
    CloudFormAwsSsoRoleNameChanged(String),
    /// Kubernetes (Kubeconfig) auth fields.
    CloudFormKubeconfigPathChanged(String),
    CloudFormContextChanged(String),
    /// GCP project id field in the cloud wizard.
    CloudFormGcpProjectChanged(String),
    CloudFormAzureSubscriptionChanged(String),
    /// CLI profile / region fields shared by the Alibaba Cloud and
    /// Tencent Cloud wizard panels (`CloudForm::cli_profile` /
    /// `cli_region`).
    CloudFormCliProfileChanged(String),
    CloudFormCliRegionChanged(String),
    /// Kicks off a `test_credentials` round-trip via the registered
    /// provider. The result lands as `CloudFormTestResult`.
    CloudFormTestCredentials,
    CloudFormTestResult(Result<(), String>),
    SaveCloudProfile,
    DeleteCloudProfile(Uuid),
    /// Open the kebab context menu on a cloud account card. Anchored
    /// to the cursor like the host-card menu.
    ShowCloudCardMenu(Uuid),
    CloudCardHovered(Uuid),
    CloudCardUnhovered(uuid::Uuid),
    /// Open the cloud-provider picker dropdown next to the "+ Host"
    /// button (only when at least one cloud profile is configured).
    ShowCloudProviderPicker,
    ShowCloudDiscover(Uuid),
    HideCloudDiscover,
    CloudDiscoverRefresh,
    /// Result of `provider.discover()`, payload boxed because
    /// `DiscoveryResult` carries collections per resource family and
    /// clippy yells about the variant size otherwise.
    CloudDiscoverResult(Result<Box<oryxis_cloud::DiscoveryResult>, String>),
    CloudDiscoverToggleEc2(String),
    /// Toggle an ECS service entry in the discovery panel. Carries
    /// the `cluster/service/container` key.
    CloudDiscoverToggleEcs(String),
    /// Toggle a discovered K8s workload (`namespace/kind/name`).
    CloudDiscoverToggleK8s(String),
    CloudDiscoverImport,
    /// Triggered from the transport-confirmation modal: actually run
    /// the import using the picked default transport.
    CloudDiscoverImportConfirmed,
    /// Close the transport-confirmation modal without importing.
    CloudDiscoverImportCancelled,
    CloudDiscoverFilterChanged(String),
    /// Toggle expanded/collapsed state of a section header in the
    /// discovery panel. Carries the section key (e.g. `"ec2"`).
    CloudDiscoverToggleSection(String),
    /// Add a discovered GKE cluster: fetch its kubeconfig
    /// (get-credentials) and create a Kubernetes account pointed at the
    /// resulting context.
    CloudDiscoverAddGke { cluster: String, location: String },
    /// get-credentials succeeded: `(label, context)` for the new K8s
    /// account to create.
    CloudDiscoverGkeCredentials(String, String),
    /// Result of the GKE add: `Ok(())` created the k8s account (refresh),
    /// `Err(msg)` surfaces on the discovery panel.
    CloudDiscoverGkeAdded(Result<(), String>),
    /// Add a discovered AKS cluster: fetch its kubeconfig
    /// (get-credentials) and create a Kubernetes account pointed at the
    /// resulting context.
    CloudDiscoverAddAks { cluster: String, resource_group: String },
    /// get-credentials succeeded: `(label, context)` for the new K8s
    /// account to create.
    CloudDiscoverAksCredentials(String, String),
    /// Result of the AKS add: `Ok(())` created the k8s account (refresh),
    /// `Err(msg)` surfaces on the discovery panel.
    CloudDiscoverAksAdded(Result<(), String>),
    /// Add (or refresh) a managed cluster whose provider RETURNS the
    /// kubeconfig (ACK / TKE, `DiscoveredManagedCluster`): fetch the YAML,
    /// store it in the cluster's own file and create a Kubernetes account
    /// pointed at that file. `family` is the product family (`ack` /
    /// `tke`), `id` the cluster id, `name` the display name for the label.
    CloudDiscoverAddManagedCluster {
        family: String,
        id: String,
        name: String,
    },
    /// The kubeconfig was written: `label` for the new account, `path`
    /// of the file, the file's `context` (blank when it
    /// names none) and whether every server it names is a private
    /// address. The YAML itself never rides a message: `Message` derives
    /// `Debug`.
    CloudDiscoverManagedClusterStored {
        label: String,
        path: String,
        context: String,
        intranet: bool,
    },
    /// The fetch or the write failed for the file at `path` (which ends
    /// the cluster's in-flight state); `error` surfaces as a toast.
    CloudDiscoverManagedClusterFailed {
        path: String,
        error: String,
    },
    CloudDiscoverDefaultTransportChanged(oryxis_core::models::cloud::TransportKind),
    CloudDiscoverDefaultGroupNameChanged(String),
    CloudDiscoverDefaultGroupPick(String),
    /// Toggle the floating group-picker overlay rendered at the top
    /// of the Discover import modal. Independent of the global
    /// OverlayState so it can sit on top of the modal scrim.
    ToggleCloudDiscoverGroupPicker,
    /// Live filter typed inside the group-picker overlay's own
    /// search field. Doesn't affect the main "Import into" input.
    CloudDiscoverDefaultGroupPickerSearchChanged(String),
    /// Manual sync of a cloud profile, re-runs discovery and updates
    /// every already-imported host whose `cloud_ref.profile_id` matches.
    /// Fields the user has flagged in `customized_fields` are preserved.
    /// Hosts not in the upstream result get their `cloud_ref.orphaned_at`
    /// set; hosts that come back get it cleared.
    CloudProfileSync(Uuid),
    CloudProfileSyncResult(Uuid, Result<Box<oryxis_cloud::DiscoveryResult>, String>),
    /// Fired by the iced subscription when the auto-refresh interval
    /// elapses. Iterates every cloud profile and dispatches a
    /// `CloudProfileSync(pid)` for each.
    CloudAutoRefreshTick,
    DynamicGroupFormLabelChanged(String),
    DynamicGroupFormParentChanged(String),
    DynamicGroupFormClusterChanged(String),
    DynamicGroupFormServiceChanged(String),
    DynamicGroupFormContainerChanged(String),
    /// K8s dynamic-group source fields (context / namespace / selector
    /// kind + value).
    DynamicGroupFormK8sContextChanged(String),
    DynamicGroupFormNamespaceChanged(String),
    DynamicGroupFormK8sSelectorKindChanged(crate::state::K8sSelectorKind),
    DynamicGroupFormK8sSelectorValueChanged(String),
    /// Open the shared icon + color picker pre-filled with the current
    /// dynamic-group form values. On Save the picker writes back to the
    /// form (not directly to the vault) so the deferred Save button on
    /// the form panel still controls when the group is persisted.
    ShowIconPickerForDynamicGroupForm,
    /// Kick off `provider.resolve_query()` for a dynamic group. The
    /// async result lands as `DynamicGroupResolved`. Idempotent
    /// safe to dispatch even if a resolve is already running for the
    /// same group; the dashboard handler dedupes.
    DynamicGroupResolve(Uuid),
    /// User clicked a task row inside an open dynamic group. Carries
    /// the group id (so we can find the cloud_query) and the task's
    /// `resource_id` (the task ARN suffix). Triggers ECS Exec.
    /// Connect to whichever task of the dynamic group is currently
    /// running, re-resolving first when the cached listing is stale.
    /// Used by pinned-tab reopen (the stored task id is ephemeral by
    /// nature) and by the "connect to current task" recovery button
    /// after an exec failure. `fallback_task_id` wins when it still
    /// exists; otherwise the first RUNNING task is picked.
    EcsExecConnectFreshTask {
        group_id: Uuid,
        container: String,
        fallback_task_id: String,
    },
    ConnectEcsExecTask {
        group_id: Uuid,
        task_id: String,
        task_label: String,
        /// Specific container to exec into. Required because under
        /// wildcard queries (empty `container` in `cloud_query`) the
        /// row knows which container the user actually clicked while
        /// the query itself doesn't pin one. Always populated from
        /// the row's `DiscoveredHost.container_name`.
        container: String,
    },
    /// Open an interactive shell in a Kubernetes pod by spawning
    /// `kubectl exec -it` in a local PTY. No provider round-trip; the
    /// dispatch builds the kubectl args from the group's profile + query.
    ConnectKubectlExecPod {
        group_id: Uuid,
        namespace: String,
        pod: String,
        /// Container to exec into, empty = the pod's default (kubectl
        /// picks the first container).
        container: String,
    },
    /// Result of `ecs:ExecuteCommand` + plugin invocation prep. On
    /// success the dispatch spawns the plugin and opens a tab; on
    /// error it's surfaced in the UI.
    EcsExecSessionReady {
        /// Group the task belongs to. Carried so the error arm can
        /// re-resolve the dynamic group's list: a failed connect on a
        /// recycled task means the cached list is stale, refreshing it
        /// surfaces the live task without a manual Refresh click.
        group_id: Uuid,
        task_label: String,
        /// Task id + container the session targets. Carried so the
        /// spawn handler can rebuild a `ConnectEcsExecTask` and stash
        /// it on the tab as its relaunch message (used by Duplicate Tab,
        /// ECS tabs have no saved `Connection` to look up by label).
        task_id: String,
        container: String,
        result: Result<Box<oryxis_cloud::SessionPayload>, String>,
    },
    /// SSM Session result, same plugin payload shape as ECS Exec, so
    /// we reuse the spawn path. Carries the host's display label so
    /// the spawned tab gets a useful title.
    SsmSessionReady {
        host_label: String,
        result: Result<Box<oryxis_cloud::SessionPayload>, String>,
    },
    DynamicGroupResolved(Uuid, Result<Vec<oryxis_cloud::DiscoveredHost>, String>),
    EditDynamicGroup(Uuid),
    HideDynamicGroupForm,
    DynamicGroupFormUsernameChanged(String),
    DynamicGroupFormInitialCommandChanged(String),
    DynamicGroupFormTransportChanged(oryxis_core::models::cloud::TransportKind),
    DynamicGroupFormKeyChanged(String),
    DynamicGroupFormIdentityChanged(String),
    SaveDynamicGroup,
    DeleteDynamicGroup(Uuid),
    /// ⋮ menu on a dynamic-group card.
    ShowDynamicGroupCardMenu(Uuid),
    DynamicGroupCardHovered(Uuid),
    DynamicGroupCardUnhovered(uuid::Uuid),
}
