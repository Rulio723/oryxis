//! Adding a managed Kubernetes cluster (GKE, AKS, ACK, TKE) as a
//! Kubernetes account, straight from the discovery list.
//!
//! Every provider follows the same three steps: ask for the cluster,
//! obtain its credentials off-thread, then record the result. GKE and
//! AKS have their CLI merge `~/.kube/config` and hand back a context
//! name; ACK and TKE hand back the kubeconfig ITSELF, which is written
//! to a file of its own (`crate::kubeconfig_file`) that the account
//! then points at. They are here rather than with `import` because they
//! create a live query, not a batch of hosts.

use super::*;

impl Oryxis {
    pub(super) fn handle_discover_clusters(
        &mut self,
        message: CloudMessage,
    ) -> Result<Task<Message>, CloudMessage> {
        match message {
            CloudMessage::CloudDiscoverAddGke { cluster, location } => {
                // Add a GKE cluster: run get-credentials through the GCP
                // provider (writes the kubeconfig), then create a K8s
                // account pointed at the resulting context. Discovering
                // that account then lists its workloads.
                let Some(profile_id) = self.cloud_discover.profile_id else {
                    return Ok(Task::none());
                };
                let Some(mut profile) = self
                    .cloud_profiles
                    .iter()
                    .find(|p| p.id == profile_id)
                    .cloned()
                else {
                    return Ok(Task::none());
                };
                let registry: Arc<CloudProviderRegistry> =
                    self.cloud_provider_registry.clone();
                let Some(provider) = registry.get(&profile.provider) else {
                    return Ok(Task::none());
                };
                if let Some(vault) = &self.vault {
                    profile.secret =
                        vault.get_cloud_profile_secret(&profile_id).ok().flatten();
                }
                // Label the new K8s account after the cluster so it reads
                // clearly in the accounts list.
                let label = format!("GKE: {cluster}");
                return Ok(Task::perform(
                    async move {
                        let context = provider
                            .gke_get_credentials(&profile, &cluster, &location)
                            .await?;
                        Ok::<(String, String), oryxis_cloud::CloudError>((label, context))
                    },
                    |res| match res {
                        Ok((label, context)) => {
                            Message::Cloud(CloudMessage::CloudDiscoverGkeCredentials(label, context))
                        }
                        Err(e) => Message::Cloud(CloudMessage::CloudDiscoverGkeAdded(Err(e.to_string()))),
                    },
                ));
            }
            CloudMessage::CloudDiscoverGkeCredentials(label, context) => {
                // Credentials fetched: create + save the K8s profile
                // (auth = kubeconfig, default file, the GKE context) unless
                // one already points at this context (idempotent re-add).
                let Some(vault) = self.vault.as_ref() else {
                    return Ok(Task::none());
                };
                let exists = self.cloud_profiles.iter().any(|p| {
                    p.provider == "k8s"
                        && serde_json::from_str::<serde_json::Value>(&p.config)
                            .ok()
                            .and_then(|v| {
                                v.get("context").and_then(|c| c.as_str()).map(str::to_string)
                            })
                            .as_deref()
                            == Some(context.as_str())
                });
                if !exists {
                    let mut profile = oryxis_core::models::CloudProfile::new(label, "k8s");
                    profile.auth_kind = "kubeconfig".to_string();
                    profile.config =
                        serde_json::json!({ "context": context }).to_string();
                    if let Err(e) = vault.save_cloud_profile(&profile, None) {
                        return Ok(self.show_toast(format!(
                            "{}: {e}",
                            crate::i18n::t("cloud_gke_add_failed")
                        )));
                    }
                    self.load_data_from_vault();
                }
                return Ok(self.show_toast(crate::i18n::t("cloud_gke_added").to_string()));
            }
            CloudMessage::CloudDiscoverGkeAdded(result) => {
                if let Err(e) = result {
                    return Ok(self.show_toast(format!(
                        "{}: {e}",
                        crate::i18n::t("cloud_gke_add_failed")
                    )));
                }
            }
            CloudMessage::CloudDiscoverAddAks {
                cluster,
                resource_group,
            } => {
                // Add an AKS cluster: run get-credentials through the Azure
                // provider (writes the kubeconfig), then create a K8s
                // account pointed at the resulting context. Discovering
                // that account then lists its workloads. Mirrors the GKE
                // path; AKS keys credentials by resource group, not region.
                //
                // Dup-guard before the fetch: a k8s account may already
                // point at this cluster, either under the composite
                // `<cluster>-<resource_group>` context this build mints
                // (mirrors `oryxis-cloud-azure::aks::context_name`) or
                // under the bare cluster name older builds stored (az's
                // default context name). Bail with the "added" toast
                // instead of minting a duplicate; the bare form cannot be
                // checked post-fetch (the returned context is composite),
                // so it must be recognized here.
                // Must match `aks::context_name` in the azure plugin (the
                // source of truth; the plugin boundary keeps us from
                // importing it). `.` separator, not `-`: a cluster name
                // can't contain a dot, so `cluster.rg` never collides the
                // way `cluster-rg` did across hyphenated resource groups.
                let composite = format!("{cluster}.{resource_group}");
                let already = self.cloud_profiles.iter().any(|p| {
                    p.provider == "k8s"
                        && serde_json::from_str::<serde_json::Value>(&p.config)
                            .ok()
                            .and_then(|v| {
                                v.get("context").and_then(|c| c.as_str()).map(str::to_string)
                            })
                            .is_some_and(|c| c == composite || c == cluster)
                });
                if already {
                    return Ok(self.show_toast(crate::i18n::t("cloud_aks_added").to_string()));
                }
                let Some(profile_id) = self.cloud_discover.profile_id else {
                    return Ok(Task::none());
                };
                let Some(mut profile) = self
                    .cloud_profiles
                    .iter()
                    .find(|p| p.id == profile_id)
                    .cloned()
                else {
                    return Ok(Task::none());
                };
                let registry: Arc<CloudProviderRegistry> = self.cloud_provider_registry.clone();
                let Some(provider) = registry.get(&profile.provider) else {
                    return Ok(Task::none());
                };
                if let Some(vault) = &self.vault {
                    profile.secret = vault.get_cloud_profile_secret(&profile_id).ok().flatten();
                }
                // Label the new K8s account after the cluster so it reads
                // clearly in the accounts list.
                let label = format!("AKS: {cluster}");
                return Ok(Task::perform(
                    async move {
                        let context = provider
                            .aks_get_credentials(&profile, &cluster, &resource_group)
                            .await?;
                        Ok::<(String, String), oryxis_cloud::CloudError>((label, context))
                    },
                    |res| match res {
                        Ok((label, context)) => Message::Cloud(CloudMessage::CloudDiscoverAksCredentials(label, context)),
                        Err(e) => Message::Cloud(CloudMessage::CloudDiscoverAksAdded(Err(e.to_string()))),
                    },
                ));
            }
            CloudMessage::CloudDiscoverAksCredentials(label, context) => {
                // Credentials fetched: create + save the K8s profile
                // (auth = kubeconfig, default file, the AKS context) unless
                // one already points at this context (idempotent re-add).
                let Some(vault) = self.vault.as_ref() else {
                    return Ok(Task::none());
                };
                let exists = self.cloud_profiles.iter().any(|p| {
                    p.provider == "k8s"
                        && serde_json::from_str::<serde_json::Value>(&p.config)
                            .ok()
                            .and_then(|v| {
                                v.get("context").and_then(|c| c.as_str()).map(str::to_string)
                            })
                            .as_deref()
                            == Some(context.as_str())
                });
                if !exists {
                    let mut profile = oryxis_core::models::CloudProfile::new(label, "k8s");
                    profile.auth_kind = "kubeconfig".to_string();
                    profile.config = serde_json::json!({ "context": context }).to_string();
                    if let Err(e) = vault.save_cloud_profile(&profile, None) {
                        return Ok(self.show_toast(format!(
                            "{}: {e}",
                            crate::i18n::t("cloud_aks_add_failed")
                        )));
                    }
                    self.load_data_from_vault();
                }
                return Ok(self.show_toast(crate::i18n::t("cloud_aks_added").to_string()));
            }
            CloudMessage::CloudDiscoverAksAdded(result) => {
                if let Err(e) = result {
                    return Ok(self.show_toast(format!(
                        "{}: {e}",
                        crate::i18n::t("cloud_aks_add_failed")
                    )));
                }
            }
            CloudMessage::CloudDiscoverAddManagedCluster { family, id, name } => {
                // Add (or refresh) an ACK / TKE cluster: the provider
                // returns the kubeconfig YAML, which is written to the
                // cluster's own 0600 file inside the async task (the YAML
                // is a credential and `Message` derives `Debug`, so it
                // never rides a message), and the completion carries
                // only the path and what the view needs to know about
                // it. The path is deterministic per (cluster, cloud
                // account), so a second Add on the same pair overwrites
                // the file: that is the refresh an expiring ACK
                // credential needs.
                let Some(profile_id) = self.cloud_discover.profile_id else {
                    return Ok(Task::none());
                };
                let path = match crate::kubeconfig_file::path_for(&family, profile_id, &id) {
                    Ok(p) => p,
                    Err(e) => {
                        return Ok(self.show_toast(format!(
                            "{}: {e}",
                            crate::i18n::t("cloud_managed_cluster_add_failed")
                        )));
                    }
                };
                // One fetch per file at a time: the button is disabled
                // while this runs, and a keyboard activation or a double
                // click that got through anyway lands here.
                if self.cloud_discover.managed_in_flight.contains(&path) {
                    return Ok(Task::none());
                }
                let Some(mut profile) = self
                    .cloud_profiles
                    .iter()
                    .find(|p| p.id == profile_id)
                    .cloned()
                else {
                    return Ok(Task::none());
                };
                let registry: Arc<CloudProviderRegistry> = self.cloud_provider_registry.clone();
                let Some(provider) = registry.get(&profile.provider) else {
                    return Ok(Task::none());
                };
                if let Some(vault) = &self.vault {
                    profile.secret = vault.get_cloud_profile_secret(&profile_id).ok().flatten();
                }
                self.cloud_discover.managed_in_flight.insert(path.clone());
                // Label the new K8s account after the cluster so it reads
                // clearly in the accounts list: `ACK: prod`, `TKE: dev`.
                let label = format!("{}: {name}", family.to_uppercase());
                let path_str = path.to_string_lossy().into_owned();
                let failed_path = path_str.clone();
                return Ok(Task::perform(
                    async move {
                        let yaml = provider
                            .cluster_kubeconfig(&profile, &id)
                            .await
                            .map_err(|e| e.to_string())?;
                        let context =
                            crate::kubeconfig_file::current_context(&yaml).unwrap_or_default();
                        let intranet = crate::kubeconfig_file::servers_are_private(&yaml);
                        crate::kubeconfig_file::write_secret_file(&path, &yaml)
                            .map_err(|e| format!("writing {}: {e}", path.display()))?;
                        Ok::<_, String>((label, context, intranet))
                    },
                    move |res| match res {
                        Ok((label, context, intranet)) => {
                            Message::Cloud(CloudMessage::CloudDiscoverManagedClusterStored {
                                label,
                                path: path_str.clone(),
                                context,
                                intranet,
                            })
                        }
                        Err(error) => Message::Cloud(CloudMessage::CloudDiscoverManagedClusterFailed {
                            path: failed_path.clone(),
                            error,
                        }),
                    },
                ));
            }
            CloudMessage::CloudDiscoverManagedClusterStored {
                label,
                path,
                context,
                intranet,
            } => {
                self.cloud_discover
                    .managed_in_flight
                    .remove(std::path::Path::new(&path));
                let points_at = |p: &oryxis_core::models::CloudProfile, file: &str| {
                    p.provider == "k8s"
                        && serde_json::from_str::<serde_json::Value>(&p.config)
                            .ok()
                            .and_then(|v| v.get("kubeconfig")?.as_str().map(str::to_string))
                            .as_deref()
                            == Some(file)
                };
                // The file is in place: create the K8s account pointed at
                // it (auth = kubeconfig, that file, its context) unless one
                // already does, in which case the overwrite WAS the whole
                // operation (a refresh) and nothing is minted twice. Only
                // THIS cloud account's file counts: the path carries the
                // account id, so another account that sees the same
                // cluster (a different RAM user, a different RBAC) never
                // has its Kubernetes account repointed at our credential.
                let existing = self
                    .cloud_profiles
                    .iter()
                    .find(|p| points_at(p, &path))
                    .cloned();
                let Some(vault) = self.vault.as_ref().filter(|v| !v.is_locked()) else {
                    // The vault locked while the fetch ran. An account
                    // already on this file still works with the fresh
                    // credential; a file nothing points at would be a
                    // credential no list shows, so it goes.
                    if existing.is_some() {
                        return Ok(self.show_toast(
                            crate::i18n::t("cloud_managed_cluster_refreshed").to_string(),
                        ));
                    }
                    let _ = std::fs::remove_file(&path);
                    return Ok(self.show_toast(format!(
                        "{}: {}",
                        crate::i18n::t("cloud_managed_cluster_add_failed"),
                        crate::i18n::t("cloud_managed_cluster_vault_locked")
                    )));
                };
                let mut toast = if let Some(existing) = existing {
                    // A refresh: the file is new, so the context it names
                    // is re-read too rather than assumed stable across
                    // fetches. Same account; only the config changes, and
                    // only when the context it names moved.
                    if let Ok(mut cfg) = serde_json::from_str::<serde_json::Value>(&existing.config)
                    {
                        let context_moved = !context.is_empty()
                            && cfg.get("context").and_then(|c| c.as_str()) != Some(context.as_str());
                        if context_moved {
                            let mut refreshed = existing.clone();
                            cfg["context"] = serde_json::Value::String(context);
                            refreshed.config = cfg.to_string();
                            if let Err(e) = vault.save_cloud_profile(&refreshed, None) {
                                return Ok(self.show_toast(format!(
                                    "{}: {e}",
                                    crate::i18n::t("cloud_managed_cluster_add_failed")
                                )));
                            }
                            self.load_data_from_vault();
                        }
                    }
                    crate::i18n::t("cloud_managed_cluster_refreshed").to_string()
                } else {
                    let mut profile = oryxis_core::models::CloudProfile::new(label, "k8s");
                    profile.auth_kind = "kubeconfig".to_string();
                    let mut cfg = serde_json::json!({ "kubeconfig": path });
                    if !context.is_empty() {
                        cfg["context"] = serde_json::Value::String(context);
                    }
                    profile.config = cfg.to_string();
                    if let Err(e) = vault.save_cloud_profile(&profile, None) {
                        // No account will point at the file: drop it
                        // rather than leave a credential nothing lists.
                        let _ = std::fs::remove_file(&path);
                        return Ok(self.show_toast(format!(
                            "{}: {e}",
                            crate::i18n::t("cloud_managed_cluster_add_failed")
                        )));
                    }
                    self.load_data_from_vault();
                    crate::i18n::t("cloud_managed_cluster_added").to_string()
                };
                // Where the file points is the one thing the user cannot
                // see from the list and the first thing a failing kubectl
                // needs to know.
                toast.push(' ');
                toast.push_str(if intranet {
                    crate::i18n::t("cloud_managed_cluster_intranet_note")
                } else {
                    crate::i18n::t("cloud_managed_cluster_endpoint_note")
                });
                return Ok(self.show_toast_secs(toast, 8));
            }
            CloudMessage::CloudDiscoverManagedClusterFailed { path, error } => {
                self.cloud_discover
                    .managed_in_flight
                    .remove(std::path::Path::new(&path));
                return Ok(self.show_toast(format!(
                    "{}: {error}",
                    crate::i18n::t("cloud_managed_cluster_add_failed")
                )));
            }
            // The parent routed us here, so a message that is not
            // in this family is a grouping mistake. Hand it back
            // rather than swallow it.
            m => return Err(m),
        }
        Ok(Task::none())
    }
}

impl Oryxis {
    /// Remove managed kubeconfig files (`~/.oryxis/kubeconfig/`) that no
    /// Kubernetes account points at any more. The UI delete removes its
    /// own file (`DeleteCloudProfile`), but an account deleted on ANOTHER
    /// device arrives as a sync tombstone, which runs no UI arm, and
    /// would leave a cluster credential on disk that no list shows.
    ///
    /// The account list is read from the vault here, never from
    /// `self.cloud_profiles` (which `load_vault_entities` fills with an
    /// empty default when the read fails), and a failed read or a locked
    /// vault sweeps nothing: an empty list would read as "nothing is
    /// referenced" and take every file with it. Files whose fetch is in
    /// flight are spared, since their account does not exist yet.
    pub(crate) fn sweep_orphan_kubeconfigs(&self) {
        let Some(vault) = self.vault.as_ref().filter(|v| !v.is_locked()) else {
            return;
        };
        let Ok(profiles) = vault.list_cloud_profiles() else {
            return;
        };
        let Some(dir) = crate::kubeconfig_file::dir() else {
            return;
        };
        let referenced = crate::kubeconfig_file::referenced_paths(&profiles);
        for path in crate::kubeconfig_file::sweep_unreferenced(
            &dir,
            &referenced,
            &self.cloud_discover.managed_in_flight,
        ) {
            tracing::info!(
                "removed kubeconfig {} (no Kubernetes account points at it)",
                path.display()
            );
        }
    }
}
