//! `Oryxis::handle_cloud_discovery`, the discovery half of the cloud
//! domain, routed by what the user is doing.
//!
//! Was a 777-line match that had grown well past the sub-handler it
//! started as. The groups are the panel and its lifecycle (`panel`),
//! the choices made inside it (`selection`), the two managed-Kubernetes
//! add flows (`clusters`), the import batch (`import`), and the
//! background refresh that never opens a panel at all (`profile_sync`).
//!
//! Note this router is a FILTER, not a total function: `CloudMessage` is
//! wider than the discovery half, so the tail hands the rest back to
//! `handle_cloud`. Unlike the exhaustive routers elsewhere, a new
//! discovery variant that nobody lists here compiles fine and falls
//! through silently, so add the pattern with the arm.

// Dispatch sub-handlers, one file per arm family.
mod panel;
mod selection;
mod clusters;
mod profile_sync;
mod import;

use std::sync::Arc;

use iced::Task;
use oryxis_cloud::CloudProviderRegistry;
use oryxis_core::models::cloud::{
    CloudQuery, CloudQueryKind, CloudRef, CloudResourceType, ConnectionTemplate, TransportKind,
};
use oryxis_core::models::connection::Connection;
use oryxis_core::models::group::Group;

use crate::app::{CloudMessage, Message, Oryxis};
use crate::state::CloudDiscoverState;

impl Oryxis {
    pub(super) fn handle_cloud_discovery(
        &mut self,
        message: CloudMessage,
    ) -> Result<Task<Message>, CloudMessage> {
        match message {
            m @ (
                CloudMessage::ShowCloudDiscover(..)
                | CloudMessage::HideCloudDiscover
                | CloudMessage::CloudDiscoverRefresh
                | CloudMessage::CloudDiscoverResult(..)
            ) => self.handle_discover_panel(m),
            m @ (
                CloudMessage::CloudDiscoverToggleEc2(..)
                | CloudMessage::CloudDiscoverToggleEcs(..)
                | CloudMessage::CloudDiscoverToggleK8s(..)
                | CloudMessage::CloudDiscoverFilterChanged(..)
                | CloudMessage::CloudDiscoverToggleSection(..)
                | CloudMessage::CloudDiscoverDefaultTransportChanged(..)
                | CloudMessage::CloudDiscoverDefaultGroupNameChanged(..)
                | CloudMessage::CloudDiscoverDefaultGroupPick(..)
                | CloudMessage::ToggleCloudDiscoverGroupPicker
                | CloudMessage::CloudDiscoverDefaultGroupPickerSearchChanged(..)
            ) => self.handle_discover_selection(m),
            m @ (
                CloudMessage::CloudDiscoverAddGke { .. }
                | CloudMessage::CloudDiscoverGkeCredentials(..)
                | CloudMessage::CloudDiscoverGkeAdded(..)
                | CloudMessage::CloudDiscoverAddAks { .. }
                | CloudMessage::CloudDiscoverAksCredentials(..)
                | CloudMessage::CloudDiscoverAksAdded(..)
                | CloudMessage::CloudDiscoverAddManagedCluster { .. }
                | CloudMessage::CloudDiscoverManagedClusterStored { .. }
                | CloudMessage::CloudDiscoverManagedClusterFailed { .. }
            ) => self.handle_discover_clusters(m),
            m @ (
                CloudMessage::CloudAutoRefreshTick
                | CloudMessage::CloudProfileSync(..)
                | CloudMessage::CloudProfileSyncResult(..)
            ) => self.handle_discover_profile_sync(m),
            m @ (
                CloudMessage::CloudDiscoverImport
                | CloudMessage::CloudDiscoverImportCancelled
                | CloudMessage::CloudDiscoverImportConfirmed
            ) => self.handle_discover_import(m),
            m => Err(m),
        }
    }
}
