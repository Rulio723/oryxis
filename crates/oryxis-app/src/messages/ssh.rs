//! SSH connect flow: connect/quick-connect, progress, banners, host-key verify, keyboard-interactive, legacy-algo fallback, OS detect, wrapped by [`crate::messages::Message::Ssh`]. Handled by `Oryxis::handle_ssh`.

use uuid::Uuid;
use crate::state::{ConnectionStep};

use super::Message;

#[derive(Debug, Clone)]
pub enum SshMessage {
    ConnectSsh(usize),
    /// Connect a saved host BY ID, for senders that outlive the list
    /// order they were built under (the progress screen's Retry, the
    /// legacy-algorithm dialog's re-dial): both fire long after their
    /// connect began, and an auto-saved rename or a sync apply can
    /// re-sort `connections` in between. Resolves to `ConnectSsh`.
    ConnectSavedHost(uuid::Uuid),
    /// Connect an ad-hoc quick-connect host (never persisted). The entry
    /// is inserted into `quick_connects` keyed by its connection id; a
    /// retry for an id already present reuses the stored entry so
    /// in-place mutations (expanded legacy algorithms) survive.
    QuickConnect(Box<crate::state::QuickConnectEntry>),
    /// Protocol badge picked on the quick-connect card (issue #174),
    /// for the case where the typed text names no `scheme://`.
    QuickConnectProtocolPicked(oryxis_core::models::connection::ConnectionProtocol),
    /// Progress step for the dial of `(pane_id)`. The pane id is part of
    /// the message so a later, unrelated connect can't capture an earlier
    /// dial's timeline on its progress card (concurrent tabs).
    SshProgress(Uuid, ConnectionStep, String),
    /// Pre-auth banner (RFC 4252 §5.4) for the connect in progress:
    /// `(pane_id, text)`; shown on the progress card (when it is tracking
    /// this pane's dial) and written to that pane's tab terminal.
    SshBanner(Uuid, String),
    /// Pre-auth banner for a split-pane connect (no progress card):
    /// written straight to that pane's terminal.
    SshPaneBanner(Uuid, String),
    /// A line a command proxy printed while the tab dial of `pane_id` is
    /// pending: shown on the progress card tracking that dial.
    SshProxyOutput(Uuid, oryxis_ssh::ProxyOutputLine),
    /// The same for a split-pane / in-place dial (no card): written into
    /// the pane as a dim marker line.
    SshPaneProxyOutput(Uuid, oryxis_ssh::ProxyOutputLine),
    SshConnected(Uuid, crate::state::TerminalTransport),  // (pane_id, transport)
    /// Opening a session on a pooled connection failed (F2 reuse), so
    /// the pane dials for real: `(pane_id)`. The tab index is
    /// recomputed on arrival (a tab closed mid-attempt shifts every
    /// later index). Never surfaced to the user; a pooled connection
    /// that turns out to be unusable is an optimisation missing, not
    /// an error.
    ReuseFailedDialFresh(Uuid),

    SshDisconnected(Uuid),  // (pane_id)
    /// A tab-connect dial failed: `(pane_id, error)`. The pane id lets the
    /// error land on the progress card that is actually tracking this dial;
    /// a failure for a dial whose card was superseded by a newer connect
    /// falls back to writing into that pane's terminal instead.
    SshError(Uuid, String),
    /// Handshake hit "no common algorithm". Prompts the legacy-fallback
    /// dialog for `conn_id` (the failed category + what the server offered).
    SshNoCommonAlgo {
        conn_id: uuid::Uuid,
        category: oryxis_ssh::NegCategory,
        server_offers: Vec<String>,
        /// Action to re-run after the user enables legacy algorithms (the
        /// originating connect: terminal / SFTP / port-forward / backup).
        retry: Box<Message>,
    },
    /// Accept the legacy fallback: enable the legacy algorithms on the
    /// pending host and reconnect. `remember` persists the change.
    LegacyAlgoAccept { remember: bool },
    LegacyAlgoCancel,
    SshHostKeyVerify(oryxis_ssh::HostKeyQuery),
    SshHostKeyReject,
    SshHostKeyContinue,
    SshHostKeyAcceptAndSave,
    /// The engine is about to spawn a command proxy and wants this
    /// device's answer. Already-approved lines are answered without a
    /// prompt; the mode decides what an unapproved one does (ask, or
    /// refuse silently on a dial nobody is watching).
    SshProxyCommandVerify(
        Box<oryxis_ssh::ProxyCommandQuery>,
        crate::state::ProxyConsentMode,
    ),
    SshProxyCommandReject,
    /// Spawn it for this dial only, remembering nothing.
    SshProxyCommandOnce,
    /// Spawn it and record the approval for this device, so the same
    /// line stops asking (`trusted_proxy_commands`).
    SshProxyCommandAlways,
    /// A keyboard-interactive challenge round arrived from the engine.
    /// The `Option<Uuid>` is the quick-connect entry id when the prompt
    /// belongs to an ad-hoc connect (it unlocks the saved identity / key
    /// selector in the modal); `None` for saved hosts.
    SshKbiPrompt(Option<Uuid>, oryxis_ssh::KbiQuery),
    /// User edited the answer for prompt `usize` in the current round.
    SshKbiInput(usize, super::Redacted),
    /// User submitted all answers for the current round.
    SshKbiSubmit,
    /// User cancelled the interactive auth.
    SshKbiCancel,
    /// User picked a saved identity / key for a quick-connect host (from
    /// the interactive-prompt modal or the failed-connect screen). Mutates
    /// the ephemeral entry and retries the connect with it.
    QuickAuthSwitch(Uuid, crate::state::QuickAuthChoice),
    SshCloseProgress,
    SshEditFromProgress,
    SshRetry,
    /// A pane's SSH connect failed; surface the error inside the pane.
    PaneConnectError(Uuid, String),
    OsDetected(Uuid, Option<String>),
}
