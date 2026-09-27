use super::*;

#[test]
fn export_import_roundtrip() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter};

    let vault = unlocked_vault();

    // Populate vault
    let conn = Connection::new("prod-web", "192.168.1.10");
    vault.save_connection(&conn, Some("secret123")).unwrap();

    let g = Group::new("Production");
    vault.save_group(&g).unwrap();

    let s = Snippet::new("deploy", "make deploy");
    vault.save_snippet(&s).unwrap();

    let kh = KnownHost::new("192.168.1.10", 22, "ed25519", "SHA256:abc");
    vault.save_known_host(&kh).unwrap();

    let mut pf = oryxis_core::models::port_forward_rule::PortForwardRule::new(
        "db tunnel",
        oryxis_core::models::port_forward_rule::ForwardKind::Local,
        conn.id,
    );
    pf.listen_port = 5432;
    pf.target_host = "10.0.0.5".into();
    pf.target_port = 5432;
    vault.save_port_forward_rule(&pf).unwrap();

    // Export
    let export_pw = "export-password";
    let data = export_vault(&vault, export_pw, ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: crate::portable::ExportSelection::all() }).unwrap();

    // Verify header
    assert_eq!(&data[..6], b"ORYXIS");

    // Import into fresh vault
    let vault2 = unlocked_vault();
    let result = import_vault(&vault2, &data, export_pw, &crate::portable::ExportSelection::all(), None).unwrap();

    assert_eq!(result.connections_added, 1);
    assert_eq!(result.groups_added, 1);
    assert_eq!(result.snippets_added, 1);
    assert_eq!(result.known_hosts_added, 1);
    assert_eq!(result.port_forward_rules_added, 1);

    // Verify data
    let conns = vault2.list_connections().unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].label, "prod-web");

    let pw = vault2.get_connection_password(&conns[0].id).unwrap();
    assert_eq!(pw, Some("secret123".into()));

    assert_eq!(vault2.list_groups().unwrap().len(), 1);
    assert_eq!(vault2.list_snippets().unwrap().len(), 1);
    assert_eq!(vault2.list_known_hosts().unwrap().len(), 1);
    let rules = vault2.list_port_forward_rules().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].listen_port, 5432);
    assert_eq!(rules[0].target_host, "10.0.0.5");
}


/// A Telnet host and a Serial host (with non-default line params) must
/// survive export → import intact: the `protocol` field and the whole
/// `serial` struct ride the portable payload via the model flatten.
#[test]
fn export_import_protocol_and_serial_round_trip() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions};
    use oryxis_core::models::connection::ConnectionProtocol;
    use oryxis_core::models::serial::{
        SerialFlowControl, SerialLineEnding, SerialParams, SerialParity, SerialStopBits,
    };

    let vault = unlocked_vault();
    let mut telnet = Connection::new("router", "192.168.0.1");
    telnet.protocol = ConnectionProtocol::Telnet;
    telnet.port = 23;
    vault.save_connection(&telnet, None).unwrap();

    let params = SerialParams {
        baud: 115200,
        data_bits: 7,
        parity: SerialParity::Even,
        stop_bits: SerialStopBits::Two,
        flow_control: SerialFlowControl::Hardware,
        local_echo: true,
        line_ending: SerialLineEnding::CrLf,
    };
    let mut serial = Connection::new("uart", "/dev/ttyUSB0");
    serial.protocol = ConnectionProtocol::Serial;
    serial.serial = Some(params);
    vault.save_connection(&serial, None).unwrap();

    // Remote-desktop host rides the same flatten (kind + gateway).
    let gateway_id = uuid::Uuid::new_v4();
    let mut desktop = Connection::new("desk", "10.0.0.9");
    desktop.protocol = ConnectionProtocol::RemoteDesktop;
    desktop.port = 5901;
    desktop.rd_kind = oryxis_core::models::remote_desktop::RemoteDesktopKind::Vnc;
    desktop.rd_gateway_id = Some(gateway_id);
    vault.save_connection(&desktop, None).unwrap();

    let data = export_vault(
        &vault,
        "export-pw",
        ExportOptions {
            include_private_keys: false,
            filter: ExportFilter::All,
            selection: crate::portable::ExportSelection::all(),
        },
    )
    .unwrap();

    let vault2 = unlocked_vault();
    import_vault(&vault2, &data, "export-pw", &crate::portable::ExportSelection::all(), None).unwrap();

    let conns = vault2.list_connections().unwrap();
    let t = conns.iter().find(|c| c.label == "router").expect("telnet host");
    assert_eq!(t.protocol, ConnectionProtocol::Telnet);
    let s = conns.iter().find(|c| c.label == "uart").expect("serial host");
    assert_eq!(s.protocol, ConnectionProtocol::Serial);
    assert_eq!(s.serial, Some(params));
    let d = conns.iter().find(|c| c.label == "desk").expect("desktop host");
    assert_eq!(d.protocol, ConnectionProtocol::RemoteDesktop);
    assert_eq!(d.rd_kind, oryxis_core::models::remote_desktop::RemoteDesktopKind::Vnc);
    assert_eq!(d.rd_gateway_id, Some(gateway_id));
}

/// mosh options must survive export → import, and a host that never
/// asked for mosh must come back without any.
///
/// Both halves matter and they fail in opposite directions. Options
/// that did not travel turn a roaming host into a plain SSH one on the
/// machine that imported it, silently, and the person there never chose
/// that. Options invented for a host that had none would carry an
/// enabled flag nobody set, and the flag is what puts a command on a
/// remote shell.
///
/// It rides the model flatten, the same way `serial` and the
/// remote-desktop fields above do, which is exactly why it is asked
/// rather than assumed: a flatten carries what it is given, and nothing
/// in `portable.rs` names this field for a reader to notice it missing.
#[test]
fn export_import_mosh_round_trip() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions};
    use oryxis_core::models::mosh::MoshOptions;

    let vault = unlocked_vault();
    let options = MoshOptions {
        enabled: true,
        server_path: "/opt/mosh/bin/mosh-server".into(),
        port_range: "60000:60010".into(),
        command: "tmux new -A -s main".into(),
    };
    let mut roamer = Connection::new("roamer", "10.0.0.7");
    roamer.mosh = Some(options.clone());
    vault.save_connection(&roamer, None).unwrap();

    // Filled in and then switched off: the settings are kept so turning
    // it back on does not mean typing the path again, and an export that
    // dropped them would quietly undo that.
    let mut parked = Connection::new("parked", "10.0.0.8");
    parked.mosh = Some(MoshOptions {
        enabled: false,
        server_path: "/usr/local/bin/mosh-server".into(),
        ..Default::default()
    });
    vault.save_connection(&parked, None).unwrap();

    let plain = Connection::new("plain", "10.0.0.9");
    vault.save_connection(&plain, None).unwrap();

    let data = export_vault(
        &vault,
        "export-pw",
        ExportOptions {
            include_private_keys: false,
            filter: ExportFilter::All,
            selection: crate::portable::ExportSelection::all(),
        },
    )
    .unwrap();

    let vault2 = unlocked_vault();
    import_vault(&vault2, &data, "export-pw", &crate::portable::ExportSelection::all(), None).unwrap();

    let conns = vault2.list_connections().unwrap();
    let of = |label: &str| {
        conns
            .iter()
            .find(|c| c.label == label)
            .unwrap_or_else(|| panic!("{label} did not survive the import"))
            .mosh
            .clone()
    };
    assert_eq!(of("roamer"), Some(options), "the whole option travelled or none of it did");
    let parked = of("parked").expect("settings outlive being switched off");
    assert!(!parked.enabled);
    assert_eq!(parked.server_path, "/usr/local/bin/mosh-server");
    assert_eq!(of("plain"), None, "an untouched host is not a mosh host");
}

/// Round-trip a connection that uses both an inline proxy (with
/// password in its own encrypted column) and a saved proxy
/// identity (with its own password). Both passwords + the
/// identity reference must survive export → import.
#[test]
fn export_import_proxy_round_trip() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions};
    use oryxis_core::models::connection::{ProxyConfig, ProxyType};

    let vault = unlocked_vault();

    // Saved proxy identity (with password)
    let mut pi = ProxyIdentity::new("corp-bastion");
    pi.proxy_type = ProxyType::Http;
    pi.host = "proxy.corp.local".into();
    pi.port = 8080;
    pi.username = Some("alice".into());
    vault.save_proxy_identity(&pi, Some("ident-pw")).unwrap();

    // Connection 1: links to the saved identity
    let mut conn_id = Connection::new("via-identity", "10.0.0.1");
    conn_id.proxy_identity_id = Some(pi.id);
    vault.save_connection(&conn_id, None).unwrap();

    // Connection 2: inline proxy with its own password
    let mut conn_inline = Connection::new("via-inline", "10.0.0.2");
    conn_inline.proxy = Some(ProxyConfig {
        proxy_type: ProxyType::Socks5,
        host: "inline.proxy".into(),
        port: 1080,
        username: Some("bob".into()),
        password: None,
    });
    vault.save_connection(&conn_inline, None).unwrap();
    vault
        .set_proxy_password(&conn_inline.id, Some("inline-pw"))
        .unwrap();

    // Export everything
    let data = export_vault(
        &vault,
        "export-pw",
        ExportOptions {
            include_private_keys: false,
            filter: ExportFilter::All,
            selection: crate::portable::ExportSelection::all(),
        },
    )
    .unwrap();

    // Import into a fresh vault
    let vault2 = unlocked_vault();
    let result = import_vault(&vault2, &data, "export-pw", &crate::portable::ExportSelection::all(), None).unwrap();
    assert_eq!(result.connections_added, 2);
    assert_eq!(result.proxy_identities_added, 1);

    // Saved identity round-tripped, including its password.
    let pi_round = vault2.list_proxy_identities().unwrap();
    assert_eq!(pi_round.len(), 1);
    assert_eq!(pi_round[0].host, "proxy.corp.local");
    assert_eq!(
        vault2
            .get_proxy_identity_password(&pi_round[0].id)
            .unwrap()
            .as_deref(),
        Some("ident-pw"),
    );

    // The identity-linked connection still references the same id.
    let conns = vault2.list_connections().unwrap();
    let by_label = |l: &str| conns.iter().find(|c| c.label == l).unwrap();
    assert_eq!(by_label("via-identity").proxy_identity_id, Some(pi.id));

    // The inline proxy survived with its password in the encrypted
    // column (NOT inside the proxy JSON).
    let inline_conn = by_label("via-inline");
    assert_eq!(inline_conn.proxy_identity_id, None);
    assert_eq!(
        inline_conn.proxy.as_ref().map(|p| p.host.clone()),
        Some("inline.proxy".into()),
    );
    assert_eq!(
        vault2
            .get_proxy_password(&inline_conn.id)
            .unwrap()
            .as_deref(),
        Some("inline-pw"),
    );
}


#[test]
fn export_wrong_password_fails() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter};

    let vault = unlocked_vault();
    let conn = Connection::new("test", "10.0.0.1");
    vault.save_connection(&conn, None).unwrap();

    let data = export_vault(&vault, "correct", ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: crate::portable::ExportSelection::all() }).unwrap();
    let result = import_vault(&vault, &data, "wrong", &crate::portable::ExportSelection::all(), None);
    assert!(result.is_err());
}


#[test]
fn export_invalid_file_rejected() {
    use crate::portable::{import_vault, is_valid_export};

    let vault = unlocked_vault();
    assert!(!is_valid_export(b"not an oryxis file"));
    assert!(import_vault(&vault, b"not an oryxis file", "pw", &crate::portable::ExportSelection::all(), None).is_err());
}


#[test]
fn import_skip_existing() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter};

    let vault = unlocked_vault();
    let conn = Connection::new("server", "10.0.0.1");
    vault.save_connection(&conn, Some("pw1")).unwrap();

    let data = export_vault(&vault, "pass", ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: crate::portable::ExportSelection::all() }).unwrap();

    // Import again into same vault, should skip
    let result = import_vault(&vault, &data, "pass", &crate::portable::ExportSelection::all(), None).unwrap();
    assert_eq!(result.connections_skipped, 1);
    assert_eq!(result.connections_added, 0);

    // Still only 1 connection
    assert_eq!(vault.list_connections().unwrap().len(), 1);
}


#[test]
fn import_updates_newer() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter};

    let vault1 = unlocked_vault();
    let mut conn = Connection::new("server", "10.0.0.1");
    conn.updated_at = chrono::Utc::now();
    vault1.save_connection(&conn, Some("old_pw")).unwrap();

    // Export
    let data = export_vault(&vault1, "pass", ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: crate::portable::ExportSelection::all() }).unwrap();

    // Create vault2 with same connection but older timestamp
    let vault2 = unlocked_vault();
    let mut old_conn = conn.clone();
    old_conn.updated_at = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z").unwrap().with_timezone(&chrono::Utc);
    vault2.save_connection(&old_conn, Some("old_pw")).unwrap();

    // Import, should update because export is newer
    let result = import_vault(&vault2, &data, "pass", &crate::portable::ExportSelection::all(), None).unwrap();
    assert_eq!(result.connections_updated, 1);
    assert_eq!(result.connections_added, 0);
}


#[test]
fn export_with_keys() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter, export_includes_keys};

    let vault = unlocked_vault();

    // Generate a key
    let generated = crate::keygen::generate_ed25519("test-key").unwrap();
    vault.save_key(&generated.key, Some(&generated.private_pem)).unwrap();

    // Export WITH keys
    let data_with = export_vault(&vault, "pass", ExportOptions { include_private_keys: true, filter: ExportFilter::All, selection: crate::portable::ExportSelection::all() }).unwrap();
    assert!(export_includes_keys(&data_with));

    // Export WITHOUT keys
    let data_without = export_vault(&vault, "pass", ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: crate::portable::ExportSelection::all() }).unwrap();
    assert!(!export_includes_keys(&data_without));

    // Import with keys into fresh vault
    let vault2 = unlocked_vault();
    let result = import_vault(&vault2, &data_with, "pass", &crate::portable::ExportSelection::all(), None).unwrap();
    assert_eq!(result.keys_added, 1);

    let pk = vault2.get_key_private(&generated.key.id).unwrap();
    assert!(pk.is_some());

    // Import without keys, key added but no private key
    let vault3 = unlocked_vault();
    let result = import_vault(&vault3, &data_without, "pass", &crate::portable::ExportSelection::all(), None).unwrap();
    assert_eq!(result.keys_added, 1);

    let pk = vault3.get_key_private(&generated.key.id).unwrap();
    assert!(pk.is_none());
}

// ── Sync Peers CRUD ──


#[test]
fn share_single_host() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter};

    let vault = unlocked_vault();

    let c1 = Connection::new("shared-host", "10.0.0.1");
    vault.save_connection(&c1, Some("pw1")).unwrap();
    let c2 = Connection::new("private-host", "10.0.0.2");
    vault.save_connection(&c2, Some("pw2")).unwrap();

    // Share only c1
    let data = export_vault(&vault, "share-pass", ExportOptions {
        include_private_keys: false,
        filter: ExportFilter::Hosts(vec![c1.id]),
        selection: crate::portable::ExportSelection::all(),
    }).unwrap();

    let vault2 = unlocked_vault();
    let result = import_vault(&vault2, &data, "share-pass", &crate::portable::ExportSelection::all(), None).unwrap();

    assert_eq!(result.connections_added, 1);
    let conns = vault2.list_connections().unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].label, "shared-host");
}


#[test]
fn share_group() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter};

    let vault = unlocked_vault();

    let g = Group::new("Team");
    vault.save_group(&g).unwrap();

    let mut c1 = Connection::new("web", "10.0.0.1");
    c1.group_id = Some(g.id);
    vault.save_connection(&c1, None).unwrap();

    let mut c2 = Connection::new("db", "10.0.0.2");
    c2.group_id = Some(g.id);
    vault.save_connection(&c2, None).unwrap();

    let c3 = Connection::new("personal", "10.0.0.3");
    vault.save_connection(&c3, None).unwrap();

    // Share group
    let data = export_vault(&vault, "pass", ExportOptions {
        include_private_keys: false,
        filter: ExportFilter::Group(g.id),
        selection: crate::portable::ExportSelection::all(),
    }).unwrap();

    let vault2 = unlocked_vault();
    let result = import_vault(&vault2, &data, "pass", &crate::portable::ExportSelection::all(), None).unwrap();

    assert_eq!(result.connections_added, 2);
    assert_eq!(result.groups_added, 1);
    let conns = vault2.list_connections().unwrap();
    assert_eq!(conns.len(), 2);
}


#[test]
fn share_includes_dependencies() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter};
    use oryxis_core::models::identity::Identity;

    let vault = unlocked_vault();

    // Create key
    let generated = crate::keygen::generate_ed25519("shared-key").unwrap();
    vault.save_key(&generated.key, Some(&generated.private_pem)).unwrap();

    // Create identity
    let mut ident = Identity::new("shared-ident");
    ident.key_id = Some(generated.key.id);
    vault.save_identity(&ident, Some("ident-pw")).unwrap();

    // Create group
    let g = Group::new("Shared");
    vault.save_group(&g).unwrap();

    // Create connection referencing all deps
    let mut conn = Connection::new("server", "10.0.0.1");
    conn.key_id = Some(generated.key.id);
    conn.identity_id = Some(ident.id);
    conn.group_id = Some(g.id);
    vault.save_connection(&conn, Some("conn-pw")).unwrap();

    // Create unrelated data
    let unrelated = Connection::new("other", "10.0.0.2");
    vault.save_connection(&unrelated, None).unwrap();
    let unrelated_key = SshKey::new("other-key", KeyAlgorithm::Ed25519);
    vault.save_key(&unrelated_key, None).unwrap();

    // Share only the one connection
    let data = export_vault(&vault, "pass", ExportOptions {
        include_private_keys: true,
        filter: ExportFilter::Hosts(vec![conn.id]),
        selection: crate::portable::ExportSelection::all(),
    }).unwrap();

    let vault2 = unlocked_vault();
    let result = import_vault(&vault2, &data, "pass", &crate::portable::ExportSelection::all(), None).unwrap();

    // Should have 1 connection, 1 key, 1 identity, 1 group
    assert_eq!(result.connections_added, 1);
    assert_eq!(result.keys_added, 1);
    assert_eq!(result.identities_added, 1);
    assert_eq!(result.groups_added, 1);

    // Should NOT have unrelated data
    assert_eq!(vault2.list_connections().unwrap().len(), 1);
    assert_eq!(vault2.list_keys().unwrap().len(), 1);

    // Password should be preserved
    let pw = vault2.get_connection_password(&conn.id).unwrap();
    assert_eq!(pw, Some("conn-pw".into()));
}


#[test]
fn share_no_snippets_or_known_hosts() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter};

    let vault = unlocked_vault();

    let conn = Connection::new("host", "10.0.0.1");
    vault.save_connection(&conn, None).unwrap();

    let s = Snippet::new("test", "echo hi");
    vault.save_snippet(&s).unwrap();

    let kh = KnownHost::new("10.0.0.1", 22, "ed25519", "SHA256:abc");
    vault.save_known_host(&kh).unwrap();

    // Share only the connection
    let data = export_vault(&vault, "pass", ExportOptions {
        include_private_keys: false,
        filter: ExportFilter::Hosts(vec![conn.id]),
        selection: crate::portable::ExportSelection::all(),
    }).unwrap();

    let vault2 = unlocked_vault();
    let result = import_vault(&vault2, &data, "pass", &crate::portable::ExportSelection::all(), None).unwrap();

    assert_eq!(result.connections_added, 1);
    assert_eq!(result.snippets_added, 0);
    assert_eq!(result.known_hosts_added, 0);
}

// ── Settings (key/value) ─────────────────────────────────────
// Backs the app's user-preference persistence. Worth pinning
// explicitly since the UI relies on round-trip identity for
// anything stored as a string (timeouts, keepalive, parallelism,
// booleans-as-strings, etc.).

/// The denylist is the only thing standing between a portable export
/// and leaking device identity / lock state / plaintext tokens. Pin it
/// so a future setting can't silently start riding along.
#[test]
fn settings_denylist_blocks_device_local_keys() {
    use crate::portable::is_portable_setting;

    // Device identity, per-vault lock flag, device name + port,
    // plaintext bearer tokens, service-activation toggles, per-install
    // state, one-time hints, one-shot migration / boot markers.
    for denied in [
        "sync_device_identity",
        "has_user_password",
        "sync_device_name",
        "sync_listen_port",
        "sync_signaling_token",
        "mcp_server_token",
        "sync_enabled",
        "sync_mode",
        "mcp_server_enabled",
        "skipped_update_version",
        "pinned_tabs",
        "hint_link_click_used",
        "port_forwards_migrated",
        "keepalive_default_v2_applied",
        // Sync-transport endpoints: per-device config, and the Git
        // remote can carry an inline credential in cleartext.
        "sync_git_remote",
        "sync_webdav_url",
        "sync_webdav_user",
        "sync_folder_path",
    ] {
        assert!(!is_portable_setting(denied), "{denied} must not be portable");
    }

    // Encrypted-under-this-vault settings are a separate class: they
    // arrive as unreadable bytes, and the target's next master-password
    // change walks every one of them in STRICT mode and aborts on the
    // first it cannot decrypt. Exporting one wedges the OTHER vault's
    // password change, which is why they are denied and not merely
    // useless.
    for denied in [
        "sync_sftp_passphrase",
        "sync_webdav_password",
        "files_recent_folders",
    ] {
        assert!(
            !is_portable_setting(denied),
            "{denied} is encrypted per-vault and must not be portable"
        );
    }

    // Genuine preferences ride along.
    for ok in [
        "language",
        "app_theme",
        "terminal_font_size",
        "scrollback_rows",
        "ai_provider",
        "ai_model",
        "ai_api_key",
        "sync_passwords",
        "sync_signaling_url",
    ] {
        assert!(is_portable_setting(ok), "{ok} should be portable");
    }
}

/// Full export → import round-trips portable preferences (including the
/// AI key, re-encrypted under the target's master key) and drops every
/// device-local / security key, even when one is present on the source.
#[test]
fn settings_export_import_roundtrip() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions, ExportSelection};

    let vault = unlocked_vault();

    // Portable preferences.
    vault.set_setting("language", "pt-BR").unwrap();
    vault.set_setting("app_theme", "Nord").unwrap();
    vault.set_setting("terminal_font_size", "15").unwrap();
    // AI key, stored encrypted under the source master key.
    vault.set_ai_api_key("sk-secret-123").unwrap();
    // Device-local / security keys that must never leave.
    vault.set_setting("has_user_password", "true").unwrap();
    vault.set_setting("sync_device_name", "source-laptop").unwrap();
    vault.set_setting("mcp_server_token", "tok-abc").unwrap();
    vault.set_setting("hint_link_click_used", "true").unwrap();

    let data = export_vault(
        &vault,
        "pass",
        ExportOptions {
            include_private_keys: false,
            filter: ExportFilter::All,
            selection: ExportSelection::all(),
        },
    )
    .unwrap();

    let vault2 = unlocked_vault();
    // vault2's own lock flag, set by `set_master_password`. Importing
    // the source's `has_user_password` must not touch it.
    let lock_flag_before = vault2.get_setting("has_user_password").unwrap();
    let result = import_vault(&vault2, &data, "pass", &ExportSelection::all(), None).unwrap();

    // language, app_theme, terminal_font_size, ai_api_key = 4 portable
    // keys written; the 4 device-local ones were filtered on the way out.
    assert_eq!(result.settings_imported, 4);

    assert_eq!(vault2.get_setting("language").unwrap().as_deref(), Some("pt-BR"));
    assert_eq!(vault2.get_setting("app_theme").unwrap().as_deref(), Some("Nord"));
    assert_eq!(vault2.get_setting("terminal_font_size").unwrap().as_deref(), Some("15"));

    // AI key decrypts to the original plaintext under vault2's own key.
    assert_eq!(vault2.get_ai_api_key().unwrap().as_deref(), Some("sk-secret-123"));
    // ...and is NOT stored verbatim, the column holds base64 ciphertext.
    assert_ne!(vault2.get_setting("ai_api_key").unwrap().as_deref(), Some("sk-secret-123"));

    // Device-local / security keys never crossed. The lock flag keeps
    // vault2's own value (the import didn't clobber it with the source's).
    assert_eq!(vault2.get_setting("has_user_password").unwrap(), lock_flag_before);
    assert_eq!(vault2.get_setting("sync_device_name").unwrap(), None);
    assert_eq!(vault2.get_setting("mcp_server_token").unwrap(), None);
    assert_eq!(vault2.get_setting("hint_link_click_used").unwrap(), None);
}

/// Unchecking the Settings category leaves an export with no settings,
/// and inspection reports the per-category counts the import dialog
/// needs.
#[test]
fn settings_excluded_when_category_off_and_inspect_counts() {
    use crate::portable::{export_vault, inspect_export, ExportFilter, ExportOptions, ExportSelection};

    let vault = unlocked_vault();
    vault.save_connection(&Connection::new("h", "10.0.0.1"), None).unwrap();
    vault.set_setting("language", "fr").unwrap();

    // Settings unchecked.
    let mut sel = ExportSelection::all();
    sel.settings = false;
    let data = export_vault(
        &vault,
        "pass",
        ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: sel },
    )
    .unwrap();

    let summary = inspect_export(&data, "pass").unwrap();
    assert_eq!(summary.connections, 1);
    assert_eq!(summary.settings, 0);
    assert!(summary.present(crate::portable::ExportCategory::Connections));
    assert!(!summary.present(crate::portable::ExportCategory::Settings));
}

/// Importing connections while deselecting their dependency categories
/// must NULL the now-dangling references, the app's invariant (deleted
/// parents cascade-NULL) means a `Some(missing)` group/key/identity
/// would make the host vanish from the dashboard.
#[test]
fn partial_import_nulls_dangling_refs() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions, ExportSelection};
    use oryxis_core::models::identity::Identity;

    let vault = unlocked_vault();
    let key = crate::keygen::generate_ed25519("k").unwrap();
    vault.save_key(&key.key, Some(&key.private_pem)).unwrap();
    let mut ident = Identity::new("id");
    ident.key_id = Some(key.key.id);
    vault.save_identity(&ident, None).unwrap();
    let g = Group::new("G");
    vault.save_group(&g).unwrap();
    let mut conn = Connection::new("h", "10.0.0.1");
    conn.group_id = Some(g.id);
    conn.key_id = Some(key.key.id);
    conn.identity_id = Some(ident.id);
    vault.save_connection(&conn, None).unwrap();

    let data = export_vault(
        &vault,
        "pw",
        ExportOptions { include_private_keys: true, filter: ExportFilter::All, selection: ExportSelection::all() },
    )
    .unwrap();

    // Import connections only, into a vault with none of the deps.
    let mut sel = ExportSelection::none();
    sel.connections = true;
    let vault2 = unlocked_vault();
    let result = import_vault(&vault2, &data, "pw", &sel, None).unwrap();
    assert_eq!(result.connections_added, 1);
    assert_eq!(result.groups_added, 0);
    assert_eq!(result.keys_added, 0);
    assert_eq!(result.identities_added, 0);

    let conns = vault2.list_connections().unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].group_id, None);
    assert_eq!(conns[0].key_id, None);
    assert_eq!(conns[0].identity_id, None);
}

/// The mirror case: when the parent already lives in the target vault,
/// a connections-only import must KEEP the link, not blindly NULL it.
#[test]
fn partial_import_preserves_existing_parent_link() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions, ExportSelection};

    let vault = unlocked_vault();
    let g = Group::new("G");
    vault.save_group(&g).unwrap();
    let mut conn = Connection::new("h", "10.0.0.1");
    conn.group_id = Some(g.id);
    vault.save_connection(&conn, None).unwrap();

    let data = export_vault(
        &vault,
        "pw",
        ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: ExportSelection::all() },
    )
    .unwrap();

    // Target already has the group; import connections only.
    let vault2 = unlocked_vault();
    vault2.save_group(&g).unwrap();
    let mut sel = ExportSelection::none();
    sel.connections = true;
    import_vault(&vault2, &data, "pw", &sel, None).unwrap();

    let conns = vault2.list_connections().unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].group_id, Some(g.id));
}


/// A cycle that exists only in the MERGE: neither the file nor the
/// target vault loops on its own, but the import re-parents each side's
/// folder into the other's. This is the case a per-file or per-vault
/// check would miss, and the reason the repair runs over the merged
/// tree after every group has landed.
#[test]
fn import_breaks_a_parent_cycle_created_by_the_merge() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions, ExportSelection};

    // Source vault: A is parented under B.
    let vault = unlocked_vault();
    let mut a = Group::new("a");
    let mut b = Group::new("b");
    a.updated_at = chrono::DateTime::from_timestamp(100, 0).unwrap();
    b.updated_at = chrono::DateTime::from_timestamp(200, 0).unwrap();
    a.parent_id = Some(b.id);
    vault.save_group(&a).unwrap();

    let data = export_vault(
        &vault,
        "pw",
        ExportOptions {
            include_private_keys: false,
            filter: ExportFilter::All,
            selection: ExportSelection::all(),
        },
    )
    .unwrap();

    // Target vault already holds B, parented under A: on its own that
    // is a dangling parent, and only the import closes the loop.
    let vault2 = unlocked_vault();
    let mut b_local = b.clone();
    b_local.parent_id = Some(a.id);
    vault2.save_group(&b_local).unwrap();

    import_vault(&vault2, &data, "pw", &ExportSelection::all(), None).unwrap();

    let stored = vault2.list_groups().unwrap();
    assert_eq!(stored.len(), 2, "both folders must survive the repair");
    for g in &stored {
        assert!(
            g.parent_id.is_none() || Group::is_reachable_from_root(&stored, g.id),
            "{} still cyclic after import",
            g.label
        );
    }
    // The newer edge is the detached one, same rule as the sync path.
    assert_eq!(
        stored.iter().find(|g| g.id == b.id).unwrap().parent_id,
        None
    );
}

/// A well-nested hierarchy must import untouched: the repair only fires
/// on real loops, never on a legitimate parent chain.
#[test]
fn import_leaves_a_clean_hierarchy_alone() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions, ExportSelection};

    let vault = unlocked_vault();
    let root = Group::new("root");
    let mut child = Group::new("child");
    child.parent_id = Some(root.id);
    let mut grandchild = Group::new("grandchild");
    grandchild.parent_id = Some(child.id);
    vault.save_group(&root).unwrap();
    vault.save_group(&child).unwrap();
    vault.save_group(&grandchild).unwrap();

    let data = export_vault(
        &vault,
        "pw",
        ExportOptions {
            include_private_keys: false,
            filter: ExportFilter::All,
            selection: ExportSelection::all(),
        },
    )
    .unwrap();

    let vault2 = unlocked_vault();
    import_vault(&vault2, &data, "pw", &ExportSelection::all(), None).unwrap();

    let stored = vault2.list_groups().unwrap();
    assert_eq!(
        stored.iter().find(|g| g.id == child.id).unwrap().parent_id,
        Some(root.id)
    );
    assert_eq!(
        stored.iter().find(|g| g.id == grandchild.id).unwrap().parent_id,
        Some(child.id)
    );
}

/// A login script, its per-host variables and the target password it
/// types must all survive a portable export/import. The script rides
/// the Connections category (it has no checkbox of its own), so the
/// second half asserts that: unchecking Connections drops both.
#[test]
fn export_import_login_script_round_trip() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions};
    use oryxis_core::login_script::{ExpectPattern, LoginStep, SecretRef, SendPayload};
    use oryxis_core::models::connection::ScriptVar;

    let vault = unlocked_vault();

    let mut script = LoginScript::new("jumpserver");
    script.steps = vec![
        LoginStep {
            expect: Some(ExpectPattern::Suffix("opt>".into())),
            send: SendPayload::Text("{asset}".into()),
            timeout_ms: 0,
            optional: false,
        },
        LoginStep {
            expect: Some(ExpectPattern::Suffix("password:".into())),
            send: SendPayload::Secret(SecretRef::TargetPassword),
            timeout_ms: 12_000,
            optional: false,
        },
    ];
    vault.save_login_script(&script).unwrap();

    let mut conn = Connection::new("behind-bastion", "10.0.0.7");
    conn.login_script_id = Some(script.id);
    conn.login_script_vars = vec![ScriptVar {
        name: "asset".into(),
        value: "web-01".into(),
    }];
    vault.save_connection(&conn, Some("bastion-pw")).unwrap();
    vault
        .set_connection_target_password(&conn.id, Some("asset-pw"))
        .unwrap();

    let data = export_vault(
        &vault,
        "export-pw",
        ExportOptions {
            include_private_keys: false,
            filter: ExportFilter::All,
            selection: crate::portable::ExportSelection::all(),
        },
    )
    .unwrap();

    let vault2 = unlocked_vault();
    let result = import_vault(
        &vault2,
        &data,
        "export-pw",
        &crate::portable::ExportSelection::all(), None,
    )
    .unwrap();
    assert_eq!(result.connections_added, 1);
    assert_eq!(result.login_scripts_added, 1);

    let scripts = vault2.list_login_scripts().unwrap();
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0].steps, script.steps);

    let conn2 = &vault2.list_connections().unwrap()[0];
    assert_eq!(conn2.login_script_id, Some(script.id));
    assert_eq!(conn2.login_script_vars[0].value, "web-01");
    // Both secrets land in their own encrypted columns.
    assert_eq!(
        vault2.get_connection_password(&conn2.id).unwrap().as_deref(),
        Some("bastion-pw")
    );
    assert_eq!(
        vault2
            .get_connection_target_password(&conn2.id)
            .unwrap()
            .as_deref(),
        Some("asset-pw")
    );

    // Unchecking Connections drops the scripts with them, so an import
    // can never produce a script nothing references.
    let vault3 = unlocked_vault();
    let mut narrowed = crate::portable::ExportSelection::all();
    narrowed.connections = false;
    let result = import_vault(&vault3, &data, "export-pw", &narrowed, None).unwrap();
    assert_eq!(result.connections_added, 0);
    assert_eq!(result.login_scripts_added, 0);
    assert!(vault3.list_login_scripts().unwrap().is_empty());
}

/// A locked store still answers every `list_*` call while the
/// per-field decrypts degrade to `None` through their `unwrap_or`, so
/// an export run against it would write a structurally valid file
/// with every password silently missing; an import could land a
/// partial write (plaintext families save fine without the key, the
/// first encrypted field aborts the loop halfway). Both refuse up
/// front instead.
#[test]
fn export_and_import_refuse_a_locked_vault() {
    use crate::portable::{export_vault, import_vault, ExportOptions, ExportFilter, ExportSelection};

    let mut vault = unlocked_vault();
    let conn = Connection::new("prod-web", "192.168.1.10");
    vault.save_connection(&conn, Some("secret123")).unwrap();

    let options = || ExportOptions {
        include_private_keys: false,
        filter: ExportFilter::All,
        selection: ExportSelection::all(),
    };
    let data = export_vault(&vault, "export-pw", options()).unwrap();

    vault.lock();
    assert!(matches!(
        export_vault(&vault, "export-pw", options()),
        Err(VaultError::Locked)
    ));
    assert!(matches!(
        import_vault(&vault, &data, "export-pw", &ExportSelection::all(), None),
        Err(VaultError::Locked)
    ));
    assert!(vault.list_connections().unwrap().len() == 1, "locked import must write nothing");
}

/// The folder the user had open when they picked the file is where the
/// import lands (issue #230): new hosts with no folder, the file's root
/// folders and new session groups all go under it.
#[test]
fn import_lands_in_the_target_folder() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions, ExportSelection};

    let source = unlocked_vault();
    let loose = Connection::new("loose", "10.0.0.1");
    source.save_connection(&loose, None).unwrap();
    let sub = Group::new("Sub");
    source.save_group(&sub).unwrap();
    let mut filed = Connection::new("filed", "10.0.0.2");
    filed.group_id = Some(sub.id);
    source.save_connection(&filed, None).unwrap();
    let data = export_vault(
        &source,
        "pw",
        ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: ExportSelection::all() },
    )
    .unwrap();

    let target = unlocked_vault();
    let prod = Group::new("Prod");
    target.save_group(&prod).unwrap();
    let before_import = chrono::Utc::now();
    let result = import_vault(&target, &data, "pw", &ExportSelection::all(), Some(prod.id)).unwrap();
    assert_eq!(result.connections_added, 2);
    assert_eq!(result.groups_added, 1);

    let conns = target.list_connections().unwrap();
    let by_label = |l: &str| conns.iter().find(|c| c.label == l).unwrap().clone();
    // A host with no folder of its own lands in the open one.
    assert_eq!(by_label("loose").group_id, Some(prod.id));
    // A host filed under one of the file's own folders keeps it...
    assert_eq!(by_label("filed").group_id, Some(sub.id));
    // ...and that folder, at the file's root, is parented under the
    // open one, so the whole tree arrives inside it.
    let groups = target.list_groups().unwrap();
    let imported_sub = groups.iter().find(|g| g.id == sub.id).unwrap();
    assert_eq!(imported_sub.parent_id, Some(prod.id));
    assert_eq!(groups.iter().find(|g| g.id == prod.id).unwrap().parent_id, None);

    // What the placement pass rewrote is stamped at the import, so it
    // out-ranks the source device's copy under last-writer-wins instead
    // of tying with it; what it left alone keeps the file's stamp.
    assert!(by_label("loose").updated_at >= before_import);
    assert!(imported_sub.updated_at >= before_import);
    assert_eq!(by_label("filed").updated_at, filed.updated_at);
}

/// A host the vault already knows keeps the placement its newer copy
/// carries: the folder choice scopes what the import adds, never what
/// last-writer-wins updates.
#[test]
fn import_target_folder_does_not_reparent_a_known_host() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions, ExportSelection};

    let target = unlocked_vault();
    let prod = Group::new("Prod");
    target.save_group(&prod).unwrap();
    let elsewhere = Group::new("Elsewhere");
    target.save_group(&elsewhere).unwrap();
    let mut old = Connection::new("known", "10.0.0.3");
    old.group_id = Some(elsewhere.id);
    old.updated_at = chrono::Utc::now() - chrono::Duration::hours(1);
    target.save_connection(&old, None).unwrap();

    // The newer copy in the file says "no folder".
    let source = unlocked_vault();
    let mut newer = old.clone();
    newer.group_id = None;
    newer.updated_at = chrono::Utc::now();
    source.save_connection(&newer, None).unwrap();
    let data = export_vault(
        &source,
        "pw",
        ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: ExportSelection::all() },
    )
    .unwrap();

    let result = import_vault(&target, &data, "pw", &ExportSelection::all(), Some(prod.id)).unwrap();
    assert_eq!(result.connections_updated, 1);
    assert_eq!(result.connections_added, 0);
    let conns = target.list_connections().unwrap();
    assert_eq!(conns[0].group_id, None, "the file's own placement wins for a known host");
}

/// A target the store does not have, or a dynamic group, is ignored:
/// the rows land at the root rather than behind a parent that would
/// hide them.
#[test]
fn import_target_folder_must_be_an_existing_manual_group() {
    use crate::portable::{export_vault, import_vault, ExportFilter, ExportOptions, ExportSelection};

    let source = unlocked_vault();
    source.save_connection(&Connection::new("loose", "10.0.0.1"), None).unwrap();
    let data = export_vault(
        &source,
        "pw",
        ExportOptions { include_private_keys: false, filter: ExportFilter::All, selection: ExportSelection::all() },
    )
    .unwrap();

    let target = unlocked_vault();
    import_vault(&target, &data, "pw", &ExportSelection::all(), Some(uuid::Uuid::new_v4())).unwrap();
    assert_eq!(target.list_connections().unwrap()[0].group_id, None);

    let target = unlocked_vault();
    let mut dynamic = Group::new("EC2");
    dynamic.cloud_query = Some(oryxis_core::models::cloud::CloudQuery {
        profile_id: uuid::Uuid::new_v4(),
        kind: oryxis_core::models::cloud::CloudQueryKind::EcsTasks {
            cluster: "c".into(),
            service: "s".into(),
            container: "api".into(),
        },
        template: oryxis_core::models::cloud::ConnectionTemplate {
            username: None,
            initial_command: None,
            transport: oryxis_core::models::cloud::TransportKind::EcsExec,
            key_id: None,
            identity_id: None,
            terminal_theme: None,
        },
    });
    target.save_group(&dynamic).unwrap();
    import_vault(&target, &data, "pw", &ExportSelection::all(), Some(dynamic.id)).unwrap();
    assert_eq!(target.list_connections().unwrap()[0].group_id, None);
}
