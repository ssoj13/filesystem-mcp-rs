//! End-to-end behaviour against a temp HOME: install → status → uninstall, for every client,
//! plus the safety rules that make uninstall trustworthy.

use std::path::Path;

use crate::mcp_setup::SetupError;
use crate::mcp_setup::clients;
use crate::mcp_setup::docs::HintDocs;
use crate::mcp_setup::host::{self, HostSpec};
use crate::mcp_setup::types::{Scope, SetupContext};

const KEY: &str = "demo-mcp";
const ID: &str = "demo-mcp:1.0.0";

fn spec() -> HostSpec {
    HostSpec::new(KEY, ID, "/opt/bin/demo-mcp")
        .with_args(["--flag"])
        .with_docs(HintDocs::new([
            "## demo\n\nUse `{{MCP_SERVER_KEY}}` for X.",
        ]))
}

/// Pretend every supported agent is installed for this user, by creating the marker directory each
/// one is detected by. Driven off the registry, so a newly added client is covered automatically.
fn make_agent_dirs(home: &Path) {
    for client in clients::all() {
        std::fs::create_dir_all(client.user_marker_dir(home)).unwrap();
    }
    // Otherwise Codex would shell out to a real `codex` binary.
    unsafe { std::env::set_var("MCP_SETUP_FORCE_TOML", "1") };
}

#[test]
fn every_client_installs_reports_and_uninstalls_in_user_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    make_agent_dirs(home);
    let ctx = SetupContext::from_home(home.to_path_buf()).unwrap();
    let spec = spec();

    for client in clients::all() {
        let applied = host::install(&ctx, client, &Scope::User, &spec)
            .unwrap_or_else(|e| panic!("{} install: {e}", client.id()));
        assert!(
            applied.changed,
            "{}: first install must change",
            client.id()
        );
        assert!(applied.settings_path.is_file(), "{}", client.id());
        assert!(applied.manifest_path.is_file(), "{}", client.id());

        let raw = std::fs::read_to_string(&applied.settings_path).unwrap();
        assert!(raw.contains(KEY), "{}: key missing in config", client.id());
        assert!(
            raw.contains("MCP_SETUP_INSTALL_ID"),
            "{}: ownership marker missing",
            client.id()
        );

        // Hints landed in the agent's context file, with placeholders substituted — for the
        // agents that have one. (Claude Desktop, VS Code, Cline, … have no rules file.)
        if let Some(hints) = applied.hints_path.clone() {
            let hints_raw = std::fs::read_to_string(&hints).unwrap();
            assert!(
                hints_raw.contains("Use `demo-mcp` for X."),
                "{}",
                client.id()
            );
        }

        let status = host::status(&ctx, client, &Scope::User, &spec).unwrap();
        assert!(
            status.installed,
            "{}: status should be installed",
            client.id()
        );

        // Re-installing identical settings is a no-op.
        let again = host::install(&ctx, client, &Scope::User, &spec).unwrap();
        assert!(
            !again.changed,
            "{}: reinstall must be idempotent",
            client.id()
        );

        let removed = host::uninstall(&ctx, client, &Scope::User, &spec).unwrap();
        assert!(removed.removed, "{}: uninstall must remove", client.id());
        assert!(!removed.manifest_path.exists(), "{}", client.id());

        let raw_after = std::fs::read_to_string(&applied.settings_path).unwrap();
        assert!(!raw_after.contains(KEY), "{}: key left behind", client.id());
        if let Some(hints) = applied.hints_path.clone() {
            let hints_after = std::fs::read_to_string(&hints).unwrap_or_default();
            assert!(
                !hints_after.contains("Use `demo-mcp` for X."),
                "{}: hints left behind",
                client.id()
            );
        }

        let status = host::status(&ctx, client, &Scope::User, &spec).unwrap();
        assert!(!status.installed, "{}", client.id());
    }
}

#[test]
fn project_scope_writes_into_the_project_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let proj = tmp.path().join("repo");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&proj).unwrap();
    make_agent_dirs(&home);
    let ctx = SetupContext::from_home(home).unwrap();
    let scope = Scope::Project(proj.clone());

    for client in clients::all().into_iter().filter(|c| c.supports_project()) {
        let r = host::install(&ctx, client, &scope, &spec())
            .unwrap_or_else(|e| panic!("{} project install: {e}", client.id()));
        assert!(
            r.settings_path.starts_with(&proj),
            "{}: project install escaped the project root: {}",
            client.id(),
            r.settings_path.display()
        );
        host::uninstall(&ctx, client, &scope, &spec()).unwrap();
    }
}

/// A version bump changes the install id. The new build must still recognise the entry (and the
/// manifest) written by the old one — otherwise upgrading would leave an entry nobody can remove.
#[test]
fn a_newer_version_upgrades_and_can_remove_the_older_install() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    make_agent_dirs(home);
    let ctx = SetupContext::from_home(home.to_path_buf()).unwrap();
    let docs = HintDocs::new(["## demo\n\nUse `{{MCP_SERVER_KEY}}` for X."]);

    let old =
        HostSpec::new(KEY, format!("{KEY}:1.0.0"), "/opt/bin/demo-mcp").with_docs(docs.clone());
    let new =
        HostSpec::new(KEY, format!("{KEY}:2.0.0"), "/opt/bin/demo-mcp-v2").with_docs(docs.clone());

    for client in clients::all() {
        host::install(&ctx, client, &Scope::User, &old).unwrap();

        let upgraded = host::install(&ctx, client, &Scope::User, &new)
            .unwrap_or_else(|e| panic!("{} upgrade: {e}", client.id()));
        assert!(upgraded.changed, "{}: upgrade must rewrite", client.id());
        let raw = std::fs::read_to_string(&upgraded.settings_path).unwrap();
        assert!(
            raw.contains("2.0.0"),
            "{}: still on the old install id",
            client.id()
        );

        let status = host::status(&ctx, client, &Scope::User, &new).unwrap();
        assert!(status.installed, "{}", client.id());

        let removed = host::uninstall(&ctx, client, &Scope::User, &new).unwrap();
        assert!(
            removed.removed,
            "{}: upgraded entry must be removable",
            client.id()
        );
        let raw = std::fs::read_to_string(&upgraded.settings_path).unwrap();
        assert!(!raw.contains(KEY), "{}: entry left behind", client.id());
    }
}

#[test]
fn refuses_to_overwrite_a_hand_written_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    make_agent_dirs(home);
    std::fs::write(
        home.join(".claude.json"),
        format!(r#"{{"mcpServers":{{"{KEY}":{{"command":"/somewhere/else"}}}}}}"#),
    )
    .unwrap();
    let ctx = SetupContext::from_home(home.to_path_buf()).unwrap();

    let err = host::install(&ctx, &clients::CLAUDE_CODE, &Scope::User, &spec()).unwrap_err();
    assert!(matches!(err, SetupError::McpKeyConflict { .. }), "{err:?}");

    // …and refuses to delete it, too.
    let err = host::uninstall(&ctx, &clients::CLAUDE_CODE, &Scope::User, &spec()).unwrap_err();
    assert!(matches!(err, SetupError::NotOurInstall { .. }), "{err:?}");
}

/// `--force` is the deliberate "this key is mine now". It must overwrite, keep the old content
/// recoverable, and say what it did — a silent takeover of someone's config would be worse than
/// the refusal it replaces.
#[test]
fn force_takes_over_a_hand_written_entry_and_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    make_agent_dirs(home);
    let config = home.join(".claude.json");
    std::fs::write(
        &config,
        format!(r#"{{"mcpServers":{{"{KEY}":{{"command":"/somewhere/else"}}}}}}"#),
    )
    .unwrap();
    let ctx = SetupContext::from_home(home.to_path_buf()).unwrap();

    let forced = spec().with_force(true);
    let applied = host::install(&ctx, &clients::CLAUDE_CODE, &Scope::User, &forced).unwrap();

    assert!(applied.changed);
    let raw = std::fs::read_to_string(&config).unwrap();
    assert!(
        raw.contains("/opt/bin/demo-mcp"),
        "our command should have replaced theirs: {raw}"
    );
    assert!(
        !raw.contains("/somewhere/else"),
        "the hand-written command should be gone: {raw}"
    );
    assert!(
        raw.contains("MCP_SETUP_INSTALL_ID"),
        "the entry must now be owned: {raw}"
    );

    let backup = applied.backup_path.expect("a takeover must leave a backup");
    let saved = std::fs::read_to_string(&backup).unwrap();
    assert!(
        saved.contains("/somewhere/else"),
        "the backup must hold what was overwritten: {saved}"
    );

    let note = applied
        .note
        .expect("a takeover must be reported, not silent");
    assert!(note.contains("unmanaged"), "{note}");

    // Now that it is ours, uninstall works — the takeover is complete, not half-done.
    host::uninstall(&ctx, &clients::CLAUDE_CODE, &Scope::User, &forced).unwrap();
}

/// Same for a TOML-backed client, whose ownership guard is a separate code path.
#[test]
fn force_takes_over_a_hand_written_toml_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    make_agent_dirs(home);
    let config = home.join(".codex").join("config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        format!("[mcp_servers.{KEY}]\ncommand = \"/somewhere/else\"\n"),
    )
    .unwrap();
    let ctx = SetupContext::from_home(home.to_path_buf()).unwrap();

    // Codex wraps config.toml failures in `CodexConfigFailed`, so match on the message rather
    // than the variant — what matters is that it refused.
    let err = host::install(&ctx, &clients::CODEX, &Scope::User, &spec()).unwrap_err();
    assert!(
        err.to_string().contains("refusing to overwrite"),
        "expected a refusal without --force, got {err:?}"
    );

    host::install(
        &ctx,
        &clients::CODEX,
        &Scope::User,
        &spec().with_force(true),
    )
    .unwrap();
    let raw = std::fs::read_to_string(&config).unwrap();
    assert!(raw.contains("/opt/bin/demo-mcp"), "{raw}");
    assert!(!raw.contains("/somewhere/else"), "{raw}");
}

/// Force is opt-in: the default must still refuse, or every ordinary `install` becomes a
/// takeover. Guards the flag from being wired to the wrong default.
#[test]
fn force_defaults_off() {
    assert!(!spec().force, "HostSpec must not force by default");
    assert!(
        !spec().plan().unwrap().force,
        "the plan must inherit force=false"
    );
}

#[test]
fn status_spots_the_same_binary_under_an_unmanaged_key() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    make_agent_dirs(home);
    std::fs::write(
        home.join(".claude.json"),
        r#"{"mcpServers":{"my-own-name":{"command":"/usr/local/bin/demo-mcp"}}}"#,
    )
    .unwrap();
    let ctx = SetupContext::from_home(home.to_path_buf()).unwrap();

    let report = host::status(&ctx, &clients::CLAUDE_CODE, &Scope::User, &spec()).unwrap();
    assert!(!report.installed);
    assert!(report.custom_installed);
    assert_eq!(report.custom_key.as_deref(), Some("my-own-name"));
}

#[test]
fn missing_agent_is_reported_as_not_detected_not_created() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let ctx = SetupContext::from_home(home.to_path_buf()).unwrap();

    let err = host::install(&ctx, &clients::CURSOR, &Scope::User, &spec()).unwrap_err();
    assert!(matches!(err, SetupError::HostNotDetected { .. }), "{err:?}");
    assert!(
        !home.join(".cursor").exists(),
        "must not create the agent dir"
    );
}

#[test]
fn user_notes_outside_the_managed_block_survive_uninstall() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    make_agent_dirs(home);
    let claude_md = home.join(".claude").join("CLAUDE.md");
    std::fs::write(&claude_md, "# My own rules\n\nKeep me.\n").unwrap();
    let ctx = SetupContext::from_home(home.to_path_buf()).unwrap();

    host::install(&ctx, &clients::CLAUDE_CODE, &Scope::User, &spec()).unwrap();
    assert!(
        std::fs::read_to_string(&claude_md)
            .unwrap()
            .contains("Keep me.")
    );

    host::uninstall(&ctx, &clients::CLAUDE_CODE, &Scope::User, &spec()).unwrap();
    let after = std::fs::read_to_string(&claude_md).unwrap();
    assert!(
        after.contains("Keep me."),
        "user notes were eaten: {after:?}"
    );
    assert!(!after.contains("demo-mcp"));
}

#[test]
fn no_docs_means_no_context_file_is_touched() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    make_agent_dirs(home);
    let ctx = SetupContext::from_home(home.to_path_buf()).unwrap();
    let bare = HostSpec::new(KEY, ID, "/opt/bin/demo-mcp");

    let r = host::install(&ctx, &clients::CLAUDE_CODE, &Scope::User, &bare).unwrap();
    assert!(r.hints_path.is_none());
    assert!(!home.join(".claude").join("CLAUDE.md").exists());
    host::uninstall(&ctx, &clients::CLAUDE_CODE, &Scope::User, &bare).unwrap();
}
