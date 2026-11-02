//! The blocking wait behind `chat-wait`: the direct route to an idle agent.
//!
//! No server can start a model turn, but several clients start one when a background command the
//! model launched finishes. So the agent keeps this running in the background: it sits on `chat.db`
//! until a message nobody has been shown arrives, prints it and exits, and the client wakes the
//! model with that output. Measured on Claude Code, Antigravity and Cursor Agent; Codex does not
//! wake this way, see [`wakes_on_background_exit`].
//!
//! There is no timeout, so nothing has to keep restarting it. It ends when a message comes, when the
//! name stops being this agent's, or when the server that owns it is gone. A message already shown
//! on a tool result does not end it right away: whoever made that call is awake and has it. Usually
//! that is the agent itself, but it can be a subagent sharing the server, so if the message is still
//! unanswered once the agent has gone quiet, it is woken for it after all, once.
//! Synchronous on purpose: it owns its process.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::session::{
    ChatMode, FreshProcesses, Processes, now_ms, own_start, powershell_note, render,
};
use crate::store::{Claim, Store, Unread};

/// How often a wait looks at the database. Fast enough to feel live, slow enough that a waiting
/// agent costs nothing measurable. Also used by `chat_read`.
pub const POLL: Duration = Duration::from_millis(250);

/// How often a wait checks that its server is still there. Listing processes is the expensive part,
/// and nothing depends on noticing quickly.
const OWNER_CHECK_EVERY: Duration = Duration::from_secs(5);

/// How a wait ended, for the command to report.
#[derive(Debug, PartialEq, Eq)]
pub enum WaitEnd {
    /// The text the client hands to the model.
    Messages(String),
    /// Another wait already covers this name, so this one changes nothing.
    AlreadyWaiting,
    /// The server that owns the name stopped, or another process took the name over.
    OwnerGone,
    /// No agent has this name: it was renamed, or the name is wrong.
    NoSuchAgent,
}

/// Does this client start a model turn when a background command finishes?
///
/// Measured 2026-11-01: Codex CLI 0.164.0 does not (the command finished, no new turn in 120 s), so
/// asking it to keep a wait running would leave a process status nothing. Everything else is told to:
/// a client that turns out not to wake loses one idle process and still gets its messages on tool
/// results.
pub fn wakes_on_background_exit(client: &str) -> bool {
    !client.to_ascii_lowercase().contains("codex")
}

/// What it takes to start a wait from an agent's shell. The database is passed explicitly because a
/// client sets the server's environment, which the agent's shell does not share.
#[derive(Clone, Debug)]
pub struct WaitProgram {
    exe: String,
    db: PathBuf,
    db_text: String,
    mode: ChatMode,
}

impl WaitProgram {
    /// `None` when these paths cannot be written as one command line that means the same thing in
    /// every shell. Not a guess at a spelling: SQLite would quietly create a new, empty database at a
    /// path that came out different, and the wait would then watch nothing.
    pub fn new(exe: PathBuf, db: PathBuf) -> Option<Self> {
        Some(Self {
            exe: shell_path(&exe)?,
            db_text: shell_path(&db)?,
            db,
            mode: ChatMode::default(),
        })
    }

    /// The server's mode goes on the command line because this process does not get its environment.
    pub fn with_mode(mut self, mode: ChatMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn db(&self) -> &Path {
        &self.db
    }

    /// The command line for one agent. `owner` is the process id and start time of the server it
    /// belongs to: names come round again, and a model repeating a command from before a restart
    /// must not start listening for whoever has the name now.
    pub fn command(&self, name: &str, owner: (i64, i64)) -> String {
        format!(
            "{} chat-wait --db {} --owner {}:{}{} {name}",
            self.exe,
            self.db_text,
            owner.0,
            owner.1,
            match self.mode {
                ChatMode::Auto => "",
                ChatMode::Ask => " --mode ask",
            }
        )
    }
}

/// A path every shell an agent might have reads the same way. Forward slashes because Git Bash eats
/// backslashes and Windows accepts both. Quotes only when needed, because PowerShell then needs `&`
/// (see `powershell_note`). Refuses what double quotes do not protect in all of them.
fn shell_path(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    if text.contains(['"', '$', '`', '%', '!']) {
        return None;
    }
    let text = if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.to_owned()
    };
    let plain = text
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | ':' | '~' | '+'));
    Some(if plain { text } else { format!("\"{text}\"") })
}

/// Wait for a message for `name`. `program` is what the output tells the agent to start again.
pub fn wait_for_message(
    program: &WaitProgram,
    name: &str,
    expected_owner: (i64, i64),
) -> Result<WaitEnd> {
    let store = Store::connect(program.db())?;
    match store.owner(name)? {
        None => return Ok(WaitEnd::NoSuchAgent),
        Some(owner) if owner != expected_owner => return Ok(WaitEnd::OwnerGone),
        Some(_) => {}
    }
    let pid = i64::from(std::process::id());
    let start = own_start()?;
    let processes = FreshProcesses::default();
    let owner = match store.claim_waiter(name, pid, start, &|p, s| processes.alive(p, s))? {
        Claim::Granted { owner } => owner,
        Claim::AlreadyWaiting => return Ok(WaitEnd::AlreadyWaiting),
        Claim::OwnerGone => return Ok(WaitEnd::OwnerGone),
        Claim::NoSuchAgent => return Ok(WaitEnd::NoSuchAgent),
    };
    let end = watch(&store, program, name, owner, (pid, start));
    // Only a courtesy to `agent_ls`: once this process is gone the claim counts for nothing anyway.
    // So it must not cost the result, which may hold a message already marked shown.
    // To stderr: this command has no log, and stdout is what the model reads.
    if let Err(error) = store.release_waiter(name, pid) {
        eprintln!("chat: cannot release the wait: {error:#}");
    }
    end
}

fn watch(
    store: &Store,
    program: &WaitProgram,
    name: &str,
    owner: (i64, i64),
    me: (i64, i64),
) -> Result<WaitEnd> {
    let mut next_owner_check = Instant::now() + OWNER_CHECK_EVERY;
    let mut missed_owner = false;
    loop {
        // The owner first: a message for a name that has moved on belongs to whoever has it now.
        if store.has_wakeful(name, now_ms())?
            && store.owner(name)? == Some(owner)
            && Processes::only(owner.0).alive(owner.0, owner.1)
        {
            let unread = store.take_unread(name, now_ms())?;
            // A tool result can take the message between those two calls, and then its caller has
            // it: see the module docs.
            if unread.messages.iter().any(|message| !message.shown) {
                // Only keeps a later wait from waking it again for these, so not worth the message.
                if let Err(error) = store.mark_woken(name, &unread.messages, now_ms()) {
                    eprintln!("chat: cannot note the wake: {error:#}");
                }
                return Ok(WaitEnd::Messages(output(program, name, owner, &unread)));
            }
        }
        let now = Instant::now();
        if now >= next_owner_check {
            next_owner_check = now + OWNER_CHECK_EVERY;
            if store.owner(name)? == Some(owner) && Processes::only(owner.0).alive(owner.0, owner.1)
            {
                let messages = store.take_overdue(name, now_ms())?;
                if !messages.is_empty() {
                    let unread = Unread { messages, more: 0 };
                    return Ok(WaitEnd::Messages(output(program, name, owner, &unread)));
                }
            }
            let Some(current_owner) = store.owner(name)? else {
                return Ok(WaitEnd::NoSuchAgent);
            };
            if current_owner != owner {
                return Ok(WaitEnd::OwnerGone);
            }
            // Twice, because a failed process listing comes back empty, and an agent told its server
            // has stopped will not start another wait.
            if Processes::only(owner.0).alive(owner.0, owner.1) {
                missed_owner = false;
            } else if missed_owner {
                return Ok(WaitEnd::OwnerGone);
            } else {
                missed_owner = true;
            }
            match store.waiter(name)? {
                Some(holder) if holder == me => {}
                // The row was wiped and joined again, which took this claim with it.
                Some((0, _)) => {
                    let processes = FreshProcesses::default();
                    store.claim_waiter(name, me.0, me.1, &|p, s| processes.alive(p, s))?;
                }
                // A newer wait holds it: one is enough.
                _ => return Ok(WaitEnd::AlreadyWaiting),
            }
        }
        std::thread::sleep(POLL);
    }
}

fn output(program: &WaitProgram, name: &str, owner: (i64, i64), unread: &Unread) -> String {
    let messages =
        render(program.mode, None, unread, None).map_or_else(String::new, |delivery| delivery.text);
    let command = program.command(name, owner);
    format!(
        "{messages}\n[chat] Then restart this in the background in your client's own shell tool: \
         `{command}`{}",
        powershell_note(&command)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Target;
    use crate::store::Join;

    fn join(store: &Store, pid: i64, start: i64) -> crate::address::Address {
        store
            .join(
                &Join {
                    project: "fs".to_owned(),
                    topic: "-".to_owned(),
                    parent: "-".to_owned(),
                    client: "test".to_owned(),
                    pid,
                    pid_start: start,
                    status: None,
                },
                None,
                None,
                now_ms(),
                &|_, _| true,
            )
            .unwrap()
    }

    fn program(dir: &Path) -> WaitProgram {
        WaitProgram::new(PathBuf::from("server"), dir.join("chat.db")).unwrap()
    }

    /// A wait has no timeout of its own, so a regression must fail here and not hang the suite.
    fn wait_within_limit(program: &WaitProgram, name: &str) -> WaitEnd {
        let (done, result) = std::sync::mpsc::channel();
        let program = program.clone();
        let name = name.to_owned();
        std::thread::spawn(move || {
            done.send(wait_for_message(&program, &name, this_process()).unwrap())
        });
        result
            .recv_timeout(Duration::from_secs(20))
            .expect("the wait did not end")
    }

    /// This process stands in for the server, so the owner is alive for the whole test.
    fn this_process() -> (i64, i64) {
        let pid = i64::from(std::process::id());
        (pid, Processes::now().start_of(pid).unwrap())
    }

    #[test]
    fn a_path_with_a_space_is_quoted_and_backslashes_never_reach_the_shell() {
        let program = WaitProgram::new(
            PathBuf::from(r"C:\Program Files\s.exe"),
            PathBuf::from("/state/chat.db"),
        )
        .unwrap();
        let command = program.command("Erdos", (1, 2));
        assert!(command.ends_with("chat-wait --db /state/chat.db --owner 1:2 Erdos"));
        assert!(command.starts_with('"'));
        assert!(!powershell_note(&command).is_empty());
        if cfg!(windows) {
            assert!(command.starts_with("\"C:/Program Files/s.exe\" "));
            assert!(!command.contains('\\'));
        }
    }

    #[test]
    fn a_plain_path_is_not_quoted_and_needs_no_note_for_powershell() {
        let program =
            WaitProgram::new(PathBuf::from("/bin/server"), PathBuf::from("/s/chat.db")).unwrap();
        let command = program.command("Erdos", (1, 2));
        assert_eq!(
            command,
            "/bin/server chat-wait --db /s/chat.db --owner 1:2 Erdos"
        );
        assert!(powershell_note(&command).is_empty());
    }

    #[test]
    fn a_path_no_quoting_can_protect_leaves_no_direct_route() {
        for bad in ["/a$b/s", "/a`b/s", "/a\"b/s", "/a%b%/s", "/a!b/s"] {
            assert!(
                WaitProgram::new(PathBuf::from(bad), PathBuf::from("/s/chat.db")).is_none(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_backlog_of_unconfirmed_messages_does_not_stop_a_new_one_ending_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let program = program(dir.path());
        let store = Store::open(&program.db, now_ms()).unwrap();
        let (pid, start) = this_process();
        let sender = join(&store, pid, start);
        let waiter = join(&store, pid, start);
        let target = Target::parse(&waiter.name).unwrap();
        for _ in 0..crate::store::READ_LIMIT {
            store
                .send(&sender, Some(&target), "old", None, now_ms(), &|_, _| true)
                .unwrap();
        }
        store.take_unread(&waiter.name, now_ms()).unwrap();
        // From someone else: this many from one agent has used up what it may wake.
        let other = join(&store, pid, start);
        store
            .send(&other, Some(&target), "new", None, now_ms(), &|_, _| true)
            .unwrap();
        let WaitEnd::Messages(text) = wait_within_limit(&program, &waiter.name) else {
            panic!("expected a message");
        };
        assert!(text.contains("new"), "{text}");
    }

    #[test]
    fn a_command_from_before_a_restart_does_not_listen_for_the_new_owner_of_the_name() {
        let dir = tempfile::tempdir().unwrap();
        let program = program(dir.path());
        let store = Store::open(&program.db, now_ms()).unwrap();
        let (pid, start) = this_process();
        let agent = join(&store, pid, start);
        assert_eq!(
            wait_for_message(&program, &agent.name, (pid + 1, start)).unwrap(),
            WaitEnd::OwnerGone
        );
        assert_eq!(store.waits_started(&agent.name).unwrap(), 0);
    }

    #[test]
    fn a_mode_other_than_the_default_goes_on_the_command_line() {
        let program = WaitProgram::new("s".into(), "d".into()).unwrap();
        assert!(!program.command("E", (1, 2)).contains("--mode"));
        let ask = program.with_mode(ChatMode::Ask).command("E", (1, 2));
        assert!(ask.ends_with("--mode ask E"), "{ask}");
    }

    #[test]
    fn codex_is_the_one_client_not_asked_to_keep_a_wait_running() {
        assert!(!wakes_on_background_exit("codex-mcp-client"));
        assert!(wakes_on_background_exit("claude-code"));
        assert!(wakes_on_background_exit("antigravity"));
    }

    #[test]
    fn a_message_ends_the_wait_and_the_output_says_to_start_it_again() {
        let dir = tempfile::tempdir().unwrap();
        let program = program(dir.path());
        let store = Store::open(&program.db, now_ms()).unwrap();
        let (pid, start) = this_process();
        let sender = join(&store, pid, start);
        let waiter = join(&store, pid, start);
        let target = Target::parse(&waiter.name).unwrap();
        store
            .send(&sender, Some(&target), "hello", None, now_ms(), &|_, _| {
                true
            })
            .unwrap();
        let WaitEnd::Messages(text) = wait_within_limit(&program, &waiter.name) else {
            panic!("expected a message");
        };
        assert!(text.contains("hello"));
        assert!(text.contains("Peer message"));
        assert!(text.contains(&program.command(&waiter.name, (pid, start))));
        assert!(!store.has_fresh(&waiter.name).unwrap(), "now it is shown");
    }

    #[test]
    fn a_wait_for_an_unknown_name_ends_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let program = program(dir.path());
        Store::open(&program.db, now_ms()).unwrap();
        assert_eq!(
            wait_for_message(&program, "Nobody", (0, 0)).unwrap(),
            WaitEnd::NoSuchAgent
        );
    }

    #[test]
    fn a_wait_ends_at_once_when_the_owner_is_already_dead() {
        let dir = tempfile::tempdir().unwrap();
        let program = program(dir.path());
        let store = Store::open(&program.db, now_ms()).unwrap();
        let (pid, start) = this_process();
        let agent = join(&store, pid, start + 10);
        assert_eq!(
            wait_for_message(&program, &agent.name, (pid, start + 10)).unwrap(),
            WaitEnd::OwnerGone
        );
    }
}
