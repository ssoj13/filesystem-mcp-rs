//! Agents starting agents: `agent_start` and `agent_stop`, and the supervision behind them.
//!
//! Why here: a server already knows who is calling and shares a database with every other server, so
//! one can start a client in a way that keeps the graph true. Clients are described by `agent-runner`
//! manifests, built in and from `<state>/agents/*.toml`, which override the built-in ones by id.
//!
//! How a run goes: the store records it, which is where the depth and tree limits are checked. A task
//! here runs the client's turn and reports to the parent as an ordinary chat message, which reaches it
//! by the same routes as any other. If the client can be resumed, the run stays `idle`, and a message
//! to the agent starts another turn; nothing else can wake a client like Codex. An idle run ends after
//! [`IDLE_LIMIT`].
//!
//! None of that needs the client to reach this server. Measured on Codex 0.166.0: under `exec` it
//! refuses MCP tools, so it could not read a message or answer one with the chat tools. So the agent
//! gets its name when the run is recorded, the messages go into the prompt of the turn they start, and
//! its last message goes back to whoever wrote, unless it has answered them itself. A client that does
//! have this server joins as a child of this one, found through the process tree and tied to its run
//! by `RUN_ENV`, and takes over the name.
//!
//! A run dies with the server looking after it, on purpose: on Windows the runner's job object sees to
//! it even after a crash. `agent_stop` and the `agents stop` command only set a flag in the database,
//! which the task here polls, so they work from any process without knowing a pid.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_chat::address::{Address, NONE, Target};
use agent_chat::session::{ChatSession, FreshProcesses, Processes, RUN_ENV, now_ms};
use agent_chat::store::{Message, NewRun, RunState, Store, parse_address};
use agent_runner::{Access, AgentPlugin, AgentRegistry, SessionRunner, TurnOutcome, TurnRequest};
use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult,
    serde::Deserialize, tool, tool_router,
};
use schemars::JsonSchema;
use serde_json::json;
use tokio::process::Command;
use tracing::warn;

use crate::FileSystemServer;
use crate::core::serde::{FlexBool, FlexU64};
use crate::env_spec;
use crate::tools::chat::{chat_error, chat_me, ok};

const DEFAULT_TIMEOUT_MIN: u64 = 30;
const MAX_TIMEOUT_MIN: u64 = 24 * 60;
const POLL: Duration = Duration::from_millis(500);
/// How long a finished agent stays resumable with nothing to do.
const IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);
const MAX_TASK_BYTES: usize = 64 * 1024;
/// What the database keeps of a result, and what the message to the parent carries of it.
const MAX_RESULT_BYTES: usize = 64 * 1024;
const REPORT_CHARS: usize = 1500;
const GIT_LIMIT: Duration = Duration::from_secs(60);
/// How long a stop waits for what is under a run to end before it kills the client. The servers of
/// those runs poll their flags; a client killed first takes them with it, and on Unix what they
/// looked after would run on.
const SETTLE: Duration = Duration::from_secs(5);
/// How long a leaving server gives its runs to end. With the 5 s rmcp gives handlers, this has to stay
/// under the deadline of `exit_after_client_left`, which is counted from when the client left.
const LEAVE: Duration = Duration::from_secs(8);

const NO_ANSWER: &str = "(It ended its turn without saying anything.)";
const ENDED_UNREAD: &str = "(This agent has ended without answering this.)";
const STOPPED_UNANSWERED: &str = "(This agent was stopped before it could answer.)";

/// A resolved path can carry Windows' `\\?\` prefix, which is for this process's own file calls.
/// Handed on, `git` was seen hanging on it, and a client may not expect it either.
fn plain_path(path: &Path) -> PathBuf {
    PathBuf::from(crate::mcp_setup::host::strip_verbatim(
        &path.to_string_lossy(),
    ))
}

// Plain `//` on these wire types: a `///` here becomes schema text in every session.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct AgentStartArgs {
    client: String,
    task: String,
    cwd: Option<String>,
    access: Option<String>,
    #[serde(default, alias = "timeout_min")]
    timeout_min: FlexU64,
    #[serde(default)]
    worktree: FlexBool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct AgentStopArgs {
    run: u64,
}

fn parse_access(word: &str) -> Option<Access> {
    match word.trim().to_ascii_lowercase().as_str() {
        "read" => Some(Access::Read),
        "write" => Some(Access::Write),
        "full" => Some(Access::Full),
        _ => None,
    }
}

const fn rank(access: Access) -> u8 {
    match access {
        Access::Read => 0,
        Access::Write => 1,
        Access::Full => 2,
    }
}

/// What the user allows, from the registered settings.
struct Limits {
    spawn: bool,
    max_depth: i64,
    max_tree: i64,
    max_access: Access,
}

impl Limits {
    fn from_env() -> Self {
        let number = |key: &str, default: i64| -> i64 {
            let Some(raw) = env_spec::get(key) else {
                return default;
            };
            raw.trim().parse().unwrap_or_else(|_| {
                warn!("{key}: not a number: {raw}; using {default}");
                default
            })
        };
        let max_access = env_spec::get("FS_MCP_AGENT_MAX_ACCESS").map_or(Access::Write, |raw| {
            parse_access(&raw).unwrap_or_else(|| {
                warn!("FS_MCP_AGENT_MAX_ACCESS: not read, write or full: {raw}; using read");
                Access::Read
            })
        });
        Self {
            spawn: !env_spec::get("FS_MCP_AGENT_SPAWN")
                .is_some_and(|raw| raw.trim().eq_ignore_ascii_case("off")),
            max_depth: number("FS_MCP_AGENT_MAX_DEPTH", 2),
            max_tree: number("FS_MCP_AGENT_MAX_TREE", 8),
            max_access,
        }
    }
}

pub struct Supervisor {
    runner: SessionRunner<i64>,
    registry: AgentRegistry,
    limits: Limits,
    worktrees: PathBuf,
}

impl Supervisor {
    /// `state` is the state root: manifests under `agents`, worktrees under `worktrees`.
    pub fn new(state: &Path) -> Self {
        let builtin = AgentRegistry::builtin().unwrap_or_else(|error| {
            warn!("Agents: the built-in manifests do not parse: {error}");
            AgentRegistry::new()
        });
        let local = AgentRegistry::load_dir(&state.join("agents"));
        let registry = AgentRegistry::from_plugins(
            builtin
                .list()
                .into_iter()
                .chain(local.list())
                .cloned()
                .collect::<Vec<_>>(),
        );
        Self {
            runner: SessionRunner::new(),
            registry,
            limits: Limits::from_env(),
            worktrees: state.join("worktrees"),
        }
    }

    fn plugin(&self, client: &str) -> Result<AgentPlugin, McpError> {
        let plugin = self.registry.get(client).ok_or_else(|| {
            let known: Vec<&str> = self
                .registry
                .list()
                .into_iter()
                .filter(|plugin| plugin.enabled)
                .map(|plugin| plugin.id.as_str())
                .collect();
            McpError::invalid_params(
                format!("no client {client}; there are: {}", known.join(", ")),
                None,
            )
        })?;
        if !plugin.enabled {
            return Err(McpError::invalid_params(
                format!("{client} is turned off: {}", plugin.description),
                None,
            ));
        }
        if !plugin.binary_exists() {
            return Err(McpError::invalid_params(
                format!("{} is not installed on this machine", plugin.binary),
                None,
            ));
        }
        Ok(plugin.clone())
    }
}

/// Everything one run needs, moved into its task.
struct RunTask {
    id: i64,
    plugin: AgentPlugin,
    access: Access,
    workdir: PathBuf,
    task: String,
    timeout: Duration,
    worktree: Option<Worktree>,
}

struct Worktree {
    repo: PathBuf,
    path: PathBuf,
    /// Where in it to work: the same place in the repository as the directory asked for.
    workdir: PathBuf,
    branch: String,
    base: String,
}

async fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    // Runs inside a tool call: it must not read the client's stdin, or hold the call up for good.
    let run = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(GIT_LIMIT, run)
        .await
        .map_err(|_| format!("git {} took too long", args.join(" ")))?
        .map_err(|error| format!("cannot run git: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

impl Worktree {
    /// A worktree of its own, so that parallel agents on one repository do not fight over its files.
    async fn create(repo: &Path, root: &Path, id: i64) -> Result<Self, String> {
        std::fs::create_dir_all(root).map_err(|error| error.to_string())?;
        let path = root.join(format!("run-{id}"));
        let branch = format!("agent/run-{id}");
        let base = git(repo, &["rev-parse", "HEAD"]).await?;
        let prefix = git(repo, &["rev-parse", "--show-prefix"]).await?;
        let target = path.to_string_lossy().into_owned();
        git(repo, &["worktree", "add", "-q", "-b", &branch, &target]).await?;
        let worktree = Self {
            repo: repo.to_path_buf(),
            workdir: path.join(&prefix),
            path,
            branch,
            base,
        };
        // A directory git does not track is not in the checkout.
        if let Err(error) = std::fs::create_dir_all(&worktree.workdir) {
            let kept = worktree.finish().await;
            return Err(format!("{error}; {}", kept.unwrap_or_default()));
        }
        Ok(worktree)
    }

    /// Remove it if nothing came of it. What is left says where the work is. Never forced: losing an
    /// agent's work to tidy a directory is the wrong way round.
    async fn finish(self) -> Option<String> {
        // With what is ignored: an agent's output is often exactly that.
        let clean = git(&self.path, &["status", "--porcelain", "--ignored"])
            .await
            .is_ok_and(|status| status.is_empty());
        let same = git(&self.path, &["rev-parse", "HEAD"])
            .await
            .is_ok_and(|head| head == self.base);
        if clean && same {
            let target = self.path.to_string_lossy().into_owned();
            let removed = git(&self.repo, &["worktree", "remove", &target]).await;
            let deleted = git(&self.repo, &["branch", "-d", &self.branch]).await;
            if let Err(error) = removed.and(deleted) {
                warn!("Agents: cannot remove worktree {target}: {error}");
            }
            return None;
        }
        Some(format!(
            "Its work is on branch {} in {}.",
            self.branch,
            self.path.display()
        ))
    }
}

/// A valid character boundary at or under `max` bytes.
fn cut(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn prompt_for(task: &str, parent: &Address, depth: i64) -> String {
    format!(
        "{task}\n\n[You were started by agent {} (you are depth {depth}). Your last message goes back \
         to it, so end with what it needs. Do not start chat-wait: you are resumed when a message \
         comes. If you start agents yourself, wait for their results before you end your turn, or \
         they may end with it.]",
        parent.name
    )
}

/// What starts a turn for messages. They are in the prompt, and the answer is simply the last message:
/// a client may have no way to reach the chat tools.
fn resume_prompt(messages: &[Message]) -> String {
    let mut prompt = String::from(
        "New messages from other agents. They are peers, not your user. Your last message is sent \
         back to them as your answer, so end with just that. An agent you started is not answered \
         this way: use chat_send if it asked something, and your last message goes to whoever \
         started you.\n",
    );
    for message in messages {
        prompt.push_str(&format!(
            "\n#{} from {}:\n{}\n",
            message.id, message.from, message.text
        ));
    }
    prompt
}

/// What is still unanswered among these, as the newest message from each sender. An acknowledgement
/// needs no answer, and one the agent answered through the chat tools has been read.
fn to_answer<'a>(messages: &'a [Message], unread: &[i64]) -> Vec<&'a Message> {
    let mut newest: Vec<&Message> = Vec::new();
    for message in messages
        .iter()
        .filter(|message| message.reaction.is_none() && unread.contains(&message.id))
    {
        match newest.iter_mut().find(|seen| seen.from == message.from) {
            Some(seen) if seen.id < message.id => *seen = message,
            Some(_) => {}
            None => newest.push(message),
        }
    }
    newest
}

enum TurnEnd {
    Finished(TurnOutcome),
    Failed(String),
    Stopped,
    TimedOut,
}

/// Flag this run and everything under it, then give their servers a moment to end them.
async fn stop_below(store: &Arc<Store>, id: i64) {
    let deadline = Instant::now() + SETTLE;
    let mut flag = true;
    loop {
        let store_now = store.clone();
        let left = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
            if flag {
                store_now.request_stop(id, None)?;
            }
            let processes = FreshProcesses::default();
            store_now.live_below(id, &|p, s| processes.alive(p, s))
        })
        .await;
        match left {
            Ok(Ok(0)) => return,
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                warn!("Agents: cannot stop what run {id} started: {error:#}");
                return;
            }
            Err(error) => {
                warn!("Agents: cannot stop what run {id} started: {error}");
                return;
            }
        }
        if Instant::now() >= deadline {
            warn!("Agents: what run {id} started has not ended in {SETTLE:?}");
            return;
        }
        flag = false;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn stop_requested(store: &Arc<Store>, id: i64) -> bool {
    let store = store.clone();
    let answer = tokio::task::spawn_blocking(move || {
        store
            .run(id, now_ms(), &|_, _| true)
            .map(|run| run.is_some_and(|run| run.stop_requested))
    })
    .await;
    match answer {
        Ok(Ok(asked)) => asked,
        Ok(Err(error)) => {
            warn!("Agents: cannot read run {id}: {error:#}");
            false
        }
        Err(error) => {
            warn!("Agents: cannot read run {id}: {error}");
            false
        }
    }
}

/// One turn, until it ends, is asked to stop, or runs out of time.
async fn turn(
    sup: &Supervisor,
    store: &Arc<Store>,
    run: &RunTask,
    prompt: String,
    session: Option<String>,
) -> TurnEnd {
    let request = TurnRequest {
        key: run.id,
        plugin: run.plugin.clone(),
        access: Some(run.access),
        workdir: run.workdir.clone(),
        remote_session_id: session,
        prompt,
        extra_env: vec![(RUN_ENV.to_owned(), run.id.to_string())],
    };
    let deadline = Instant::now() + run.timeout;
    let mut ending = None;
    let work = sup.runner.run_turn(request, |_| {});
    tokio::pin!(work);
    loop {
        tokio::select! {
            outcome = &mut work => {
                return match (ending, outcome) {
                    (Some(end), _) => end,
                    (None, Ok(outcome)) => TurnEnd::Finished(outcome),
                    (None, Err(error)) => TurnEnd::Failed(error.to_string()),
                };
            }
            () = tokio::time::sleep(POLL), if ending.is_none() => {
                if stop_requested(store, run.id).await {
                    ending = Some(TurnEnd::Stopped);
                } else if Instant::now() >= deadline {
                    ending = Some(TurnEnd::TimedOut);
                }
                if ending.is_some() {
                    stop_below(store, run.id).await;
                    sup.runner.cancel(run.id).await;
                }
            }
        }
    }
}

async fn record(
    store: &Arc<Store>,
    id: i64,
    state: RunState,
    result: Option<String>,
    error: Option<String>,
) {
    let store = store.clone();
    let saved = tokio::task::spawn_blocking(move || {
        let result = result.as_deref().map(|text| cut(text, MAX_RESULT_BYTES));
        store.set_run_outcome(id, state, result, error.as_deref(), now_ms())
    })
    .await;
    match saved {
        Ok(Ok(())) => {}
        Ok(Err(error)) => warn!("Agents: cannot record run {id}: {error:#}"),
        Err(error) => warn!("Agents: cannot record run {id}: {error}"),
    }
}

/// Tell the parent, through the chat, so that it reaches it however it is listening. From the agent
/// and not from the parent's own server: a reply then goes to the one that did the work, and an agent
/// resumed by its own report would answer itself.
async fn report(chat: &ChatSession, id: i64, text: String) {
    let Some(parent) = chat.address().await else {
        return;
    };
    let sent = chat
        .blocking(move |store| {
            let processes = FreshProcesses::default();
            let alive = |p: i64, s: i64| processes.alive(p, s);
            let agent = store
                .run(id, now_ms(), &alive)?
                .and_then(|run| run.agent)
                .ok_or_else(|| anyhow::anyhow!("run #{id} has no agent"))?;
            let from = store
                .address_of(&agent)?
                .ok_or_else(|| anyhow::anyhow!("no agent {agent}"))?;
            let target = Target::parse(&parent.name).map_err(anyhow::Error::msg)?;
            store.send(&from, Some(&target), &text, None, now_ms(), &alive)
        })
        .await;
    if let Err(error) = sent {
        warn!("Agents: cannot report to the parent: {error:#}");
    }
}

/// The whole life of a run.
async fn supervise(
    sup: Arc<Supervisor>,
    chat: Arc<ChatSession>,
    parent: Address,
    mut run: RunTask,
    depth: i64,
) {
    let store = chat.store_handle();
    let prompt = prompt_for(&run.task, &parent, depth);
    let first = turn(&sup, &store, &run, prompt, None).await;
    let label = format!("Run #{} ({})", run.id, run.plugin.id);
    let worktree = run.worktree.take();

    let mut session = None;
    let finished = match first {
        TurnEnd::Finished(outcome) if outcome.cancelled => {
            Some((RunState::Stopped, format!("{label} was stopped."), None))
        }
        TurnEnd::Finished(outcome) => {
            let how = if outcome.completed {
                "finished"
            } else {
                "ended without finishing its turn"
            };
            let shown = outcome
                .full_text
                .chars()
                .take(REPORT_CHARS)
                .collect::<String>();
            let more = if shown.len() < outcome.full_text.len() {
                format!(" Whole text: agent_ls {{run:{}}}.", run.id)
            } else {
                String::new()
            };
            let text = format!("{label} {how}:\n{shown}{more}");
            session.clone_from(&outcome.remote_session_id);
            // In this order: whoever sees it idle can count on the report being there.
            report(&chat, run.id, text).await;
            record(
                &store,
                run.id,
                RunState::Idle,
                Some(outcome.full_text),
                None,
            )
            .await;
            None
        }
        TurnEnd::Failed(error) => {
            let text = format!("{label} failed: {error}");
            Some((RunState::Failed, text, Some(error)))
        }
        TurnEnd::Stopped => Some((RunState::Stopped, format!("{label} was stopped."), None)),
        TurnEnd::TimedOut => {
            let error = format!("no end in {} min", run.timeout.as_secs() / 60);
            Some((
                RunState::Failed,
                format!("{label} was stopped: {error}."),
                Some(error),
            ))
        }
    };

    let (end, error) = match finished {
        Some((state, text, error)) => {
            report(&chat, run.id, text).await;
            (state, error)
        }
        None => {
            let (state, failure) = stay_resumable(&sup, &store, &run, session).await;
            if let Some(error) = &failure {
                report(&chat, run.id, format!("{label} failed: {error}")).await;
            }
            (state, failure)
        }
    };

    if end == RunState::Stopped {
        stop_below(&store, run.id).await;
    }
    decline_unread(&store, run.id).await;
    sup.runner.stop_session(run.id).await;
    if let Some(worktree) = worktree
        && let Some(left) = worktree.finish().await
    {
        report(&chat, run.id, format!("{label}: {left}")).await;
    }
    // Last of all. This gives up the name, so anything said as this agent has to come first, and a
    // leaving server takes it to mean the run has finished tidying up.
    record(&store, run.id, end, None, error).await;
}

/// What is unread for this agent, marked as shown so that it starts one turn and not one per poll.
async fn take_unread(store: &Arc<Store>, name: &str) -> anyhow::Result<Vec<Message>> {
    let store = store.clone();
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || Ok(store.take_unread(&name, now_ms())?.messages)).await?
}

/// What is new for this agent. Something already shown to a server of its own is for that turn.
async fn take_messages(store: &Arc<Store>, name: &str) -> anyhow::Result<Vec<Message>> {
    let mut messages = take_unread(store, name).await?;
    messages.retain(|message| !message.shown);
    Ok(messages)
}

/// Send the agent's last message to whoever it has not answered itself, and settle what it was given:
/// a message left open would start one paid turn after another. An agent that started the sender has
/// the chat tools, or it could not have, so it answers that one itself if it wants to; what it says
/// about the result of its own work goes to whoever started it.
async fn answer(
    store: &Arc<Store>,
    id: i64,
    messages: &[Message],
    text: &str,
) -> anyhow::Result<()> {
    let store = store.clone();
    let messages = messages.to_vec();
    let text = if text.trim().is_empty() {
        NO_ANSWER.to_owned()
    } else {
        cut(text, MAX_RESULT_BYTES).to_owned()
    };
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        // Read now: the agent may have renamed itself during the turn.
        let name = store
            .run(id, now_ms(), &|_, _| true)?
            .and_then(|run| run.agent)
            .ok_or_else(|| anyhow::anyhow!("run #{id} has no agent"))?;
        let me = store
            .address_of(&name)?
            .ok_or_else(|| anyhow::anyhow!("no agent {name}"))?;
        let still = store.unread_ids(&name)?;
        let processes = FreshProcesses::default();
        let alive = |p: i64, s: i64| processes.alive(p, s);
        let mut upward = false;
        for message in to_answer(&messages, &still) {
            let sender = parse_address(&message.from)
                .map_or_else(|| message.from.clone(), |address| address.name);
            if store
                .address_of(&sender)?
                .is_some_and(|address| address.parent == name)
            {
                upward = true;
                continue;
            }
            // One that cannot be delivered must not cost the others theirs.
            if let Err(error) = store.send(&me, None, &text, Some(message.id), now_ms(), &alive) {
                warn!("Agents: {name} cannot answer #{}: {error:#}", message.id);
            }
        }
        if upward && me.parent != NONE {
            let target = Target::parse(&me.parent).map_err(anyhow::Error::msg)?;
            if let Err(error) = store.send(&me, Some(&target), &text, None, now_ms(), &alive) {
                warn!("Agents: {name} cannot report to {}: {error:#}", me.parent);
            }
        }
        // The earlier ones from those senders are answered by the same text.
        let shown: Vec<i64> = messages.iter().map(|message| message.id).collect();
        store.ack(&name, &shown, now_ms())?;
        Ok(())
    })
    .await?
}

/// Whoever wrote to it and was not read gets told, rather than waiting on an agent that is not coming.
async fn decline_unread(store: &Arc<Store>, id: i64) {
    let store_now = store.clone();
    let agent = tokio::task::spawn_blocking(move || {
        store_now
            .run(id, now_ms(), &|_, _| true)
            .map(|run| run.and_then(|run| run.agent))
    })
    .await;
    let name = match agent {
        Ok(Ok(Some(name))) => name,
        Ok(Ok(None)) => return,
        Ok(Err(error)) => {
            warn!("Agents: cannot read run {id}: {error:#}");
            return;
        }
        Err(error) => {
            warn!("Agents: cannot read run {id}: {error}");
            return;
        }
    };
    match take_unread(store, &name).await {
        Ok(messages) if messages.is_empty() => {}
        Ok(messages) => {
            if let Err(error) = answer(store, id, &messages, ENDED_UNREAD).await {
                warn!("Agents: cannot answer for run {id}: {error:#}");
            }
        }
        Err(error) => warn!("Agents: cannot read messages of run {id}: {error:#}"),
    }
}

/// A server is leaving. What it started goes with it either way; this is so that those runs end
/// properly first, with worktrees tidied and states recorded, rather than being cut off.
pub struct Leaving {
    store: Arc<Store>,
    owner: (i64, i64),
}

impl Leaving {
    pub fn new(chat: &ChatSession) -> Self {
        Self {
            store: chat.store_handle(),
            owner: chat.owner(),
        }
    }

    pub async fn finish(self) {
        let deadline = Instant::now() + LEAVE;
        loop {
            let store = self.store.clone();
            let owner = self.owner;
            match tokio::task::spawn_blocking(move || store.stop_owned(owner)).await {
                Ok(Ok(0)) => return,
                Ok(Ok(left)) => {
                    if Instant::now() >= deadline {
                        warn!("Agents: leaving with {left} runs not ended");
                        return;
                    }
                }
                Ok(Err(error)) => {
                    warn!("Agents: cannot stop runs on the way out: {error:#}");
                    return;
                }
                Err(error) => {
                    warn!("Agents: cannot stop runs on the way out: {error}");
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// Its turn is over. Start another when a message comes for it, until it has been idle too long.
async fn stay_resumable(
    sup: &Supervisor,
    store: &Arc<Store>,
    run: &RunTask,
    mut session: Option<String>,
) -> (RunState, Option<String>) {
    let warm = matches!(
        run.plugin.transport,
        agent_runner::TransportMode::PersistentNdjson
    );
    let mut idle_since = Instant::now();
    while idle_since.elapsed() < IDLE_LIMIT {
        if stop_requested(store, run.id).await {
            return (RunState::Stopped, None);
        }
        tokio::time::sleep(POLL).await;
        let resumable = warm || (session.is_some() && !run.plugin.args_resume.is_empty());
        if !resumable {
            return (RunState::Done, None);
        }
        let id = run.id;
        let store_for_read = store.clone();
        let due = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<String>> {
            let now = now_ms();
            let Some(name) = store_for_read
                .run(id, now, &|_, _| true)?
                .and_then(|row| row.agent)
            else {
                return Ok(None);
            };
            Ok(store_for_read.has_wakeful(&name, now)?.then_some(name))
        })
        .await;
        let name = match due {
            Ok(Ok(Some(name))) => name,
            Ok(Ok(None)) => continue,
            Ok(Err(error)) => {
                warn!("Agents: cannot check run {id}: {error:#}");
                continue;
            }
            Err(error) => {
                warn!("Agents: cannot check run {id}: {error}");
                continue;
            }
        };
        let messages = match take_messages(store, &name).await {
            Ok(messages) if messages.is_empty() => continue,
            Ok(messages) => messages,
            Err(error) => {
                warn!("Agents: cannot read messages of run {id}: {error:#}");
                continue;
            }
        };
        record(store, id, RunState::Running, None, None).await;
        let prompt = resume_prompt(&messages);
        match turn(sup, store, run, prompt, session.clone()).await {
            TurnEnd::Finished(outcome) if !outcome.cancelled => {
                if outcome.remote_session_id.is_some() {
                    session.clone_from(&outcome.remote_session_id);
                }
                if let Err(error) = answer(store, id, &messages, &outcome.full_text).await {
                    warn!("Agents: cannot send the answer of run {id}: {error:#}");
                }
                record(store, id, RunState::Idle, Some(outcome.full_text), None).await;
                idle_since = Instant::now();
            }
            TurnEnd::Failed(error) => return give_up(store, id, &messages, error).await,
            TurnEnd::TimedOut => {
                let error = format!("no end in {} min", run.timeout.as_secs() / 60);
                return give_up(store, id, &messages, error).await;
            }
            TurnEnd::Finished(_) | TurnEnd::Stopped => {
                if let Err(error) = answer(store, id, &messages, STOPPED_UNANSWERED).await {
                    warn!("Agents: cannot answer for run {id}: {error:#}");
                }
                return (RunState::Stopped, None);
            }
        }
    }
    (RunState::Done, None)
}

/// A resumed turn has failed: whoever wrote is told, and `supervise` tells whoever started it.
async fn give_up(
    store: &Arc<Store>,
    id: i64,
    messages: &[Message],
    error: String,
) -> (RunState, Option<String>) {
    let text = format!("I could not answer this: {error}");
    if let Err(failure) = answer(store, id, messages, &text).await {
        warn!("Agents: cannot report the failure of run {id}: {failure:#}");
    }
    (RunState::Failed, Some(error))
}

#[tool_router(router = agents_router, vis = "pub(crate)")]
impl FileSystemServer {
    #[tool(
        name = "agent_start",
        description = "Start another agent on a task and go on working: its result comes back as a chat message. `client` is claude, codex, agy or cursor. `access`: read (default), write, full, within what your user allows. `worktree`: true gives it its own git worktree. `timeoutMin`: per turn, default 30. It can be sent messages by name; agent_ls shows it. Tell your user what you started."
    )]
    async fn agent_start(
        &self,
        Parameters(args): Parameters<AgentStartArgs>,
    ) -> Result<CallToolResult, McpError> {
        let invalid = |text: String| McpError::invalid_params(text, None);
        let chat = self.chat_session()?;
        let chat_arc = self
            .chat
            .clone()
            .ok_or_else(|| invalid("the chat is off".to_owned()))?;
        let sup = self
            .agents
            .clone()
            .ok_or_else(|| invalid("starting agents is not available in this server".to_owned()))?;
        if !sup.limits.spawn {
            return Err(invalid(
                "your user has turned this off: FS_MCP_AGENT_SPAWN".to_owned(),
            ));
        }
        if args.task.trim().is_empty() || args.task.len() > MAX_TASK_BYTES {
            return Err(invalid(format!(
                "a task is not empty and at most {MAX_TASK_BYTES} bytes: put more in a file and name it"
            )));
        }
        let me = chat_me(chat).await?;
        let plugin = sup.plugin(&args.client)?;
        let access = match args.access.as_deref() {
            Some(word) => parse_access(word)
                .ok_or_else(|| invalid(format!("access is read, write or full, not {word}")))?,
            None => Access::Read,
        };
        if rank(access) > rank(sup.limits.max_access) {
            return Err(invalid(format!(
                "your user allows at most {} access: FS_MCP_AGENT_MAX_ACCESS",
                sup.limits.max_access
            )));
        }
        let cwd = match args.cwd.as_deref() {
            Some(raw) => plain_path(&self.resolve(raw).await?),
            None => std::env::current_dir()
                .map_err(|error| McpError::internal_error(error.to_string(), None))?,
        };
        // Refused here, in the answer, and not later in a message: a level this client cannot express.
        plugin
            .render_args(None, "", &cwd, Some(access))
            .map_err(|error| invalid(error.to_string()))?;
        let timeout_min = args
            .timeout_min
            .get()
            .unwrap_or(DEFAULT_TIMEOUT_MIN)
            .clamp(1, MAX_TIMEOUT_MIN);

        let owner = chat.owner();
        let (client, task, cwd_text, word) = (
            plugin.id.clone(),
            args.task.clone(),
            cwd.to_string_lossy().into_owned(),
            access.to_string(),
        );
        let (max_depth, max_tree) = (sup.limits.max_depth, sup.limits.max_tree);
        let me_for_store = me.clone();
        let (id, depth, agent) = chat
            .blocking(move |store| {
                let processes = Processes::now();
                let alive = |p: i64, s: i64| processes.alive(p, s);
                let now = now_ms();
                // An agent cannot hand out more than it was given. One with a parent and no run of
                // its own was given something nobody here can tell: its client filtered the variable
                // that says which run it is, or it is a second server of that client.
                let own = match store.run_of_agent(&me_for_store.name, now, &alive)? {
                    Some(mine) => Some(parse_access(&mine.access).unwrap_or(Access::Read)),
                    None if store.depth_of(&me_for_store.name)? > 0 => Some(Access::Read),
                    None => None,
                };
                if let Some(own) = own
                    && rank(access) > rank(own)
                {
                    anyhow::bail!("you have {own} access, so you cannot give {access}");
                }
                let new = NewRun {
                    owner,
                    client: &client,
                    task: &task,
                    cwd: &cwd_text,
                    access: &word,
                    max_depth,
                    max_tree,
                };
                let id = store.start_run(&me_for_store, &new, now, &alive)?;
                let run = store
                    .run(id, now, &alive)?
                    .ok_or_else(|| anyhow::anyhow!("run #{id} has gone"))?;
                Ok((id, run.depth, run.agent))
            })
            .await
            .map_err(chat_error)?;

        let worktree = if *args.worktree {
            match Worktree::create(&cwd, &sup.worktrees, id).await {
                Ok(worktree) => {
                    let path = worktree.path.to_string_lossy().into_owned();
                    let saved = chat
                        .blocking(move |store| store.set_run_worktree(id, &path))
                        .await;
                    if let Err(error) = saved {
                        // Nothing will look after this run, so it must not read as running.
                        let text = error.to_string();
                        let closed = chat
                            .blocking(move |store| {
                                store.set_run_outcome(
                                    id,
                                    RunState::Failed,
                                    None,
                                    Some(&text),
                                    now_ms(),
                                )
                            })
                            .await;
                        if let Err(failure) = closed {
                            warn!("Agents: cannot close run {id}: {failure:#}");
                        }
                        if let Some(left) = worktree.finish().await {
                            warn!("Agents: run {id} left a worktree: {left}");
                        }
                        return Err(chat_error(error));
                    }
                    Some(worktree)
                }
                Err(error) => {
                    let message = format!("cannot make a worktree of {}: {error}", cwd.display());
                    let text = message.clone();
                    chat.blocking(move |store| {
                        store.set_run_outcome(id, RunState::Failed, None, Some(&text), now_ms())
                    })
                    .await
                    .map_err(chat_error)?;
                    return Err(invalid(message));
                }
            }
        } else {
            None
        };
        let workdir = worktree
            .as_ref()
            .map_or_else(|| cwd.clone(), |worktree| worktree.workdir.clone());
        // A started agent's server ends with its turn on most clients, and takes this one with it.
        let next = if depth > 1 {
            "Its result arrives as a chat message, and you can write to it by name. Wait for it with chat_read {waitS} before you end your turn: it may end with yours."
        } else {
            "Its result arrives as a chat message, and you can write to it by name. Go on with your work."
        };
        let reply = json!({
            "run": id,
            "agent": agent,
            "depth": depth,
            "workdir": workdir.to_string_lossy(),
            "next": next,
        });
        let run = RunTask {
            id,
            plugin,
            access,
            workdir,
            task: args.task,
            timeout: Duration::from_secs(timeout_min * 60),
            worktree,
        };
        tokio::spawn(supervise(sup, chat_arc, me, run, depth));
        ok(reply)
    }

    #[tool(
        name = "agent_stop",
        description = "Stop an agent you started, or one started by an agent you started, with everything it started. `run` is its number in agent_start or agent_ls."
    )]
    async fn agent_stop(
        &self,
        Parameters(args): Parameters<AgentStopArgs>,
    ) -> Result<CallToolResult, McpError> {
        let chat = self.chat_session()?;
        let me = chat_me(chat).await?;
        let id = args.run as i64;
        let state = chat
            .blocking(move |store| {
                store.request_stop(id, Some(&me))?;
                let processes = FreshProcesses::default();
                store
                    .run(id, now_ms(), &|p, s| processes.alive(p, s))?
                    .map(|run| run.state)
                    .ok_or_else(|| anyhow::anyhow!("run #{id} has gone"))
            })
            .await
            .map_err(chat_error)?;
        ok(json!({ "run": id, "was": state, "next": state.stop_note() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: i64, from: &str, reaction: Option<&str>) -> Message {
        Message {
            id,
            from: from.to_owned(),
            to: "Kid".to_owned(),
            text: format!("text {id}"),
            reply_to: None,
            reaction: reaction.map(str::to_owned),
            hops: 0,
            sent_at: 0,
            shown: false,
        }
    }

    #[tokio::test]
    async fn an_agent_is_not_answered_to_one_it_started_and_says_it_to_whoever_started_it() {
        use agent_chat::store::Join;

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("chat.db"), now_ms()).unwrap());
        let alive = |_: i64, _: i64| true;
        let join = |pid: i64, parent: &str| {
            let join = Join {
                project: "p".to_owned(),
                topic: NONE.to_owned(),
                parent: parent.to_owned(),
                client: "c".to_owned(),
                pid,
                pid_start: 1,
                status: None,
            };
            store.join(&join, None, None, now_ms(), &alive).unwrap()
        };
        let root = join(1, NONE);
        let new = NewRun {
            owner: (1, 1),
            client: "c",
            task: "t",
            cwd: "/",
            access: "read",
            max_depth: 8,
            max_tree: 8,
        };
        let id = store.start_run(&root, &new, now_ms(), &alive).unwrap();
        let agent = store
            .run(id, now_ms(), &alive)
            .unwrap()
            .unwrap()
            .agent
            .unwrap();
        let kid = join(3, &agent);
        let target = Target::parse(&agent).unwrap();
        store
            .send(&kid, Some(&target), "done", None, now_ms(), &alive)
            .unwrap();
        let messages = store.take_unread(&agent, now_ms()).unwrap().messages;
        answer(&store, id, &messages, "my result").await.unwrap();

        assert!(!store.has_unread(&agent).unwrap(), "settled");
        assert!(
            !store.has_unread(&kid.name).unwrap(),
            "no answer to the kid"
        );
        let up = store.take_unread(&root.name, now_ms()).unwrap().messages;
        assert_eq!(up.len(), 1, "{up:?}");
        assert_eq!(up[0].text, "my result");
    }

    #[test]
    fn the_messages_are_in_the_prompt_because_a_client_may_not_reach_the_chat_tools() {
        let prompt = resume_prompt(&[message(7, "Erdos", None)]);
        assert!(prompt.contains("#7 from Erdos"), "{prompt}");
        assert!(prompt.contains("text 7"), "{prompt}");
        assert!(!prompt.contains("chat_read"), "{prompt}");
    }

    #[test]
    fn one_answer_goes_to_each_sender_and_never_to_what_it_answered_itself() {
        let messages = [
            message(1, "Erdos", None),
            message(2, "Erdos", None),
            message(3, "Halsted", None),
            message(4, "Noether", None),
            message(5, "Curie", Some("ok")),
        ];
        // Halsted's was answered through the chat tools, so it is no longer unread.
        let answered = to_answer(&messages, &[1, 2, 4, 5]);
        let ids: Vec<i64> = answered.iter().map(|message| message.id).collect();
        assert_eq!(ids, [2, 4]);
    }

    #[test]
    fn a_path_handed_on_has_no_verbatim_prefix() {
        assert_eq!(
            plain_path(Path::new(r"\\?\C:\work\a")),
            Path::new(r"C:\work\a")
        );
        assert_eq!(plain_path(Path::new("/work/a")), Path::new("/work/a"));
    }

    #[test]
    fn a_cut_never_splits_a_character() {
        assert_eq!(cut("abc", 10), "abc");
        assert_eq!(cut("\u{44f}\u{44f}", 3), "\u{44f}");
        assert_eq!(cut("", 3), "");
    }

    #[test]
    fn access_levels_are_ordered_and_a_typo_is_nothing() {
        assert!(rank(Access::Read) < rank(Access::Write));
        assert!(rank(Access::Write) < rank(Access::Full));
        assert_eq!(parse_access(" Write "), Some(Access::Write));
        assert_eq!(parse_access("everything"), None);
    }

    #[test]
    fn the_prompt_tells_a_started_agent_who_started_it_and_not_to_wait() {
        let parent = Address {
            project: "p".to_owned(),
            topic: "-".to_owned(),
            name: "Erdos".to_owned(),
            parent: "-".to_owned(),
        };
        let prompt = prompt_for("review it", &parent, 2);
        assert!(prompt.starts_with("review it"));
        assert!(prompt.contains("Erdos"));
        assert!(prompt.contains("depth 2"));
        assert!(prompt.contains("chat-wait"));
    }
}
