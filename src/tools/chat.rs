//! `crates/agent-chat` as MCP: the `chat_*` tools and the two hooks `call_tool` runs around every
//! tool, which are how a message reaches a working agent.
//!
//! Lives here rather than in the crate because `#[tool_router]` is tied to the server type, and a
//! separate gated impl block because it cannot gate a method. Messages are written to `content` and
//! to the `chat` field of `structuredContent` because a client may read either one: Claude Code
//! 2.1.316 shows the model only `structuredContent` when a result has it, so a `content` block alone
//! never arrives there.

use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_chat::address::{Address, NONE, Target, clean_segment, git_project};
use agent_chat::session::{
    Change, ChatSession, Delivery, FreshProcesses, PARENT_ENV, Processes, READ_LABEL, advice,
    messages_json, now_ms, read_page,
};
use agent_chat::store::{AgentState, Reaction, Store};
use agent_chat::wait::POLL;
use rmcp::{
    ErrorData as McpError, RoleServer,
    handler::server::wrapper::Parameters,
    model::{CallToolResponse, CallToolResult, ContentBlock, ProgressNotificationParam},
    serde::Deserialize,
    service::RequestContext,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde_json::{Value, json};
use tracing::warn;

use crate::core::serde::{FlexU64, vec_or_string};
use crate::{FileSystemServer, WithStructured};

/// The longest single wait. Under the 3 minutes Antigravity gives an MCP call, because a call cut off
/// by the client returns nothing. Staying reachable while idle is `chat-wait`'s job, not this one's.
const MAX_WAIT_S: u64 = 150;
/// Some clients reset their timeout on progress, which only helps if it keeps coming.
const PROGRESS_EVERY: Duration = Duration::from_secs(20);
/// Larger than this belongs in a file, with the path in the message.
const MAX_TEXT_BYTES: usize = 64 * 1024;
/// How many of this agent's own messages `sent` may ask about.
const MAX_SENT: u64 = 100;
/// A status is a line in a list that other agents read, not a place for a message.
const MAX_STATUS_BYTES: usize = 200;

// Plain `//` on these wire types: a `///` here becomes schema text in every session.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ChatJoinArgs {
    name: Option<String>,
    topic: Option<String>,
    parent: Option<String>,
    project: Option<String>,
    status: Option<String>,
    #[serde(default, alias = "quiet_min")]
    quiet_min: FlexU64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ChatSendArgs {
    text: Option<String>,
    react: Option<String>,
    to: Option<String>,
    #[serde(default, alias = "reply_to")]
    reply_to: FlexU64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ChatReadArgs {
    #[serde(default, alias = "wait_s")]
    wait_s: FlexU64,
    #[serde(default, deserialize_with = "vec_or_string")]
    ack: Vec<i64>,
    #[serde(default, deserialize_with = "vec_or_string")]
    show: Vec<i64>,
    #[serde(default)]
    sent: FlexU64,
}

/// A database failure is ours; anything else the store refuses is about what the caller asked for.
fn chat_error(error: anyhow::Error) -> McpError {
    if error.chain().any(|cause| cause.is::<rusqlite::Error>()) {
        McpError::internal_error(format!("{error:#}"), None)
    } else {
        McpError::invalid_params(format!("{error:#}"), None)
    }
}

fn ok(value: Value) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string(&value)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(value))
}

/// `run_command` must not start `chat-wait`. It would look right, the agent would read as `listening`,
/// and no client would ever wake for it, since a client only wakes for a process it started itself.
/// Measured on Cursor Agent, and likely wherever a session policy steers all shell work to this
/// server. Looks for the words of the command, so a search for that text in quotes is not refused.
pub(crate) fn refuse_chat_wait(command: &str, args: &[String]) -> Result<(), McpError> {
    let words: Vec<&str> = command
        .split_whitespace()
        .chain(args.iter().map(String::as_str))
        .collect();
    if words.contains(&"chat-wait") && words.contains(&"--db") {
        return Err(McpError::invalid_params(
            "chat-wait has to run through your client's own built-in shell tool as a background \
             command: your client can only wake you for a process it started itself. This is the \
             one exception to using this server for shell work.",
            None,
        ));
    }
    Ok(())
}

/// Both channels: see the module docs. Text that is not an object has nowhere to put a field, and
/// the MCP spec requires an object there anyway.
fn apply(result: &mut CallToolResult, delivery: Delivery) {
    result.content.push(ContentBlock::text(delivery.text));
    if let Some(Value::Object(structured)) = result.structured_content.as_mut() {
        structured.insert("chat".to_owned(), delivery.json);
    }
}

/// Clears `listening` however the wait ends, including the client dropping the call.
struct Listening {
    store: Arc<Store>,
    name: String,
    until: i64,
}

impl Drop for Listening {
    fn drop(&mut self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = self.store.clone();
        let name = std::mem::take(&mut self.name);
        let until = self.until;
        runtime.spawn_blocking(move || {
            if let Err(error) = store.clear_listening(&name, until) {
                warn!("chat: cannot clear listening: {error:#}");
            }
        });
    }
}

#[tool_router(router = chat_router, vis = "pub(crate)")]
impl FileSystemServer {
    #[tool(
        name = "chat_join",
        description = "Set your status, as in any chat. `status` says what you are up to, empty clears it. `quietMin` asks not to be disturbed for that many minutes, 0 ends it: messages wait until then and senders are told. Also `topic`, `parent`, `project`; `name` renames you or takes over a closed agent's name with its unread messages."
    )]
    async fn chat_join(
        &self,
        Parameters(args): Parameters<ChatJoinArgs>,
    ) -> Result<CallToolResult, McpError> {
        let chat = self.chat_session()?;
        if let Some(status) = &args.status
            && (status.len() > MAX_STATUS_BYTES || status.contains('\n'))
        {
            return Err(McpError::invalid_params(
                format!("a status is one line, at most {MAX_STATUS_BYTES} bytes"),
                None,
            ));
        }
        let renamed = args.name.is_some();
        let quiet_min = args.quiet_min.get();
        let me = chat
            .change(Change {
                name: args.name,
                topic: args.topic,
                parent: args.parent,
                project: args.project,
                status: args.status,
                quiet_min,
            })
            .await
            .map_err(chat_error)?;
        let mut reply = json!({ "you": me.to_string() });
        // A rename ends a running wait, whose command names the old name.
        if renamed && let Some(command) = chat.wait_command(&me.name) {
            reply["waitCommand"] = json!(command);
        }
        ok(reply)
    }

    #[tool(
        name = "chat_who",
        description = "Agents in the chat on this machine: address project:topic:name:parent, client, state (listening, quiet, working, idle, closed), unread count, status."
    )]
    async fn chat_who(&self) -> Result<CallToolResult, McpError> {
        let chat = self.chat_session()?;
        let me = chat_me(chat).await?;
        let agents = chat
            .blocking(|store| {
                let processes = Processes::now();
                store.who(now_ms(), &|p, s| processes.alive(p, s))
            })
            .await
            .map_err(chat_error)?;
        ok(json!({ "you": me.to_string(), "agents": agents }))
    }

    #[tool(
        name = "chat_send",
        description = "Send a message to another agent: ask one when stuck or when it may know. `to` is a name (Erdos), a full address, or a mask with * per segment (myproject:*:*:*) reaching live agents. `replyTo` answers a message by id, goes back to its sender without `to`, and marks it read. Instead of `text`, `react` answers it in one word, cheap for both sides: yes, no, dontknow, wilco, sayagain wake the sender; roger, ok, seen, thanks, standby, out do not and take no answer. It arrives at once if the recipient is `listening`, else in their next tool result."
    )]
    async fn chat_send(
        &self,
        Parameters(args): Parameters<ChatSendArgs>,
    ) -> Result<CallToolResult, McpError> {
        let chat = self.chat_session()?;
        let me = chat_me(chat).await?;
        let reply_to = args.reply_to.get().map(|id| id as i64);
        let reaction = match (&args.text, &args.react, reply_to) {
            (Some(_), Some(_), _) => {
                return Err(McpError::invalid_params("text or react, not both", None));
            }
            (None, Some(_), Some(_)) if args.to.is_some() => {
                return Err(McpError::invalid_params(
                    "react goes to the other side of replyTo: no `to` with it",
                    None,
                ));
            }
            (None, None, _) => return Err(McpError::invalid_params("text is empty", None)),
            (None, Some(_), None) => {
                return Err(McpError::invalid_params(
                    "react answers a message: say which with replyTo",
                    None,
                ));
            }
            (None, Some(word), Some(_)) => Some(Reaction::parse(word).ok_or_else(|| {
                let words: Vec<&str> = Reaction::ALL.into_iter().map(Reaction::word).collect();
                McpError::invalid_params(format!("react is one of {}", words.join(", ")), None)
            })?),
            (Some(_), None, _) => None,
        };
        let text = args.text.unwrap_or_default();
        if reaction.is_none() && text.trim().is_empty() {
            return Err(McpError::invalid_params("text is empty", None));
        }
        if text.len() > MAX_TEXT_BYTES {
            return Err(McpError::invalid_params(
                format!(
                    "text is {} bytes, the limit is {MAX_TEXT_BYTES}: write it to a file and send the path",
                    text.len()
                ),
                None,
            ));
        }
        let target = args
            .to
            .as_deref()
            .map(Target::parse)
            .transpose()
            .map_err(|error| McpError::invalid_params(error, None))?;
        let sent = chat
            .blocking(move |store| {
                let processes = FreshProcesses::default();
                let alive = |p: i64, s: i64| processes.alive(p, s);
                match (reaction, reply_to) {
                    (Some(reaction), Some(id)) => store.react(&me, id, reaction, now_ms(), &alive),
                    _ => store.send(&me, target.as_ref(), &text, reply_to, now_ms(), &alive),
                }
            })
            .await
            .map_err(chat_error)?;
        let of_state =
            |state: AgentState| sent.iter().any(|message| message.recipient_state == state);
        let quiet = sent.iter().any(|message| message.quiet_for.is_some());
        // All of them: on a broadcast the others were woken, and each entry says which were not.
        let over_limit = sent.iter().all(|message| message.over_limit);
        let next = if over_limit {
            Some(
                "Too many messages or replies: this wakes nobody and arrives at their next activity. Stop and ask your human if it still matters.",
            )
        } else if quiet {
            Some("It asked for quiet and gets this when that ends. Do not resend.")
        } else if of_state(AgentState::Closed) {
            Some("That agent has closed: this waits for whoever takes its name, if anyone does.")
        } else if of_state(AgentState::Idle) {
            Some("It gets this at its next activity.")
        } else {
            None
        };
        let mut reply = json!({ "sent": sent });
        if let Some(next) = next {
            reply["next"] = json!(next);
        }
        ok(reply)
    }

    #[tool(
        name = "chat_read",
        description = "Read your unread chat messages. `waitS` waits up to that many seconds (at most 150) for a new one, for a reply you expect now. `ack` confirms ids as read. `show` gets the text of ids of yours, read or not. `sent` reports the state of your last N sent messages."
    )]
    async fn chat_read(
        &self,
        Parameters(args): Parameters<ChatReadArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let chat = self.chat_session()?;
        let me = chat_me(chat).await?;
        let name = me.name.clone();

        let wait_s = args.wait_s.get().unwrap_or(0).min(MAX_WAIT_S);
        let mut timed_out = false;
        // Without a wait, what has already been shown stays out of the reply: its text went out once
        // and `show` fetches it, or every call here would pay for it again.
        let mut new_after = i64::MAX;
        if wait_s > 0 {
            let (arrived, after) = self
                .chat_wait(chat, &name, wait_s, &context)
                .await
                .map_err(chat_error)?;
            timed_out = !arrived;
            new_after = after;
        }

        let sent = match args.sent.get().filter(|limit| *limit > 0) {
            Some(limit) => {
                let limit = limit.min(MAX_SENT) as i64;
                let name = name.clone();
                let statuses = chat
                    .blocking(move |store| store.sent_status(&name, limit))
                    .await
                    .map_err(chat_error)?;
                Some(statuses)
            }
            None => None,
        };
        let show = args.show;
        let shown = if show.is_empty() {
            Vec::new()
        } else {
            let name = name.clone();
            chat.blocking(move |store| store.show(&name, &show))
                .await
                .map_err(chat_error)?
        };
        let ack = args.ack;
        let acked = if ack.is_empty() {
            0
        } else {
            let name = name.clone();
            chat.blocking(move |store| store.ack(&name, &ack, now_ms()))
                .await
                .map_err(chat_error)?
        };
        // Last, when nothing else can fail: this is what marks messages shown.
        let unread = chat
            .blocking(move |store| store.take_unread(&name, now_ms()))
            .await
            .map_err(chat_error)?;

        let (new, older): (Vec<_>, Vec<_>) = unread
            .messages
            .into_iter()
            .partition(|message| !message.shown || message.id > new_after);
        let (messages, held_back) = read_page(new);
        let more = unread.more + held_back;
        let mut reply = json!({ "messages": messages_json(&messages) });
        if !older.is_empty() {
            let ids: Vec<i64> = older.iter().map(|message| message.id).collect();
            reply["unread"] = json!(ids);
        }
        if !shown.is_empty() {
            let (shown, not_returned) = read_page(shown);
            reply["shown"] = messages_json(&shown);
            if not_returned > 0 {
                reply["shownMore"] = json!(not_returned);
            }
        }
        if acked > 0 {
            reply["acked"] = json!(acked);
        }
        if more > 0 {
            reply["more"] = json!(more);
        }
        if let Some(statuses) = sent {
            reply["sent"] = json!(statuses);
        }
        // `label`: JSON keys sort, and this has to come before the `messages` and `shown` it labels.
        let needs_advice: Vec<_> = messages
            .iter()
            .filter(|message| message.reaction.is_none())
            .collect();
        if !needs_advice.is_empty() {
            reply["label"] = json!(advice(chat.mode(), needs_advice.into_iter()));
        } else if reply.get("shown").is_some() {
            reply["label"] = json!(READ_LABEL);
        }
        if timed_out {
            reply["timedOut"] = json!(true);
        }
        ok(reply)
    }
}

async fn chat_me(chat: &ChatSession) -> Result<Address, McpError> {
    chat.confirm_name().await;
    chat.address().await.ok_or_else(|| {
        McpError::internal_error(
            "not registered in the chat: see this server's log for why",
            None,
        )
    })
}

impl FileSystemServer {
    fn chat_session(&self) -> Result<&ChatSession, McpError> {
        self.chat.as_deref().ok_or_else(|| {
            McpError::internal_error(
                "the chat is off: chat.db could not be opened, see this server's log",
                None,
            )
        })
    }

    /// Wait for a new message: whether one arrived, and the newest id from before the wait, which is
    /// what makes a message new to this call. One already shown before
    /// this call does not end the wait: an agent that has not confirmed it yet would otherwise spin
    /// here without ever waiting. One that arrives during it does, even if a running `chat-wait`
    /// shows it first.
    async fn chat_wait(
        &self,
        chat: &ChatSession,
        name: &str,
        wait_s: u64,
        context: &RequestContext<RoleServer>,
    ) -> anyhow::Result<(bool, i64)> {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(wait_s);
        let until = now_ms() + (wait_s as i64) * 1000;
        let after = chat
            .blocking({
                let name = name.to_owned();
                move |store| {
                    store.set_listening(&name, until)?;
                    store.latest_unread_id(&name)
                }
            })
            .await?;
        let _listening = Listening {
            store: chat.store_handle(),
            name: name.to_owned(),
            until,
        };
        let progress = context.meta.get_progress_token();
        let mut next_progress = started + PROGRESS_EVERY;
        let mut sequence = 0u64;
        loop {
            let fresh = {
                let name = name.to_owned();
                chat.blocking(move |store| store.has_new(&name, after))
                    .await?
            };
            if fresh {
                return Ok((true, after));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok((false, after));
            }
            if let Some(token) = progress.clone()
                && now >= next_progress
            {
                next_progress = now + PROGRESS_EVERY;
                sequence += 1;
                let param = ProgressNotificationParam::new(token, sequence as f64)
                    .with_message("Listening to the chat");
                // Progress only keeps a client's timeout from firing. A client that is gone is
                // handled by the cancellation below, not by this.
                if let Err(error) = context.peer.notify_progress(param).await {
                    warn!("chat: progress notification failed: {error}");
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(POLL.min(deadline - now)) => {}
                _ = context.ct.cancelled() => anyhow::bail!("cancelled"),
            }
        }
    }

    /// Before every tool: join on the first call and note that this agent is active. Runs before
    /// the tool rather than after so that a first `chat_who` or `chat_send` already has an address.
    pub(crate) async fn chat_before_call(&self, context: &RequestContext<RoleServer>) {
        let Some(chat) = self.chat.as_deref() else {
            return;
        };
        // Two places because there are two protocols: a client on the stateless 2026-07-28 revision
        // (Claude Code 2.1.316) names itself per request and never sends `initialize`.
        let named = || {
            context.client_info().map(|info| info.name).or_else(|| {
                context
                    .peer
                    .peer_info()
                    .map(|info| info.client_info.name.clone())
            })
        };
        if !chat.is_registered().await {
            if let Err(error) = self.chat_join_as(named()).await {
                warn!("chat: cannot join: {error:#}");
                return;
            }
        } else if chat.client_unknown().await
            && let Some(client) = named()
            && let Err(error) = chat.identify(client).await
        {
            warn!("chat: cannot record the client's name: {error:#}");
        }
        chat.touch().await;
    }

    /// Run a tool. A long one still counts as this agent being active.
    pub(crate) async fn chat_while_busy<T>(&self, work: impl Future<Output = T>) -> T {
        match self.chat.as_deref() {
            Some(chat) => chat.while_busy(work).await,
            None => work.await,
        }
    }

    /// Join under this client's name, or as unknown until it says.
    async fn chat_join_as(&self, client: Option<String>) -> anyhow::Result<()> {
        let chat = self
            .chat_session()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let client = client.unwrap_or_else(|| "unknown".to_owned());
        chat.register(client, self.chat_project().await).await?;
        Ok(())
    }

    /// At startup, so that a broadcast reaches a session that has not called a tool yet. Its messages
    /// wait for it from here on.
    pub(crate) async fn chat_join_at_start(&self, client: Option<String>) {
        if self.chat.is_some()
            && let Err(error) = self.chat_join_as(client).await
        {
            warn!("chat: cannot join at startup: {error:#}");
        }
    }

    /// After every tool: carry what this agent has not read, which is the route that needs nothing
    /// from the agent. `chat_read` has just returned those messages itself, so repeating them would
    /// only spend tokens. A response that is not a finished result carries nothing, and the messages
    /// simply wait for the next one.
    pub(crate) async fn chat_after_call(
        &self,
        was_chat_read: bool,
        response: CallToolResponse,
    ) -> CallToolResponse {
        let Some(chat) = self.chat.as_deref() else {
            return response;
        };
        match response {
            CallToolResponse::Complete(mut result) => {
                if let Some(delivery) = chat.deliver(!was_chat_read).await {
                    apply(&mut result, delivery);
                }
                CallToolResponse::Complete(result)
            }
            other => other,
        }
    }

    /// What `run_command` adds to its child's environment: the child's parent is this agent. A
    /// value the caller set itself wins.
    pub(crate) async fn chat_child_env(
        &self,
        env: Option<std::collections::HashMap<String, String>>,
    ) -> Option<std::collections::HashMap<String, String>> {
        let Some(chat) = self.chat.as_deref() else {
            return env;
        };
        let Some(me) = chat.address().await else {
            return env;
        };
        let mut env = env.unwrap_or_default();
        env.entry(PARENT_ENV.to_owned()).or_insert(me.name);
        Some(env)
    }

    /// The working directory's git root, else an allowed root's, else the directory's own name.
    async fn chat_project(&self) -> String {
        let cwd = std::env::current_dir().ok();
        if let Some(project) = cwd.as_deref().and_then(git_project) {
            return project;
        }
        for root in self.allowed.snapshot().await {
            if let Some(project) = git_project(&root) {
                return project;
            }
        }
        cwd.as_deref()
            .and_then(std::path::Path::file_name)
            .map_or_else(
                || NONE.to_owned(),
                |name| clean_segment(&name.to_string_lossy()),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capability a model is not told about does not exist. This fails when a new word or setting
    /// reaches the code without reaching the two places a model learns about it, and when either
    /// says the wrong thing about which words wake.
    #[test]
    fn a_model_is_told_about_every_reaction_and_setting() {
        let source = include_str!("chat.rs");
        let from = source.find("name = \"chat_send\"").unwrap();
        let to = from + source[from..].find("async fn chat_send").unwrap();
        let description = &source[from..to];
        let policy = include_str!("../docs/chat_policy.md");
        let policy_line = policy
            .lines()
            .find(|line| line.contains("`react`"))
            .unwrap();
        let (waking_tool, quiet_tool) = description.split_once("wake the sender").unwrap();
        let (waking_policy, quiet_policy) = policy_line.split_once("wake the sender").unwrap();
        let has_word = |text: &str, word: &str| {
            text.split(|c: char| !c.is_ascii_alphabetic())
                .any(|token| token == word)
        };
        for reaction in Reaction::ALL {
            let word = reaction.word();
            let (tool, policy) = if reaction.wakes() {
                (waking_tool, waking_policy)
            } else {
                (quiet_tool, quiet_policy)
            };
            assert!(
                has_word(tool, word),
                "chat_send, wakes={}: {word}",
                reaction.wakes()
            );
            assert!(
                has_word(policy, word),
                "the policy, wakes={}: {word}",
                reaction.wakes()
            );
        }
        for setting in ["status", "quietMin"] {
            assert!(
                source.contains(&format!("`{setting}`")),
                "chat_join: {setting}"
            );
            assert!(policy.contains(setting), "the policy: {setting}");
        }
    }
    fn delivery() -> Delivery {
        Delivery {
            text: "hi".to_owned(),
            json: json!({"new": [{"text": "hi"}]}),
        }
    }

    #[test]
    fn delivery_reaches_both_channels_and_keeps_the_tools_own_data() {
        let mut result = CallToolResult::success(vec![ContentBlock::text("tool output")]);
        result.structured_content = Some(json!({"value": 42}));
        apply(&mut result, delivery());
        assert_eq!(result.content[0].as_text().unwrap().text, "tool output");
        assert!(result.content[1].as_text().unwrap().text.contains("hi"));
        let structured = result.structured_content.unwrap();
        assert_eq!(structured["value"], 42);
        assert_eq!(structured["chat"]["new"][0]["text"], "hi");
    }

    #[test]
    fn a_result_without_structured_data_gets_none_invented() {
        let mut result = CallToolResult::success(vec![ContentBlock::text("tool output")]);
        apply(&mut result, delivery());
        assert!(result.structured_content.is_none());
        assert_eq!(result.content.len(), 2);
    }
}
