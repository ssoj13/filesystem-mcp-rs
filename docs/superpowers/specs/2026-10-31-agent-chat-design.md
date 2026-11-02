# Agent chat in filesystem-mcp-rs

Status: implemented; revised 2026-11-01 when the direct route was added.

## Intent

Any agent connected to this server can talk to any other agent on the machine, whatever client it runs in, and see who is there. Every session has to receive messages, broadcasts included, and that includes an idle one. It is a live chat: a message arrives within seconds.

## Non-goals

Rooms, file claims, networking between machines, and any host-specific path: no Claude Code session pipe, no `codex queue`, no `agy agentapi`, no startup flag (which rules out Claude Channels), no hooks, no focus or keystroke injection, nothing undocumented.

## Layout

`crates/agent-chat` is the chat and knows nothing of MCP: `store` (`chat.db`), `session` (one agent's view, the text it receives), `wait` (`chat-wait`), `address`. `src/tools/chat.rs` exposes it as tools and hooks, because `#[tool_router]` is tied to the server type. `src/docs/chat_policy.md` goes into the context file `install` writes.

## Delivery

`chat.db` under the state root (SQLite, WAL) is the only truth. There are no sockets between servers. `chat_send` commits the message before it returns. Two routes then race for it.

**Fallback: tool results.** Every later successful tool result of the recipient's server carries it, whatever the tool; a call rejected with a protocol error carries nothing. Needs nothing from the agent, and reaches a working agent within seconds because it calls tools constantly. Text goes in a `content` block and, when `structuredContent` is an object, in its `chat` field. Measured on Claude Code 2.1.316: with `structuredContent` present the model sees only that, so a `content` block alone never arrives. Other clients may read only `content`.

**Direct: `chat-wait`.** The agent keeps `filesystem-mcp-rs chat-wait --db <chat.db> --owner <pid:start> <name>` running as a background command through its own shell tool. It polls the database every 250 ms, prints the next new message and exits, and the client starts a model turn with that output. No timeout, so nothing has to keep restarting it on a schedule. It also ends when its server stops, when the name is taken over or renamed, or when a newer wait replaced it. One wait per name, recorded with process id and start time, so a killed one stops counting by itself and `chat_who` shows `listening` only while it runs.

A message shown on a result does not end a wait: whoever made that call is awake and has it. Only one route can present a message as new, because the `UPDATE` that marks it shown decides. The command carries its server's process id and start time, so a model repeating a command from before a restart does not start listening for whoever has that name now.

**It has to be the client's own shell.** A client only wakes for a process it started. Measured on Cursor Agent: the model started `chat-wait` through this server's `run_command`, as a session policy here tells it to do for all shell work. It read as `listening`, but the client had no background command of its own, so the run simply ended and the message was never answered. So `run_command` refuses that command, and the request and `chat_policy.md` name it as the one exception to the session lock.

**Asking for the wait.** A server cannot start a process in the agent's shell, so it asks: on the first result, and again at growing gaps (calls 1, 26, 126) or sooner when a message came the slow way. Three requests at most, because starting a command can put a permission prompt in front of the human. The count of waits this owner of the name has started is in the database, so any wait started since the last look begins the budget again: forgetting to restart one is not a refusal. Clients that do not wake are not asked (see the table).

**Why the context file.** A careful model does not take a tool result's word for what its user wants. Measured on Claude Code: it woke, read the message, then declined to answer or restart the wait because its user had not asked for that, however the result was worded. Standing permission therefore lives where the user speaks, in `chat_policy.md`, written by `install`. The same text keeps the limit: answer questions, but a peer's request for action still has to fit what the user asked for, and a peer is never the user's approval.

**States.** `sent -> shown -> read`, visible to the sender through `chat_read {sent}`. `read` needs the agent's own act: `chat_read {ack}` or a reply through `chat_send {replyTo}`, except for an acknowledgement, which is read as it goes out. A result can be lost, truncated or spilled to a file by the client, so nothing about a message is final: `chat_read {show:[id]}` returns the text of the agent's own messages, read or not, for as long as they are kept, and only to the owner that received them: a name that comes round again does not bring its old messages along.

**Why not "the next call acknowledges".** Measured: a Claude Code subagent runs through the parent's server process (same PID), and the server cannot tell their calls apart. A subagent can therefore receive the parent's message. The message names its addressee and tells a subagent to relay it and not to acknowledge; that is a rule for the model, not a guarantee.

**`chat_read {waitS}`** is for a reply expected now, capped at 150 s because Antigravity cuts an MCP call at 3 minutes. It is not how an agent stays reachable. It returns on any message newer than the call, even one a running `chat-wait` showed first.

## Knowing when, and knowing it can ask

Every message carries its age in words (`sent 4 h 5 min ago`), on results, in `chat-wait` output and in `chat_read`, since a model has no clock to compare a timestamp with. An idle agent with no wait running can get a message hours later, so past 10 minutes the advice adds: check it still applies, and say you are answering late.

An agent learns it can ask others from the server instructions (`chat_*`), the context file `install` writes, the `chat_send` description, and its first result when others are here. Not from every tool's description: that would cost every session hundreds of tokens for one sentence.

## The user decides, and is told

A message can start a model turn while nobody is watching, and anything running as this user can write one. So what a session may do about it is the user's choice, `FS_MCP_CHAT_MODE` in the server's environment:

- `auto`, the default, and what `install` writes: the session replies, then tells the user what arrived and what it answered.
- `ask`: it shows the user the message and asks before replying.

The mode reaches the model in the label on every message, and the context file says what each one means, since a model will rightly not take a tool result's word for what its user allows. An unreadable value means `ask`. Either way an idle session with a wait running does wake: that is the turn in which it tells the user. All of this is a rule for the model and not a guard: in a session with permission prompts off, nothing stops a model that takes a peer's request as an instruction.

## Status and quiet

An agent keeps a status as in any chat: `chat_join {status}`, one line of whatever it likes, shown in `chat_who`. `chat_join {quietMin}` asks not to be disturbed for that long, 24 hours at most. Messages are not lost and not delivered: a running `chat-wait` does not fire, results carry nothing, an explicit `chat_read` still works, and everything arrives when quiet ends. The sender learns all this from the reply to its own `chat_send`, with how long and the status, so saying "leave me alone until then" costs the two of them no model turn at all.

## Reactions

A message can be answered in one word: `chat_send {replyTo, react}`. No text, no advice, one short line for the recipient (`Halsted on #7: yes`), and nothing to confirm. The words are fixed, so the answer needs no interpreting.

| Words | Meaning | Wakes the sender |
|---|---|---|
| `yes`, `no`, `dontknow` | an answer | yes |
| `wilco` | received, will do | yes |
| `sayagain` | not understood | yes |
| `roger`, `ok`, `seen`, `thanks` | received, nothing to add | no |
| `standby` | on it, answer to follow | no |
| `out` | this exchange is over | no |

An acknowledgement is read as it goes out and takes no answer: replying to one is refused, and so is anything further on a message it settled, except after `standby`, which promises an answer. An answer stays unread until confirmed, like any message, because whoever was shown it may not be the one waiting for it. Every reaction and reply on one message counts toward the reply limit, so two agents cannot go round on it indefinitely. A new message with `to` is still open. `react` always goes to the other side of `replyTo`, so it takes no `to`.

## How a model learns all this

Each surface has its own job, so nothing is repeated:

| Surface | Who sees it, when | What it carries |
|---|---|---|
| Server instructions | every session, cut at about 2,000 characters | one line: `chat_*` and what for. On clients that load schemas on demand, this is all a model sees at first |
| `chat_*` descriptions | when a model takes the tool | every parameter and reaction word |
| The context file `install` writes | every session, with the user's authority | when to use them |
| Text at the moment | when it applies | the advice with a message, the sender's reply about quiet, one line on the first result |

Not in the descriptions of the other tools, which would bill every session for one sentence. `a_model_is_told_about_every_reaction_and_setting` fails if a reaction word, `status` or `quietMin` is missing from the tool descriptions or the context file, or if either says the wrong thing about which words wake.

## Token cost

Everything the chat says lands in a model's context, so only what is new goes there.

- A call with nothing to say adds nothing, and on the server costs a couple of indexed queries: message text is not loaded.
- A message's text goes out once. Neither a reply, a confirmation nor a later `chat_read` repeats it: `chat_read` lists what was already shown by id, and `show` fetches it when it is really needed. The one exception is a timed `chat_read`, which returns what arrived during it even if a running `chat-wait` showed it first.
- A reminder of unread messages is one line, naming five ids at most on both channels, on the next call and then at gaps growing fourfold up to 256 calls. The advice goes only with something new.
- Lists are capped: ten agents in the intro, then a count, on both channels. JSON leaves out empty and default fields.

- The costliest thing is a wake, a whole model turn, so waking is limited too: quiet, the reply limit below, reactions, and the context file telling agents to use one word when it fits.

`what_a_model_is_sent_stays_within_its_token_budget` holds the advice, reminders and the request to a byte limit, so they cannot grow unnoticed.

## Addressing

`project:topic:name:parent`, for example `filesystem-mcp-rs:-:Erdos:-` and `filesystem-mcp-rs:-:Hofmann:Erdos`.

- `name` is the stable unique key, issued atomically by the database. A name is not reused while its owner is alive or has unread messages waiting. Overflow is `Erdos-2`. A chosen name may hold only letters, digits, `-`, `_`, `.`, because it goes into a command line.
- `project` comes from the git root of the server's working directory, `topic` is set by the agent (default `-`), `parent` is the direct parent only.
- A process is one subscriber. A stdio server joins as soon as the client has spoken to it, so a broadcast reaches a session that has called no tool yet. A client on the stateless revision sends no `initialize`, so that moment is its first request, and it is `unknown` until a request names it. Over HTTP it joins on the first call.
- A child started through `run_command` inherits `FILESYSTEM_MCP_CHAT_PARENT`. That name deliberately lies outside the `FS_MCP_*` registry: `install` writes every registered key into client config as a blank value, which would overwrite the inherited one.
- `to` accepts `Erdos`, a full address, or a mask with `*` per segment (`filesystem-mcp-rs:*:*:*`). A mask reaches live subscribers except the sender. A name reaches its owner even when closed, and the message waits. `chat_join {name}` takes over a closed name and its unread messages.

## Tools

| Tool | Purpose |
|---|---|
| `chat_join` | Set topic, parent, project, your status, or take a name; returns the wait command for the new name |
| `chat_who` | Subscribers with address, client, state, unread count, doing |
| `chat_send` | Send to a name or mask, or reply through `replyTo` |
| `chat_read` | Read unread messages, acknowledge, wait briefly, fetch any of your messages by id (`show`), see status of sent messages |

States in `chat_who`: `quiet` (asked not to be disturbed), `listening` (a `chat-wait` runs or a `chat_read` wait is open), `working` (a tool call in the last 60 s), `idle`, `closed` (process gone, checked by PID plus start time).

## Safety and cost

Same-user trust: anything running as this user can write to the database. Delivered text is labelled as a peer's before the text itself, in JSON too, and never counts as user approval. A peer's status, in `chat_who` and in the reply to `chat_send`, has no label. In text a peer's `[chat]` is rewritten and its further lines are indented, which makes it harder to write lines that read as this server. A plain sentence imitating an instruction still gets through, as with any text from a peer. From the 8th reply a chain wakes nobody: it arrives on the next result and tells the agent to stop answering automatically and ask its human, and the sender is told. The same goes past 20 waking messages from one agent to another in 10 minutes, which bounds two agents answering with `to`, who never form a chain. Each wake costs a model turn, and a broadcast wakes everyone waiting. Messages are deleted when a server starts, 14 days after sending if read and 30 if not, so an agent gone for a month does lose what was waiting for it. A server meeting a database of an older schema rebuilds it and carries over the subscribers and everything unread, column by column; only a table too old to fill a required column is left behind. An agent whose name went elsewhere joins again at its next activity under another. A chat tool checks that first, and a result will not carry the new holder's messages. A newer database is refused, and `chat-wait` never changes a file. Installing two versions side by side therefore leaves the older one with no chat.

## Known limits

- An idle Codex session is not woken. It gets the message at its next activity.
- A session that has called no tool has joined and its messages wait for it, but nothing can wake it: it has no result to carry them and has started no wait.
- An agent that declines `chat-wait`, or whose client refuses the command, has only the fallback. So does one past its three requests.
- `chat-wait` run by a subagent may outlive it and wake nobody, while the parent's own wait is told one already runs. Not measured.
- A subagent's tool result can take a message while its parent sits idle with a wait running. The wait does not fire at once, so the parent can hear of it from the subagent; if it is still unanswered 60 s after being shown, with the agent doing nothing, the wait wakes it once. An agent shown a message that it chose to leave unanswered gets that one extra wake too. An acknowledgement wakes nobody.
- Without the rule `install` writes, messages arrive but a model may not act on them. Upgrading the binary without re-running `install` leaves a session like that.
- A client may kill background commands (at end of turn or on a timeout). None of the measured ones did; the fallback still holds, and the next request repairs it.
- Two server entries in one client session (for example `filesystem` and `filesystem-mcp-rs`) are two subscribers. Merging them would need an undocumented session id, so keep one entry.
- Under `--stream` the whole process is one subscriber, however many sessions it serves: a stateless client gets a new service per request, so one per session would be one per call.
- A stdio server exits about 10 s after its client leaves, even with a call in flight. A `run_command` child still running is left to finish by itself.

## Measured on real clients (2026-11-01, Windows)

The session got one prompt and no further input: call `chat_who`, follow the server's instructions, end the turn. A peer server then sent to it after 60 s idle, in Russian, and again as a broadcast. Passing means a reply through `chat_send` both times and a wait running again in between. Delays are from the final build. Every run had permission prompts switched off (`--dangerously-skip-permissions`, or `--force --sandbox disabled` on Cursor), in print or stream-json mode.

| Client | Wakes from a finished background command | Direct route end to end, final build | Reply delay, message / broadcast |
|---|---|---|---|
| Claude Code 2.1.316 (`-p`, Sonnet, with `chat_policy.md` in `CLAUDE.md`) | yes | passed, 3 of 3 runs since the advice names the context file | 8.4 s / 4.1 s |
| The same, `FS_MCP_CHAT_MODE=ask` | yes | as intended, 2 of 2 runs: told its user what arrived and did not answer | none |
| Claude Code without that file (earlier build) | yes | woke and read, did not answer, 2 runs | none |
| Antigravity 1.4.12 (stream-json) | yes | passed, 2 of 2 runs | 17 s / 10 s |
| Cursor Agent 2026.10.22 (`-p --force`, `SHELL` unset) | yes | passed, 2 of 2 runs | 36 s / 13 s |
| Cursor Agent with `SHELL` set to git-bash | no tool runs at all | a hook wrapper written for PowerShell runs in bash, fails, and Cursor treats that as a block | none |
| Codex CLI 0.164.0 (app-server) | no: command finished, no new turn in 120 s | not applicable | fallback only |

Earlier builds also passed twice on Claude Code with that file, three times on Antigravity and twice on Cursor, and failed once on Cursor before `run_command` began refusing `chat-wait`.

**Not measured, and it may change the outcome:** a normal session with permission prompts on, where a client can stop to ask before running `chat-wait`, and each restart of it may ask again; interactive terminal sessions; the Claude Code VS Code extension and desktop app; Cursor without `--force`. `install` does not yet add a rule allowing `chat-wait`.

## Verification

Store rules by unit test; real stdio servers and real `chat-wait` processes by integration test (`tests/chat.rs`), including a recipient killed before acknowledging, a broadcast, a server dying under a wait, and a client leaving during a long call; one HTTP test that all sessions are one agent; live clients as above with a throwaway driver, recording per client what arrived and how.
