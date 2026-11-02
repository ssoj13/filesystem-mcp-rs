# Agents starting agents: the graph and the runs

## Intent

An agent can hand a job to another agent, in another repository or with another model, and go on working. Everyone can see who started whom. The user stays in charge: limits they set, a command to stop anything, and their direct word over any standing permission.

## Who started whom

The parent is not an argument. It is the nearest ancestor process that is some agent's server, found when a server joins. An agent's server is an ancestor of whatever it runs, by `agent_start` or by `run_command` alike, and a session a person opened has no such ancestor. So it cannot be claimed, forgotten or lost when a client filters the environment.

Depth and tree are decided in the store from the parent's row. A session a person opened is depth 0 and the root of its own tree.

An agent already in the chat keeps its place: a later join takes parent, depth and tree from its own row, because the parent's name it remembers can be out of date after a rename, and looking that up would make it the root of a new tree, out of reach of its limits and its ancestors.

`FILESYSTEM_MCP_AGENT_RUN` only says which row of `runs` a started agent's server belongs to, so that a resumed agent keeps its name and messages. A value inherited through `run_command`, which disagrees with the tree, is ignored. It stays outside the `FS_MCP_*` registry because `install` writes those into client config, blank values included, which would overwrite it.

A name the server gives out carries a random number, `Halsted-4821`, and is one this file has never held, so a message, a reply or a stop meant for its holder cannot reach anyone later. Only a name an agent chooses with `chat_join` can recur; a stop follows runs and not names for that reason, and an agent cannot take a name a live run holds.

## Tools

| Tool | What it does |
|---|---|
| `agent_ls` | Agents with depth and parent, and `runs`. `run` gets one in full. Replaced `chat_who` |
| `agent_start` | `client`, `task`, optional `cwd`, `access`, `timeoutMin`, `worktree` |
| `agent_stop` | Stops a run the caller started, itself or through what it started, with everything under it |
| `filesystem-mcp-rs agents` | The tree in a terminal. `agents stop N` stops any run that still has a server looking after it: only a person can |

Stopping is a flag in `chat.db`, set on the run and everything under it, that the supervising tasks poll, so it works from any process and needs no pid. A run gives what is under it up to 5 seconds to end before it kills its client, because a killed client takes its server with it. A run whose server has already gone has nothing polling its flag: the answer says so rather than promising a stop.

## A run's life

1. `start_run` records it and checks the limits in one transaction, so parallel calls cannot share the last place.
2. A task in the starting server runs the client's turn through `agent-runner`.
3. The result reaches the parent as an ordinary chat message, by the same routes as any other.
4. If the client can be resumed the run stays `idle`, and a message to the agent starts another turn. This is what wakes Codex, which no background command can. A started agent is not asked to start `chat-wait`.
5. After 30 minutes idle it is `done`.

**None of this needs the client to reach this server.** Measured on Codex 0.166.0: under `exec` it refuses MCP tools with "requires approval, but approval policy is never", so a started Codex could neither read a message nor answer one with the chat tools, and it does not join this server's chat at all. So:

- The agent gets its name when the run is recorded, and the starting server holds it. A client that does have this server takes the name over when its server joins. While the run is looked after the name is nobody else's, even between turns, when its client has no process.
- The messages go into the prompt of the turn they start.
- The agent's last message goes back to each sender as an ordinary reply. A message it answered itself through the chat tools has been read and gets no second answer. A turn that says nothing still settles what it was given, with a note saying so, or each message would start one paid turn after another.
- Reports come from the agent, so a reply reaches it. An agent is not auto-answered to one it started, which would have the two resume each other: it has the chat tools, or it could not have started it, and its last message goes to whoever started it.
- A message nobody read when a run ends is answered with a note, so its sender is not left waiting.

A run dies with the server looking after it, on purpose; a demon that outlives its parent is a separate project. On Windows a kill-on-close job makes that hold even after a crash. On Unix a crash can leave it behind. A run whose server has gone reads as `lost` and takes no place in its tree.

## Limits

| Setting | Default | Meaning |
|---|---|---|
| `FS_MCP_AGENT_SPAWN` | `on` | `off` refuses `agent_start` |
| `FS_MCP_AGENT_MAX_DEPTH` | 2 | A session is 0, what it starts is 1 |
| `FS_MCP_AGENT_MAX_TREE` | 8 | Started agents running at once under one session |
| `FS_MCP_AGENT_MAX_ACCESS` | `write` | The most a started agent may be given; an unreadable value means `read` |

A call asks for `read` unless it says otherwise, and an agent cannot hand out more than it was given. An agent with a parent and no run of its own, because its client filtered the variable or configures a second server, can hand out only `read`: nobody can tell what it was given. A level the client cannot express is refused in the answer: `write` on Cursor under Windows, for one.

## Clients

`<state>/agents/*.toml` override and add to the manifests built into `agent-runner`.

## Known limits

- These limits stop an accident, not an agent set on going around them: `run_command` can start a client directly. Such a client still shows in the graph through the process tree, but no limit applies to it.
- The built-in subagents of a client share its server, so the graph does not see them.
- A session in the user's own window cannot be resumed this way. It wakes through `chat-wait`, as before.
- A started agent answers only at the end of a turn. Asking something back in the middle takes the chat tools, which a client like Codex under `exec` cannot use.
- `access` is what the client is told, and it is not a guarantee. A started agent's own server does not know its level and still offers `write_file` and `run_command`. Measured 2026-11-01 on Claude Code with `read` (`--permission-mode plan`): told to write through those tools and its built-in `Write`, it saw the tools, called none of them and wrote nothing, citing plan mode. So what stopped it was the model following the mode; whether the client would block such a call was not shown. Do not rely on `read` in a repository that matters until the server itself enforces it.
- Each server reads the limits from its own environment, so a client configured differently from the session that started it applies its own `FS_MCP_AGENT_MAX_*`. The access an agent was given still caps what it hands out.
- On a client whose server ends with its turn, which is every built-in except `agy`, what a started agent starts ends when its turn does: it is told to wait for the result first. A leaving server stops its runs and tidies their worktrees within about 8 seconds, but the agent above is told nothing of it.
- A second server of a client configured with two joins under a name of its own, as a child with no run, and so does a resumed turn's server while the previous turn's is still exiting. What such a server starts is not reached by a stop of the run above it, which follows runs and not names.
- An agent can still address itself by name, or two agents answer each other, up to the reply limit of 8 hops.

## Live runs

2026-11-01, Windows 11, default build, in a temporary state directory, by a script driving the server over stdio: `agent_start` with `read` access, the report arrives, a message resumes the agent and its answer returns, `agent_stop` stops it.

| Client | Result |
|---|---|
| Codex | Passed |
| Claude Code | Passed |

In those runs the client's own server did not join this chat: the agent's row still carried the starter's name for the client. So finding the parent through the process tree, and taking over the name, are covered by tests against a scripted client, not by a live run.
