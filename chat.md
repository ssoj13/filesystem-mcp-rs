# Cross-agent chat: idea

Status: proposal, nothing built. Written 2026-10-31 from reading this repo, not from a prototype.

**Can oh-my-harness host a literal chat between all connected agents? Yes, as a shared room with delivery at each
agent's next step.** It needs no daemon, because every host already runs `omh`. It cannot interrupt a model mid-thought,
and neither can Claude Code's own `SendMessage`, whose messages drain at the receiver's next tool round. The hard part is
not the chat but waking an idle agent, and that differs per host.

## Why

Claude Code's cross-session messaging only sees Claude sessions: `ListAgents` shows no Antigravity, Cursor, or Codex.
The case that prompted this: Antigravity edited a crate in internal ML development while a Claude audit reported P0s in the same
files. Neither could tell the other, so the operator had to carry messages by hand.

## What already exists

| Need | Already here |
|---|---|
| One process reachable from every host | `omh mcp` over stdio, installed for Claude Code, Codex, Cursor, Antigravity, and others |
| Tool surface | `rmcp` router in `crates/harness-cli/src/mcp.rs` |
| Safe concurrent writes | `File::lock` plus atomic rename in `crates/harness-core/src/store.rs` (`State::update`) |
| Machine-wide directory | home-based path in `crates/harness-core/src/paths.rs` |
| Passive injection into a turn | `HookOutput::context`; the `user-prompt` role injects keyword context today. The `post-tool` role only counts today, so injecting there is new and untested |
| Resuming a finished turn | `additionalContext` on `Stop` resumes the session (verified, `crates/harness-cli/AGENTS.md`), with an existing cap |
| Status line | `omh hud`, which can show an unread count |

PLAN 2.2 chose native agent teams and no `harness team` subcommand. This does not reopen that: native teams stay the way
to talk to your own subagents. Chat is for agents that have no shared host.

## Design

```
 Claude Code      Codex        Cursor      Antigravity    human
   hooks+MCP     hooks+MCP    hooks+MCP      MCP only     omh chat
      |             |            |              |            |
      v             v            v              v            v
   omh mcp       omh mcp      omh mcp        omh mcp      omh chat
      |             |            |              |            |
      +-------------+-----+------+--------------+------------+
                          v
             ~/.omh/chat/  (no broker)
               rooms/<room>.jsonl     append-only, seq assigned under lock
               agents/<id>.json       host, cwd, repo, branch, heartbeat, status
               cursors/<id>           last seq delivered to this agent
```

Per-project `.omh/` is the wrong home: the point is reaching across repositories and hosts, so this lives in the home
directory. No daemon also means no new way into the inherited-handle hang described in
`crates/harness-core/src/handles.rs`.

MCP tools:

- `chat_join(name, session?)`: register, idempotent, safe to repeat after compaction.
- `chat_who()`: live agents, with what each is working on.
- `chat_post(body, to?, room?, kind?, reply_to?)`: `to` empty means the whole room. `kind` is `fyi` or `ask`.
- `chat_read(since?, room?)`: unread messages; advances the cursor.
- `chat_wait(timeout)`: blocks until a message arrives or the timeout ends. This is how an agent idles while listening.

The human gets `omh chat`, a tail plus a prompt, and is simply one more participant.

## Delivery per host

| Situation | Claude Code, Codex, Cursor | Antigravity and other MCP-only hosts |
|---|---|---|
| Mid-turn, agent is working | `post-tool` hook injects unread messages | Only if the model calls a tool that reports them (see below) |
| New user prompt | `user-prompt` hook injects | Instruction in a skill or rules file to call `chat_read` first |
| Turn just ended, message waiting | `stop` hook resumes the session, capped | Not available |
| Fully idle, nothing running | **Nothing fires, unless the agent sits in `chat_wait`** | Same |

Confirmed for Claude Code: `stop` and `user-prompt`. Not yet tested anywhere: injecting from `post-tool`, which step 2
must prove first, since mid-turn delivery depends on it. Behaviour on Codex and Cursor is assumed from the shared hook
contract and has to be tested.

Two ways to close the gaps, both unverified:

1. **Piggyback on a server the agent already calls constantly.** `filesystem-mcp-rs` already appends a periodic footer to
   its tool results (`FS_MCP_SESSION_FOOTER_EVERY`). If it also checked the chat cursor, an MCP-only host would see
   `[chat: 2 unread from claude-ml]` mid-turn with no hooks at all. This is the best available route for Antigravity. It
   needs a change in that repo, and needs Antigravity to actually use that server.
2. **MCP push.** The Telegram plugin delivers `<channel source=...>` messages into a running Claude Code session, so a push
   path exists there. Whether a third-party plugin may use it, and whether any other host has an equivalent, is unknown.

Driving another host's GUI by simulated keystrokes would also reach an idle agent. It is fragile and outside this design.

## Problems to solve up front

**Identity.** Hooks receive `session_id` on stdin; the MCP server gets no session identifier (no such env read exists in
the source). Without a shared key, a hook and an MCP call from one session look like two agents and deliver twice.
Proposal: the `session-start` hook injects the session id, the model passes it to `chat_join`, and both sides key the
cursor on it. MCP-only hosts join by name.

**Messages are untrusted input.** A chat that any local agent can write to is a prompt-injection channel straight into
every other agent, some with broad permissions (`ask.rs` documents bypass flags). Injected text must be wrapped and labelled
as data from a named peer, never as instructions from the user. A peer's message must never count as user approval. `from`
is unauthenticated, which is acceptable only under a same-user, same-machine trust model, and that must be stated.

**Runaway cost.** Two agents that always answer can burn tokens forever. Hooks and `chat_wait` wake only on `ask`, never
on `fyi`. Stop-resume uses the existing continuation cap. Add a per-pair rate limit and cap injected text at about 2 KB,
with the rest behind `chat_read`.

**Failure policy.** `store.rs` says hooks must never fail loudly, and that holds for the hook path: a broken room must not
block tool calls. `chat_post` and `chat_read` should still return real errors, because a message silently lost is worse
than a failed call.

**Hook budget.** `post-tool` fires on every tool call under a 3-5 s budget. The unread check must stay at a cursor read and
a file-length comparison, with no JSON parse when nothing is new.

**Retention.** Rooms grow without limit, and agents crash without saying goodbye. Rotate by size, and treat an agent as
gone after a missed heartbeat.

## Build order

- [ ] 1. Store and tools: `chat_join`, `chat_who`, `chat_post`, `chat_read`, plus `omh chat`. | verify: concurrent posts
  from several processes keep a gapless `seq` with no torn lines.
- [ ] 2. Hook delivery on Claude Code (`post-tool`, `user-prompt`). | verify: two real sessions exchange a message, each
  delivered once, with unread-check overhead measured.
- [ ] 3. `chat_wait` and `stop` resume with caps. | verify: an `ask` wakes a waiting agent; a two-agent reply loop stops at
  the cap.
- [ ] 4. Real Antigravity test. | verify: it joins, reads, and replies. **This is the go/no-go test for the whole idea.**
  Run it early: it can be tried by hand right after step 1.
- [ ] 5. Footer in `filesystem-mcp-rs`. | verify: an MCP-only host sees an unread notice mid-turn.
- [ ] 6. Advisory file claims: `chat_claim(paths)`, with a warning on `chat_who` and in `pre-tool` when another agent holds
  a path. This is what would have helped most in the case above.
- [ ] 7. Codex and Cursor hook tests, HUD unread count.

## Not building

No broker or network transport, so one machine only. No replacement for native teams. No authentication beyond the
same-user trust model. No automatic execution of anything a message asks for.

## Open questions

1. One global room, or one per repository with a global lobby? Proposal: one per repository, because that is where agents
   collide, plus `global`.
2. Should an agent join automatically at session start, or only when asked? Proposal: automatic on hook hosts but silent
   until addressed, to spend no tokens on idle chatter.
3. Does the system prompt of an MCP-only host follow an instruction to poll? Only step 4 can answer that.
