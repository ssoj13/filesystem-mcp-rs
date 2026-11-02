//! The agent chat across real server processes: separate stdio servers sharing one state root,
//! which is the only thing connecting them in production too. Store rules live in unit tests;
//! these check that the pieces meet, including a recipient that dies before confirming.

#![cfg(feature = "chat-tools")]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_filesystem-mcp-rs"))
}

struct Agent {
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

impl Agent {
    async fn start(state: &Path, root: &Path) -> Result<Self> {
        Self::start_as(state, root, "chat-test").await
    }

    async fn start_as(state: &Path, root: &Path, client: &str) -> Result<Self> {
        Self::start_with_env(state, root, client, &[]).await
    }

    async fn start_with_env(
        state: &Path,
        root: &Path,
        client: &str,
        env: &[(&str, &str)],
    ) -> Result<Self> {
        let mut command = Command::new(binary());
        command.envs(env.iter().copied());
        command
            .arg("--no-session-footer")
            .arg(root)
            .env("FS_MCP_STATE_DIR", state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().context("stdin")?;
        let stdout = BufReader::new(child.stdout.take().context("stdout")?).lines();
        let mut agent = Self {
            child,
            stdin,
            stdout,
            next_id: 0,
        };
        agent
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": client, "version": "1" }
                }),
            )
            .await?;
        agent
            .write(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await?;
        Ok(agent)
    }

    async fn write(&mut self, message: &Value) -> Result<()> {
        let mut line = serde_json::to_vec(message)?;
        line.push(b'\n');
        self.stdin.write_all(&line).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn read_response(&mut self) -> Result<Value> {
        loop {
            let line = self.stdout.next_line().await?.context("server closed")?;
            let value: Value = serde_json::from_str(&line)?;
            if value.get("id").is_some() && value.get("method").is_none() {
                return Ok(value);
            }
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        self.write(&json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params}))
            .await?;
        self.read_response().await
    }

    /// The `result` of a tool call that has to succeed.
    async fn call(&mut self, tool: &str, arguments: Value) -> Result<Value> {
        let response = self
            .request("tools/call", json!({"name": tool, "arguments": arguments}))
            .await?;
        let result = response
            .get("result")
            .with_context(|| format!("{tool} failed: {response}"))?;
        assert_ne!(result["isError"], json!(true), "{tool}: {result}");
        Ok(result.clone())
    }

    async fn structured(&mut self, tool: &str, arguments: Value) -> Result<Value> {
        Ok(self.call(tool, arguments).await?["structuredContent"].clone())
    }

    /// A tool that has nothing to do with the chat, to see what its result carries.
    async fn work(&mut self) -> Result<Value> {
        self.call("which", json!({"command": "no-such-program"}))
            .await
    }

    async fn name(&mut self) -> Result<String> {
        let who = self.structured("agent_ls", json!({})).await?;
        let you = who["you"].as_str().context("you")?;
        Ok(you.split(':').nth(2).context("name")?.to_owned())
    }
}

fn dirs() -> Result<(TempDir, TempDir)> {
    Ok((TempDir::new()?, TempDir::new()?))
}

/// A `chat-wait` the way an agent's shell starts it.
fn start_wait(state: &Path, name: &str) -> Result<Child> {
    let db = state.join("chat.db");
    // What the server would have put in the command it hands out.
    let owner: (i64, i64) = if db.exists() {
        rusqlite::Connection::open(&db)?
            .query_row(
                "SELECT pid, pid_start FROM subscribers WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or((0, 0))
    } else {
        (0, 0)
    };
    Ok(Command::new(binary())
        .args(["chat-wait", "--db"])
        .arg(db)
        .arg("--owner")
        .arg(format!("{}:{}", owner.0, owner.1))
        .arg(name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?)
}

/// What a wait printed, once it ended by itself.
async fn wait_output(child: Child, within: Duration) -> Result<String> {
    let output = tokio::time::timeout(within, child.wait_with_output())
        .await
        .context("the wait did not end")??;
    assert!(output.status.success(), "{output:?}");
    Ok(String::from_utf8(output.stdout)?)
}

async fn state_of(agent: &mut Agent, name: &str) -> Result<String> {
    let who = agent.structured("agent_ls", json!({})).await?;
    let listed = who["agents"]
        .as_array()
        .context("agents")?
        .iter()
        .find(|entry| entry["name"] == name)
        .with_context(|| format!("{name} not listed: {who}"))?;
    Ok(listed["state"].as_str().context("state")?.to_owned())
}

async fn until_listening(agent: &mut Agent, name: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while state_of(agent, name).await? != "listening" {
        assert!(Instant::now() < deadline, "{name} never listening");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

fn content_text(result: &Value) -> String {
    result["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|block| block["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The setting has two readers, the wait's command line and the text on results, and the second one
/// once ignored it. A model told "Mode auto" answers without asking its user.
#[tokio::test]
async fn the_ask_mode_reaches_what_results_tell_the_model() -> Result<()> {
    let (state, root) = dirs()?;
    let env = [("FS_MCP_CHAT_MODE", "ask")];
    let mut asking = Agent::start_with_env(state.path(), root.path(), "chat-test", &env).await?;
    let mut peer = Agent::start(state.path(), root.path()).await?;
    let name = asking.name().await?;
    peer.call("chat_send", json!({"to": name, "text": "question"}))
        .await?;
    let text = content_text(&asking.work().await?);
    assert!(text.contains("question"), "{text}");
    assert!(text.contains("Mode ask"), "{text}");
    assert!(!text.contains("Mode auto"), "{text}");
    Ok(())
}

#[tokio::test]
async fn a_session_that_has_called_no_tool_yet_still_gets_a_broadcast() -> Result<()> {
    let (state, root) = dirs()?;
    let mut sender = Agent::start(state.path(), root.path()).await?;
    let mut quiet = Agent::start(state.path(), root.path()).await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let who = sender.structured("agent_ls", json!({})).await?;
        if who["agents"].as_array().context("agents")?.len() >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "it never joined: {who}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    sender
        .call("chat_send", json!({"to": "*:*:*:*", "text": "to everyone"}))
        .await?;
    let text = content_text(&quiet.work().await?);
    assert!(text.contains("to everyone"), "{text}");
    Ok(())
}

#[tokio::test]
async fn two_agents_see_each_other_and_exchange_a_question_and_an_answer() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_a = a.name().await?;
    let name_b = b.name().await?;
    assert_ne!(name_a, name_b);

    let who = a.structured("agent_ls", json!({})).await?;
    let listed: Vec<&str> = who["agents"]
        .as_array()
        .context("agents")?
        .iter()
        .filter_map(|agent| agent["name"].as_str())
        .collect();
    assert!(listed.contains(&name_a.as_str()) && listed.contains(&name_b.as_str()));
    assert_eq!(who["agents"][0]["client"], "chat-test");

    let sent = a
        .structured("chat_send", json!({"to": name_b, "text": "how are you"}))
        .await?;
    let question = sent["sent"][0]["id"].as_i64().context("id")?;

    let carried = b.work().await?;
    assert_eq!(
        carried["structuredContent"]["chat"]["new"][0]["text"], "how are you",
        "a client reading structuredContent has to see it"
    );
    assert!(
        content_text(&carried).contains("how are you"),
        "a client reading content has to see it"
    );

    b.structured("chat_send", json!({"replyTo": question, "text": "fine"}))
        .await?;
    let read = a.structured("chat_read", json!({"sent": 5})).await?;
    assert_eq!(read["messages"][0]["text"], "fine");
    assert_eq!(read["messages"][0]["replyTo"], question);
    assert_eq!(read["sent"][0]["state"], "read", "answering confirms it");
    Ok(())
}

#[tokio::test]
async fn an_unconfirmed_message_is_mentioned_until_it_is_confirmed() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    let sent = a
        .structured("chat_send", json!({"to": name_b, "text": "secret text"}))
        .await?;
    let id = sent["sent"][0]["id"].as_i64().context("id")?;

    assert!(content_text(&b.work().await?).contains("secret text"));
    let reminder = b.work().await?;
    assert!(content_text(&reminder).contains(&format!("Unread #{id}")));
    assert!(
        !content_text(&reminder).contains("secret text"),
        "a reminder does not spend the text again"
    );
    assert_eq!(
        a.structured("chat_read", json!({"sent": 1})).await?["sent"][0]["state"],
        "shown"
    );

    b.structured("chat_read", json!({"ack": [id]})).await?;
    assert!(!content_text(&b.work().await?).contains("[chat]"));
    assert_eq!(
        a.structured("chat_read", json!({"sent": 1})).await?["sent"][0]["state"],
        "read"
    );
    Ok(())
}

#[tokio::test]
async fn a_waiting_agent_gets_the_message_at_once_and_shows_as_listening() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    a.name().await?;

    let started = Instant::now();
    let waiting = tokio::spawn(async move {
        let read = b.structured("chat_read", json!({"waitS": 60})).await;
        (b, read)
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let who = a.structured("agent_ls", json!({})).await?;
        let listening = who["agents"]
            .as_array()
            .context("agents")?
            .iter()
            .any(|agent| agent["name"] == name_b.as_str() && agent["state"] == "listening");
        if listening {
            break;
        }
        assert!(Instant::now() < deadline, "never listening: {who}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    a.structured("chat_send", json!({"to": name_b, "text": "wake up"}))
        .await?;
    let (mut b, read) = waiting.await?;
    assert_eq!(read?["messages"][0]["text"], "wake up");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "returned because of the message, not the timeout"
    );

    let who = b.structured("agent_ls", json!({})).await?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut who = who;
    while who.to_string().contains("listening") {
        assert!(Instant::now() < deadline, "still listening: {who}");
        tokio::time::sleep(Duration::from_millis(50)).await;
        who = b.structured("agent_ls", json!({})).await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_timed_wait_ends_without_asking_the_agent_to_keep_calling() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let read = a.structured("chat_read", json!({"waitS": 1})).await?;
    assert_eq!(read["timedOut"], true);
    assert!(read.get("next").is_none(), "{read}");
    Ok(())
}

#[tokio::test]
async fn an_idle_agents_wait_ends_with_the_message_and_says_to_start_again() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    a.name().await?;

    let wait = start_wait(state.path(), &name_b)?;
    until_listening(&mut a, &name_b).await?;
    let sent = a
        .structured("chat_send", json!({"to": name_b, "text": "проснись"}))
        .await?;
    assert_eq!(sent["sent"][0]["recipientState"], "listening");
    assert!(sent.get("next").is_none(), "{sent}");

    let printed = wait_output(wait, Duration::from_secs(10)).await?;
    assert!(printed.contains("проснись"), "{printed}");
    assert!(printed.contains("Peer message"), "{printed}");
    assert!(printed.contains("chat-wait --db"), "{printed}");
    assert!(printed.contains(&name_b), "{printed}");

    assert_ne!(state_of(&mut a, &name_b).await?, "listening");
    let reminder = content_text(&b.work().await?);
    assert!(
        reminder.contains("Unread #"),
        "the wait showed it: {reminder}"
    );
    assert!(!reminder.contains("проснись"), "{reminder}");
    Ok(())
}

#[tokio::test]
async fn a_broadcast_ends_every_wait() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let mut c = Agent::start(state.path(), root.path()).await?;
    a.name().await?;
    let name_b = b.name().await?;
    let name_c = c.name().await?;
    let wait_b = start_wait(state.path(), &name_b)?;
    let wait_c = start_wait(state.path(), &name_c)?;
    until_listening(&mut a, &name_b).await?;
    until_listening(&mut a, &name_c).await?;

    a.structured("chat_send", json!({"to": "*:*:*:*", "text": "всем"}))
        .await?;
    assert!(
        wait_output(wait_b, Duration::from_secs(10))
            .await?
            .contains("всем")
    );
    assert!(
        wait_output(wait_c, Duration::from_secs(10))
            .await?
            .contains("всем")
    );
    Ok(())
}

#[tokio::test]
async fn a_wait_ends_when_its_server_dies() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let name_a = a.name().await?;
    let wait = start_wait(state.path(), &name_a)?;
    until_listening(&mut a, &name_a).await?;
    a.child.kill().await?;
    a.child.wait().await?;
    let printed = wait_output(wait, Duration::from_secs(20)).await?;
    assert!(printed.contains("has stopped"), "{printed}");
    Ok(())
}

#[tokio::test]
async fn a_second_wait_for_the_same_name_ends_at_once() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let name_a = a.name().await?;
    let _first = start_wait(state.path(), &name_a)?;
    until_listening(&mut a, &name_a).await?;
    let second = start_wait(state.path(), &name_a)?;
    let printed = wait_output(second, Duration::from_secs(10)).await?;
    assert!(printed.contains("already covers"), "{printed}");
    Ok(())
}

#[tokio::test]
async fn a_message_already_shown_on_a_result_does_not_end_a_wait() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    a.structured("chat_send", json!({"to": name_b, "text": "first"}))
        .await?;
    assert!(content_text(&b.work().await?).contains("first"));

    let mut wait = start_wait(state.path(), &name_b)?;
    until_listening(&mut a, &name_b).await?;
    // Past the wait's two looks at its owner too: if those misread a live server, every wait would
    // end falsely within seconds.
    tokio::time::sleep(Duration::from_secs(11)).await;
    assert!(
        wait.try_wait()?.is_none(),
        "there was nothing new to wake for"
    );

    a.structured("chat_send", json!({"to": name_b, "text": "second"}))
        .await?;
    let printed = wait_output(wait, Duration::from_secs(10)).await?;
    assert!(printed.contains("second"), "{printed}");
    assert!(!printed.contains("first"), "{printed}");
    Ok(())
}

#[tokio::test]
async fn a_wait_for_an_unknown_name_fails_and_says_where_to_look() -> Result<()> {
    let (state, root) = dirs()?;
    Agent::start(state.path(), root.path()).await?;
    let output = start_wait(state.path(), "Nobody")?
        .wait_with_output()
        .await?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("agent_ls"));
    Ok(())
}

/// A server whose client has gone must not stay behind: it would read as a live agent in the chat,
/// and a `chat-wait` for it would never end. Measured on a real session 2026-11-01: the client closed
/// the connection during a long `run_command`, and the server was still running minutes later.
#[tokio::test]
async fn a_server_exits_after_its_client_closes_the_connection_during_a_long_call() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    a.name().await?;
    let long = if cfg!(windows) {
        "ping -n 40 127.0.0.1"
    } else {
        "sleep 40"
    };
    a.write(&json!({
        "jsonrpc":"2.0", "id": 900, "method":"tools/call",
        "params": {"name":"run_command","arguments":{"command": long}}
    }))
    .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let Agent {
        mut child, stdin, ..
    } = a;
    drop(stdin);
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await;
    assert!(status.is_ok(), "still running 20 s after the client left");
    Ok(())
}

#[tokio::test]
async fn a_recipient_killed_before_confirming_loses_nothing() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_a = a.name().await?;
    let name_b = b.name().await?;
    a.structured("chat_send", json!({"to": name_b, "text": "do not lose me"}))
        .await?;
    assert!(content_text(&b.work().await?).contains("do not lose me"));

    b.child.kill().await?;
    b.child.wait().await?;

    let who = a.structured("agent_ls", json!({})).await?;
    let closed = who["agents"]
        .as_array()
        .context("agents")?
        .iter()
        .any(|agent| agent["name"] == name_b.as_str() && agent["state"] == "closed");
    assert!(closed, "{who}");

    // A new process is not handed the dead agent's name while a message waits for it.
    let mut c = Agent::start(state.path(), root.path()).await?;
    let name_c = c.name().await?;
    assert_ne!(name_c, name_b);
    assert_ne!(name_c, name_a);

    // It has to claim it, and then the message arrives, as new, on that very result.
    let joined = c.structured("chat_join", json!({"name": name_b})).await?;
    assert!(joined["you"].as_str().context("you")?.contains(&name_b));
    assert_eq!(
        joined["chat"]["new"][0]["text"], "do not lose me",
        "{joined}"
    );
    Ok(())
}

#[tokio::test]
async fn the_first_result_tells_a_newcomer_who_is_here_and_only_the_first() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let name_a = a.name().await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let first = b.work().await?;
    assert!(
        content_text(&first).contains(&format!(":{name_a}:")),
        "{first}"
    );
    assert_eq!(
        first["structuredContent"]["chat"]["others"][0]
            .as_str()
            .context("others")?
            .split(':')
            .nth(2),
        Some(name_a.as_str())
    );
    assert!(b.work().await?["structuredContent"].get("chat").is_none());
    Ok(())
}

#[tokio::test]
async fn a_lone_agent_is_asked_to_start_a_wait_because_others_may_come_later() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let first = a.work().await?;
    assert!(content_text(&first).contains("chat-wait"), "{first}");
    assert!(first["structuredContent"]["chat"]["startWait"].is_string());
    assert!(first["structuredContent"]["chat"].get("others").is_none());
    let second = a.work().await?;
    assert!(!content_text(&second).contains("[chat]"), "{second}");
    Ok(())
}

#[tokio::test]
async fn a_client_that_does_not_wake_is_not_asked_and_a_lone_one_hears_nothing() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start_as(state.path(), root.path(), "codex-mcp-client").await?;
    let result = a.work().await?;
    assert!(!content_text(&result).contains("[chat]"), "{result}");
    assert!(result["structuredContent"].get("chat").is_none());
    Ok(())
}

#[tokio::test]
async fn an_agent_with_a_wait_running_is_not_asked_to_start_another() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    a.name().await?;
    a.structured("chat_send", json!({"to": name_b, "text": "no wait yet"}))
        .await?;
    let without = content_text(&b.work().await?);
    assert!(
        without.contains("no wait yet") && without.contains("chat-wait"),
        "{without}"
    );

    let _wait = start_wait(state.path(), &name_b)?;
    until_listening(&mut a, &name_b).await?;
    // Past the next two slots of the schedule, so that a due request has to look for the wait.
    for _ in 0..130 {
        let with = content_text(&b.work().await?);
        assert!(!with.contains("background command"), "{with}");
    }
    Ok(())
}

#[tokio::test]
async fn a_rename_ends_the_wait_and_says_the_old_name_is_gone() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let name_a = a.name().await?;
    let wait = start_wait(state.path(), &name_a)?;
    until_listening(&mut a, &name_a).await?;
    let renamed = a.structured("chat_join", json!({"name": "Newton"})).await?;
    assert!(
        renamed["waitCommand"]
            .as_str()
            .context("waitCommand")?
            .ends_with(" Newton"),
        "{renamed}"
    );
    let output = tokio::time::timeout(Duration::from_secs(15), wait.wait_with_output())
        .await
        .context("the wait did not end")??;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("agent_ls"));
    Ok(())
}

/// Nothing forces which of two pollers shows the message first, so the test shows it itself, as a
/// running wait would. If the read is quicker the message simply arrives as new.
#[tokio::test]
async fn a_timed_read_returns_a_message_something_else_showed_during_the_wait() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    a.name().await?;

    let started = Instant::now();
    let reading =
        tokio::spawn(async move { b.structured("chat_read", json!({"waitS": 60})).await });
    tokio::time::sleep(Duration::from_secs(2)).await;
    let db = rusqlite::Connection::open(state.path().join("chat.db"))?;
    a.structured("chat_send", json!({"to": name_b, "text": "both"}))
        .await?;
    db.execute("UPDATE messages SET shown_at = 1", [])?;
    let read = reading.await??;
    assert_eq!(read["messages"][0]["text"], "both", "{read}");
    assert!(started.elapsed() < Duration::from_secs(30), "{read}");
    Ok(())
}

/// An answer may be what the other side is waiting for, and an acknowledgement is not worth a turn.
#[tokio::test]
async fn an_answer_ends_a_wait_and_an_acknowledgement_arrives_without_ending_it() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_a = a.name().await?;
    let name_b = b.name().await?;
    let sent = a
        .structured("chat_send", json!({"to": name_b, "text": "готово?"}))
        .await?;
    let question = sent["sent"][0]["id"].as_i64().context("id")?;
    let mut wait = start_wait(state.path(), &name_a)?;
    until_listening(&mut b, &name_a).await?;

    let roger = b
        .structured("chat_send", json!({"replyTo": question, "react": "roger"}))
        .await?;
    let ack = roger["sent"][0]["id"].as_i64().context("id")?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        wait.try_wait()?.is_none(),
        "an acknowledgement must not wake"
    );
    let refused = b
        .request(
            "tools/call",
            json!({"name": "chat_send", "arguments": {"replyTo": ack, "text": "?"}}),
        )
        .await?;
    assert!(refused.to_string().contains("takes no answer"), "{refused}");

    let second = a
        .structured("chat_send", json!({"to": name_b, "text": "точно?"}))
        .await?;
    let second = second["sent"][0]["id"].as_i64().context("id")?;
    b.structured("chat_send", json!({"replyTo": second, "react": "yes"}))
        .await?;
    let printed = wait_output(wait, Duration::from_secs(10)).await?;
    assert!(printed.contains(&format!("on #{second}: yes")), "{printed}");
    assert!(!printed.contains("Peer message"), "{printed}");
    Ok(())
}

#[tokio::test]
async fn a_reaction_is_checked_before_anything_is_sent() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    a.name().await?;
    for (arguments, says) in [
        (json!({"replyTo": 1, "react": "maybe"}), "wilco"),
        (json!({"react": "yes"}), "replyTo"),
        (
            json!({"to": "x", "text": "a", "react": "yes", "replyTo": 1}),
            "not both",
        ),
        (json!({"to": "x"}), "text is empty"),
        (json!({"to": "x", "react": "yes", "replyTo": 1}), "no `to`"),
    ] {
        let response = a
            .request(
                "tools/call",
                json!({"name": "chat_send", "arguments": arguments}),
            )
            .await?;
        assert!(response.to_string().contains(says), "{response}");
    }
    Ok(())
}

#[tokio::test]
async fn confirming_a_message_without_reading_it_still_shows_its_text() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    let sent = a
        .structured("chat_send", json!({"to": name_b, "text": "only copy"}))
        .await?;
    let id = sent["sent"][0]["id"].as_i64().context("id")?;
    // A wait took it, and its output never reached the model.
    let wait = start_wait(state.path(), &name_b)?;
    wait_output(wait, Duration::from_secs(10)).await?;

    let reminder = content_text(&b.work().await?);
    assert!(reminder.contains("chat_read {show:["), "{reminder}");
    let read = b.structured("chat_read", json!({"ack": [id]})).await?;
    assert_eq!(read["acked"], 1, "{read}");
    assert_eq!(read["messages"], json!([]), "not listed twice: {read}");
    let shown = b.structured("chat_read", json!({"show": [id]})).await?;
    assert_eq!(shown["shown"][0]["text"], "only copy", "{shown}");
    assert!(shown["shown"][0]["age"].is_string(), "{shown}");
    Ok(())
}

#[tokio::test]
async fn a_read_does_not_repeat_text_already_shown_and_show_fetches_it_while_unread() -> Result<()>
{
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    let sent = a
        .structured("chat_send", json!({"to": name_b, "text": "once only"}))
        .await?;
    let id = sent["sent"][0]["id"].as_i64().context("id")?;
    assert!(content_text(&b.work().await?).contains("once only"));

    let read = b.structured("chat_read", json!({})).await?;
    assert_eq!(read["messages"], json!([]), "{read}");
    assert_eq!(read["unread"][0], id, "{read}");
    let shown = b.structured("chat_read", json!({"show": [id]})).await?;
    assert_eq!(shown["shown"][0]["text"], "once only", "{shown}");
    assert_eq!(
        shown["messages"],
        json!([]),
        "not twice in one reply: {shown}"
    );
    Ok(())
}

/// Quiet is how an agent says leave me alone until then, at no cost to anyone: the sender is told
/// at once and nothing wakes.
#[tokio::test]
async fn a_quiet_agent_stays_asleep_and_the_message_arrives_when_quiet_ends() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    a.name().await?;
    let mut wait = start_wait(state.path(), &name_b)?;
    b.structured(
        "chat_join",
        json!({"status": "пересобираю", "quietMin": 20}),
    )
    .await?;
    let sent = a
        .structured("chat_send", json!({"to": name_b, "text": "later"}))
        .await?;
    assert_eq!(sent["sent"][0]["recipientState"], "quiet", "{sent}");
    assert_eq!(sent["sent"][0]["status"], "пересобираю", "{sent}");
    assert!(sent["sent"][0]["quietFor"].is_string(), "{sent}");
    assert!(
        sent["next"]
            .as_str()
            .context("next")?
            .contains("Do not resend")
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(wait.try_wait()?.is_none(), "quiet must not wake it");
    assert!(!content_text(&b.work().await?).contains("later"));
    assert_eq!(
        b.structured("chat_read", json!({})).await?["messages"][0]["text"],
        "later",
        "an explicit read works during quiet"
    );
    a.structured("chat_send", json!({"to": name_b, "text": "much later"}))
        .await?;

    // As if the time had passed: a result would carry it first if the agent itself ended quiet, and
    // the point here is the idle agent, whose wait has to fire by itself.
    rusqlite::Connection::open(state.path().join("chat.db"))?
        .execute("UPDATE subscribers SET quiet_until = 0", [])?;
    let printed = wait_output(wait, Duration::from_secs(10)).await?;
    assert!(printed.contains("much later"), "{printed}");
    Ok(())
}

/// A result cuts long text and a reply confirms, so the rest has to stay reachable, without either
/// of them spending the whole text again.
#[tokio::test]
async fn a_message_a_result_cut_can_be_fetched_whole_even_after_the_reply() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let mut b = Agent::start(state.path(), root.path()).await?;
    let name_b = b.name().await?;
    let long = "я".repeat(10_000);
    let sent = a
        .structured("chat_send", json!({"to": name_b, "text": long}))
        .await?;
    let id = sent["sent"][0]["id"].as_i64().context("id")?;
    assert_eq!(
        b.work().await?["structuredContent"]["chat"]["new"][0]["cut"],
        true
    );
    let reply = b
        .structured("chat_send", json!({"replyTo": id, "text": "ok"}))
        .await?;
    assert!(!reply.to_string().contains("яя"), "not repeated: {reply}");
    let shown = b.structured("chat_read", json!({"show": [id]})).await?;
    assert_eq!(shown["shown"][0]["text"].as_str(), Some(long.as_str()));
    Ok(())
}

#[tokio::test]
async fn run_command_refuses_to_start_a_wait_no_client_could_wake_for() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    for arguments in [
        json!({"command": "server chat-wait --db x Erdos"}),
        json!({"command": "server", "args": ["chat-wait", "--db", "x", "Erdos"], "mode": "detached"}),
    ] {
        let response = a
            .request(
                "tools/call",
                json!({"name": "run_command", "arguments": arguments}),
            )
            .await?;
        assert!(
            response.to_string().contains("built-in shell"),
            "{response}"
        );
    }
    let search = a
        .request(
            "tools/call",
            json!({"name": "run_command", "arguments": {
                "command": if cfg!(windows) { "where" } else { "which" },
                "args": ["chat-wait"]
            }}),
        )
        .await?;
    // It ran. By the outcome and not the wording: this result also asks for a wait.
    assert!(search.to_string().contains("exit code"), "{search}");
    Ok(())
}

#[tokio::test]
async fn a_wait_given_a_mistyped_database_path_fails_and_creates_nothing() -> Result<()> {
    let state = TempDir::new()?;
    let output = start_wait(state.path(), "Erdos")?
        .wait_with_output()
        .await?;
    assert!(!output.status.success());
    assert!(!state.path().join("chat.db").exists());
    Ok(())
}

#[tokio::test]
async fn a_clients_parallel_first_calls_make_one_subscriber() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    for id in [101, 102, 103] {
        a.write(&json!({
            "jsonrpc":"2.0", "id": id, "method":"tools/call",
            "params": {"name":"which","arguments":{"command":"no-such-program"}}
        }))
        .await?;
    }
    for _ in 0..3 {
        a.read_response().await?;
    }
    let who = a.structured("agent_ls", json!({})).await?;
    assert_eq!(
        who["agents"].as_array().context("agents")?.len(),
        1,
        "{who}"
    );
    Ok(())
}

#[tokio::test]
async fn a_server_started_under_an_agent_finds_its_parent_in_the_process_tree() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let name_a = a.name().await?;
    // Nobody tells it: a process run by this agent's server finds that server by looking up.
    let input = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"child","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"agent_ls","arguments":{}}}),
    ]
    .iter()
    .map(Value::to_string)
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";
    let ran = a
        .structured(
            "run_command",
            json!({
                "command": binary().to_string_lossy(),
                "args": ["--no-session-footer", root.path().to_string_lossy()],
                "stdin": {"kind": "inline", "text": input},
            }),
        )
        .await?;
    let stdout = ran["stdout"].as_str().context("stdout")?;
    let suffix = format!(":{name_a}");
    assert!(stdout.contains(&suffix), "{stdout}");
    Ok(())
}

#[tokio::test]
async fn a_session_nobody_started_has_no_parent_and_cannot_be_given_one() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let joined = a
        .structured("chat_join", json!({"parent": "Someone"}))
        .await?;
    assert!(
        joined["you"].as_str().context("you")?.ends_with(":-"),
        "{joined}"
    );
    Ok(())
}

#[cfg(feature = "agent-tools")]
mod agents {
    use super::*;

    const PYTHON: &str = if cfg!(windows) { "python" } else { "python3" };

    /// Told apart by the file it leaves. It prints what Codex prints, so that it can be resumed.
    const RESUMED: &str = r#"
import json
import sys
open("resumed.txt", "w").write(sys.stdin.read())
print(json.dumps({"type": "thread.started", "thread_id": "t1"}))
print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "the answer"}}))
print(json.dumps({"type": "turn.completed"}))
"#;

    /// A client with no way to the chat at all, the way Codex is under `exec`: it never starts a
    /// server, and all it can do is print.
    const CUT_OFF: &str = r#"
import json
print(json.dumps({"type": "thread.started", "thread_id": "t1"}))
print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "started"}}))
print(json.dumps({"type": "turn.completed"}))
"#;

    /// Everything unread that arrives within the time.
    async fn read_until(agent: &mut Agent, wanted: &str) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(40);
        let mut seen = String::new();
        while Instant::now() < deadline {
            let read = agent.structured("chat_read", json!({"waitS": 2})).await?;
            seen.push_str(&read.to_string());
            // Any other call may have carried a message already, so what is unread is asked for by id.
            if read["unread"].as_array().is_some_and(|ids| !ids.is_empty()) {
                let shown = agent
                    .structured("chat_read", json!({"show": read["unread"]}))
                    .await?;
                seen.push_str(&shown.to_string());
            }
            if seen.contains(wanted) {
                return Ok(seen);
            }
        }
        anyhow::bail!("{wanted} never came: {seen}")
    }

    #[tokio::test]
    async fn a_client_that_cannot_reach_the_chat_still_gets_messages_and_answers_them() -> Result<()>
    {
        let (state, root) = dirs()?;
        scripted_client(state.path(), "cutoff", CUT_OFF, RESUMED, ALL)?;
        let mut parent = Agent::start(state.path(), root.path()).await?;
        let started = parent
            .structured(
                "agent_start",
                json!({"client": "cutoff", "task": "x", "cwd": root.path().to_string_lossy()}),
            )
            .await?;
        let id = run_id(&started)?;
        let name = started["agent"]
            .as_str()
            .context("a name from the start")?
            .to_owned();
        until_state(&mut parent, id, "idle").await?;

        parent
            .call("chat_send", json!({"to": name, "text": "the question"}))
            .await?;
        read_until(&mut parent, "the answer").await?;
        // What it was told came in its prompt.
        let prompt = std::fs::read_to_string(root.path().join("resumed.txt"))?;
        assert!(prompt.contains("the question"), "{prompt}");
        Ok(())
    }

    #[tokio::test]
    async fn a_name_that_was_given_out_is_never_given_out_again() -> Result<()> {
        let (state, root) = dirs()?;
        scripted_client(state.path(), "cutoff", CUT_OFF, RESUMED, ALL)?;
        let mut parent = Agent::start(state.path(), root.path()).await?;
        let args = json!({"client": "cutoff", "task": "x", "cwd": root.path().to_string_lossy()});
        let mut names = vec![parent.name().await?];
        for _ in 0..3 {
            let started = parent.structured("agent_start", args.clone()).await?;
            let id = run_id(&started)?;
            let name = started["agent"].as_str().context("name")?.to_owned();
            let (_, number) = name.rsplit_once('-').context("a number")?;
            assert!(number.parse::<u32>().is_ok(), "{name}");
            assert!(!names.contains(&name), "{name} again: {names:?}");
            let (first, _) = names[0].rsplit_once('-').context("a number")?;
            assert!(!name.starts_with(first), "{name} beside {names:?}");
            names.push(name);
            until_state(&mut parent, id, "idle").await?;
            parent.call("agent_stop", json!({"run": id})).await?;
            until_state(&mut parent, id, "stopped").await?;
        }
        Ok(())
    }

    /// Says nothing, and counts its turns. Its server joins, as a real client's does, which makes
    /// what is unread new again: a message nothing settled would start one turn after another.
    const MUTE: &str = r#"
import json, subprocess, sys
lines = [
  {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18",
   "capabilities": {}, "clientInfo": {"name": "scripted", "version": "1"}}},
  {"jsonrpc": "2.0", "method": "notifications/initialized"},
]
subprocess.run([sys.argv[1], "--no-session-footer", "."],
  input="\n".join(json.dumps(line) for line in lines) + "\n", capture_output=True, text=True)
open("turns.txt", "a").write("x")
print(json.dumps({"type": "thread.started", "thread_id": "t1"}))
print(json.dumps({"type": "turn.completed"}))
"#;

    #[tokio::test]
    async fn a_turn_that_says_nothing_settles_the_message_and_does_not_start_another() -> Result<()>
    {
        let (state, root) = dirs()?;
        scripted_client(state.path(), "mute", CUT_OFF, MUTE, ALL)?;
        let mut parent = Agent::start(state.path(), root.path()).await?;
        let started = parent
            .structured(
                "agent_start",
                json!({"client": "mute", "task": "x", "cwd": root.path().to_string_lossy()}),
            )
            .await?;
        let id = run_id(&started)?;
        let name = started["agent"].as_str().context("name")?.to_owned();
        until_state(&mut parent, id, "idle").await?;
        parent
            .call("chat_send", json!({"to": name, "text": "are you there"}))
            .await?;
        read_until(&mut parent, "without saying anything").await?;
        // Long enough for several polls of the supervisor and another turn.
        tokio::time::sleep(Duration::from_secs(4)).await;
        let turns = std::fs::read_to_string(root.path().join("turns.txt"))?;
        assert_eq!(turns, "x", "it must be resumed once");
        Ok(())
    }

    /// Its server does not learn which run it is, as under a client that filters the environment, and
    /// tries to hand out more than anyone can say it was given.
    const GRANTS: &str = r#"
import json, os, subprocess, sys
env = {k: v for k, v in os.environ.items() if k != "FILESYSTEM_MCP_AGENT_RUN"}
lines = [
  {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18",
   "capabilities": {}, "clientInfo": {"name": "scripted", "version": "1"}}},
  {"jsonrpc": "2.0", "method": "notifications/initialized"},
  {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "agent_start",
   "arguments": {"client": "cutoff", "task": "x", "access": "write"}}},
]
done = subprocess.run([sys.argv[1], "--no-session-footer", sys.argv[2]], env=env,
  input="\n".join(json.dumps(line) for line in lines) + "\n", capture_output=True, text=True)
answer = [line for line in done.stdout.splitlines() if json.loads(line).get("id") == 2]
print(json.dumps({"type": "thread.started", "thread_id": "t1"}))
print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": str(answer)}}))
print(json.dumps({"type": "turn.completed"}))
"#;

    #[tokio::test]
    async fn an_agent_nobody_can_place_cannot_hand_out_more_than_read() -> Result<()> {
        let (state, root) = dirs()?;
        scripted_client(state.path(), "cutoff", CUT_OFF, RESUMED, ALL)?;
        scripted_client(state.path(), "grants", GRANTS, RESUMED, ALL)?;
        let mut parent = Agent::start(state.path(), root.path()).await?;
        let started = parent
            .structured(
                "agent_start",
                json!({"client": "grants", "task": "x", "access": "write",
                       "cwd": root.path().to_string_lossy()}),
            )
            .await?;
        let run = until_state(&mut parent, run_id(&started)?, "idle").await?;
        let result = run["result"].as_str().context("result")?;
        assert!(result.contains("you have read access"), "{result}");
        Ok(())
    }

    /// Does what a real client does: starts a server, which joins the chat, and reports.
    const JOINS: &str = r#"
import json, subprocess, sys
lines = [
  {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18",
   "capabilities": {}, "clientInfo": {"name": "scripted", "version": "1"}}},
  {"jsonrpc": "2.0", "method": "notifications/initialized"},
  {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "agent_ls", "arguments": {}}},
]
done = subprocess.run([sys.argv[1], "--no-session-footer", sys.argv[2]],
  input="\n".join(json.dumps(line) for line in lines) + "\n", capture_output=True, text=True)
you = ""
for line in done.stdout.splitlines():
    reply = json.loads(line)
    if reply.get("id") == 2:
        you = reply["result"]["structuredContent"]["you"]
print(json.dumps({"type": "thread.started", "thread_id": "t1"}))
print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": you}}))
print(json.dumps({"type": "turn.completed"}))
"#;

    /// A client of the given scripts: a manifest in the state directory, as a user would add one.
    fn scripted_client(
        state: &Path,
        id: &str,
        first: &str,
        resumed: &str,
        levels: &str,
    ) -> Result<()> {
        let dir = state.join("agents");
        std::fs::create_dir_all(&dir)?;
        let binary = binary();
        let manifest = format!(
            "id = \"{id}\"\nname = \"{id}\"\nbinary = \"{PYTHON}\"\ntransport = \"oneshot-jsonl\"\n\
             prompt_delivery = \"stdin-text\"\n\
             args_new = [\"-u\", \"-c\", '''{first}''', '{}', '{{workdir}}', \"{{access}}\"]\n\
             args_resume = [\"-u\", \"-c\", '''{resumed}''', '{}', \"{{remote_session_id}}\", \"{{access}}\"]\n\
             [access]\n{levels}\n[parser]\nkind = \"codex-jsonl\"\n",
            binary.display(),
            binary.display()
        );
        std::fs::write(dir.join(format!("{id}.toml")), manifest)?;
        Ok(())
    }

    const ALL: &str = "read = []\nwrite = []\nfull = []";

    async fn run_of(agent: &mut Agent, id: u64) -> Result<Value> {
        let listed = agent.structured("agent_ls", json!({"run": id})).await?;
        Ok(listed["run"].clone())
    }

    async fn until_state(agent: &mut Agent, id: u64, wanted: &str) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            let run = run_of(agent, id).await?;
            if run["state"] == wanted {
                return Ok(run);
            }
            assert!(Instant::now() < deadline, "never {wanted}: {run}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn run_id(started: &Value) -> Result<u64> {
        started["run"].as_u64().context("run")
    }

    #[tokio::test]
    async fn a_started_agent_joins_as_a_child_reports_and_is_resumed_by_a_message() -> Result<()> {
        let (state, root) = dirs()?;
        scripted_client(state.path(), "scripted", JOINS, RESUMED, ALL)?;
        let mut parent = Agent::start(state.path(), root.path()).await?;
        let name = parent.name().await?;
        let started = parent
            .structured(
                "agent_start",
                json!({"client": "scripted", "task": "look around",
                       "cwd": root.path().to_string_lossy()}),
            )
            .await?;
        assert_eq!(started["depth"], 1);
        let id = run_id(&started)?;

        let run = until_state(&mut parent, id, "idle").await?;
        let child = run["agent"]
            .as_str()
            .context("its server joined")?
            .to_owned();
        let result = run["result"].as_str().context("result")?;
        assert!(
            result.ends_with(&format!(":{child}:{name}")),
            "it found its parent: {result}"
        );
        let listed = parent.structured("agent_ls", json!({})).await?;
        let entry = listed["agents"]
            .as_array()
            .context("agents")?
            .iter()
            .find(|agent| agent["name"] == child.as_str())
            .with_context(|| format!("{listed}"))?;
        assert_eq!(entry["depth"], 1, "{entry}");

        // The result came the way any message does. A poll above may have carried it, so by id.
        let unread = parent.structured("chat_read", json!({})).await?;
        let ids = unread["unread"].clone();
        let shown = parent.structured("chat_read", json!({"show": ids})).await?;
        assert!(
            shown.to_string().contains(&format!("Run #{id}")),
            "{unread} {shown}"
        );
        // From the agent, so that a reply goes to it and not back to the parent itself.
        assert!(
            shown.to_string().contains(&format!(":{child}:{name}\"")),
            "{shown}"
        );

        // Its process is gone. A message to its name starts another turn.
        parent
            .call("chat_send", json!({"to": child, "text": "one more thing"}))
            .await?;
        let marker = root.path().join("resumed.txt");
        let deadline = Instant::now() + Duration::from_secs(40);
        while !marker.exists() {
            assert!(Instant::now() < deadline, "it was not resumed");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        parent.call("agent_stop", json!({"run": id})).await?;
        until_state(&mut parent, id, "stopped").await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_long_turn_is_stopped_on_request_and_counts_against_the_tree_until_then() -> Result<()>
    {
        let (state, root) = dirs()?;
        let slow = "import time\ntime.sleep(120)";
        scripted_client(state.path(), "slow", slow, slow, ALL)?;
        let env = [("FS_MCP_AGENT_MAX_TREE", "1")];
        let mut parent =
            Agent::start_with_env(state.path(), root.path(), "chat-test", &env).await?;
        let args = json!({"client": "slow", "task": "wait", "cwd": root.path().to_string_lossy()});
        let started = parent.structured("agent_start", args.clone()).await?;
        let id = run_id(&started)?;
        let name = started["agent"].as_str().context("name")?.to_owned();
        parent
            .call("chat_send", json!({"to": name, "text": "are you there"}))
            .await?;

        let refused = parent
            .request(
                "tools/call",
                json!({"name": "agent_start", "arguments": args.clone()}),
            )
            .await?;
        assert!(refused.to_string().contains("limit is 1"), "{refused}");

        parent.call("agent_stop", json!({"run": id})).await?;
        until_state(&mut parent, id, "stopped").await?;
        // Whoever wrote is not left waiting on an agent that is not coming.
        read_until(&mut parent, "without answering").await?;
        parent.structured("agent_start", args).await?;
        Ok(())
    }

    /// Starts an agent of its own through its server, and stays until it is stopped.
    const MIDDLE: &str = r#"
import json, subprocess, sys, time
lines = [
  {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18",
   "capabilities": {}, "clientInfo": {"name": "scripted", "version": "1"}}},
  {"jsonrpc": "2.0", "method": "notifications/initialized"},
  {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "agent_start",
   "arguments": {"client": "slow", "task": "x"}}},
]
server = subprocess.Popen([sys.argv[1], "--no-session-footer", sys.argv[2]], stdin=subprocess.PIPE,
  stdout=subprocess.DEVNULL, text=True)
for line in lines:
    server.stdin.write(json.dumps(line) + "\n")
server.stdin.flush()
time.sleep(120)
"#;

    #[tokio::test]
    async fn a_stop_ends_what_the_stopped_agent_started_and_not_just_the_agent() -> Result<()> {
        let (state, root) = dirs()?;
        let slow = "import time\ntime.sleep(120)";
        scripted_client(state.path(), "slow", slow, slow, ALL)?;
        scripted_client(state.path(), "middle", MIDDLE, slow, ALL)?;
        let mut parent = Agent::start(state.path(), root.path()).await?;
        let started = parent
            .structured(
                "agent_start",
                json!({"client": "middle", "task": "x", "cwd": root.path().to_string_lossy()}),
            )
            .await?;
        let id = run_id(&started)?;
        let deadline = Instant::now() + Duration::from_secs(40);
        let below = loop {
            let listed = parent.structured("agent_ls", json!({})).await?;
            let runs = listed["runs"].as_array().context("runs")?;
            if let Some(run) = runs.iter().find(|run| run["id"] != id) {
                break run["id"].as_u64().context("id")?;
            }
            assert!(Instant::now() < deadline, "it started nothing: {listed}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        parent.call("agent_stop", json!({"run": id})).await?;
        // `stopped` and not `lost`: its own server ended it, and was not killed first.
        until_state(&mut parent, below, "stopped").await?;
        until_state(&mut parent, id, "stopped").await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_leaving_server_ends_its_runs_and_tidies_their_worktrees() -> Result<()> {
        let (state, root) = dirs()?;
        let repo = root.path();
        for args in [
            vec!["init", "-q"],
            vec![
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "start",
            ],
        ] {
            let done = std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(args)
                .output()?;
            assert!(done.status.success(), "{done:?}");
        }
        let slow = "import time\ntime.sleep(120)";
        scripted_client(state.path(), "slow", slow, slow, ALL)?;
        let mut parent = Agent::start(state.path(), repo).await?;
        let started = parent
            .structured(
                "agent_start",
                json!({"client": "slow", "task": "x", "worktree": true,
                       "cwd": repo.to_string_lossy()}),
            )
            .await?;
        let id = run_id(&started)?;
        let dir = PathBuf::from(started["workdir"].as_str().context("workdir")?);
        assert!(dir.exists());

        // What a client does when it goes: closes the pipe.
        let Agent {
            mut child, stdin, ..
        } = parent;
        drop(stdin);
        tokio::time::timeout(Duration::from_secs(30), child.wait()).await??;
        assert!(!dir.exists(), "the worktree was left behind");
        let mut later = Agent::start(state.path(), repo).await?;
        let run = run_of(&mut later, id).await?;
        assert_eq!(run["state"], "stopped", "{run}");
        Ok(())
    }

    #[tokio::test]
    async fn a_resumed_turn_that_fails_tells_whoever_wrote_and_whoever_started_it() -> Result<()> {
        let (state, root) = dirs()?;
        scripted_client(
            state.path(),
            "breaks",
            CUT_OFF,
            "import sys\nsys.exit(3)",
            ALL,
        )?;
        let mut parent = Agent::start(state.path(), root.path()).await?;
        let started = parent
            .structured(
                "agent_start",
                json!({"client": "breaks", "task": "x", "cwd": root.path().to_string_lossy()}),
            )
            .await?;
        let id = run_id(&started)?;
        let name = started["agent"].as_str().context("name")?.to_owned();
        until_state(&mut parent, id, "idle").await?;
        parent
            .call("chat_send", json!({"to": name, "text": "one more"}))
            .await?;
        let seen = read_until(&mut parent, "failed:").await?;
        assert!(seen.contains("could not answer"), "{seen}");
        let run = until_state(&mut parent, id, "failed").await?;
        assert!(run["error"].is_string(), "{run}");
        Ok(())
    }

    #[tokio::test]
    async fn access_is_refused_in_the_answer_when_it_is_too_much_or_cannot_be_expressed()
    -> Result<()> {
        let (state, root) = dirs()?;
        scripted_client(state.path(), "readonly", RESUMED, RESUMED, "read = []")?;
        let mut parent = Agent::start(state.path(), root.path()).await?;
        let try_access = |access: &str| {
            json!({"name": "agent_start", "arguments": {"client": "readonly", "task": "x",
                   "access": access, "cwd": root.path().to_string_lossy()}})
        };
        let full = parent.request("tools/call", try_access("full")).await?;
        assert!(
            full.to_string().contains("FS_MCP_AGENT_MAX_ACCESS"),
            "{full}"
        );
        let write = parent.request("tools/call", try_access("write")).await?;
        assert!(write.to_string().contains("does not declare"), "{write}");
        let typo = parent.request("tools/call", try_access("root")).await?;
        assert!(typo.to_string().contains("read, write or full"), "{typo}");
        let who = parent.structured("agent_ls", json!({})).await?;
        assert!(who.get("runs").is_none(), "nothing was started: {who}");
        Ok(())
    }

    #[tokio::test]
    async fn the_user_can_turn_it_off_and_a_missing_client_says_what_there_is() -> Result<()> {
        let (state, root) = dirs()?;
        let env = [("FS_MCP_AGENT_SPAWN", "off")];
        let mut off = Agent::start_with_env(state.path(), root.path(), "chat-test", &env).await?;
        let call = json!({"name": "agent_start", "arguments": {"client": "claude", "task": "x"}});
        let refused = off.request("tools/call", call).await?;
        assert!(
            refused.to_string().contains("FS_MCP_AGENT_SPAWN"),
            "{refused}"
        );

        let mut on = Agent::start(state.path(), root.path()).await?;
        let call = json!({"name": "agent_start", "arguments": {"client": "nobody", "task": "x"}});
        let unknown = on.request("tools/call", call).await?;
        assert!(unknown.to_string().contains("claude"), "{unknown}");
        Ok(())
    }

    #[tokio::test]
    async fn a_worktree_with_nothing_in_it_is_removed_and_one_with_work_stays() -> Result<()> {
        let (state, root) = dirs()?;
        let repo = root.path();
        let git = |args: &[&str]| {
            let done = std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(["-c", "commit.gpgsign=false"])
                .args(args)
                .output()
                .unwrap();
            assert!(done.status.success(), "{done:?}");
        };
        git(&["init", "-q"]);
        std::fs::write(repo.join(".gitignore"), "*.log\n")?;
        git(&["add", ".gitignore"]);
        git(&["commit", "-q", "-m", "start"]);
        std::fs::create_dir(repo.join("sub"))?;
        let output = "open('out.log', 'w').close()\nprint('{\"type\": \"turn.completed\"}')";
        scripted_client(state.path(), "logger", output, output, ALL)?;
        let commits = "import subprocess\nsubprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@t', \
                       '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'w'], check=True)\n\
                       print('{\"type\": \"turn.completed\"}')";
        scripted_client(state.path(), "committer", commits, commits, ALL)?;
        let leaves = "open('work.txt', 'w').close()\nprint('{\"type\": \"turn.completed\"}')";
        scripted_client(state.path(), "writer", leaves, leaves, ALL)?;
        let nothing = "print('{\"type\": \"turn.completed\"}')";
        scripted_client(state.path(), "idler", nothing, nothing, ALL)?;
        let mut parent = Agent::start(state.path(), root.path()).await?;

        let start = |client: &str| {
            json!({"client": client, "task": "x", "worktree": true,
                   "cwd": repo.to_string_lossy()})
        };
        let idle = parent.structured("agent_start", start("idler")).await?;
        let idle_dir = PathBuf::from(idle["workdir"].as_str().context("workdir")?);
        assert!(idle_dir.exists());
        until_state(&mut parent, run_id(&idle)?, "done").await?;

        let wrote = parent.structured("agent_start", start("writer")).await?;
        let wrote_dir = PathBuf::from(wrote["workdir"].as_str().context("workdir")?);
        until_state(&mut parent, run_id(&wrote)?, "done").await?;

        let deadline = Instant::now() + Duration::from_secs(20);
        while idle_dir.exists() {
            assert!(Instant::now() < deadline, "the empty worktree stayed");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(wrote_dir.join("work.txt").exists(), "its work was kept");

        // Output git ignores is still its work, and a subdirectory is still where it was asked to be.
        let args = json!({"client": "logger", "task": "x", "worktree": true,
                          "cwd": repo.join("sub").to_string_lossy()});
        let logged = parent.structured("agent_start", args).await?;
        let logged_dir = PathBuf::from(logged["workdir"].as_str().context("workdir")?);
        assert!(logged_dir.ends_with("sub"), "{logged}");
        until_state(&mut parent, run_id(&logged)?, "done").await?;
        assert!(logged_dir.join("out.log").exists(), "its output was kept");

        // Nothing changed on disk, but a commit is work too.
        let committed = parent.structured("agent_start", start("committer")).await?;
        let committed_dir = PathBuf::from(committed["workdir"].as_str().context("workdir")?);
        until_state(&mut parent, run_id(&committed)?, "done").await?;
        assert!(committed_dir.exists(), "its commit was kept");
        Ok(())
    }
}

#[tokio::test]
async fn an_empty_name_is_refused() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let response = a
        .request(
            "tools/call",
            json!({"name":"chat_join","arguments":{"name":"  "}}),
        )
        .await?;
    assert!(
        response.to_string().contains("cannot be empty"),
        "{response}"
    );
    Ok(())
}

#[tokio::test]
async fn a_mistyped_address_is_an_error_that_lists_who_is_there() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path()).await?;
    let name_a = a.name().await?;
    let response = a
        .request(
            "tools/call",
            json!({"name":"chat_send","arguments":{"to":"Nobody","text":"hi"}}),
        )
        .await?;
    let text = response.to_string();
    assert!(text.contains("nobody matches"), "{text}");
    assert!(text.contains(&name_a), "{text}");
    Ok(())
}
