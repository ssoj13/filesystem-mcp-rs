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
    async fn start(state: &Path, root: &Path, parent: Option<&str>) -> Result<Self> {
        Self::start_as(state, root, parent, "chat-test").await
    }

    async fn start_as(
        state: &Path,
        root: &Path,
        parent: Option<&str>,
        client: &str,
    ) -> Result<Self> {
        Self::start_with_env(state, root, parent, client, &[]).await
    }

    async fn start_with_env(
        state: &Path,
        root: &Path,
        parent: Option<&str>,
        client: &str,
        env: &[(&str, &str)],
    ) -> Result<Self> {
        let mut command = Command::new(binary());
        command.envs(env.iter().copied());
        command
            .arg("--no-session-footer")
            .arg(root)
            .env("FS_MCP_STATE_DIR", state)
            .env_remove("FILESYSTEM_MCP_CHAT_PARENT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        if let Some(parent) = parent {
            command.env("FILESYSTEM_MCP_CHAT_PARENT", parent);
        }
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
        let who = self.structured("chat_who", json!({})).await?;
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
    let who = agent.structured("chat_who", json!({})).await?;
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
    let mut asking =
        Agent::start_with_env(state.path(), root.path(), None, "chat-test", &env).await?;
    let mut peer = Agent::start(state.path(), root.path(), None).await?;
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
    let mut sender = Agent::start(state.path(), root.path(), None).await?;
    let mut quiet = Agent::start(state.path(), root.path(), None).await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let who = sender.structured("chat_who", json!({})).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
    let name_a = a.name().await?;
    let name_b = b.name().await?;
    assert_ne!(name_a, name_b);

    let who = a.structured("chat_who", json!({})).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
    let name_b = b.name().await?;
    a.name().await?;

    let started = Instant::now();
    let waiting = tokio::spawn(async move {
        let read = b.structured("chat_read", json!({"waitS": 60})).await;
        (b, read)
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let who = a.structured("chat_who", json!({})).await?;
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

    let who = b.structured("chat_who", json!({})).await?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut who = who;
    while who.to_string().contains("listening") {
        assert!(Instant::now() < deadline, "still listening: {who}");
        tokio::time::sleep(Duration::from_millis(50)).await;
        who = b.structured("chat_who", json!({})).await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_timed_wait_ends_without_asking_the_agent_to_keep_calling() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let read = a.structured("chat_read", json!({"waitS": 1})).await?;
    assert_eq!(read["timedOut"], true);
    assert!(read.get("next").is_none(), "{read}");
    Ok(())
}

#[tokio::test]
async fn an_idle_agents_wait_ends_with_the_message_and_says_to_start_again() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
    let mut c = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    Agent::start(state.path(), root.path(), None).await?;
    let output = start_wait(state.path(), "Nobody")?
        .wait_with_output()
        .await?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("chat_who"));
    Ok(())
}

/// A server whose client has gone must not stay behind: it would read as a live agent in the chat,
/// and a `chat-wait` for it would never end. Measured on a real session 2026-11-01: the client closed
/// the connection during a long `run_command`, and the server was still running minutes later.
#[tokio::test]
async fn a_server_exits_after_its_client_closes_the_connection_during_a_long_call() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
    let name_a = a.name().await?;
    let name_b = b.name().await?;
    a.structured("chat_send", json!({"to": name_b, "text": "do not lose me"}))
        .await?;
    assert!(content_text(&b.work().await?).contains("do not lose me"));

    b.child.kill().await?;
    b.child.wait().await?;

    let who = a.structured("chat_who", json!({})).await?;
    let closed = who["agents"]
        .as_array()
        .context("agents")?
        .iter()
        .any(|agent| agent["name"] == name_b.as_str() && agent["state"] == "closed");
    assert!(closed, "{who}");

    // A new process is not handed the dead agent's name while a message waits for it.
    let mut c = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let name_a = a.name().await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start_as(state.path(), root.path(), None, "codex-mcp-client").await?;
    let result = a.work().await?;
    assert!(!content_text(&result).contains("[chat]"), "{result}");
    assert!(result["structuredContent"].get("chat").is_none());
    Ok(())
}

#[tokio::test]
async fn an_agent_with_a_wait_running_is_not_asked_to_start_another() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
    assert!(String::from_utf8(output.stderr)?.contains("chat_who"));
    Ok(())
}

/// Nothing forces which of two pollers shows the message first, so the test shows it itself, as a
/// running wait would. If the read is quicker the message simply arrives as new.
#[tokio::test]
async fn a_timed_read_returns_a_message_something_else_showed_during_the_wait() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let mut b = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
    let who = a.structured("chat_who", json!({})).await?;
    assert_eq!(
        who["agents"].as_array().context("agents")?.len(),
        1,
        "{who}"
    );
    Ok(())
}

#[tokio::test]
async fn a_child_started_by_run_command_is_told_its_parent() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path(), None).await?;
    let name_a = a.name().await?;
    let command = if cfg!(windows) {
        "echo %FILESYSTEM_MCP_CHAT_PARENT%"
    } else {
        "printenv FILESYSTEM_MCP_CHAT_PARENT"
    };
    let ran = a
        .structured("run_command", json!({"command": command, "shell": true}))
        .await?;
    assert_eq!(ran["stdout"].as_str().context("stdout")?.trim(), name_a);

    // And a server started with that environment puts it in its address.
    let mut child = Agent::start(state.path(), root.path(), Some(&name_a)).await?;
    let who = child.structured("chat_who", json!({})).await?;
    assert!(
        who["you"]
            .as_str()
            .context("you")?
            .ends_with(&format!(":{name_a}")),
        "{who}"
    );
    Ok(())
}

#[tokio::test]
async fn an_empty_name_is_refused() -> Result<()> {
    let (state, root) = dirs()?;
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
    let mut a = Agent::start(state.path(), root.path(), None).await?;
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
