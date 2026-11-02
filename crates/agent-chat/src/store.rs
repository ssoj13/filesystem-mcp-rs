//! `chat.db`: who is here and every message, shared by all server processes on the machine.
//!
//! The database is the only channel between servers, so a crash on either side cannot lose a
//! committed message. Everything is synchronous; `session` calls it through `spawn_blocking`, and
//! `wait` owns its process. Time and process liveness are arguments, which keeps the rules testable
//! without sleeping or killing anything.
//!
//! A message moves `sent -> shown -> read`. `shown` means a result carried it to the client, which
//! says nothing about the model having seen it: a client can truncate or drop a result, and a
//! subagent shares the parent's server process. So only the agent's own act marks it `read`, and
//! it keeps being mentioned until then. The one exception is an acknowledgement, a reaction that asks
//! nothing and wakes nobody: it is `read` as soon as it has gone out.
//!
//! An agent shows as `listening` while something would hand it a message at once: an open
//! `chat_read` wait, or a running `chat-wait` process. A process id plus start time records the
//! second, so a killed wait stops counting without anyone having to clean up after it.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;

use crate::address::{Address, Target, next_name};

/// Bumped when the tables change. A server meeting an older file rebuilds it and carries over who is
/// here and everything unread, because an upgrade must not lose a message: see `carry_over`. A newer
/// file is refused, so that two installed versions cannot keep rebuilding each other's.
const SCHEMA_VERSION: i64 = 6;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS subscribers (
    name TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    topic TEXT NOT NULL,
    parent TEXT NOT NULL,
    client TEXT NOT NULL,
    pid INTEGER NOT NULL,
    pid_start INTEGER NOT NULL,
    seen_at INTEGER NOT NULL,
    listening_until INTEGER NOT NULL DEFAULT 0,
    waiter_pid INTEGER NOT NULL DEFAULT 0,
    waiter_start INTEGER NOT NULL DEFAULT 0,
    waits_started INTEGER NOT NULL DEFAULT 0,
    quiet_until INTEGER NOT NULL DEFAULT 0,
    status TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    sender_address TEXT NOT NULL,
    sender_pid INTEGER NOT NULL,
    sender_start INTEGER NOT NULL,
    recipient TEXT NOT NULL,
    recipient_pid INTEGER NOT NULL,
    recipient_start INTEGER NOT NULL,
    text TEXT NOT NULL,
    reaction TEXT,
    wakes INTEGER NOT NULL DEFAULT 1,
    closes INTEGER NOT NULL DEFAULT 0,
    reply_to INTEGER,
    hops INTEGER NOT NULL,
    sent_at INTEGER NOT NULL,
    shown_at INTEGER,
    woken_at INTEGER,
    read_at INTEGER
);
CREATE INDEX IF NOT EXISTS messages_unread ON messages(recipient) WHERE read_at IS NULL;
CREATE INDEX IF NOT EXISTS messages_by_sender ON messages(sender, id);
"#;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const KEEP_READ_MS: i64 = 14 * DAY_MS;
const KEEP_UNREAD_MS: i64 = 30 * DAY_MS;
/// How long a closed subscriber with nothing waiting stays on the list.
const KEEP_CLOSED_LISTED_MS: i64 = DAY_MS;
/// A tool call this recent reads as `working`.
const WORKING_MS: i64 = 60_000;
const BUSY_TIMEOUT: Duration = Duration::from_secs(10);
/// Unread messages one read hands back; the rest are reported as a count.
pub const READ_LIMIT: i64 = 50;

/// From this many replies on, a message no longer wakes anyone and tells the agent to stop answering
/// automatically, so two agents cannot spend turns on each other indefinitely. It is still delivered
/// on the next result: a limit that dropped messages would break the one promise the chat makes.
pub const HOP_LIMIT: i64 = 8;

/// Waking messages one agent may send another in [`WAKE_WINDOW_MS`]; the rest arrive without waking.
/// `HOP_LIMIT` bounds a chain, and two agents that answer with `to` instead of `replyTo` never make
/// one, so this is what bounds them. It is well above any real exchange, which is also why going
/// over it is reported to the sender.
const WAKE_BUDGET: i64 = 20;
const WAKE_WINDOW_MS: i64 = 10 * 60 * 1000;

/// How long a message can sit shown and unanswered, with its agent doing nothing, before a wait wakes
/// it anyway. A subagent sharing the server can be the one that was shown it; its parent then sits
/// idle knowing nothing, unless the subagent passes it on.
const OVERDUE_MS: i64 = 60_000;

/// Is the process with this id and start time still running? An argument so tests can decide.
pub type Alive<'a> = &'a dyn Fn(i64, i64) -> bool;

/// Everything `join` records about a subscriber.
pub struct Join {
    pub project: String,
    pub topic: String,
    pub parent: String,
    pub client: String,
    pub pid: i64,
    pub pid_start: i64,
    pub status: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: i64,
    pub from: String,
    pub to: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<i64>,
    /// Set for a one-word answer, whose `text` is that word.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reaction: Option<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub hops: i64,
    // A raw timestamp means nothing to a model without a clock: `session::age_text` says it in words.
    #[serde(skip)]
    pub sent_at: i64,
    #[serde(skip)]
    pub shown: bool,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// A one-word answer, the way radio traffic does it: unambiguous, and cheap for both sides. The sender
/// spends no text and the recipient gets one short line with no advice attached.
///
/// Whether it wakes the recipient is the point of the distinction: an answer may be what it is
/// waiting for, while an acknowledgement is not worth starting a model turn for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reaction {
    Yes,
    No,
    DontKnow,
    Wilco,
    SayAgain,
    Roger,
    Ok,
    Seen,
    Thanks,
    Standby,
    Out,
}

impl Reaction {
    pub const ALL: [Self; 11] = [
        Self::Yes,
        Self::No,
        Self::DontKnow,
        Self::Wilco,
        Self::SayAgain,
        Self::Roger,
        Self::Ok,
        Self::Seen,
        Self::Thanks,
        Self::Standby,
        Self::Out,
    ];

    pub fn word(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::DontKnow => "dontknow",
            Self::Wilco => "wilco",
            Self::SayAgain => "sayagain",
            Self::Roger => "roger",
            Self::Ok => "ok",
            Self::Seen => "seen",
            Self::Thanks => "thanks",
            Self::Standby => "standby",
            Self::Out => "out",
        }
    }

    pub fn parse(word: &str) -> Option<Self> {
        let word = word.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|reaction| reaction.word() == word)
    }

    /// An answer the other side may be waiting for, as opposed to an acknowledgement.
    pub fn wakes(self) -> bool {
        matches!(
            self,
            Self::Yes | Self::No | Self::DontKnow | Self::Wilco | Self::SayAgain
        )
    }

    /// This settles the message it answers, so nothing more follows on it. Not `standby`: that
    /// promises an answer to the very message it was given on.
    pub fn closes(self) -> bool {
        !self.wakes() && self != Self::Standby
    }
}

/// What a sender or `chat_who` can tell about an agent right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentState {
    Listening,
    /// Asked not to be disturbed for a while: messages wait until then.
    Quiet,
    Working,
    Idle,
    Closed,
}

/// How far one message got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Progress {
    Sent,
    Shown,
    Read,
}

#[cfg(test)]
impl PartialEq<&str> for AgentState {
    fn eq(&self, other: &&str) -> bool {
        serde_json::to_value(self).is_ok_and(|value| value == *other)
    }
}

#[cfg(test)]
impl PartialEq<&str> for Progress {
    fn eq(&self, other: &&str) -> bool {
        serde_json::to_value(self).is_ok_and(|value| value == *other)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscriber {
    pub address: String,
    pub name: String,
    pub client: String,
    pub state: AgentState,
    #[serde(skip_serializing_if = "is_zero")]
    pub unread: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// How much longer it asked to be left alone, in words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quiet_for: Option<String>,
    #[serde(skip)]
    pub owner: (i64, i64),
}

/// One message as its sender sees it right after sending.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sent {
    pub id: i64,
    pub to: String,
    pub recipient_state: AgentState,
    /// Set when the recipient asked for quiet: the sender learns why, and that it need not resend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quiet_for: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Past the reply limit or the sender's wake budget: it will be delivered, but it wakes nobody.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub over_limit: bool,
}

/// One earlier message and how far it got.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentStatus {
    pub id: i64,
    pub to: String,
    pub state: Progress,
}

/// The answer to a `chat-wait` asking to wait for a name.
#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    /// This wait now covers the name. Holds the owner's process id and start time, which the wait
    /// watches: when they stop matching a live process, there is nobody left to wake.
    Granted {
        owner: (i64, i64),
    },
    AlreadyWaiting,
    OwnerGone,
    NoSuchAgent,
}

/// What `Store::post` sends.
struct Post<'a> {
    target: Option<&'a Target>,
    text: &'a str,
    reply_to: Option<i64>,
    reaction: Option<Reaction>,
}

/// What a recipient's next result or read has to carry.
#[derive(Debug, Default)]
pub struct Unread {
    pub messages: Vec<Message>,
    /// Unread beyond what `messages` holds.
    pub more: i64,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// For a server: create the file if needed, rebuild one of an older version, and drop what has
    /// expired. Housekeeping: a sweep that fails costs nothing today and runs again at the next start.
    pub fn open(path: &Path, now: i64) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("cannot open chat database {}", path.display()))?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        prepare_with_retries(&conn)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        if let Err(error) = store.conn().execute(
            "DELETE FROM messages WHERE (read_at IS NOT NULL AND sent_at < ?1) OR sent_at < ?2",
            params![now - KEEP_READ_MS, now - KEEP_UNREAD_MS],
        ) {
            tracing::warn!("chat: cannot sweep old messages: {error}");
        }
        Ok(store)
    }

    /// For a `chat-wait`. It changes nothing about the file: it is given a path on a command line, and
    /// a mistyped one must not be created, nor an unrelated database rebuilt.
    pub fn connect(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .with_context(|| format!("no chat database at {}", path.display()))?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            bail!(
                "{} is not a chat database of this version ({version}, expected {SCHEMA_VERSION})",
                path.display()
            );
        }
        conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    // A panic while holding this leaves a connection that is still valid: every write here is one
    // statement or one transaction, which SQLite rolls back on its own.
    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record a subscriber and return its address.
    ///
    /// `current` is the name this session already has. `wanted` takes a name instead: refused if
    /// another live process owns it, and otherwise the unread messages come with it. With neither,
    /// the next free name is issued, where free means no owner alive and nothing unread.
    pub fn join(
        &self,
        join: &Join,
        current: Option<&str>,
        wanted: Option<&str>,
        now: i64,
        alive: Alive<'_>,
    ) -> Result<Address> {
        let mut conn = self.conn();
        // IMMEDIATE so that two servers starting together cannot pick the same name: the second
        // one waits here and sees the first one's row.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // A name this process no longer holds, because the file was rebuilt and someone else has it
        // now, must not be taken over by updating a topic, nor its messages by a rename.
        if let Some(current) = current {
            let owner: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT pid, pid_start FROM subscribers WHERE name = ?1",
                    [current],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((pid, start)) = owner
                && (pid, start) != (join.pid, join.pid_start)
                && alive(pid, start)
            {
                bail!("the name {current} belongs to a live agent");
            }
        }
        let name = match (wanted, current) {
            (Some(wanted), _) => {
                let owner: Option<(i64, i64)> = tx
                    .query_row(
                        "SELECT pid, pid_start FROM subscribers WHERE name = ?1",
                        [wanted],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                if let Some((pid, start)) = owner
                    && current != Some(wanted)
                    && alive(pid, start)
                {
                    bail!("the name {wanted} belongs to a live agent");
                }
                wanted.to_owned()
            }
            (None, Some(current)) => current.to_owned(),
            (None, None) => {
                let mut rows = Vec::new();
                {
                    let mut stmt = tx.prepare(
                        "SELECT s.name, s.pid, s.pid_start, EXISTS(SELECT 1 FROM messages m \
                         WHERE m.recipient = s.name AND m.read_at IS NULL) FROM subscribers s",
                    )?;
                    let mapped = stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, bool>(3)?,
                        ))
                    })?;
                    for row in mapped {
                        rows.push(row?);
                    }
                }
                next_name(|candidate| {
                    rows.iter().any(|(name, pid, start, unread)| {
                        name == candidate && (*unread || alive(*pid, *start))
                    })
                })
            }
        };
        // A rename is the same agent: what it said about itself goes with it.
        let mut carried = None;
        if let Some(current) = current
            && current != name
        {
            carried = tx
                .query_row(
                    "SELECT status, quiet_until FROM subscribers WHERE name = ?1",
                    [current],
                    |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?;
            tx.execute(
                "UPDATE messages SET recipient = ?1 WHERE recipient = ?2",
                params![name, current],
            )?;
            tx.execute(
                "UPDATE messages SET sender = ?1 WHERE sender = ?2",
                params![name, current],
            )?;
            tx.execute("DELETE FROM subscribers WHERE name = ?1", [current])?;
        }
        tx.execute(
            "INSERT INTO subscribers \
             (name, project, topic, parent, client, pid, pid_start, seen_at, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
             ON CONFLICT(name) DO UPDATE SET project = excluded.project, topic = excluded.topic, \
             parent = excluded.parent, client = excluded.client, pid = excluded.pid, \
             pid_start = excluded.pid_start, seen_at = excluded.seen_at, \
             listening_until = 0, \
             status = CASE WHEN pid = excluded.pid AND pid_start = excluded.pid_start \
             THEN COALESCE(excluded.status, status) ELSE excluded.status END, \
             waiter_pid = CASE WHEN pid = excluded.pid AND pid_start = excluded.pid_start \
             THEN waiter_pid ELSE 0 END, \
             waits_started = CASE WHEN pid = excluded.pid AND pid_start = excluded.pid_start \
             THEN waits_started ELSE 0 END, \
             quiet_until = CASE WHEN pid = excluded.pid AND pid_start = excluded.pid_start \
             THEN quiet_until ELSE 0 END",
            params![
                name,
                join.project,
                join.topic,
                join.parent,
                join.client,
                join.pid,
                join.pid_start,
                now,
                join.status
            ],
        )?;
        if let Some((status, quiet_until)) = carried {
            tx.execute(
                "UPDATE subscribers SET status = COALESCE(status, ?2), quiet_until = ?3 \
                 WHERE name = ?1",
                params![name, status, quiet_until],
            )?;
        }
        // A new owner takes over what is unread, and has seen none of it. What was already read stays
        // with the old owner: see `show`.
        tx.execute(
            "UPDATE messages SET recipient_pid = ?2, recipient_start = ?3, shown_at = NULL, \
             woken_at = NULL WHERE recipient = ?1 AND read_at IS NULL \
             AND (recipient_pid != ?2 OR recipient_start != ?3)",
            params![name, join.pid, join.pid_start],
        )?;
        tx.commit()?;
        Ok(Address {
            project: join.project.clone(),
            topic: join.topic.clone(),
            name,
            parent: join.parent.clone(),
        })
    }

    /// Note activity. `false` when this process no longer holds the name: a server of a newer version
    /// rebuilt the file, and the name may even have gone to someone else since. The caller has to
    /// join again, or it can never be reached and may read another agent's messages.
    pub fn touch(&self, name: &str, owner: (i64, i64), now: i64) -> Result<bool> {
        let updated = self.conn().execute(
            "UPDATE subscribers SET seen_at = ?4 WHERE name = ?1 AND pid = ?2 AND pid_start = ?3",
            params![name, owner.0, owner.1, now],
        )?;
        Ok(updated > 0)
    }

    /// Ask not to be disturbed until `until`; a time in the past ends it.
    pub fn set_quiet(&self, name: &str, until: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE subscribers SET quiet_until = ?2 WHERE name = ?1",
            params![name, until],
        )?;
        Ok(())
    }

    pub fn is_quiet(&self, name: &str, now: i64) -> Result<bool> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM subscribers WHERE name = ?1 AND quiet_until > ?2)",
        )?;
        Ok(stmt.query_row(params![name, now], |row| row.get(0))?)
    }

    /// Mark this subscriber as waiting in `chat_read` until `until`.
    pub fn set_listening(&self, name: &str, until: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE subscribers SET listening_until = ?2 WHERE name = ?1",
            params![name, until],
        )?;
        Ok(())
    }

    /// End that wait, unless a later one has replaced it: one call ending must not hide another.
    pub fn clear_listening(&self, name: &str, until: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE subscribers SET listening_until = 0 WHERE name = ?1 AND listening_until = ?2",
            params![name, until],
        )?;
        Ok(())
    }

    /// Let a `chat-wait` process wait for this name, unless a live one already does. One at a time
    /// because an agent that starts a second by mistake would otherwise leave it behind forever: the
    /// first takes the message, and nothing would ever end the other.
    pub fn claim_waiter(
        &self,
        name: &str,
        pid: i64,
        start: i64,
        alive: Alive<'_>,
    ) -> Result<Claim> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(i64, i64, i64, i64)> = tx
            .query_row(
                "SELECT pid, pid_start, waiter_pid, waiter_start FROM subscribers WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((owner_pid, owner_start, waiter_pid, waiter_start)) = row else {
            return Ok(Claim::NoSuchAgent);
        };
        if !alive(owner_pid, owner_start) {
            return Ok(Claim::OwnerGone);
        }
        if waiter_pid != 0
            && (waiter_pid, waiter_start) != (pid, start)
            && alive(waiter_pid, waiter_start)
        {
            return Ok(Claim::AlreadyWaiting);
        }
        tx.execute(
            "UPDATE subscribers SET waiter_pid = ?2, waiter_start = ?3, \
             waits_started = waits_started + 1 WHERE name = ?1",
            params![name, pid, start],
        )?;
        tx.commit()?;
        Ok(Claim::Granted {
            owner: (owner_pid, owner_start),
        })
    }

    /// End this process's claim. Someone else's claim stays.
    pub fn release_waiter(&self, name: &str, pid: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE subscribers SET waiter_pid = 0 WHERE name = ?1 AND waiter_pid = ?2",
            params![name, pid],
        )?;
        Ok(())
    }

    /// Is a live `chat-wait` covering this name?
    pub fn has_waiter(&self, name: &str, alive: Alive<'_>) -> Result<bool> {
        let row: Option<(i64, i64)> = self
            .conn()
            .query_row(
                "SELECT waiter_pid, waiter_start FROM subscribers WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(row.is_some_and(|(pid, start)| pid != 0 && alive(pid, start)))
    }

    /// How many waits have ever been granted for this name. Unlike [`Store::has_waiter`], this also
    /// sees a wait that has already ended, and proves the agent did not refuse.
    pub fn waits_started(&self, name: &str) -> Result<i64> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare_cached("SELECT waits_started FROM subscribers WHERE name = ?1")?;
        Ok(stmt
            .query_row([name], |row| row.get(0))
            .optional()?
            .unwrap_or(0))
    }

    /// The process id and start time of the wait holding this name, if the name exists.
    pub fn waiter(&self, name: &str) -> Result<Option<(i64, i64)>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT waiter_pid, waiter_start FROM subscribers WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// The process id and start time of whoever owns this name now.
    pub fn owner(&self, name: &str) -> Result<Option<(i64, i64)>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT pid, pid_start FROM subscribers WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// Send to one subscriber or a group, in one transaction: a group gets it whole or not at all.
    ///
    /// A reply marks the message it answers as read: answering it is proof it was seen. With no
    /// `target` a reply goes to the other side of the message it answers.
    pub fn send(
        &self,
        me: &Address,
        target: Option<&Target>,
        text: &str,
        reply_to: Option<i64>,
        now: i64,
        alive: Alive<'_>,
    ) -> Result<Vec<Sent>> {
        let post = Post {
            target,
            text,
            reply_to,
            reaction: None,
        };
        self.post(me, post, now, alive)
    }

    /// Answer message `id` with one word.
    pub fn react(
        &self,
        me: &Address,
        id: i64,
        reaction: Reaction,
        now: i64,
        alive: Alive<'_>,
    ) -> Result<Vec<Sent>> {
        let post = Post {
            target: None,
            text: reaction.word(),
            reply_to: Some(id),
            reaction: Some(reaction),
        };
        self.post(me, post, now, alive)
    }

    fn post(&self, me: &Address, post: Post<'_>, now: i64, alive: Alive<'_>) -> Result<Vec<Sent>> {
        let Post {
            target,
            text,
            reply_to,
            reaction,
        } = post;
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut hops = 0;
        let mut other_side = None;
        if let Some(id) = reply_to {
            type Owner = (i64, i64);
            let (sender, recipient, parent_hops, sender_owner, recipient_owner, closed): (
                String,
                String,
                i64,
                Owner,
                Owner,
                bool,
            ) = tx
                .query_row(
                    "SELECT sender, recipient, hops, sender_pid, sender_start, recipient_pid, \
                     recipient_start, reaction IS NOT NULL AND wakes = 0 FROM messages \
                     WHERE id = ?1",
                    [id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            (row.get(3)?, row.get(4)?),
                            (row.get(5)?, row.get(6)?),
                            row.get(7)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| anyhow!("no message #{id} to reply to"))?;
            // An acknowledgement ends the exchange: answering one is how two agents thank each other
            // forever. A new message to them with `to` is still open.
            let settled: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE reply_to = ?1 AND closes = 1)",
                [id],
                |row| row.get(0),
            )?;
            if (closed || settled) && target.is_none() {
                bail!(
                    "#{id} takes no answer, it was acknowledged: send `text` with `to` for something new"
                );
            }
            // Names come round again, and an answer must not reach a stranger who has the name now.
            // Asking for them by name with `to` is still possible, knowingly.
            let still_theirs = |name: &str, owner: Owner| -> Result<()> {
                let now_owned: Option<Owner> = tx
                    .query_row(
                        "SELECT pid, pid_start FROM subscribers WHERE name = ?1",
                        [name],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                if target.is_none() && now_owned != Some(owner) {
                    bail!(
                        "the other agent of #{id} is gone and {name} now means someone else: send \
                         `text` with `to` if you mean them"
                    );
                }
                Ok(())
            };
            if recipient == me.name {
                tx.execute(
                    "UPDATE messages SET read_at = ?2 WHERE id = ?1 AND read_at IS NULL",
                    params![id, now],
                )?;
                still_theirs(&sender, sender_owner)?;
                other_side = Some(sender);
            } else if sender == me.name {
                still_theirs(&recipient, recipient_owner)?;
                other_side = Some(recipient);
            } else {
                bail!("message #{id} was not sent to or by {}", me.name);
            }
            // Counted over everything already said on this message, not from it alone: otherwise two
            // agents reacting to the same message would never reach the limit.
            let deepest: i64 = tx.query_row(
                "SELECT COALESCE(MAX(hops), 0) FROM messages WHERE reply_to = ?1",
                [id],
                |row| row.get(0),
            )?;
            hops = parent_hops.max(deepest) + 1;
        }
        let target = match (target, other_side) {
            (Some(target), _) => target.clone(),
            (None, Some(name)) => Target::Name(name),
            (None, None) => bail!("say who it is for: to, or replyTo"),
        };
        let everyone = subscribers(&tx, now, alive, Listing::All)?;
        let recipients: Vec<&Subscriber> = everyone
            .iter()
            .filter(|subscriber| {
                let matched = parse_address(&subscriber.address)
                    .is_some_and(|address| target.matches(&address));
                matched
                    && (target.is_exact()
                        || (subscriber.state != AgentState::Closed && subscriber.name != me.name))
            })
            .collect();
        if recipients.is_empty() {
            let live: Vec<&str> = everyone
                .iter()
                .filter(|subscriber| subscriber.state != AgentState::Closed)
                .map(|subscriber| subscriber.address.as_str())
                .collect();
            bail!("nobody matches; live agents: {}", live.join(", "));
        }
        let (my_pid, my_start): (i64, i64) = tx.query_row(
            "SELECT pid, pid_start FROM subscribers WHERE name = ?1",
            [&me.name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let mut sent = Vec::with_capacity(recipients.len());
        let wakes_by_kind = reaction.is_none_or(Reaction::wakes);
        for recipient in recipients {
            let recent_wakes: i64 = tx.query_row(
                "SELECT COUNT(*) FROM messages WHERE sender = ?1 AND recipient = ?2 AND wakes = 1 \
                 AND sent_at > ?3",
                params![me.name, recipient.name, now - WAKE_WINDOW_MS],
                |row| row.get(0),
            )?;
            // Not a reaction: `wakes = 0` on one means an acknowledgement, which is read as it goes
            // out and takes no answer. A reaction has a `replyTo`, so the reply limit bounds it.
            let over_budget = reaction.is_none() && wakes_by_kind && recent_wakes >= WAKE_BUDGET;
            tx.execute(
                "INSERT INTO messages (sender, sender_address, sender_pid, sender_start, \
                 recipient, recipient_pid, recipient_start, text, reaction, wakes, closes, reply_to, \
                 hops, sent_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    me.name,
                    me.to_string(),
                    my_pid,
                    my_start,
                    recipient.name,
                    recipient.owner.0,
                    recipient.owner.1,
                    text,
                    reaction.map(Reaction::word),
                    wakes_by_kind && !over_budget,
                    reaction.is_some_and(Reaction::closes),
                    reply_to,
                    hops,
                    now
                ],
            )?;
            sent.push(Sent {
                id: tx.last_insert_rowid(),
                to: recipient.address.clone(),
                recipient_state: recipient.state,
                over_limit: hops >= HOP_LIMIT || over_budget,
                quiet_for: recipient.quiet_for.clone(),
                status: recipient
                    .quiet_for
                    .as_ref()
                    .and_then(|_| recipient.status.clone()),
            });
        }
        tx.commit()?;
        Ok(sent)
    }

    /// Is something waiting that no result has carried yet? The cheap question a wait polls.
    pub fn has_fresh(&self, name: &str) -> Result<bool> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM messages \
             WHERE recipient = ?1 AND read_at IS NULL AND shown_at IS NULL)",
        )?;
        Ok(stmt.query_row([name], |row| row.get(0))?)
    }

    /// Should a `chat-wait` end now? Not during quiet, not for a message past the reply limit, and not
    /// for an acknowledgement: all still arrive, but none is worth starting a model turn for.
    pub fn has_wakeful(&self, name: &str, now: i64) -> Result<bool> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE recipient = ?1 AND read_at IS NULL \
             AND shown_at IS NULL AND hops < ?2 AND wakes = 1) AND NOT EXISTS(SELECT 1 FROM subscribers \
             WHERE name = ?1 AND quiet_until > ?3)",
        )?;
        Ok(stmt.query_row(params![name, HOP_LIMIT, now], |row| row.get(0))?)
    }

    /// Messages shown long ago and still unanswered, with this agent doing nothing since: whoever was
    /// shown them may not be it. Each comes back once, marked woken here, and a message a wait has
    /// already woken it for never does (`mark_woken`), so an agent that chose not to answer is not
    /// woken over and over. Not during quiet, and only what could wake it at all.
    pub fn take_overdue(&self, name: &str, now: i64) -> Result<Vec<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "UPDATE messages SET woken_at = ?2 WHERE recipient = ?1 AND read_at IS NULL \
             AND woken_at IS NULL AND wakes = 1 AND hops < ?3 AND shown_at <= ?2 - ?4 \
             AND EXISTS(SELECT 1 FROM subscribers s WHERE s.name = ?1 AND s.seen_at <= ?2 - ?4 \
             AND s.quiet_until <= ?2) \
             RETURNING id, sender_address, recipient, text, reply_to, hops, sent_at, FALSE, reaction",
        )?;
        let mapped = stmt.query_map(params![name, now, HOP_LIMIT, OVERDUE_MS], message_of_row)?;
        let mut messages = Vec::new();
        for message in mapped {
            messages.push(message?);
        }
        messages.sort_by_key(|message| message.id);
        Ok(messages)
    }

    /// A wait has just woken this agent with these messages.
    pub fn mark_woken(&self, name: &str, messages: &[Message], now: i64) -> Result<()> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare_cached("UPDATE messages SET woken_at = ?3 WHERE id = ?1 AND recipient = ?2")?;
        for message in messages {
            stmt.execute(params![message.id, name, now])?;
        }
        Ok(())
    }

    /// Is anything unread at all? The first question on every tool call, so it stays this cheap:
    /// nearly always the answer is no, and no message text gets loaded.
    pub fn has_unread(&self, name: &str) -> Result<bool> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE recipient = ?1 AND read_at IS NULL)",
        )?;
        Ok(stmt.query_row([name], |row| row.get(0))?)
    }

    /// For a timed wait: the newest unread message now, to compare against.
    pub fn latest_unread_id(&self, name: &str) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT COALESCE(MAX(id), 0) FROM messages WHERE recipient = ?1 AND read_at IS NULL",
            [name],
            |row| row.get(0),
        )?)
    }

    /// Has anything arrived for a timed wait to return? A message newer than `after` counts even if
    /// a running `chat-wait` has already shown it: this caller is waiting for it just the same.
    pub fn has_new(&self, name: &str, after: i64) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE recipient = ?1 AND read_at IS NULL \
             AND (shown_at IS NULL OR id > ?2))",
            params![name, after],
            |row| row.get(0),
        )?)
    }

    /// Unread messages in id order, up to the limit, marking the ones not shown before as shown.
    ///
    /// Not-yet-shown ones are picked first: picking oldest first would let a backlog of shown,
    /// unconfirmed messages hide a new one for good. `Message::shown` is decided by the marking
    /// `UPDATE` itself, so two processes racing for a message cannot both present it as new. Takes
    /// the write lock only when there is something to mark: this runs on every tool call, and the
    /// usual answer is nothing.
    pub fn take_unread(&self, name: &str, now: i64) -> Result<Unread> {
        let mut conn = self.conn();
        let mut messages = Vec::new();
        {
            let mut stmt = conn.prepare_cached(
                "SELECT id, sender_address, recipient, text, reply_to, hops, sent_at, \
                 shown_at IS NOT NULL, reaction FROM messages \
                 WHERE recipient = ?1 AND read_at IS NULL \
                 ORDER BY shown_at IS NOT NULL, id LIMIT ?2",
            )?;
            let mapped = stmt.query_map(params![name, READ_LIMIT], message_of_row)?;
            for message in mapped {
                messages.push(message?);
            }
        }
        if messages.is_empty() {
            return Ok(Unread::default());
        }
        // Before anything changes, so that this can fail with nothing marked, and so that the
        // acknowledgements about to be retired count: they were beyond the limit and were not sent.
        let more = if messages.len() as i64 == READ_LIMIT {
            let total: i64 = conn.query_row(
                "SELECT COUNT(*) FROM messages WHERE recipient = ?1 AND read_at IS NULL",
                [name],
                |row| row.get(0),
            )?;
            (total - READ_LIMIT).max(0)
        } else {
            0
        };
        let last_new = messages
            .iter()
            .filter(|message| !message.shown)
            .map(|message| message.id)
            .max();
        if let Some(last_new) = last_new {
            // One transaction: a failure after marking would lose the text, since nothing that
            // follows would present these as new again.
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut won = Vec::new();
            {
                let mut stmt = tx.prepare_cached(
                    "UPDATE messages SET shown_at = ?3 WHERE recipient = ?1 AND read_at IS NULL \
                     AND shown_at IS NULL AND id <= ?2 RETURNING id",
                )?;
                for id in
                    stmt.query_map(params![name, last_new, now], |row| row.get::<_, i64>(0))?
                {
                    won.push(id?);
                }
            }
            // An acknowledgement has nothing to confirm or remind about once it has gone out. An
            // answer does: whoever was shown it may not be the one waiting for it.
            tx.execute(
                "UPDATE messages SET read_at = ?2 WHERE recipient = ?1 AND read_at IS NULL \
                 AND reaction IS NOT NULL AND wakes = 0 AND shown_at IS NOT NULL",
                params![name, now],
            )?;
            tx.commit()?;
            for message in &mut messages {
                message.shown = !won.contains(&message.id);
            }
        }
        messages.sort_by_key(|message| message.id);
        Ok(Unread { messages, more })
    }

    /// This subscriber's own messages by id, read or not, so that text is never out of reach while
    /// it is kept: an agent can confirm a message it never saw, or saw cut. An id from someone else's
    /// conversation returns nothing, and that includes the previous owner of a name that came round
    /// again. Does not change any message's state.
    pub fn show(&self, name: &str, ids: &[i64]) -> Result<Vec<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT m.id, m.sender_address, m.recipient, m.text, m.reply_to, m.hops, m.sent_at, \
             TRUE, m.reaction FROM messages m JOIN subscribers s ON s.name = m.recipient \
             AND s.pid = m.recipient_pid AND s.pid_start = m.recipient_start \
             WHERE m.id = ?1 AND m.recipient = ?2",
        )?;
        let mut messages = Vec::with_capacity(ids.len());
        for id in ids {
            messages.extend(
                stmt.query_row(params![id, name], message_of_row)
                    .optional()?,
            );
        }
        Ok(messages)
    }

    /// Mark messages read. Only this subscriber's own: an id from someone else's conversation
    /// changes nothing and is not counted.
    pub fn ack(&self, name: &str, ids: &[i64], now: i64) -> Result<usize> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut acked = 0;
        for id in ids {
            acked += tx.execute(
                "UPDATE messages SET read_at = ?3 \
                 WHERE id = ?1 AND recipient = ?2 AND read_at IS NULL",
                params![id, name, now],
            )?;
        }
        tx.commit()?;
        Ok(acked)
    }

    pub fn who(&self, now: i64, alive: Alive<'_>) -> Result<Vec<Subscriber>> {
        subscribers(&self.conn(), now, alive, Listing::ForPeople)
    }

    /// The last `limit` messages this subscriber sent, newest first, and how far each got.
    pub fn sent_status(&self, name: &str, limit: i64) -> Result<Vec<SentStatus>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT m.id, m.recipient, m.read_at IS NOT NULL, m.shown_at IS NOT NULL \
             FROM messages m JOIN subscribers s ON s.name = m.sender \
             AND s.pid = m.sender_pid AND s.pid_start = m.sender_start \
             WHERE m.sender = ?1 ORDER BY m.id DESC LIMIT ?2",
        )?;
        let mapped = stmt.query_map(params![name, limit], |row| {
            let read: bool = row.get(2)?;
            let shown: bool = row.get(3)?;
            Ok(SentStatus {
                id: row.get(0)?,
                to: row.get(1)?,
                state: if read {
                    Progress::Read
                } else if shown {
                    Progress::Shown
                } else {
                    Progress::Sent
                },
            })
        })?;
        let mut statuses = Vec::new();
        for status in mapped {
            statuses.push(status?);
        }
        Ok(statuses)
    }
}

/// The columns `take_unread` and `show` select, in that order.
fn message_of_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Message> {
    Ok(Message {
        id: row.get(0)?,
        from: row.get(1)?,
        to: row.get(2)?,
        text: row.get(3)?,
        reply_to: row.get(4)?,
        hops: row.get(5)?,
        sent_at: row.get(6)?,
        shown: row.get(7)?,
        reaction: row.get(8)?,
    })
}

/// Switch to WAL and bring the tables to this version. The switch needs an exclusive lock that a busy
/// timeout does not always wait for, and several servers first opening one new file together do
/// collide on it.
fn prepare_with_retries(conn: &Connection) -> Result<()> {
    const ATTEMPTS: u32 = 10;
    const PAUSE: Duration = Duration::from_millis(100);
    let prepare = || -> rusqlite::Result<i64> {
        // Dozens of servers share this file, and a message must survive any one of them dying.
        // NORMAL under WAL can lose the last commits only on a power cut, never on a crash.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        // IMMEDIATE so that two processes meeting an old file cannot both rebuild it, the second
        // wiping what the first has just received.
        let tx = rusqlite::Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version < SCHEMA_VERSION {
            tx.execute_batch(
                "DROP TABLE IF EXISTS old_messages; DROP TABLE IF EXISTS old_subscribers;",
            )?;
            for (table, old) in [
                ("messages", "old_messages"),
                ("subscribers", "old_subscribers"),
            ] {
                if table_exists(&tx, table)? {
                    tx.execute_batch(&format!("ALTER TABLE {table} RENAME TO {old}"))?;
                }
            }
            // The indexes go with their renamed table but keep their names.
            tx.execute_batch(
                "DROP INDEX IF EXISTS messages_unread; DROP INDEX IF EXISTS messages_by_sender;",
            )?;
            tx.execute_batch(SCHEMA)?;
            carry_over(&tx, "messages", "old_messages", "WHERE read_at IS NULL")?;
            carry_over(&tx, "subscribers", "old_subscribers", "")?;
            // Ids must not come round again: a stale `replyTo` would mark a stranger's message read.
            // The counter went with the renamed table, and only the read rows knew its highest.
            tx.execute_batch(
                "DELETE FROM sqlite_sequence WHERE name = 'messages'; \
                 INSERT INTO sqlite_sequence (name, seq) \
                 SELECT 'messages', seq FROM sqlite_sequence WHERE name = 'old_messages';",
            )?;
            tx.execute_batch(
                "DROP TABLE IF EXISTS old_messages; DROP TABLE IF EXISTS old_subscribers;",
            )?;
            tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
        }
        tx.commit()?;
        Ok(version)
    };
    let mut attempt = 1;
    loop {
        match prepare() {
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy && attempt < ATTEMPTS =>
            {
                attempt += 1;
                std::thread::sleep(PAUSE);
            }
            Ok(version) if version > SCHEMA_VERSION => {
                bail!("this chat database is newer ({version}) than this server ({SCHEMA_VERSION})")
            }
            other => {
                other?;
                return Ok(());
            }
        }
    }
}

fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
}

/// Copy what an older table held into its new version, column by column, so that a new column needs
/// no code here. A table too old to fill a required new column is left behind: the alternative is a
/// row that makes no sense. `filter` also has to be possible, which the same check decides, since it
/// only names a column the old table may lack.
fn carry_over(conn: &Connection, table: &str, old: &str, filter: &str) -> rusqlite::Result<()> {
    if !table_exists(conn, old)? {
        return Ok(());
    }
    let columns = |of: &str| -> rusqlite::Result<Vec<(String, bool)>> {
        let mut stmt = conn.prepare(&format!(
            "SELECT name, \"notnull\" AND dflt_value IS NULL AND pk = 0 FROM pragma_table_info('{of}')"
        ))?;
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect()
    };
    let wanted = columns(table)?;
    let had = columns(old)?;
    let has = |name: &str| had.iter().any(|(column, _)| column == name);
    let filter_possible = filter.is_empty() || has("read_at");
    if !filter_possible
        || wanted
            .iter()
            .any(|(name, required)| *required && !has(name))
    {
        tracing::warn!("chat: {old} is too old to carry over");
        return Ok(());
    }
    let common = wanted
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| has(name))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute_batch(&format!(
        "INSERT INTO {table} ({common}) SELECT {common} FROM {old} {filter}"
    ))
}

/// A span in words: `18 min`, `4 h 5 min`, `2 d 3 h`.
pub fn duration_text(ms: i64) -> String {
    let minutes = ms.max(0) / 60_000;
    match minutes {
        0 => "under a min".to_owned(),
        1..=59 => format!("{minutes} min"),
        60..=1439 => format!("{} h {} min", minutes / 60, minutes % 60),
        _ => format!("{} d {} h", minutes / 1440, minutes % 1440 / 60),
    }
}

fn parse_address(raw: &str) -> Option<Address> {
    let mut parts = raw.split(':');
    Some(Address {
        project: parts.next()?.to_owned(),
        topic: parts.next()?.to_owned(),
        name: parts.next()?.to_owned(),
        parent: parts.next()?.to_owned(),
    })
}

/// Who a query is for. A message can still be sent to an agent long gone; the list need not show it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Listing {
    All,
    ForPeople,
}

fn subscribers(
    conn: &Connection,
    now: i64,
    alive: Alive<'_>,
    listing: Listing,
) -> Result<Vec<Subscriber>> {
    let mut stmt = conn.prepare(
        "SELECT s.project, s.topic, s.name, s.parent, s.client, s.pid, s.pid_start, s.seen_at, \
         s.listening_until, s.status, (SELECT COUNT(*) FROM messages m \
         WHERE m.recipient = s.name AND m.read_at IS NULL), s.waiter_pid, s.waiter_start, \
         s.quiet_until FROM subscribers s ORDER BY s.name",
    )?;
    let mapped = stmt.query_map([], |row| {
        let address = Address {
            project: row.get(0)?,
            topic: row.get(1)?,
            name: row.get(2)?,
            parent: row.get(3)?,
        };
        let client: String = row.get(4)?;
        let pid: i64 = row.get(5)?;
        let start: i64 = row.get(6)?;
        let seen_at: i64 = row.get(7)?;
        let listening_until: i64 = row.get(8)?;
        let status: Option<String> = row.get(9)?;
        let unread: i64 = row.get(10)?;
        let waiter_pid: i64 = row.get(11)?;
        let waiter_start: i64 = row.get(12)?;
        let quiet_until: i64 = row.get(13)?;
        let state = if !alive(pid, start) {
            AgentState::Closed
        } else if quiet_until > now {
            AgentState::Quiet
        } else if listening_until > now || (waiter_pid != 0 && alive(waiter_pid, waiter_start)) {
            AgentState::Listening
        } else if now - seen_at < WORKING_MS {
            AgentState::Working
        } else {
            AgentState::Idle
        };
        let quiet_for = (quiet_until > now && state != AgentState::Closed)
            .then(|| duration_text(quiet_until - now));
        let status = status.filter(|text| !text.is_empty());
        Ok((
            address,
            client,
            state,
            seen_at,
            status,
            unread,
            quiet_for,
            (pid, start),
        ))
    })?;
    let mut out = Vec::new();
    for row in mapped {
        let (address, client, state, seen_at, status, unread, quiet_for, owner) = row?;
        // Without this the list grows by one line per session for as long as the file lives.
        if listing == Listing::ForPeople
            && state == AgentState::Closed
            && unread == 0
            && now - seen_at > KEEP_CLOSED_LISTED_MS
        {
            continue;
        }
        out.push(Subscriber {
            address: address.to_string(),
            name: address.name,
            client,
            state,
            unread,
            status,
            quiet_for,
            owner,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000_000_000;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("chat.db"), NOW).unwrap();
        (dir, store)
    }

    fn join_of(pid: i64) -> Join {
        Join {
            project: "fs".to_owned(),
            topic: "-".to_owned(),
            parent: "-".to_owned(),
            client: "test".to_owned(),
            pid,
            pid_start: 1,
            status: None,
        }
    }

    fn everyone_alive(_: i64, _: i64) -> bool {
        true
    }

    fn nobody_alive(_: i64, _: i64) -> bool {
        false
    }

    fn subscribe(store: &Store, pid: i64) -> Address {
        store
            .join(&join_of(pid), None, None, NOW, &everyone_alive)
            .unwrap()
    }

    fn to(name: &str) -> Target {
        Target::parse(name).unwrap()
    }

    #[test]
    fn two_live_agents_never_get_the_same_name() {
        let (_dir, store) = store();
        let first = subscribe(&store, 1);
        let second = subscribe(&store, 2);
        assert_eq!(first.name, "Erdos");
        assert_eq!(second.name, "Halsted");
    }

    #[test]
    fn parallel_joins_from_separate_connections_get_distinct_names() {
        let dir = tempfile::tempdir().unwrap();
        // Not created beforehand: first opening a new file together is part of what is tested.
        let path = dir.path().join("chat.db");
        let handles: Vec<_> = (0..8)
            .map(|pid| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let store = Store::open(&path, NOW).unwrap();
                    subscribe(&store, pid).name
                })
            })
            .collect();
        let mut names: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 8);
    }

    #[test]
    fn a_name_with_unread_messages_stays_out_of_circulation() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        let next = store
            .join(&join_of(3), None, None, NOW, &nobody_alive)
            .unwrap();
        assert_eq!(next.name, "Erdos", "the dead Erdos has nothing waiting");
        assert_ne!(next.name, halsted.name);
    }

    #[test]
    fn a_backlog_of_unconfirmed_messages_cannot_hide_a_new_one() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let send = |text: &str| {
            store
                .send(
                    &erdos,
                    Some(&to("Halsted")),
                    text,
                    None,
                    NOW,
                    &everyone_alive,
                )
                .unwrap()[0]
                .id
        };
        for _ in 0..READ_LIMIT {
            send("old");
        }
        store.take_unread("Halsted", NOW).unwrap();
        let newest = send("new");
        assert!(store.has_fresh("Halsted").unwrap());

        let unread = store.take_unread("Halsted", NOW).unwrap();
        assert_eq!(unread.messages.len() as i64, READ_LIMIT);
        assert_eq!(unread.more, 1, "and the count of the rest is still right");
        let new = unread.messages.iter().find(|m| m.id == newest).unwrap();
        assert!(!new.shown);
        assert_eq!(new.text, "new");
        assert!(!store.has_fresh("Halsted").unwrap());
        assert!(unread.messages.windows(2).all(|w| w[0].id < w[1].id));
    }

    #[test]
    fn only_one_of_many_readers_racing_for_a_message_sees_it_as_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let store = Store::open(&path, NOW).unwrap();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        for _ in 0..20 {
            store
                .send(
                    &erdos,
                    Some(&to("Halsted")),
                    "hi",
                    None,
                    NOW,
                    &everyone_alive,
                )
                .unwrap();
            let start = std::sync::Arc::new(std::sync::Barrier::new(4));
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    let path = path.clone();
                    let start = start.clone();
                    std::thread::spawn(move || {
                        let reader = Store::connect(&path).unwrap();
                        start.wait();
                        let unread = reader.take_unread("Halsted", NOW).unwrap();
                        unread.messages.iter().filter(|m| !m.shown).count()
                    })
                })
                .collect();
            let new: usize = readers.into_iter().map(|r| r.join().unwrap()).sum();
            assert_eq!(new, 1);
            let id = store.take_unread("Halsted", NOW).unwrap().messages[0].id;
            store.ack("Halsted", &[id], NOW).unwrap();
        }
    }

    #[test]
    fn a_confirmed_message_can_still_be_shown_and_only_to_its_recipient() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let id = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "text",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        store.ack("Halsted", &[id], NOW).unwrap();
        assert_eq!(store.show("Halsted", &[id]).unwrap()[0].text, "text");
        assert!(store.show("Freud", &[id]).unwrap().is_empty());
        assert_eq!(store.sent_status("Erdos", 1).unwrap()[0].state, "read");
    }

    #[test]
    fn a_renamed_agent_keeps_its_read_messages_and_its_sent_history() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        let id = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "text",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        store.ack("Halsted", &[id], NOW).unwrap();
        store
            .send(
                &halsted,
                Some(&to("Erdos")),
                "back",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        store
            .join(
                &join_of(2),
                Some("Halsted"),
                Some("Newton"),
                NOW,
                &everyone_alive,
            )
            .unwrap();
        assert_eq!(store.show("Newton", &[id]).unwrap()[0].text, "text");
        assert_eq!(store.sent_status("Newton", 5).unwrap().len(), 1);
    }

    #[test]
    fn a_reply_does_not_reach_a_stranger_who_inherited_the_senders_name() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        let id = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "q",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        store
            .join(&join_of(3), None, Some("Erdos"), NOW, &|pid, _| pid != 1)
            .unwrap();
        let error = store
            .send(&halsted, None, "a", Some(id), NOW, &everyone_alive)
            .unwrap_err()
            .to_string();
        assert!(error.contains("someone else"), "{error}");
        assert!(
            store
                .send(
                    &halsted,
                    Some(&to("Erdos")),
                    "a",
                    Some(id),
                    NOW,
                    &everyone_alive
                )
                .is_ok(),
            "asking for them by name is deliberate"
        );
    }

    #[test]
    fn one_wait_ending_does_not_clear_a_later_one() {
        let (_dir, store) = store();
        subscribe(&store, 1);
        store.set_listening("Erdos", NOW + 10).unwrap();
        store.set_listening("Erdos", NOW + 20).unwrap();
        store.clear_listening("Erdos", NOW + 10).unwrap();
        assert_eq!(
            store.who(NOW + 1, &everyone_alive).unwrap()[0].state,
            "listening"
        );
        store.clear_listening("Erdos", NOW + 20).unwrap();
        assert_eq!(
            store.who(NOW + 1, &everyone_alive).unwrap()[0].state,
            "working"
        );
    }

    #[test]
    fn a_reply_from_the_sender_does_not_reach_a_stranger_either() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let id = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "q",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        // Read, so it stays with the agent that read it: unread ones pass to whoever takes the name.
        store.ack("Halsted", &[id], NOW).unwrap();
        store
            .join(&join_of(3), None, Some("Halsted"), NOW, &|pid, _| pid != 2)
            .unwrap();
        assert!(
            store
                .send(&erdos, None, "more", Some(id), NOW, &everyone_alive)
                .is_err()
        );
    }

    #[test]
    fn the_next_owner_of_a_name_sees_nothing_the_last_one_read_or_sent() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        let read = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "private",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        store.ack("Halsted", &[read], NOW).unwrap();
        store
            .send(
                &halsted,
                Some(&to("Erdos")),
                "mine",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        store
            .join(&join_of(3), None, Some("Halsted"), NOW, &|pid, _| pid != 2)
            .unwrap();
        assert!(store.show("Halsted", &[read]).unwrap().is_empty());
        assert!(store.sent_status("Halsted", 5).unwrap().is_empty());
    }

    #[test]
    fn taking_over_a_name_makes_its_unread_messages_new_again() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        store.take_unread("Halsted", NOW).unwrap();
        assert!(!store.has_fresh("Halsted").unwrap());
        store
            .join(&join_of(3), None, Some("Halsted"), NOW, &|pid, _| pid != 2)
            .unwrap();
        assert!(store.has_fresh("Halsted").unwrap());
    }

    #[test]
    fn a_quiet_agent_is_not_woken_and_the_sender_is_told_for_how_long_and_why() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let mut busy = join_of(2);
        busy.status = Some("rebuilding".to_owned());
        store.join(&busy, None, None, NOW, &everyone_alive).unwrap();
        store.set_quiet("Halsted", NOW + 20 * 60_000).unwrap();
        let sent = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        assert_eq!(sent[0].recipient_state, "quiet");
        assert_eq!(sent[0].quiet_for.as_deref(), Some("20 min"));
        assert_eq!(sent[0].status.as_deref(), Some("rebuilding"));
        assert!(!store.has_wakeful("Halsted", NOW).unwrap());
        assert!(store.is_quiet("Halsted", NOW).unwrap());
        assert!(
            store.has_wakeful("Halsted", NOW + 20 * 60_000).unwrap(),
            "it ends by itself"
        );
        assert_eq!(
            store.take_unread("Halsted", NOW).unwrap().messages.len(),
            1,
            "an explicit read always works"
        );
    }

    #[test]
    fn a_long_chain_stops_waking_but_still_arrives() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        let mut id = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "0",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        let mut turn = [&halsted, &erdos].into_iter().cycle();
        for _ in 0..HOP_LIMIT {
            let from = turn.next().unwrap();
            id = store
                .send(from, None, "again", Some(id), NOW, &everyone_alive)
                .unwrap()[0]
                .id;
        }
        let last = if HOP_LIMIT % 2 == 0 {
            "Halsted"
        } else {
            "Erdos"
        };
        assert!(!store.has_wakeful(last, NOW).unwrap());
        let other = if last == "Halsted" { &erdos } else { &halsted };
        let normal = store
            .send(
                other,
                Some(&to(last)),
                "new topic",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        assert!(!normal[0].over_limit);
        assert!(
            store.has_wakeful(last, NOW).unwrap(),
            "a normal message still wakes past one over the limit"
        );
        let arrived = store.take_unread(last, NOW).unwrap();
        assert!(arrived.messages.iter().any(|m| m.hops == HOP_LIMIT));
    }

    #[test]
    fn a_file_from_a_newer_version_is_refused_and_a_wait_never_changes_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE messages (keep TEXT); INSERT INTO messages VALUES ('x');",
            )
            .unwrap();
        }
        assert!(Store::connect(&path).is_err(), "not a chat database");
        let conn = Connection::open(&path).unwrap();
        let kept: String = conn
            .query_row("SELECT keep FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, "x");
        conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION + 1))
            .unwrap();
        drop(conn);
        assert!(Store::open(&path, NOW).is_err());
        let conn = Connection::open(&path).unwrap();
        let kept: String = conn
            .query_row("SELECT keep FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, "x", "a newer file is left as it was");
    }

    #[test]
    fn an_answer_wakes_and_an_acknowledgement_does_not_and_neither_needs_confirming() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        let question = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "q",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        let answer = store
            .react(&halsted, question, Reaction::Yes, NOW, &everyone_alive)
            .unwrap();
        assert_eq!(
            store.sent_status("Erdos", 1).unwrap()[0].state,
            "read",
            "it answers"
        );
        assert!(store.has_wakeful("Erdos", NOW).unwrap());
        let got = store.take_unread("Erdos", NOW).unwrap();
        assert_eq!(got.messages[0].reaction.as_deref(), Some("yes"));
        assert_eq!(got.messages[0].reply_to, Some(question));
        assert!(
            store.has_unread("Erdos").unwrap(),
            "whoever was shown it may not be the one waiting"
        );
        assert!(
            store.has_new("Erdos", 0).unwrap(),
            "a timed read still sees it"
        );
        store.ack("Erdos", &[got.messages[0].id], NOW).unwrap();
        assert!(!store.has_unread("Erdos").unwrap());

        let next = store
            .send(
                &erdos,
                None,
                "thanks then",
                Some(answer[0].id),
                NOW,
                &everyone_alive,
            )
            .unwrap();
        let ack = store
            .react(&halsted, next[0].id, Reaction::Roger, NOW, &everyone_alive)
            .unwrap();
        assert!(!store.has_wakeful("Erdos", NOW).unwrap());
        assert!(store.has_fresh("Erdos").unwrap(), "it still arrives");
        let error = store
            .send(
                &erdos,
                None,
                "you too",
                Some(ack[0].id),
                NOW,
                &everyone_alive,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("takes no answer"), "{error}");
        store.take_unread("Erdos", NOW).unwrap();
        assert!(
            !store.has_unread("Erdos").unwrap(),
            "an acknowledgement asks nothing"
        );
    }

    #[test]
    fn reacting_over_and_over_to_one_message_reaches_the_limit_and_a_closed_one_stays_closed() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        let id = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "q",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        let mut turn = [&halsted, &erdos].into_iter().cycle();
        let mut last = Vec::new();
        for _ in 0..HOP_LIMIT {
            last = store
                .react(
                    turn.next().unwrap(),
                    id,
                    Reaction::Yes,
                    NOW,
                    &everyone_alive,
                )
                .unwrap();
        }
        assert!(last[0].over_limit, "the same message cannot go on forever");

        let other = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "q2",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        store
            .react(&halsted, other, Reaction::Standby, NOW, &everyone_alive)
            .unwrap();
        assert!(
            store
                .send(
                    &halsted,
                    None,
                    "the answer",
                    Some(other),
                    NOW,
                    &everyone_alive
                )
                .is_ok(),
            "standby promises an answer"
        );
        store
            .react(&halsted, other, Reaction::Out, NOW, &everyone_alive)
            .unwrap();
        assert!(
            store
                .react(&erdos, other, Reaction::Yes, NOW, &everyone_alive)
                .is_err(),
            "out ends it for both"
        );
    }

    #[test]
    fn every_reaction_word_reads_back_and_only_answers_wake() {
        for reaction in Reaction::ALL {
            assert_eq!(Reaction::parse(reaction.word()), Some(reaction));
        }
        assert_eq!(Reaction::parse(" ROGER "), Some(Reaction::Roger));
        assert_eq!(Reaction::parse("maybe"), None);
        let waking: Vec<&str> = Reaction::ALL
            .into_iter()
            .filter(|reaction| reaction.wakes())
            .map(Reaction::word)
            .collect();
        assert_eq!(waking, ["yes", "no", "dontknow", "wilco", "sayagain"]);
    }

    #[test]
    fn a_rename_keeps_what_the_agent_said_about_itself() {
        let (_dir, store) = store();
        subscribe(&store, 1);
        let mut me = join_of(2);
        me.status = Some("busy".to_owned());
        store
            .join(&me, None, Some("Halsted"), NOW, &everyone_alive)
            .unwrap();
        store.set_quiet("Halsted", NOW + 60_000).unwrap();
        store
            .join(
                &join_of(2),
                Some("Halsted"),
                Some("Newton"),
                NOW,
                &everyone_alive,
            )
            .unwrap();
        assert!(store.is_quiet("Newton", NOW).unwrap());
        let listed = store.who(NOW, &everyone_alive).unwrap();
        let newton = listed.iter().find(|agent| agent.name == "Newton").unwrap();
        assert_eq!(newton.status.as_deref(), Some("busy"));
    }

    #[test]
    fn a_name_someone_else_holds_now_cannot_be_taken_by_updating_a_topic() {
        let (_dir, store) = store();
        subscribe(&store, 2);
        assert!(
            store
                .join(&join_of(1), Some("Erdos"), None, NOW, &everyone_alive)
                .is_err()
        );
        assert_eq!(store.owner("Erdos").unwrap(), Some((2, 1)));
    }

    #[test]
    fn touching_a_name_held_by_someone_else_says_so() {
        let (_dir, store) = store();
        subscribe(&store, 1);
        assert!(store.touch("Erdos", (1, 1), NOW).unwrap());
        assert!(!store.touch("Erdos", (2, 1), NOW).unwrap());
    }

    #[test]
    fn a_file_from_another_schema_version_is_rebuilt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE messages (old TEXT); PRAGMA user_version = 1;")
                .unwrap();
        }
        let store = Store::open(&path, NOW).unwrap();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        drop(store);
        let again = Store::open(&path, NOW).unwrap();
        assert!(
            again.has_unread("Halsted").unwrap(),
            "the same version is kept"
        );
    }

    /// As a version 5 server left it: no `woken_at`.
    fn downgrade(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("ALTER TABLE messages DROP COLUMN woken_at; PRAGMA user_version = 5;")
            .unwrap();
    }

    #[test]
    fn an_upgrade_keeps_who_is_here_and_everything_unread_and_drops_what_was_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let store = Store::open(&path, NOW).unwrap();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let target = to("Halsted");
        let send = |text| {
            store
                .send(&erdos, Some(&target), text, None, NOW, &everyone_alive)
                .unwrap()[0]
                .id
        };
        let unread = send("keep me");
        let read = send("read");
        store.ack("Halsted", &[read], NOW).unwrap();
        drop(store);
        downgrade(&path);

        let upgraded = Store::open(&path, NOW).unwrap();
        let next = upgraded
            .send(&erdos, Some(&target), "after", None, NOW, &everyone_alive)
            .unwrap()[0]
            .id;
        assert!(next > read, "an id does not come round again");
        upgraded.ack("Halsted", &[next], NOW).unwrap();
        assert_eq!(upgraded.owner("Halsted").unwrap(), Some((2, 1)));
        let taken = upgraded.take_unread("Halsted", NOW).unwrap();
        assert_eq!(taken.messages.len(), 1);
        assert_eq!(taken.messages[0].id, unread);
        assert_eq!(taken.messages[0].text, "keep me");
        assert!(!taken.messages[0].shown);
    }

    #[test]
    fn a_table_too_old_to_fill_a_required_column_is_left_behind_and_the_file_still_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE subscribers (name TEXT PRIMARY KEY); \
                 INSERT INTO subscribers VALUES ('Old'); PRAGMA user_version = 2;",
            )
            .unwrap();
        }
        let store = Store::open(&path, NOW).unwrap();
        assert_eq!(store.owner("Old").unwrap(), None);
    }

    #[test]
    fn the_count_of_what_is_left_includes_acknowledgements_retired_by_the_same_read() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        let target = to("Erdos");
        let question = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "q",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        for _ in 0..READ_LIMIT {
            store
                .react(&halsted, question, Reaction::Standby, NOW, &everyone_alive)
                .unwrap();
        }
        for _ in 0..30 {
            store
                .send(&halsted, Some(&target), "more", None, NOW, &everyone_alive)
                .unwrap();
        }
        let taken = store.take_unread("Erdos", NOW).unwrap();
        assert_eq!(taken.messages.len() as i64, READ_LIMIT);
        assert_eq!(taken.more, 30);
    }

    #[test]
    fn a_rename_cannot_take_a_name_that_went_to_someone_else() {
        let (_dir, store) = store();
        subscribe(&store, 1);
        // Another process has taken over `Erdos` while this one still believes it is that.
        store
            .join(&join_of(2), None, Some("Erdos"), NOW, &nobody_alive)
            .unwrap();
        let stale = store.join(
            &join_of(1),
            Some("Erdos"),
            Some("Elsewhere"),
            NOW,
            &everyone_alive,
        );
        assert!(stale.is_err());
        assert_eq!(store.owner("Erdos").unwrap(), Some((2, 1)));
        assert_eq!(store.owner("Elsewhere").unwrap(), None);
    }

    #[test]
    fn answering_with_to_instead_of_reply_is_bounded_by_the_wake_budget() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        let target = to("Halsted");
        for _ in 0..WAKE_BUDGET {
            let sent = store
                .send(&erdos, Some(&target), "again", None, NOW, &everyone_alive)
                .unwrap();
            assert!(!sent[0].over_limit);
        }
        store.take_unread("Halsted", NOW).unwrap();
        let over = store
            .send(
                &erdos,
                Some(&target),
                "too many",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        assert!(over[0].over_limit);
        assert!(store.has_unread("Halsted").unwrap(), "still delivered");
        assert!(
            !store.has_wakeful("Halsted", NOW).unwrap(),
            "but wakes nobody"
        );
        // An answer is still an answer: treated as an acknowledgement it would be read unseen.
        let question = store
            .send(
                &halsted,
                Some(&to("Erdos")),
                "q",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        let answer = store
            .react(&erdos, question, Reaction::No, NOW, &everyone_alive)
            .unwrap();
        assert!(!answer[0].over_limit);
        store.take_unread("Halsted", NOW).unwrap();
        assert!(
            store
                .take_unread("Halsted", NOW)
                .unwrap()
                .messages
                .iter()
                .any(|message| message.id == answer[0].id),
            "unread until confirmed"
        );
        // The window passes, and it is an ordinary message again.
        let later = NOW + WAKE_WINDOW_MS + 1;
        let fine = store
            .send(&erdos, Some(&target), "later", None, later, &everyone_alive)
            .unwrap();
        assert!(!fine[0].over_limit);
    }

    #[test]
    fn a_message_someone_else_was_shown_wakes_an_idle_agent_once() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        store.take_unread("Halsted", NOW).unwrap();
        assert!(
            store
                .take_overdue("Halsted", NOW + 1000)
                .unwrap()
                .is_empty(),
            "too soon"
        );
        store.touch("Halsted", (2, 1), NOW + 50_000).unwrap();
        assert!(
            store
                .take_overdue("Halsted", NOW + OVERDUE_MS + 1000)
                .unwrap()
                .is_empty(),
            "it is active"
        );
        let idle = NOW + 50_000 + OVERDUE_MS;
        let woken = store.take_overdue("Halsted", idle).unwrap();
        assert_eq!(woken.len(), 1);
        assert!(!woken[0].shown, "its text goes out");
        assert!(store.take_overdue("Halsted", idle + 1).unwrap().is_empty());
    }

    #[test]
    fn a_new_owner_can_be_woken_for_what_woke_the_old_one() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        let taken = store.take_unread("Halsted", NOW).unwrap();
        store.mark_woken("Halsted", &taken.messages, NOW).unwrap();
        store
            .join(&join_of(3), None, Some("Halsted"), NOW, &nobody_alive)
            .unwrap();
        store.take_unread("Halsted", NOW).unwrap();
        let woken = store.take_overdue("Halsted", NOW + OVERDUE_MS).unwrap();
        assert_eq!(woken.len(), 1);
    }

    #[test]
    fn a_message_a_wait_already_woke_for_is_not_overdue_and_neither_is_one_during_quiet() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let target = to("Halsted");
        store
            .send(&erdos, Some(&target), "a", None, NOW, &everyone_alive)
            .unwrap();
        let taken = store.take_unread("Halsted", NOW).unwrap();
        store.mark_woken("Halsted", &taken.messages, NOW).unwrap();
        let idle = NOW + OVERDUE_MS * 2;
        assert!(store.take_overdue("Halsted", idle).unwrap().is_empty());

        store
            .send(&erdos, Some(&target), "b", None, NOW, &everyone_alive)
            .unwrap();
        store.take_unread("Halsted", NOW).unwrap();
        store.set_quiet("Halsted", idle + 1000).unwrap();
        assert!(store.take_overdue("Halsted", idle).unwrap().is_empty());
        assert_eq!(store.take_overdue("Halsted", idle + 1000).unwrap().len(), 1);
    }

    #[test]
    fn a_new_owner_of_a_name_starts_with_no_waits_counted() {
        let (_dir, store) = store();
        subscribe(&store, 1);
        store.claim_waiter("Erdos", 9, 1, &everyone_alive).unwrap();
        assert_eq!(store.waits_started("Erdos").unwrap(), 1);
        store
            .join(&join_of(1), Some("Erdos"), None, NOW, &everyone_alive)
            .unwrap();
        assert_eq!(store.waits_started("Erdos").unwrap(), 1, "the same owner");
        store
            .join(&join_of(2), None, Some("Erdos"), NOW, &nobody_alive)
            .unwrap();
        assert_eq!(store.waits_started("Erdos").unwrap(), 0);
    }

    #[test]
    fn an_agent_long_gone_is_off_the_list_but_can_still_be_written_to() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let later = NOW + KEEP_CLOSED_LISTED_MS + 1;
        let only_erdos = |pid: i64, _: i64| pid == 1;
        assert_eq!(store.who(later, &only_erdos).unwrap().len(), 1);
        let sent = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "waits",
                None,
                later,
                &only_erdos,
            )
            .unwrap();
        assert_eq!(sent[0].recipient_state, "closed");
    }

    #[test]
    fn a_timed_wait_sees_a_message_someone_else_has_already_shown() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let before = store.latest_unread_id("Halsted").unwrap();
        assert!(!store.has_new("Halsted", before).unwrap());
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        store.take_unread("Halsted", NOW).unwrap();
        assert!(store.has_new("Halsted", before).unwrap());
        let after = store.latest_unread_id("Halsted").unwrap();
        assert!(!store.has_new("Halsted", after).unwrap(), "no longer new");
    }

    #[test]
    fn a_new_owner_does_not_inherit_what_the_dead_one_was_doing() {
        let (_dir, store) = store();
        let mut first = join_of(1);
        first.status = Some("old work".to_owned());
        store
            .join(&first, None, None, NOW, &everyone_alive)
            .unwrap();
        let taken = store
            .join(&join_of(2), None, Some("Erdos"), NOW, &nobody_alive)
            .unwrap();
        assert_eq!(taken.name, "Erdos");
        let listed = store.who(NOW, &everyone_alive).unwrap();
        assert_eq!(listed[0].status, None);
    }

    #[test]
    fn a_closed_name_can_be_taken_with_its_messages_but_a_live_one_cannot() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        let refused = store.join(&join_of(3), None, Some("Halsted"), NOW, &everyone_alive);
        assert!(refused.is_err());
        let taken = store
            .join(&join_of(3), None, Some("Halsted"), NOW, &nobody_alive)
            .unwrap();
        assert_eq!(taken.name, "Halsted");
        let unread = store.take_unread("Halsted", NOW).unwrap();
        assert_eq!(unread.messages[0].text, "hi");
    }

    #[test]
    fn renaming_moves_unread_messages_and_frees_the_old_row() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        store
            .join(
                &join_of(2),
                Some(&halsted.name),
                Some("Newton"),
                NOW,
                &everyone_alive,
            )
            .unwrap();
        assert_eq!(store.take_unread("Newton", NOW).unwrap().messages.len(), 1);
        let names: Vec<String> = store
            .who(NOW, &everyone_alive)
            .unwrap()
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, ["Erdos", "Newton"]);
    }

    #[test]
    fn a_message_moves_from_sent_to_shown_to_read_and_only_an_ack_finishes_it() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let sent = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        let id = sent[0].id;
        assert_eq!(store.sent_status("Erdos", 5).unwrap()[0].state, "sent");
        assert!(store.has_fresh("Halsted").unwrap());

        let first = store.take_unread("Halsted", NOW).unwrap();
        assert!(!first.messages[0].shown);
        assert_eq!(store.sent_status("Erdos", 5).unwrap()[0].state, "shown");
        assert!(!store.has_fresh("Halsted").unwrap());

        let again = store.take_unread("Halsted", NOW).unwrap();
        assert!(again.messages[0].shown, "still unread, now a reminder");

        assert_eq!(store.ack("Halsted", &[id], NOW).unwrap(), 1);
        assert_eq!(store.sent_status("Erdos", 5).unwrap()[0].state, "read");
        assert!(
            store
                .take_unread("Halsted", NOW)
                .unwrap()
                .messages
                .is_empty()
        );
    }

    #[test]
    fn acknowledging_someone_elses_message_changes_nothing() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        subscribe(&store, 3);
        let id = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        assert_eq!(store.ack("Freud", &[id], NOW).unwrap(), 0);
        assert_eq!(store.take_unread("Halsted", NOW).unwrap().messages.len(), 1);
    }

    #[test]
    fn a_reply_goes_back_marks_the_question_read_and_counts_a_hop() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let halsted = subscribe(&store, 2);
        let question = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "q",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        let reply = store
            .send(&halsted, None, "a", Some(question), NOW, &everyone_alive)
            .unwrap();
        assert_eq!(reply[0].to, erdos.to_string());
        assert_eq!(store.sent_status("Erdos", 1).unwrap()[0].state, "read");
        let got = store.take_unread("Erdos", NOW).unwrap();
        assert_eq!(got.messages[0].hops, 1);
        assert_eq!(got.messages[0].reply_to, Some(question));
    }

    #[test]
    fn a_stranger_cannot_reply_into_a_conversation() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let freud = subscribe(&store, 3);
        let id = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "q",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        assert!(
            store
                .send(&freud, None, "a", Some(id), NOW, &everyone_alive)
                .is_err()
        );
        assert_eq!(store.take_unread("Halsted", NOW).unwrap().messages.len(), 1);
    }

    #[test]
    fn a_mask_reaches_live_agents_and_not_the_sender_or_the_closed() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        subscribe(&store, 3);
        let only_pid_1_and_2 = |pid: i64, _: i64| pid != 3;
        let sent = store
            .send(
                &erdos,
                Some(&to("fs:*:*:*")),
                "all",
                None,
                NOW,
                &only_pid_1_and_2,
            )
            .unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "fs:-:Halsted:-");
        assert!(store.take_unread("Erdos", NOW).unwrap().messages.is_empty());
        assert!(store.take_unread("Freud", NOW).unwrap().messages.is_empty());
    }

    #[test]
    fn a_closed_agent_named_directly_still_gets_the_message() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let only_pid_1 = |pid: i64, _: i64| pid == 1;
        let sent = store
            .send(&erdos, Some(&to("Halsted")), "wait", None, NOW, &only_pid_1)
            .unwrap();
        assert_eq!(sent[0].recipient_state, "closed");
        assert_eq!(store.take_unread("Halsted", NOW).unwrap().messages.len(), 1);
    }

    #[test]
    fn sending_to_nobody_is_an_error_that_lists_who_is_there() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        let error = store
            .send(&erdos, Some(&to("Nobody")), "?", None, NOW, &everyone_alive)
            .unwrap_err()
            .to_string();
        assert!(error.contains("fs:-:Erdos:-"), "{error}");
    }

    #[test]
    fn states_follow_the_process_the_wait_and_the_last_call() {
        let (_dir, store) = store();
        subscribe(&store, 1);
        let state = |now: i64, alive: Alive<'_>| store.who(now, alive).unwrap()[0].state;
        assert_eq!(state(NOW + 1, &everyone_alive), "working");
        assert_eq!(state(NOW + WORKING_MS + 1, &everyone_alive), "idle");
        assert_eq!(state(NOW + 1, &nobody_alive), "closed");
        store.set_listening("Erdos", NOW + 10).unwrap();
        assert_eq!(state(NOW + 1, &everyone_alive), "listening");
        assert_eq!(state(NOW + 11, &everyone_alive), "working");
        assert_eq!(state(NOW + 1, &nobody_alive), "closed");
    }

    #[test]
    fn a_running_wait_reads_as_listening_and_a_killed_one_stops_counting() {
        let (_dir, store) = store();
        subscribe(&store, 1);
        let waiter = 9;
        assert_eq!(
            store
                .claim_waiter("Erdos", waiter, 1, &everyone_alive)
                .unwrap(),
            Claim::Granted { owner: (1, 1) }
        );
        let state = |alive: Alive<'_>| store.who(NOW + 1, alive).unwrap()[0].state;
        assert_eq!(state(&everyone_alive), "listening");
        assert_eq!(state(&|pid, _| pid != waiter), "working");
        assert!(store.has_waiter("Erdos", &everyone_alive).unwrap());
        assert!(!store.has_waiter("Erdos", &|pid, _| pid != waiter).unwrap());
    }

    #[test]
    fn only_one_wait_covers_a_name_until_it_is_gone_or_released() {
        let (_dir, store) = store();
        subscribe(&store, 1);
        store.claim_waiter("Erdos", 9, 1, &everyone_alive).unwrap();
        assert_eq!(
            store.claim_waiter("Erdos", 10, 1, &everyone_alive).unwrap(),
            Claim::AlreadyWaiting
        );
        assert!(matches!(
            store
                .claim_waiter("Erdos", 10, 1, &|pid, _| pid != 9)
                .unwrap(),
            Claim::Granted { .. }
        ));
        store.release_waiter("Erdos", 9).unwrap();
        assert!(
            store.has_waiter("Erdos", &everyone_alive).unwrap(),
            "9 no longer holds it, and releasing must not touch 10's claim"
        );
        store.release_waiter("Erdos", 10).unwrap();
        assert!(!store.has_waiter("Erdos", &everyone_alive).unwrap());
    }

    #[test]
    fn a_wait_has_nobody_to_wake_for_a_dead_owner_or_an_unknown_name() {
        let (_dir, store) = store();
        subscribe(&store, 1);
        assert_eq!(
            store
                .claim_waiter("Erdos", 9, 1, &|pid, _| pid != 1)
                .unwrap(),
            Claim::OwnerGone
        );
        assert_eq!(
            store.claim_waiter("Nobody", 9, 1, &everyone_alive).unwrap(),
            Claim::NoSuchAgent
        );
    }

    #[test]
    fn changing_a_topic_keeps_the_wait_and_a_new_owner_drops_it() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        store.claim_waiter("Erdos", 9, 1, &everyone_alive).unwrap();
        store
            .join(&join_of(1), Some(&erdos.name), None, NOW, &everyone_alive)
            .unwrap();
        assert!(store.has_waiter("Erdos", &everyone_alive).unwrap());
        store
            .join(&join_of(2), None, Some("Erdos"), NOW, &|pid, _| pid == 9)
            .unwrap();
        assert!(!store.has_waiter("Erdos", &everyone_alive).unwrap());
        assert_eq!(store.owner("Erdos").unwrap(), Some((2, 1)));
    }

    #[test]
    fn the_list_forgets_a_long_closed_agent_unless_a_message_waits_for_it() {
        let (_dir, store) = store();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let later = NOW + KEEP_CLOSED_LISTED_MS + 1;
        assert!(store.who(later, &nobody_alive).unwrap().is_empty());
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        let listed = store.who(later, &nobody_alive).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Halsted");
    }

    #[test]
    fn opening_sweeps_old_read_and_very_old_unread_messages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let store = Store::open(&path, NOW).unwrap();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        let read = store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "read",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap()[0]
            .id;
        store.ack("Halsted", &[read], NOW).unwrap();
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "unread",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        drop(store);

        let store = Store::open(&path, NOW + KEEP_READ_MS + 1).unwrap();
        assert!(
            store
                .sent_status("Erdos", 5)
                .unwrap()
                .iter()
                .all(|s| s.id != read)
        );
        assert_eq!(store.take_unread("Halsted", NOW).unwrap().messages.len(), 1);
        drop(store);

        let store = Store::open(&path, NOW + KEEP_UNREAD_MS + 1).unwrap();
        assert!(
            store
                .take_unread("Halsted", NOW)
                .unwrap()
                .messages
                .is_empty()
        );
    }

    #[test]
    fn a_committed_message_survives_the_process_that_sent_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let store = Store::open(&path, NOW).unwrap();
        let erdos = subscribe(&store, 1);
        subscribe(&store, 2);
        store
            .send(
                &erdos,
                Some(&to("Halsted")),
                "hi",
                None,
                NOW,
                &everyone_alive,
            )
            .unwrap();
        drop(store);
        let reopened = Store::open(&path, NOW).unwrap();
        assert_eq!(
            reopened.take_unread("Halsted", NOW).unwrap().messages.len(),
            1
        );
    }
}
