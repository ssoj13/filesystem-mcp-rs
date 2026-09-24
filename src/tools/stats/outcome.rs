//! How a finished tool call is scored: one function, both failure axes.
//!
//! This is invariant I5 of the statistics design, and it is the difference between a table that
//! tells the truth and one that reports roughly 0% errors for a server that is failing
//! constantly. In this codebase a *tool-level* failure is reported **inside a successful
//! result**: `CallToolResult::is_error = Some(true)` is what a parse error, a `run_command` the
//! watchdog killed or that timed out, and a failed `kill_process` all come back as. The
//! transport-level `Err` arm carries only the failures rmcp itself raises - a request whose
//! parameters did not fit the schema, or a tool that broke below the handler.
//!
//! So classification is exhaustive over **both** axes: the [`Result`], and what is inside a
//! successful [`CallToolResponse`]. Anything that inspects only the outer `Result` counts the
//! single most interesting failure in this server - a command killed by its own timeout - as a
//! success.
//!
//! Deliberately pure and free of anything from the server: it takes the result and returns an
//! [`Outcome`], which is what lets the test below enumerate every shape without a running
//! server. Called once per tool call from `main.rs`'s `call_tool`, on the way out.

use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolResponse, ErrorCode};

/// The rmcp release whose response and error shapes the `match` below was written against.
///
/// This is the tripwire that stands in for the compiler error we cannot have. Because
/// [`CallToolResponse`] is `#[non_exhaustive]`, a fourth variant would compile silently here and
/// be counted [`Outcome::UnknownShape`] for as long as nobody looked. `the_audited_rmcp_version_
/// is_the_resolved_one` compares this constant against the version `Cargo.lock` actually
/// resolves, so bumping rmcp fails the build until someone re-reads the catch-all arms and moves
/// this string deliberately. One edit per bump, which is exactly the review that was lost.
// A tripwire is read by the test it arms and by nobody else, which is exactly what makes it a
// tripwire; `expect` rather than `allow` so that a future non-test reader retires the suppression
// instead of leaving it to rot.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "read by the version tripwire test below")
)]
const AUDITED_RMCP_VERSION: &str = "3.4.0";

/// Which counter a finished tool call increments.
///
/// Six outcomes, not two, because a bare success/failure split cannot tell an operator whether
/// they are calling a name this build does not serve ([`Outcome::ErrParams`]), the tool itself is
/// broken ([`Outcome::ErrInternal`]), or the tool ran and reported its own failure
/// ([`Outcome::ErrFlagged`]). Note that a malformed *argument* is the third of those and not the
/// first - see [`Outcome::ErrParams`], which is the one column whose name reads as more than it
/// means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The call completed and reported no failure of its own.
    Ok,
    /// The call completed but flagged itself failed: `is_error == Some(true)`. A killed or
    /// timed-out `run_command` lands here, which is why this variant exists at all.
    ErrFlagged,
    /// rmcp rejected the request with `-32602` and the tool never ran. **In this build that means
    /// the tool name is not one it serves**, not that the arguments were malformed.
    ///
    /// The obvious reading - "callers are getting my parameters wrong" - is the wrong one, and
    /// the difference matters because the remedies are opposite. rmcp answers an unknown or
    /// disabled name with `invalid_params("tool not found")`
    /// (`rmcp-3.1.3/src/handler/server/router/tool.rs:566,571`), which lands here. But a request
    /// whose *arguments* fail to deserialise does not: `into_tool_argument_error`
    /// (`tool.rs:145-153`) turns that into `Ok(CallToolResult::error(..))`, so it arrives as
    /// `is_error = true` and is counted as [`Outcome::ErrFlagged`] instead - in the same column
    /// as a `run_command` that timed out.
    ///
    /// So: a rising count here means a client is calling a name this build was renamed out of or
    /// never had, and the call is attributed to the interned `__unknown`, there being no
    /// registered tool to name. Schema mistakes have to be read out of `err_flagged`, where they
    /// are not separable from a tool's own reported failures. Pinned by
    /// `an_argument_error_is_flagged_not_counted_as_bad_params`.
    ErrParams,
    /// The call failed below the handler (`-32603`, and every other protocol code): the tool
    /// broke rather than the caller.
    ErrInternal,
    /// The call has not finished: the server asked the client for input, or materialised a task
    /// the client will poll for. Not a completion, so no latency is attributed to it - the
    /// elapsed time here measures how long the server took to *defer*, not how long the work
    /// took.
    ///
    /// On this server's paths it should be a constant zero: no tool here returns either shape,
    /// and rmcp converts both to `internal_error` before they reach the handler. A non-zero
    /// count is therefore a signal in its own right.
    Deferred,
    /// The response was a [`CallToolResponse`] variant this build does not know - rmcp grew one
    /// after [`AUDITED_RMCP_VERSION`] and `#[non_exhaustive]` let it through without a compiler
    /// error.
    ///
    /// Stored with [`Outcome::Deferred`] in the `deferred` column, because the schema has one
    /// bucket for "did not complete" and an unknown shape is not known to have completed;
    /// **counted apart** by task 3 in a process-wide counter that task 6's health section
    /// reports. Folding the two together in the count would leave an operator unable to tell
    /// "the server deferred" from "this build does not understand rmcp's answer", which are the
    /// same number and entirely different problems. A log line will not do that job: under stdio
    /// there may be no subscriber at all.
    UnknownShape,
}

/// Score one finished tool call.
///
/// The `Ok` arm is examined as closely as the `Err` arm; see the module documentation for why
/// that is the whole point of this function.
///
/// # A note on the catch-all arms
///
/// The design intent was a `match` with no `_` arm anywhere, so that a new rmcp response variant
/// would *break the build* rather than be silently folded into [`Outcome::Ok`]. Neither axis
/// permits that, and neither compromise is silent:
///
/// - [`CallToolResponse`] is `#[non_exhaustive]`, so rustc *requires* a catch-all in a
///   downstream crate; omitting one does not compile. The known variants are still listed
///   explicitly, and the catch-all scores an unrecognised shape as its own
///   [`Outcome::UnknownShape`] - never `Ok`, because a shape this build does not understand is
///   not known to have completed, so it inflates no success rate and attributes no latency. What
///   the lost compiler error is replaced by is [`AUDITED_RMCP_VERSION`], not this arm.
/// - `ErrorCode` is a newtype over `i32`, not an enum, so its patterns are as open as the
///   integers are. Unmapped codes are genuine failures whichever number they carry, so they
///   score as [`Outcome::ErrInternal`] - the arm folds nothing that was not already an error.
pub fn classify(result: &Result<CallToolResponse, McpError>) -> Outcome {
    match result {
        Ok(CallToolResponse::Complete(complete)) => match complete.is_error {
            // `Some(false)` is what `CallToolResult::success` actually writes; `None` is the
            // field absent on the wire, which the spec says to read as a plain success. Both are
            // the same outcome, and spelling them out is how that stays true.
            Some(true) => Outcome::ErrFlagged,
            Some(false) | None => Outcome::Ok,
        },
        Ok(CallToolResponse::InputRequired(_) | CallToolResponse::Task(_)) => Outcome::Deferred,
        Ok(_) => Outcome::UnknownShape,
        Err(error) => match error.code {
            ErrorCode::INVALID_PARAMS => Outcome::ErrParams,
            // Behaviourally identical to the arm below and kept purely as documentation of the
            // code the name `ErrInternal` comes from. It is not coverage: deleting it changes
            // nothing and breaks no test.
            ErrorCode::INTERNAL_ERROR => Outcome::ErrInternal,
            _ => Outcome::ErrInternal,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{
        CallToolResult, CreateTaskResult, InputRequiredResult, ResultType, Task, TaskStatus,
    };

    /// A malformed argument is counted as flagged, NOT as bad parameters — the one place where
    /// the column name reads as more than it means.
    ///
    /// rmcp's `into_tool_argument_error` (`tool.rs:145-153`) turns a deserialisation failure into
    /// `Ok(CallToolResult::error(..))`, so it never reaches the `Err` arm. This reproduces that
    /// shape rather than calling the private helper, and asserts the two land in *different*
    /// columns: if a future rmcp routed argument errors through `Err(invalid_params)` instead,
    /// the meaning of `err_params` would silently change under an operator reading old files, and
    /// this test is what fails first. See [`AUDITED_RMCP_VERSION`].
    #[test]
    fn an_argument_error_is_flagged_not_counted_as_bad_params() {
        // The shape rmcp produces for "failed to deserialize parameters: ...".
        let argument_error = CallToolResult::error(vec![]);
        assert_eq!(
            classify(&Ok(CallToolResponse::Complete(argument_error))),
            Outcome::ErrFlagged,
            "a bad argument arrives as a flagged result, not as a protocol error"
        );
        assert_ne!(
            classify(&Ok(CallToolResponse::Complete(CallToolResult::error(
                vec![]
            )))),
            classify(&Err(McpError::invalid_params("tool not found", None))),
            "bad arguments and an unknown tool name must not share a column"
        );
    }

    /// Every shape a finished call can take, scored in one table.
    ///
    /// The point of enumerating them here rather than driving a live server is that `classify`
    /// is pure: each shape is a value, including the two deferred ones, which a real transport
    /// would take a client round trip to produce.
    #[test]
    fn every_outcome_shape_is_classified() {
        let ok = CallToolResult::success(vec![]);
        let flagged = {
            let mut r = CallToolResult::success(vec![]);
            r.is_error = Some(true);
            r
        };
        let not_flagged = {
            let mut r = CallToolResult::success(vec![]);
            r.is_error = Some(false);
            r
        };
        assert_eq!(classify(&Ok(CallToolResponse::Complete(ok))), Outcome::Ok);
        assert_eq!(
            classify(&Ok(CallToolResponse::Complete(flagged))),
            Outcome::ErrFlagged
        );
        assert_eq!(
            classify(&Ok(CallToolResponse::Complete(not_flagged))),
            Outcome::Ok
        );
        assert_eq!(
            classify(&Err(McpError::invalid_params("x", None))),
            Outcome::ErrParams
        );
        assert_eq!(
            classify(&Err(McpError::internal_error("x", None))),
            Outcome::ErrInternal
        );
    }

    /// A plain success carries `Some(false)`, and an absent field means the same thing.
    ///
    /// Asserted against the constructor rather than assumed, because the whole `Ok` axis of
    /// [`classify`] rests on which of the three `Option<bool>` states rmcp actually produces.
    #[test]
    fn a_plain_success_is_not_flagged_and_neither_is_an_absent_flag() {
        assert_eq!(CallToolResult::success(vec![]).is_error, Some(false));
        let absent = {
            let mut r = CallToolResult::success(vec![]);
            r.is_error = None;
            r
        };
        assert_eq!(
            classify(&Ok(CallToolResponse::Complete(absent))),
            Outcome::Ok
        );
    }

    /// The two ways a call can be unfinished score as neither success nor failure.
    ///
    /// They are completions of nothing: counting them `Ok` would credit the server with work it
    /// has not done, and counting them as errors would invent failures.
    #[test]
    fn a_deferred_call_is_neither_a_success_nor_a_failure() {
        let input_required = InputRequiredResult::new(None, None);
        assert_eq!(
            classify(&Ok(CallToolResponse::InputRequired(input_required))),
            Outcome::Deferred
        );

        let task = CreateTaskResult::new(Task::new(
            "task-1",
            TaskStatus::Working,
            "2026-09-18T00:00:00Z",
            "2026-09-18T00:00:00Z",
        ));
        assert_eq!(
            task.result_type,
            ResultType::TASK,
            "the seed state is a task"
        );
        assert_eq!(
            classify(&Ok(CallToolResponse::Task(task))),
            Outcome::Deferred
        );
    }

    /// The audited rmcp version is the one `Cargo.lock` resolves, or the catch-all arms are due
    /// a re-read.
    ///
    /// This is the tripwire described on [`AUDITED_RMCP_VERSION`], and the only protection left
    /// once `#[non_exhaustive]` took the compiler error away: a new response variant cannot
    /// arrive without the rmcp version changing, and the version cannot change without this
    /// failing. Reading the lock file rather than trusting a second copy of the number is what
    /// makes it deterministic - there is no way to satisfy it except by bumping the constant.
    #[test]
    fn the_audited_rmcp_version_is_the_resolved_one() {
        let lock_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
        let lock = std::fs::read_to_string(&lock_path).expect("Cargo.lock is readable");
        let resolved = resolved_version(&lock, "rmcp").expect("Cargo.lock resolves rmcp");
        assert_eq!(
            resolved, AUDITED_RMCP_VERSION,
            "rmcp moved from {AUDITED_RMCP_VERSION} to {resolved}. `CallToolResponse` is \
             #[non_exhaustive], so a new variant compiles silently into the `Ok(_) => \
             UnknownShape` catch-all in `classify`. Re-read that arm and the `ErrorCode` arm \
             against the new release, then move AUDITED_RMCP_VERSION deliberately."
        );
    }

    /// The resolved version of `name` in a `Cargo.lock`: the `version` line inside that
    /// package's own `[[package]]` block.
    ///
    /// The scan stops at the next `[[package]]` header, so a block that carried no `version`
    /// line - or that ordered `version` before `name`, which cargo does not emit - yields `None`
    /// rather than the *neighbouring* package's version. Failing is recoverable; a confidently
    /// wrong version would defeat the tripwire it feeds.
    ///
    /// Split out as a pure function so the parse can be checked against literal lock fragments,
    /// including the `rmcp-macros` entry that a looser match would seize on first.
    fn resolved_version(lock: &str, name: &str) -> Option<String> {
        let needle = format!("name = \"{name}\"");
        let mut rest = lock.lines().skip_while(|line| line.trim() != needle);
        rest.next()?;
        rest.take_while(|line| line.trim() != "[[package]]")
            .find_map(|line| {
                line.trim()
                    .strip_prefix("version = \"")
                    .and_then(|value| value.strip_suffix('"'))
                    .map(str::to_owned)
            })
    }

    /// The parse takes the package asked for, not one whose name merely begins the same way.
    #[test]
    fn the_lock_parse_does_not_confuse_rmcp_with_rmcp_macros() {
        let lock = concat!(
            "[[package]]\nname = \"rmcp-macros\"\nversion = \"9.9.9\"\n\n",
            "[[package]]\nname = \"rmcp\"\nversion = \"3.1.3\"\n"
        );
        assert_eq!(resolved_version(lock, "rmcp").as_deref(), Some("3.1.3"));
        assert_eq!(
            resolved_version(lock, "rmcp-macros").as_deref(),
            Some("9.9.9")
        );
        assert_eq!(resolved_version(lock, "absent"), None);
    }

    /// The scan stops at the next package, so a version it cannot find is `None`, never the
    /// neighbour's.
    ///
    /// The fragment is fabricated - cargo always writes `version` directly after `name` - but a
    /// parser that answers the wrong question confidently is the one failure mode the tripwire
    /// cannot survive, so the boundary is pinned rather than assumed.
    #[test]
    fn the_lock_parse_stops_at_the_package_boundary() {
        let lock = concat!(
            "[[package]]\nname = \"rmcp\"\nsource = \"registry+https://example\"\n\n",
            "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n"
        );
        assert_eq!(
            resolved_version(lock, "rmcp"),
            None,
            "a block with no version must fail, not report the next package's"
        );
        assert_eq!(resolved_version(lock, "serde").as_deref(), Some("1.0.0"));
    }

    /// A protocol code this build does not map is still a failure, never a success.
    ///
    /// `ErrorCode` is a newtype over `i32`, so the set of codes is open by construction; the
    /// guarantee that matters is the direction the unmapped ones fall in.
    #[test]
    fn an_unmapped_error_code_never_counts_as_a_success() {
        for code in [
            ErrorCode::METHOD_NOT_FOUND,
            ErrorCode::INVALID_REQUEST,
            ErrorCode::PARSE_ERROR,
            ErrorCode::RESOURCE_NOT_FOUND,
            ErrorCode(1234),
        ] {
            assert_eq!(
                classify(&Err(McpError::new(code, "x", None))),
                Outcome::ErrInternal,
                "code {code:?} must not be scored as a success"
            );
        }
    }
}
