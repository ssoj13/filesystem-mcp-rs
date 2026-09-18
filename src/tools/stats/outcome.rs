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
use tracing::warn;

/// Which counter a finished tool call increments.
///
/// Five outcomes, not two, because a bare success/failure split cannot tell an operator whether
/// *they* are calling the tool wrongly ([`Outcome::ErrParams`]) or the tool itself is broken
/// ([`Outcome::ErrInternal`]), and cannot tell either of those from the tool running to
/// completion and reporting its own failure ([`Outcome::ErrFlagged`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The call completed and reported no failure of its own.
    Ok,
    /// The call completed but flagged itself failed: `is_error == Some(true)`. A killed or
    /// timed-out `run_command` lands here, which is why this variant exists at all.
    ErrFlagged,
    /// rmcp rejected the request's parameters (`-32602`): the caller got the schema wrong, and
    /// the tool never ran.
    ErrParams,
    /// The call failed below the handler (`-32603`, and every other protocol code): the tool
    /// broke rather than the caller.
    ErrInternal,
    /// The call has not finished: the server asked the client for input, or materialised a task
    /// the client will poll for. Not a completion, so no latency is attributed to it - the
    /// elapsed time here measures how long the server took to *defer*, not how long the work
    /// took.
    Deferred,
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
///   explicitly, and the catch-all scores an unrecognised shape as [`Outcome::Deferred`] and
///   warns. Deferred, not `Ok`, because the conservative reading of a shape this build does not
///   understand is "not known to have completed": it inflates no success rate and attributes no
///   latency.
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
        Ok(unrecognised) => {
            warn!("stats: unrecognised tool response shape ({unrecognised:?}); counted deferred");
            Outcome::Deferred
        }
        Err(error) => match error.code {
            ErrorCode::INVALID_PARAMS => Outcome::ErrParams,
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
