//! # `xyz.taluslabs.math.i64.sum@1`
//!
//! Standard Nexus Tool that sums an array of [`i64`] numbers and returns the
//! result.

use {
    nexus_sdk::{fqn, ToolFqn},
    nexus_toolkit::*,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    vec: Vec<i64>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Output {
    Ok { result: i64 },
    Err { reason: String },
}

pub(crate) struct I64Sum;

impl NexusTool for I64Sum {
    type Input = Input;
    type Output = Output;

    async fn new() -> Self {
        Self
    }

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.math.i64.sum@1")
    }

    fn path() -> &'static str {
        "/i64/sum"
    }

    async fn health(&self) -> AnyResult<StatusCode> {
        // This tool has no external dependencies and as such, it is always
        // healthy if the endpoint is reachable.
        Ok(StatusCode::OK)
    }

    async fn invoke(&self, Self::Input { vec }: Self::Input) -> Self::Output {
        vec.into_iter()
            .try_fold(0i64, |acc, x| {
                acc.checked_add(x)
                    .ok_or_else(|| format!("Adding '{acc}' and '{x}' results in an overflow"))
            })
            .map_or_else(
                |reason| Output::Err { reason },
                |result| Output::Ok { result },
            )
    }
}

// TODO: tests, docs
