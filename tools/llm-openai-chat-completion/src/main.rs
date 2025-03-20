//! # `xyz.taluslabs.llm.openai.chat-completion@1`
//!
//! Standard Nexus Tool that interacts with the OpenAI chat completion API. It
//! allows for plain text completions as well as JSON. For JSON, expected output
//! schema has to be provided.
//!
//! It defines the input and output structures, as well as the logic for
//! invoking the OpenAI API to generate chat completions.
//!
//! It uses the [`async_openai`] crate to interact with the OpenAI API.
//!
//! ## Input
//!
//! - `api_key`: _encrypted_ [`String`] - The API key to invoke the OpenAI API
//!   with. Encrypted with the Tool's key pair.
//!   TODO: <TODO: encryption ticket>.
//! - `messages`: [`Vec`] of [`Message`] - The messages to send to the chat
//!   completion API. The minimum length of the vector is 1.
//! - `context`: _optional_ [`Vec`] of [`Message`] - The context to provide
//!   to the chat completion API. This is useful for providing additional
//!   context as a DAG default value. Defaults to [`Vec::default`]. Not that
//!   context messages are  **prepended** to the `messages` input port.
//! - `model`: _optional_ [`String`] - The model to use for chat completion.
//!   Defaults to [`DEFAULT_MODEL`].
//! - `max_completion_tokens`: _optional_ [`u32`] - The maximum number of tokens
//!   to generate. Defaults to [`DEFAULT_MAX_COMPLETION_TOKENS`].
//! - `temperature`: _optional_ [`f32`] - The temperature to use. This must be
//!   a floating point number between 0 and 2. Defaults to 1. Defaults to
//!   [`DEFAULT_TEMPERATURE`].
//! - `json_schema`: _optional_ [`OpenAIJsonSchema`] - The JSON schema for the
//!   expected output. Providing this will force the [`Output::Json`] variant.
//!   The LLM response will be parsed into this schema. Defaults to [`None`].
//!   Note that this is only supported for newer OpenAI models. See
//!   <https://platform.openai.com/docs/guides/structured-outputs>.
//!
//! ## Output Variants
//!
//! - `text` - The chat completion was successful and evaluated to plain text.
//! - `json` - The chat completion was successful and evaluated to JSON.
//! - `err` - An error occurred during the chat completion.
//!
//! ## Output Ports
//!
//! ### `text`
//!
//! - `id`: [`String`] - Unique identifier for the completion.
//! - `role`: [`MessageKind`] - The role of the author of the message.
//! - `completion`: [`String`] - The chat completion result as plain text.
//!
//! ### `json`
//!
//! - `id`: [`String`] - Unique identifier for the completion.
//! - `role`: [`MessageKind`] - The role of the author of the message.
//! - `completion`: [`serde_json::Value`] - The chat completion result as JSON.
//!   Note that this is opaque for the Tool but the structure is defined by
//!   [`Input::json_schema`]. One could say the Tool output is _generic over
//!   this schema_.
//!
//! ### `err`
//!
//! - `reason`: [`String`] - The reason for the error.

use {
    anyhow::anyhow,
    async_openai::{
        config::OpenAIConfig,
        error::OpenAIError,
        types::{
            ChatCompletionRequestAssistantMessageArgs,
            ChatCompletionRequestMessage,
            ChatCompletionRequestSystemMessageArgs,
            ChatCompletionRequestUserMessageArgs,
            CreateChatCompletionRequestArgs,
            ResponseFormat,
            ResponseFormatJsonSchema,
            Role,
        },
        Client,
    },
    nexus_toolkit::*,
    nexus_types::*,
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
    strum_macros::EnumString,
};

mod status;

/// The default model to use for chat completions.
const DEFAULT_MODEL: &str = "gpt-4o-mini";
/// The maximum number of tokens to generate in a chat completion.
const DEFAULT_MAX_COMPLETION_TOKENS: u32 = 512;
/// The default temperature to use for chat completions.
const DEFAULT_TEMPERATURE: f32 = 1.0;

/// Represents a message that can be sent to the OpenAI Chat Completion API.
///
/// It can be either a full message with an explicit message type or a
/// short message, defaulting to the `User` type.
#[derive(Debug, Deserialize, JsonSchema, PartialEq)]
#[serde(untagged)]
enum Message {
    /// A full message with an explicit message type and content and name.
    Full {
        /// The role of the author of the message.
        role: MessageKind,
        /// The content of the message.
        value: String,
        /// The name of the participant, this is used to differentiate between
        /// participants of the same role.
        name: Option<String>,
    },
    /// A short message, which defaults to the `User` message type.
    Short(String),
}

/// Attempts to convert a [`Message`] to an
/// [`async_openai::types::ChatCompletionRequestMessage`].
impl TryFrom<Message> for ChatCompletionRequestMessage {
    type Error = async_openai::error::OpenAIError;

    fn try_from(value: Message) -> Result<Self, Self::Error> {
        if let Message::Short(value) = value {
            return ChatCompletionRequestUserMessageArgs::default()
                .content(value)
                .build()
                .map(Into::into);
        }

        let Message::Full { role, value, name } = value else {
            unreachable!();
        };

        match role {
            MessageKind::System => {
                let mut message = ChatCompletionRequestSystemMessageArgs::default();

                if let Some(name) = name {
                    message.name(name);
                }

                message.content(value).build().map(Into::into)
            }
            MessageKind::User => {
                let mut message = ChatCompletionRequestUserMessageArgs::default();

                if let Some(name) = name {
                    message.name(name);
                }

                message.content(value).build().map(Into::into)
            }
            MessageKind::Assistant => {
                let mut message = ChatCompletionRequestAssistantMessageArgs::default();

                if let Some(name) = name {
                    message.name(name);
                }

                message.content(value).build().map(Into::into)
            }
            _ => unimplemented!("Tool and Function roles are not supported"),
        }
    }
}

/// Represents the type of a message in a chat completion request or response.
///
/// It can be `System`, `User`, or `Assistant`. When deserializing, the message
/// can be a string in which case this enum defaults to `User`.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema, EnumString)]
#[serde(rename_all = "lowercase", try_from = "String")]
enum MessageKind {
    #[default]
    User,
    System,
    Assistant,
    Tool,
    Funtion,
}

/// Attemps to convert a [`String`] to a [`MessageKind`].
impl TryFrom<String> for MessageKind {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value
            .parse::<MessageKind>()
            .map_err(|_| anyhow!("Invalid MessageKind: {}", value))
    }
}

/// Convert a [`async_openai::types::Role`] to a [`MessageKind`].
impl From<Role> for MessageKind {
    fn from(value: Role) -> Self {
        match value {
            Role::System => MessageKind::System,
            Role::User => MessageKind::User,
            Role::Assistant => MessageKind::Assistant,
            Role::Function => MessageKind::Funtion,
            Role::Tool => MessageKind::Tool,
        }
    }
}

/// Defines the structure of the `json_schema` input port.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct OpenAIJsonSchema {
    /// The name of the schema. Must match `[a-zA-Z0-9-_]`, with a maximum
    /// length of 64.
    name: String,
    /// The JSON schema for the expected output.
    schema: schemars::Schema,
    /// A description of the response format, used by the model to determine
    /// how to respond in the format.
    description: Option<String>,
    /// Whether to enable strict schema adherence when generating the output. If
    /// set to true, the model will always follow the exact schema defined in the
    /// `schema` field. Only a subset of JSON Schema is supported when `strict`
    /// is `true`. See <https://platform.openai.com/docs/guides/structured-outputs>.
    strict: Option<bool>,
}

/// Represents the input for the OpenAI chat completion Tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Input {
    /// The OpenAI API key.
    // TODO: <TODO: encryption ticket>.
    api_key: String,
    /// The messages to send to the chat completion API.
    messages: Vec<Message>,
    /// The context to provide to the chat completion API.
    #[serde(default)]
    context: Vec<Message>,
    /// The model to use for chat completion.
    #[serde(default = "default_model")]
    model: String,
    /// The maximum number of tokens to generate.
    #[serde(default = "default_max_completion_tokens")]
    max_completion_tokens: u32,
    /// The temperature to use for chat completions.
    #[serde(default = "default_temperature")]
    temperature: f32,
    /// The JSON schema for the expected output.
    #[serde(default)]
    json_schema: Option<OpenAIJsonSchema>,
}

fn default_model() -> String {
    DEFAULT_MODEL.to_string()
}

fn default_max_completion_tokens() -> u32 {
    DEFAULT_MAX_COMPLETION_TOKENS
}

fn default_temperature() -> f32 {
    DEFAULT_TEMPERATURE
}

/// Represents the output of the OpenAI chat completion Tool.
#[derive(Serialize, JsonSchema)]
enum Output {
    Text {
        id: String,
        role: MessageKind,
        completion: String,
    },
    Json {
        id: String,
        role: MessageKind,
        completion: serde_json::Value,
    },
    Err {
        reason: String,
    },
}

/// The OpenAI Chat Completion tool.
///
/// This struct implements the `NexusTool` trait to integrate with the Nexus
/// framework. It provides the logic for invoking the OpenAI chat completion
/// API.
struct OpenaiChatCompletion;

impl NexusTool for OpenaiChatCompletion {
    type Input = Input;
    type Output = Output;

    fn fqn() -> ToolFqn {
        fqn!("xyz.taluslabs.llm.openai.chat-completion@1")
    }

    /// Performs a health check on the Tool and its dependencies.
    async fn health() -> AnyResult<StatusCode> {
        status::check_api_health().await
    }

    /// Invokes the tool logic to generate a chat completion.
    async fn invoke(request: Self::Input) -> AnyResult<Self::Output> {
        let cfg = OpenAIConfig::new().with_api_key(request.api_key);
        let client = Client::with_config(cfg);

        // Parse context messages into OpenAI message types.
        let context = request.context.into_iter().map(TryInto::try_into);

        // Chain the input messages and collect.
        let messages = context
            .chain(request.messages.into_iter().map(TryInto::try_into))
            .collect::<Result<Vec<ChatCompletionRequestMessage>, OpenAIError>>();

        // Should something go wrong, return an error. This is however very
        // unlikely as the inputs are validated against a schema defined here.
        let messages = match messages {
            Ok(messages) => messages,
            Err(err) => {
                return Ok(Output::Err {
                    reason: err.to_string(),
                })
            }
        };

        // Create the request to send to the OpenAI API and assign some basic
        // parameters.
        let mut openai_request = CreateChatCompletionRequestArgs::default();

        let mut openai_request = openai_request
            .max_completion_tokens(request.max_completion_tokens)
            .model(request.model)
            .temperature(request.temperature)
            .messages(messages);

        // If a JSON schema is provided, set it on the request.
        if let Some(schema) = request.json_schema.clone() {
            let json_schema = ResponseFormatJsonSchema {
                name: schema.name,
                schema: Some(schema.schema.to_value()),
                description: schema.description,
                strict: schema.strict,
            };

            openai_request =
                openai_request.response_format(ResponseFormat::JsonSchema { json_schema });
        }

        // Build the request and handle any errors.
        let openai_request = match openai_request.build() {
            Ok(request) => request,
            Err(err) => {
                return Ok(Output::Err {
                    reason: format!("Error building OpenAI request: {}", err),
                })
            }
        };

        let response = match client.chat().create(openai_request).await {
            Ok(response) => response,
            Err(err) => {
                return Ok(Output::Err {
                    reason: format!("Error calling OpenAI API: {}", err),
                })
            }
        };

        // Parse the response into the expected output format. Current Tool
        // design only supports a single choice so we take the first one.
        //
        // This design is also better for the Nexus interface as having a single
        // plaintext field with the completion is better suited.
        let choice = match response.choices.first() {
            Some(choice) => choice,
            None => {
                return Ok(Output::Err {
                    reason: "No choices returned from OpenAI API".to_string(),
                })
            }
        };

        if let Some(refusal) = &choice.message.refusal {
            return Ok(Output::Err {
                reason: refusal.to_string(),
            });
        }

        let completion = match &choice.message.content {
            Some(completion) => completion.to_string(),
            None => {
                return Ok(Output::Err {
                    reason: "No completion returned from OpenAI API".to_string(),
                })
            }
        };

        // Plain text completion.
        if request.json_schema.is_none() {
            return Ok(Output::Text {
                id: response.id,
                role: choice.message.role.into(),
                completion,
            });
        }

        // Parse the JSON completion into a serde_json::Value and validate it
        // against the provided schema.
        let completion = match serde_json::from_str(&completion) {
            Ok(completion) => completion,
            Err(err) => {
                return Ok(Output::Err {
                    reason: format!("Error parsing JSON completion: {}", err),
                })
            }
        };

        let Some(OpenAIJsonSchema { schema, .. }) = request.json_schema else {
            unreachable!();
        };

        match jsonschema::draft202012::validate(&schema.to_value(), &completion) {
            Ok(()) => Ok(Output::Json {
                id: response.id,
                role: choice.message.role.into(),
                completion,
            }),
            Err(e) => Ok(Output::Err {
                reason: format!("JSON completion does not match schema: {}", e),
            }),
        }
    }
}

/// The main entry point for the OpenAI Chat Completion tool.
///
/// This function bootstraps the tool and starts the server.
#[tokio::main]
async fn main() {
    bootstrap!(OpenaiChatCompletion)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_kind_deserialization() {
        let json = r#""system""#;
        let kind: MessageKind = serde_json::from_str(json).unwrap();
        assert_eq!(kind, MessageKind::System);

        let json = r#""user""#;
        let kind: MessageKind = serde_json::from_str(json).unwrap();
        assert_eq!(kind, MessageKind::User);

        let json = r#""assistant""#;
        let kind: MessageKind = serde_json::from_str(json).unwrap();
        assert_eq!(kind, MessageKind::Assistant);

        let json = r#""invalid""#;
        let kind: Result<MessageKind, _> = serde_json::from_str(json);
        assert!(kind.is_err());
    }

    #[test]
    fn test_message_kind_from_role() {
        let role = Role::System;
        let kind: MessageKind = role.into();
        assert_eq!(kind, MessageKind::System);

        let role = Role::User;
        let kind: MessageKind = role.into();
        assert_eq!(kind, MessageKind::User);

        let role = Role::Assistant;
        let kind: MessageKind = role.into();
        assert_eq!(kind, MessageKind::Assistant);

        let role = Role::Function;
        let kind: MessageKind = role.into();
        assert_eq!(kind, MessageKind::Funtion);

        let role = Role::Tool;
        let kind: MessageKind = role.into();
        assert_eq!(kind, MessageKind::Tool);
    }

    #[test]
    fn test_message_deserialization_full() {
        let json = r#"{"type": "system", "value": "Hello"}"#;
        let message: Message = serde_json::from_str(json).unwrap();
        assert_eq!(
            message,
            Message::Full {
                role: MessageKind::System,
                name: None,
                value: "Hello".to_string()
            }
        );

        let json = r#"{"type": "system", name: "robot", "value": "Hello"}"#;
        let message: Message = serde_json::from_str(json).unwrap();
        assert_eq!(
            message,
            Message::Full {
                role: MessageKind::System,
                name: Some("robot".to_string()),
                value: "Hello".to_string()
            }
        );
    }

    #[test]
    fn test_message_deserialization_short() {
        let json = r#""Hello""#;
        let message: Message = serde_json::from_str(json).unwrap();
        assert_eq!(message, Message::Short("Hello".to_string()));
    }

    #[test]
    fn test_message_deserialization_default_type() {
        let json = r#"{"value": "Hello"}"#;
        let message: Message = serde_json::from_str(json).unwrap();
        assert_eq!(
            message,
            Message::Full {
                role: MessageKind::User,
                name: None,
                value: "Hello".to_string()
            }
        );
    }

    #[test]
    fn test_input_deserialization() {
        let json = r#"{
            "apiKey": "your_api_key",
            "messages": [
                {"type": "system", name: "robot", "value": "You are a helpful assistant."},
                "Hello",
                {"type": "assistant", "value": "The Los Angeles Dodgers won the World Series in 2020."}
            ]
        }"#;
        let input: Input = serde_json::from_str(json).unwrap();
        assert_eq!(input.api_key, "your_api_key");
        assert_eq!(input.model, DEFAULT_MODEL);
        assert_eq!(
            input.messages,
            vec![
                Message::Full {
                    role: MessageKind::System,
                    name: Some("robot".to_string()),
                    value: "You are a helpful assistant.".to_string()
                },
                Message::Short("Hello".to_string()),
                Message::Full {
                    role: MessageKind::Assistant,
                    name: None,
                    value: "The Los Angeles Dodgers won the World Series in 2020.".to_string()
                }
            ]
        );
    }

    #[test]
    fn test_input_empty_message() {
        let json = r#"{
            "apiKey": "your_api_key",
            "messages": []
        }"#;
        let input: Input = serde_json::from_str(json).unwrap();
        assert_eq!(input.api_key, "your_api_key");
        assert_eq!(input.model, DEFAULT_MODEL);
        assert!(input.messages.is_empty());
    }

    #[test]
    fn test_input_missing_message() {
        let json = r#"{
            "apiKey": "your_api_key"
        }"#;

        let input: Result<Input, _> = serde_json::from_str(json);

        assert!(input.is_err());
    }
}
