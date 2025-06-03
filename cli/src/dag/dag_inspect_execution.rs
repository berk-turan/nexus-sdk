use {
    crate::{
        command_title,
        display::json_output,
        item,
        notify_error,
        notify_success,
        prelude::*,
        sui::*,
    },
    bincode,
    nexus_sdk::{
        crypto::session::{Message, StandardMessage},
        events::{NexusEvent, NexusEventKind},
        idents::primitives,
        types::{NexusData, TypeName},
    },
    std::collections::HashMap,
};

/// Inspect a Nexus DAG execution process based on the provided object ID and
/// execution digest.
pub(crate) async fn inspect_dag_execution(
    dag_execution_id: sui::ObjectID,
    execution_digest: sui::TransactionDigest,
) -> AnyResult<(), NexusCliError> {
    command_title!("Inspecting Nexus DAG Execution '{dag_execution_id}'");

    // Load CLI configuration.
    let mut conf = CliConf::load().await.unwrap_or_default();

    validate_authentication(&conf)?;

    // Nexus objects must be present in the configuration.
    let primitives_pkg_id = {
        let NexusObjects {
            primitives_pkg_id, ..
        } = get_nexus_objects(&conf)?;
        *primitives_pkg_id // ObjectID is Copy
    };

    // Build Sui client.
    let sui_conf = conf.sui.clone();
    let sui = build_sui_client(&sui_conf).await?;

    // Check if we have authentication for potential decryption
    let has_session = !conf.crypto.sessions.is_empty();

    let limit = None;
    let descending_order = false;

    // Starting cursor is the provided event digest and `event_seq` always 0.
    let mut cursor = Some(sui::EventID {
        tx_digest: execution_digest,
        event_seq: 0,
    });

    let mut json_trace = Vec::new();

    // Loop until we find an `ExecutionFinished` event.
    'query: loop {
        let query = sui::EventFilter::MoveEventModule {
            package: primitives_pkg_id,
            module: primitives::Event::EVENT_WRAPPER.module.into(),
        };

        let events = match sui
            .event_api()
            .query_events(query, cursor, limit, descending_order)
            .await
        {
            Ok(page) => {
                cursor = page.next_cursor;

                page.data
            }
            Err(_) => {
                // If RPC call fails, wait and retry.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                continue;
            }
        };

        // Parse `SuiEvent` into `NexusEvent`.
        let events = events.into_iter().filter_map(|e| match e.try_into() {
            Ok(event) => Some::<NexusEvent>(event),
            Err(e) => {
                eprintln!("Failed to parse event: {:?}", e);
                None
            }
        });

        for event in events {
            match event.data {
                NexusEventKind::WalkAdvanced(e) if e.execution == dag_execution_id => {
                    notify_success!(
                        "Vertex '{vertex}' evaluated with output variant '{variant}'.",
                        vertex = e.vertex.name.truecolor(100, 100, 100),
                        variant = e.variant.name.truecolor(100, 100, 100),
                    );

                    let Ok(variant_ports_to_data) =
                        serde_json::from_value::<PortsToData>(e.variant_ports_to_data.clone())
                    else {
                        item!(
                            "With data: {data}",
                            data =
                                format!("{:?}", e.variant_ports_to_data).truecolor(100, 100, 100),
                        );

                        continue;
                    };

                    let mut json_data = Vec::new();

                    for (port, data) in variant_ports_to_data.values {
                        let (display_data, json_data_value) =
                            process_port_data(&port, &data, &mut conf);

                        item!(
                            "Port '{port}' produced data: {data}",
                            port = port.name.truecolor(100, 100, 100),
                            data = display_data.truecolor(100, 100, 100),
                        );

                        json_data.push(json_data_value);
                    }

                    json_trace.push(json!({
                        "end_state": false,
                        "vertex": e.vertex.name,
                        "variant": e.variant.name,
                        "data": json_data,
                    }));
                }

                NexusEventKind::EndStateReached(e) if e.execution == dag_execution_id => {
                    notify_success!(
                        "{end_state} Vertex '{vertex}' evaluated with output variant '{variant}'.",
                        vertex = e.vertex.name.truecolor(100, 100, 100),
                        variant = e.variant.name.truecolor(100, 100, 100),
                        end_state = "END STATE".truecolor(100, 100, 100)
                    );

                    let Ok(variant_ports_to_data) =
                        serde_json::from_value::<PortsToData>(e.variant_ports_to_data.clone())
                    else {
                        item!(
                            "With data: {data}",
                            data =
                                format!("{:?}", e.variant_ports_to_data).truecolor(100, 100, 100),
                        );

                        continue;
                    };

                    let mut json_data = Vec::new();

                    for (port, data) in variant_ports_to_data.values {
                        let (display_data, json_data_value) =
                            process_port_data(&port, &data, &mut conf);

                        item!(
                            "Port '{port}' produced data: {data}",
                            port = port.name.truecolor(100, 100, 100),
                            data = display_data.truecolor(100, 100, 100),
                        );

                        json_data.push(json_data_value);
                    }

                    json_trace.push(json!({
                        "end_state": true,
                        "vertex": e.vertex.name,
                        "variant": e.variant.name,
                        "data": json_data,
                    }));
                }

                NexusEventKind::ExecutionFinished(e) if e.execution == dag_execution_id => {
                    if e.has_any_walk_failed {
                        notify_error!("DAG execution finished unsuccessfully");

                        break 'query;
                    }

                    notify_success!("DAG execution finished successfully");

                    break 'query;
                }

                _ => {}
            }
        }
    }

    // Save the updated config if session was modified
    if has_session {
        conf.save().await.map_err(NexusCliError::Any)?;
    }

    json_output(&json_trace)?;

    Ok(())
}

/// Process port data, handling decryption if needed
fn process_port_data(
    port: &TypeName,
    data: &NexusData,
    conf: &mut CliConf,
) -> (String, serde_json::Value) {
    match data {
        NexusData::Inline { data, encrypted } if !encrypted => (
            format!("{data:?}"),
            json!({
                "port": port.name,
                "data": data,
            }),
        ),
        NexusData::Inline { data, encrypted } if *encrypted => match try_decrypt_data(data, conf) {
            Ok(decrypted_data) => (
                format!("{decrypted_data:?}"),
                json!({
                    "port": port.name,
                    "data": decrypted_data,
                    "was_encrypted": true,
                }),
            ),
            Err(e) => {
                eprintln!("Failed to decrypt data for port '{}': {}", port.name, e);
                (
                    format!("{data:?} [ENCRYPTED - FAILED TO DECRYPT]"),
                    json!({
                        "port": port.name,
                        "data": data,
                        "encrypted": true,
                        "decrypt_error": e.to_string(),
                    }),
                )
            }
        },
        _ => (
            format!("{data:?}"),
            json!({
                "port": port.name,
                "data": data,
            }),
        ),
    }
}

/// Attempt to decrypt encrypted data using the provided session
fn try_decrypt_data(
    encrypted_data: &serde_json::Value,
    conf: &mut CliConf,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if conf.crypto.sessions.is_empty() {
        return Err("No active session available for decryption".into());
    }

    let session_id = *conf.crypto.sessions.values().next().unwrap().id();
    let session = conf
        .crypto
        .sessions
        .get_mut(&session_id)
        .ok_or("Session not found in config")?;

    // Deserialize the encrypted data back to bytes
    let serialized_packet: Vec<u8> = serde_json::from_value(encrypted_data.clone())?;

    // Deserialize with bincode to get the StandardMessage
    let packet: StandardMessage = bincode::deserialize(&serialized_packet)?;

    // Create Message::Standard and decrypt
    let message = Message::Standard(packet);
    let decrypted_bytes = session.decrypt(&message)?;

    // Deserialize the decrypted bytes back to JSON
    let decrypted_value: serde_json::Value = serde_json::from_slice(&decrypted_bytes)?;

    Ok(decrypted_value)
}

/// Validates that the user has an active authentication session
fn validate_authentication(conf: &CliConf) -> Result<(), NexusCliError> {
    if conf.crypto.sessions.is_empty() {
        return Err(NexusCliError::Any(anyhow!(
            "Authentication required — run `nexus crypto auth` first"
        )));
    }
    Ok(())
}

/// Struct defining deser of the `variant_ports_to_data` field in the
/// `WalkAdvanced` and `EndStateReached` events.
// TODO: This can be later improved by making some bigger changes to the object
// crawler and porting it to the Nexus SDK.
#[derive(Clone, Debug)]
struct PortsToData {
    values: HashMap<TypeName, NexusData>,
}

impl<'de> serde::Deserialize<'de> for PortsToData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct VecMapWrapper {
            contents: Vec<VecMapEntry>,
        }

        #[derive(Deserialize)]
        struct VecMapEntry {
            key: TypeName,
            value: NexusData,
        }

        let values = VecMapWrapper::deserialize(deserializer)?;

        Ok(PortsToData {
            values: values
                .contents
                .into_iter()
                .map(|entry| (entry.key, entry.value))
                .collect(),
        })
    }
}
