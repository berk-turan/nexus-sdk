use {
    super::AuthArgs,
    crate::{command_title, display::json_output, loading, prelude::*, sui::*},
    nexus_sdk::{
        crypto::{
            session::Session,
            x3dh::{IdentityKey, PreKeyBundle},
        },
        idents::workflow,
        object_crawler::fetch_one,
        sui,
        transactions::crypto::*,
    },
};

// Temporary struct for fetching raw prekey data
#[derive(serde::Deserialize)]
struct RawPreKey {
    bytes: Vec<u8>,
}

pub(crate) async fn crypto_auth(args: AuthArgs) -> AnyResult<(), NexusCliError> {
    command_title!("crypto auth - establish a secure session with a peer");

    // 1. Load config & objects
    let mut conf = CliConf::load().await.unwrap_or_default();
    let objects = get_nexus_objects(&conf)?;

    // 2. Wallet / client / address
    let mut wallet = create_wallet_context(&conf.sui.wallet_path, conf.sui.net).await?;
    let sui = build_sui_client(&conf.sui).await?;
    let address = wallet.active_address().map_err(NexusCliError::Any)?;

    // 3. Gas coin selection
    let gas_coin = fetch_gas_coin(&sui, conf.sui.net, address, args.gas.sui_gas_coin).await?;
    let reference_gas_price = fetch_reference_gas_price(&sui).await?;

    // 4. Build claim-self PTB
    let mut tx_builder = sui::ProgrammableTransactionBuilder::new();
    // Ignore the return value, its probably empty
    let _claim_cmd =
        claim_pre_key_for_self(&mut tx_builder, &objects).map_err(NexusCliError::Any)?;
    let ptb = tx_builder.finish();

    let tx_data = sui::TransactionData::new_programmable(
        address,
        vec![gas_coin.object_ref()],
        ptb,
        args.gas.sui_gas_budget,
        reference_gas_price,
    );

    let load = loading!("Executing claim_pre_key_for_self…");
    let tx_resp = sign_and_execute_transaction(&sui, &wallet, tx_data).await?;
    load.success();

    // 5. Locate the newly‑created Prekey object in effects
    let prekey_struct_tag =
        match workflow::into_type_tag(objects.workflow_pkg_id, workflow::PreKeyVault::PRE_KEY) {
            sui::MoveTypeTag::Struct(struct_tag) => *struct_tag,
            _ => {
                return Err(NexusCliError::Any(anyhow!(
                    "Expected struct type tag for PreKey"
                )))
            }
        };

    let prekey_obj_id = tx_resp
        .object_changes
        .unwrap_or_default()
        .into_iter()
        .find_map(|chg| match chg {
            sui::ObjectChange::Transferred {
                object_type,
                object_id,
                recipient,
                ..
            } if object_type == prekey_struct_tag
                && recipient == sui::Owner::AddressOwner(address) =>
            {
                Some(object_id)
            }
            // optional: still catch Created for forward-compat
            sui::ObjectChange::Created {
                object_type,
                object_id,
                ..
            } if object_type == prekey_struct_tag => Some(object_id),
            _ => None,
        })
        .ok_or_else(|| NexusCliError::Any(anyhow!("No Prekey object transferred to caller")))?;

    // Fetch full object
    let prekey_resp = fetch_one::<RawPreKey>(&sui, prekey_obj_id)
        .await
        .map_err(NexusCliError::Any)?;
    let peer_bundle = bincode::deserialize::<PreKeyBundle>(&prekey_resp.data.bytes)
        .map_err(|e| NexusCliError::Any(anyhow!("Failed to deserialize PreKeyBundle: {:?}", e)))?;

    // 6. Ensure IdentityKey
    if conf.crypto.identity_key.is_none() {
        conf.crypto.identity_key = Some(IdentityKey::generate());
    }

    // 7. Run X3DH & store session
    let first_message = b"nexus auth";
    let (initial_msg, session) = {
        let identity_key = conf.crypto.identity_key.as_ref().unwrap();
        Session::initiate(&identity_key, &peer_bundle, first_message)
            .map_err(|e| NexusCliError::Any(anyhow!("Session initiation failed: {:?}", e)))?
    };

    // Extract InitialMessage from Message enum
    let initial_message = match initial_msg {
        nexus_sdk::crypto::session::Message::Initial(msg) => msg,
        _ => {
            return Err(NexusCliError::Any(anyhow!(
                "Expected Initial message from session initiation"
            )))
        }
    };

    // Store session and save config
    let session_id = *session.id();
    conf.crypto.sessions.insert(session_id, session);
    conf.save().await.map_err(NexusCliError::Any)?;

    // Make borrow checker happy
    let objects = get_nexus_objects(&conf)?;

    // 8. Build and execute associate_pre_key_with_sender PTB
    let mut tx_builder = sui::ProgrammableTransactionBuilder::new();
    let _associate_cmd = associate_pre_key_with_sender(
        &mut tx_builder,
        &objects,
        &prekey_resp.object_ref(),
        initial_message.clone(),
    )
    .map_err(NexusCliError::Any)?;
    let ptb = tx_builder.finish();

    let tx_data = sui::TransactionData::new_programmable(
        address,
        vec![gas_coin.object_ref()],
        ptb,
        args.gas.sui_gas_budget,
        reference_gas_price,
    );

    let load = loading!("Executing associate_pre_key_with_sender…");
    let associate_tx_resp = sign_and_execute_transaction(&sui, &wallet, tx_data).await?;
    load.success();

    // Output both transaction digests
    json_output(&json!({
        "claim_digest": tx_resp.digest,
        "associate_digest": associate_tx_resp.digest,
        "initial_message": initial_message,
    }))?;

    Ok(())
}
