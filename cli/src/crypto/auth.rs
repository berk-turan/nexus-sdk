use {
    super::AuthArgs,
    crate::{
        command_title,
        display::json_output,
        loading,
        prelude::*,
        sui::{
            build_sui_client,
            create_wallet_context,
            fetch_gas_coin,
            fetch_reference_gas_price,
            get_nexus_objects,
            sign_and_execute_transaction,
        },
    },
    anyhow::anyhow,
    nexus_sdk::{
        crypto::{session::Session, x3dh::IdentityKey},
        idents::workflow,
        object_crawler::fetch_one,
        sui,
        transactions::crypto::claim_pre_key_for_self,
        types::Prekey,
    },
    serde_json::json,
};

pub(crate) async fn auth(args: AuthArgs) -> AnyResult<(), NexusCliError> {
    command_title!("`crypto auth` - establish a secure session with a peer");

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
    let prekey_resp = fetch_one::<Prekey>(&sui, prekey_obj_id)
        .await
        .map_err(NexusCliError::Any)?;
    let peer_bundle = prekey_resp.data.bundle;

    // 6. Ensure IdentityKey
    let identity_key = match conf.crypto.identity_key.as_ref() {
        Some(key) => key,
        None => {
            let k = IdentityKey::generate();
            conf.crypto.identity_key = Some(k);
            conf.crypto.identity_key.as_ref().unwrap()
        }
    };

    // 7. Run X3DH & store session
    let first_message = b"nexus auth";
    let (initial_msg, session) = Session::initiate(identity_key, &peer_bundle, first_message)
        .map_err(|e| NexusCliError::Any(anyhow!("Session initiation failed: {:?}", e)))?;
    conf.crypto.sessions.insert(*session.id(), session);
    conf.save().await.map_err(NexusCliError::Any)?;

    // 8. Output digest + initial message
    json_output(&json!({
        "claim_digest": tx_resp.digest,
        "initial_message": initial_msg,
    }))?;

    Ok(())
}
