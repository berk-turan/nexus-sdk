use {
    crate::{
        command_title,
        display::json_output,
        loading,
        notify_success,
        prelude::*,
        sui::*,
        tool::{tool_validate::*, ToolIdent},
    },
    nexus_sdk::{
        idents::{primitives, workflow},
        transactions::tool,
    },
    nexus_toolkit::tls::{generate_key_and_hash, reqwest_with_pin},
};

/// Validate and then register a new Tool.
pub(crate) async fn register_tool(
    ident: ToolIdent,
    key_path: Option<PathBuf>,
    collateral_coin: Option<sui::ObjectID>,
    invocation_cost: u64,
    batch: bool,
    server_cert_hash: Option<String>, // TODO: Move this out, only for testing
    sui_gas_coin: Option<sui::ObjectID>,
    sui_gas_budget: u64,
) -> AnyResult<(), NexusCliError> {
    let ident_check = ident.clone();

    // Validate either a single tool or a batch of tools if the `batch` flag is
    // provided.
    let idents = if batch {
        let Some(url) = &ident.off_chain else {
            todo!("TODO: <https://github.com/Talus-Network/nexus-next/issues/96>");
        };

        // Fetch all tools on the webserver using pinned TLS client.
        let client = if let Some(ref hash) = server_cert_hash {
            reqwest_with_pin(hash).map_err(NexusCliError::Any)?
        } else {
            reqwest::Client::new() // Fallback to default client if no hash provided
        };

        let response = client
            .get(url.join("/tools").expect("Joining URL must be valid"))
            .send()
            .await
            .map_err(NexusCliError::Http)?
            .json::<Vec<String>>()
            .await
            .map_err(NexusCliError::Http)?;

        response
            .iter()
            .filter_map(|s| match url.join(s) {
                Ok(url) => Some(ToolIdent {
                    off_chain: Some(url),
                    on_chain: None,
                }),
                Err(_) => None,
            })
            .collect::<Vec<_>>()
    } else {
        vec![ident]
    };

    let mut registration_results = Vec::with_capacity(idents.len());

    for ident in idents {
        let meta = validate_tool(ident).await?;

        command_title!(
            "Registering Tool '{fqn}' at '{url}'",
            fqn = meta.fqn,
            url = meta.url
        );

        // Generate TLS key if path is provided and key doesn't already exist
        let tls_key_hash = if let Some(ref path) = key_path {
            if path.exists() {
                command_title!("Using existing TLS key at '{path}'", path = path.display());
                notify_success!("TLS key already exists, skipping generation");
                // TODO: We should still compute and return the hash of the existing key
                // For now, returning None - this may need to be adjusted based on requirements
                None
            } else {
                command_title!("Generating TLS key to '{path}'", path = path.display());

                let generation_handle = loading!("Generating TLS key...");

                let hash = match generate_key_and_hash(&path) {
                    Ok(hash) => hash,
                    Err(e) => {
                        generation_handle.error();
                        return Err(NexusCliError::Any(e));
                    }
                };

                generation_handle.success();
                notify_success!("TLS key generated successfully");

                Some(hash)
            }
        } else {
            None
        };

        // Load CLI configuration.
        let conf = CliConf::load().await.unwrap_or_default();

        // Nexus objects must be present in the configuration.
        let objects = get_nexus_objects(&conf)?;

        // Create wallet context, Sui client and find the active address.
        let mut wallet = create_wallet_context(&conf.sui.wallet_path, conf.sui.net).await?;
        let sui = build_sui_client(&conf.sui).await?;
        let address = wallet.active_address().map_err(NexusCliError::Any)?;

        // Fetch gas and collateral coin objects.
        let (gas_coin, collateral_coin) =
            fetch_gas_and_collateral_coins(&sui, address, sui_gas_coin, collateral_coin).await?;

        if gas_coin.coin_object_id == collateral_coin.coin_object_id {
            return Err(NexusCliError::Any(anyhow!(
                "Gas and collateral coins must be different."
            )));
        }

        // Fetch reference gas price.
        let reference_gas_price = fetch_reference_gas_price(&sui).await?;

        // Craft a TX to register the tool.
        let tx_handle = loading!("Crafting transaction...");

        // Explicitly check that we're registering an off-chain tool. This is mainly
        // for when we implement logic for on-chain so that we don't forget to
        // adjust the transaction.
        if ident_check.on_chain.is_some() {
            todo!("TODO: <https://github.com/Talus-Network/nexus-next/issues/96>");
        }

        let mut tx = sui::ProgrammableTransactionBuilder::new();

        if let Err(e) = tool::register_off_chain_for_self(
            &mut tx,
            objects,
            &meta,
            address.into(),
            &collateral_coin,
            invocation_cost,
            tls_key_hash.as_ref(),
        ) {
            tx_handle.error();

            return Err(NexusCliError::Any(e));
        }

        tx_handle.success();

        let tx_data = sui::TransactionData::new_programmable(
            address,
            vec![gas_coin.object_ref()],
            tx.finish(),
            sui_gas_budget,
            reference_gas_price,
        );

        // Sign and submit the TX.
        let response = sign_and_execute_transaction(&sui, &wallet, tx_data).await?;

        // Parse the owner cap object IDs from the response.
        let owner_caps = response
            .object_changes
            .unwrap_or_default()
            .into_iter()
            .filter_map(|change| match change {
                sui::ObjectChange::Created {
                    object_type,
                    object_id,
                    ..
                } if object_type.address == *objects.primitives_pkg_id
                    && object_type.module
                        == primitives::OwnerCap::CLONEABLE_OWNER_CAP.module.into()
                    && object_type.name
                        == primitives::OwnerCap::CLONEABLE_OWNER_CAP.name.into() =>
                {
                    Some((object_id, object_type))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        // Find `CloneableOwnerCap<OverTool>` object ID.
        let over_tool = owner_caps.iter().find_map(|(object_id, object_type)| {
            match object_type.type_params.first() {
                Some(sui::MoveTypeTag::Struct(what_for))
                    if what_for.module == workflow::ToolRegistry::OVER_TOOL.module.into()
                        && what_for.name == workflow::ToolRegistry::OVER_TOOL.name.into() =>
                {
                    Some(object_id)
                }
                _ => None,
            }
        });

        let Some(over_tool_id) = over_tool else {
            return Err(NexusCliError::Any(anyhow!(
                "Could not find the OwnerCap<OverTool> object ID in the transaction response."
            )));
        };

        // Find `CloneableOwnerCap<OverGas>` object ID.
        let over_gas = owner_caps.iter().find_map(|(object_id, object_type)| {
            match object_type.type_params.first() {
                Some(sui::MoveTypeTag::Struct(what_for))
                    if what_for.module == workflow::Gas::OVER_GAS.module.into()
                        && what_for.name == workflow::Gas::OVER_GAS.name.into() =>
                {
                    Some(object_id)
                }
                _ => None,
            }
        });

        let Some(over_gas_id) = over_gas else {
            return Err(NexusCliError::Any(anyhow!(
                "Could not find the OwnerCap<OverGas> object ID in the transaction response."
            )));
        };

        notify_success!(
            "OwnerCap<OverTool> object ID: {id}",
            id = over_tool_id.to_string().truecolor(100, 100, 100)
        );

        notify_success!(
            "OwnerCap<OverGas> object ID: {id}",
            id = over_gas_id.to_string().truecolor(100, 100, 100)
        );

        // Save the owner caps to the CLI conf.
        let save_handle = loading!("Saving the owner caps to the CLI configuration...");

        let mut conf = CliConf::load().await.unwrap_or_default();

        conf.tools.insert(
            meta.fqn.clone(),
            ToolOwnerCaps {
                over_tool: *over_tool_id,
                over_gas: *over_gas_id,
            },
        );

        if let Err(e) = conf.save().await {
            save_handle.error();

            return Err(NexusCliError::Any(e));
        }

        save_handle.success();

        let mut result = json!({
            "digest": response.digest,
            "tool_fqn": meta.fqn,
            "owner_cap_over_tool_id": over_tool_id,
            "owner_cap_over_gas_id": over_gas_id,
        });

        // Add TLS key information if generated
        if let (Some(path), Some(hash)) = (&key_path, &tls_key_hash) {
            result["tls_key_path"] = json!(path);
            result["tls_key_hash"] = json!(hex::encode(hash));
        }

        registration_results.push(result);
    }

    json_output(&registration_results)?;

    Ok(())
}

/// Fetch the gas and collateral coins from the Sui client. On Localnet, Devnet
/// and Testnet, we can use the faucet to get the coins. On Mainnet, this fails
/// if the coins are not present.
async fn fetch_gas_and_collateral_coins(
    sui: &sui::Client,
    addr: sui::Address,
    sui_gas_coin: Option<sui::ObjectID>,
    sui_collateral_coin: Option<sui::ObjectID>,
) -> AnyResult<(sui::Coin, sui::Coin), NexusCliError> {
    let mut coins = fetch_all_coins_for_address(sui, addr).await?;

    if coins.len() < 2 {
        return Err(NexusCliError::Any(anyhow!(
            "The wallet does not have enough coins to register the tool"
        )));
    }

    // If object IDs were specified, use them. If any of the specified coins is
    // not found, return error.
    let gas_coin = match sui_gas_coin {
        Some(id) => coins
            .iter()
            .find(|coin| coin.coin_object_id == id)
            .cloned()
            .ok_or_else(|| NexusCliError::Any(anyhow!("Coin '{id}' not found in wallet")))?,
        None => coins.remove(0),
    };

    let collateral_coin = match sui_collateral_coin {
        Some(id) => coins
            .iter()
            .find(|coin| coin.coin_object_id == id)
            .cloned()
            .ok_or_else(|| NexusCliError::Any(anyhow!("Coin '{id}' not found in wallet")))?,
        None => coins.remove(0),
    };

    Ok((gas_coin, collateral_coin))
}
