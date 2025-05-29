use crate::{
    idents::{move_std, workflow},
    sui,
    types::{NexusObjects, Prekey, PREKEY_BYTES_LENGTH},
};

/// PTB template to replenish public prekeys in the prekey vault.
pub fn replenish_prekeys(
    tx: &mut sui::ProgrammableTransactionBuilder,
    objects: &NexusObjects,
    owner_cap: sui::ObjectRef,
    prekeys: &Vec<Prekey>,
) -> anyhow::Result<sui::Argument> {
    // `self: &mut PrekeyVault`
    let prekey_vault = tx.obj(sui::ObjectArg::SharedObject {
        id: objects.prekey_vault.object_id,
        initial_shared_version: objects.prekey_vault.version,
        mutable: true,
    })?;

    // `owner_cap: &CloneableOwnerCap<OverCrypto>`
    let owner_cap = tx.obj(sui::ObjectArg::ImmOrOwnedObject(owner_cap.to_object_ref()))?;

    // `Prekey`
    let prekey_type =
        workflow::into_type_tag(objects.workflow_pkg_id, workflow::PrekeyVault::PREKEY);

    // `vector::<Prekey>::empty`
    let prekey_vector = tx.programmable_move_call(
        sui::MOVE_STDLIB_PACKAGE_ID,
        move_std::Vector::EMPTY.module.into(),
        move_std::Vector::EMPTY.name.into(),
        vec![prekey_type.clone()],
        vec![],
    );

    for prekey in prekeys {
        // `prekey_id: u32`
        let prekey_id = tx.pure(prekey.id)?;

        // `bytes: vector<u8>`
        let prekey_bytes = tx.pure(prekey.bytes.as_slice())?;

        // Ensure prekey bytes are of the correct length.
        if prekey.bytes.len() != PREKEY_BYTES_LENGTH {
            anyhow::bail!(
                "Prekey bytes must be exactly {} bytes long",
                PREKEY_BYTES_LENGTH
            );
        }

        // `prekey: Prekey`
        let new_prekey = tx.programmable_move_call(
            objects.workflow_pkg_id,
            workflow::PrekeyVault::PREKEY_FROM_BYTES.module.into(),
            workflow::PrekeyVault::PREKEY_FROM_BYTES.name.into(),
            vec![],
            vec![prekey_id, prekey_bytes],
        );

        // `vector::<Prekey>::push_back`
        tx.programmable_move_call(
            sui::MOVE_STDLIB_PACKAGE_ID,
            move_std::Vector::PUSH_BACK.module.into(),
            move_std::Vector::PUSH_BACK.name.into(),
            vec![prekey_type.clone()],
            vec![prekey_vector, new_prekey],
        );
    }

    // `nexus_workflow::prekey_vault::replenish_prekeys`
    Ok(tx.programmable_move_call(
        objects.workflow_pkg_id,
        workflow::PrekeyVault::REPLENISH_PREKEYS.module.into(),
        workflow::PrekeyVault::REPLENISH_PREKEYS.name.into(),
        vec![],
        vec![prekey_vault, owner_cap, prekey_vector],
    ))
}

/// PTB to claim a prekey for the tx sender. Note that one must have uploaded
/// gas budget before calling this function for rate limiting purposes. Also
/// rate limited per address.
pub fn claim_prekey_for_self(
    tx: &mut sui::ProgrammableTransactionBuilder,
    objects: &NexusObjects,
) -> anyhow::Result<sui::Argument> {
    // `self: &mut PrekeyVault`
    let prekey_vault = tx.obj(sui::ObjectArg::SharedObject {
        id: objects.prekey_vault.object_id,
        initial_shared_version: objects.prekey_vault.version,
        mutable: true,
    })?;

    // `gas_service: &GasService`
    let gas_service = tx.obj(sui::ObjectArg::SharedObject {
        id: objects.gas_service.object_id,
        initial_shared_version: objects.gas_service.version,
        mutable: false,
    })?;

    // `clock: &Clock`
    let clock = tx.obj(sui::CLOCK_OBJ_ARG)?;

    // `nexus_workflow::prekey_vault::claim_prekey_for_self`
    Ok(tx.programmable_move_call(
        objects.workflow_pkg_id,
        workflow::PrekeyVault::CLAIM_PREKEY_FOR_SELF.module.into(),
        workflow::PrekeyVault::CLAIM_PREKEY_FOR_SELF.name.into(),
        vec![],
        vec![prekey_vault, gas_service, clock],
    ))
}

#[cfg(test)]
mod tests {
    use {super::*, crate::test_utils::sui_mocks};

    #[test]
    fn test_replenish_prekeys() {
        let objects = sui_mocks::mock_nexus_objects();
        let owner_cap = sui_mocks::mock_sui_object_ref();
        let prekeys = vec![
            Prekey {
                id: 1,
                // must be len 33
                bytes: vec![
                    0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01,
                    0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02,
                    0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03,
                ],
            },
            Prekey {
                id: 2,
                bytes: vec![
                    0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01,
                    0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03, 0x01, 0x02,
                    0x03, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03,
                ],
            },
        ];

        let mut tx = sui::ProgrammableTransactionBuilder::new();
        replenish_prekeys(&mut tx, &objects, owner_cap, &prekeys).unwrap();
        let tx = tx.finish();

        let sui::Command::MoveCall(call) = &tx.commands.last().unwrap() else {
            panic!("Expected last command to be a MoveCall to replenish prekeys");
        };

        assert_eq!(call.package, objects.workflow_pkg_id);
        assert_eq!(
            call.module,
            workflow::PrekeyVault::REPLENISH_PREKEYS.module.to_string(),
        );
        assert_eq!(
            call.function,
            workflow::PrekeyVault::REPLENISH_PREKEYS.name.to_string()
        );
    }

    #[test]
    fn test_claim_prekey_for_self() {
        let objects = sui_mocks::mock_nexus_objects();

        let mut tx = sui::ProgrammableTransactionBuilder::new();
        claim_prekey_for_self(&mut tx, &objects).unwrap();
        let tx = tx.finish();

        let sui::Command::MoveCall(call) = &tx.commands.last().unwrap() else {
            panic!("Expected last command to be a MoveCall to claim prekey for self");
        };

        assert_eq!(call.package, objects.workflow_pkg_id);
        assert_eq!(
            call.module,
            workflow::PrekeyVault::CLAIM_PREKEY_FOR_SELF
                .module
                .to_string(),
        );
        assert_eq!(
            call.function,
            workflow::PrekeyVault::CLAIM_PREKEY_FOR_SELF
                .name
                .to_string()
        );
    }

    #[test]
    fn test_replenish_prekeys_invalid_length() {
        let objects = sui_mocks::mock_nexus_objects();
        let owner_cap = sui_mocks::mock_sui_object_ref();
        // Invalid prekey length (should be PREKEY_BYTES_LENGTH)
        let prekeys = vec![Prekey {
            id: 1,
            bytes: vec![0x01, 0x02, 0x03], // too short
        }];

        let mut tx = sui::ProgrammableTransactionBuilder::new();
        let result = replenish_prekeys(&mut tx, &objects, owner_cap, &prekeys);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains(&PREKEY_BYTES_LENGTH.to_string()),
            "Error message should mention PREKEY_BYTES_LENGTH"
        );
    }
}
