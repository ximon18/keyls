use anyhow::{anyhow, bail, Result};
use pkcs11::{
    types::{
        CKA_CLASS, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS_BITS, CKF_RW_SESSION,
        CKF_SERIAL_SESSION, CKK_RSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKU_USER, CK_ATTRIBUTE,
        CK_KEY_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG,
    },
    Ctx,
};

use crate::{
    config::{Opt, Pkcs11ServerOpt, ServerOpt},
    key::{Key, KeyType},
};

pub(crate) fn get_keys(opt: Opt) -> Result<Vec<Key>> {
    if let ServerOpt::Pkcs11(server_opt) = &opt.server {
        let ctx = Ctx::new_and_initialize(&server_opt.lib_path)?;

        let slot_id = get_slot_id(&ctx, server_opt)?;
        println!("Using PKCS#11 slot id {} ({:#x})", slot_id, slot_id);

        let session = ctx.open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)?;

        ctx.login(session, CKU_USER, server_opt.user_pin.as_deref())?;

        let mut keys = Vec::new();
        for key_id in get_key_ids(&ctx, session, CKO_PRIVATE_KEY)? {
            keys.push(get_key(&ctx, session, key_id)?);
        }
        for key_id in get_key_ids(&ctx, session, CKO_PUBLIC_KEY)? {
            keys.push(get_key(&ctx, session, key_id)?);
        }

        keys.sort_by_key(|v| v.id.clone());

        Ok(keys)
    } else {
        bail!("Expected PKCS#11 settings")
    }
}

fn get_key(ctx: &Ctx, session: CK_SESSION_HANDLE, key_id: CK_OBJECT_HANDLE) -> Result<Key> {
    let mut template: Vec<CK_ATTRIBUTE> =
        vec![CK_ATTRIBUTE::new(CKA_ID), CK_ATTRIBUTE::new(CKA_LABEL)];
    let (_, res_vec) = ctx.get_attribute_value(session, key_id, &mut template)?;
    let id_len = res_vec
        .get(0)
        .ok_or_else(|| anyhow!("Missing attribute CKA_ID"))?
        .ulValueLen as usize;
    let label_len = res_vec
        .get(1)
        .ok_or_else(|| anyhow!("Missing attribute CKA_LABEL"))?
        .ulValueLen as usize;

    let mut id = vec![0; id_len];
    let class: CK_OBJECT_CLASS = 0;
    let typ: CK_KEY_TYPE = 0;
    let len: CK_ULONG = 0;
    let mut label = vec![0; label_len];

    let mut template: Vec<CK_ATTRIBUTE> = vec![
        CK_ATTRIBUTE::new(CKA_ID).with_bytes(id.as_mut_slice()),
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&class),
        CK_ATTRIBUTE::new(CKA_MODULUS_BITS).with_ck_ulong(&len),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&typ),
        CK_ATTRIBUTE::new(CKA_LABEL).with_bytes(label.as_mut_slice()),
    ];
    ctx.get_attribute_value(session, key_id, &mut template)?;

    let alg = match typ {
        CKK_RSA => "RSA".to_string(),
        _ => "Non-RSA".to_string(),
    };

    let typ = match class {
        CKO_PRIVATE_KEY => KeyType::Private,
        CKO_PUBLIC_KEY => KeyType::Public,
        _ => bail!("Unsupported object class"),
    };

    Ok(Key {
        id: hex::encode_upper(&id),
        typ,
        name: String::from_utf8_lossy(&label).to_string(),
        alg,
        len: len.to_string(),
    })
}

fn get_key_ids(
    ctx: &Ctx,
    session: CK_SESSION_HANDLE,
    object_type: CK_OBJECT_CLASS,
) -> Result<Vec<CK_OBJECT_HANDLE>> {
    let mut key_ids = Vec::new();
    let max_object_count: CK_ULONG = 100;

    let template: Vec<CK_ATTRIBUTE> =
        vec![CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&object_type)];
    ctx.find_objects_init(session, &template)?;

    loop {
        // Find more results
        let mut found_key_ids = ctx.find_objects(session, max_object_count)?;
        let found_count: u64 = found_key_ids.len().try_into().unwrap();

        // Move the found results into the final result vector
        key_ids.append(&mut found_key_ids);

        // Stop if the find buffer was not filled, i.e. there are no more results to be found
        if found_count < max_object_count {
            break;
        }
    }

    ctx.find_objects_final(session)?;
    Ok(key_ids)
}

fn get_slot_id(ctx: &Ctx, server_opt: &Pkcs11ServerOpt) -> Result<CK_SLOT_ID> {
    fn has_token_label(ctx: &Ctx, slot_id: CK_SLOT_ID, slot_label: &str) -> bool {
        ctx.get_token_info(slot_id)
            .map(|info| info.label.to_string() == slot_label)
            .unwrap_or(false)
    }

    let slot_id = match (&server_opt.slot_id, &server_opt.slot_label) {
        (Some(id), None) => *id as u64,
        (None, Some(label)) => {
            let slot_id = match ctx
                .get_slot_list(true)?
                .into_iter()
                .find(|&slot_id| has_token_label(ctx, slot_id, label))
            {
                Some(slot_id) => slot_id,
                None => bail!("Cannot find slot with label '{}'", label),
            };
            slot_id
        }
        (Some(_), Some(_)) => bail!("Cannot specify both slot id and slot label"),
        (None, None) => bail!("Must specify at least one of slot id or slot label"),
    };

    Ok(slot_id)
}
