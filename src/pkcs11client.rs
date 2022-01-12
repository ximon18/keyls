use anyhow::{bail, Result};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, SessionFlags, UserType},
    slot::Slot,
};

use crate::{
    config::{Opt, Pkcs11ServerOpt, ServerOpt},
    key::{Key, KeyType},
};

pub(crate) fn get_keys(opt: Opt) -> Result<Vec<Key>> {
    if let ServerOpt::Pkcs11(server_opt) = &opt.server {
        let pkcs11 = Pkcs11::new(&server_opt.lib_path)?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;

        let slot = get_slot(&pkcs11, server_opt)?;
        println!("Using PKCS#11 slot id {} ({:#x})", slot.id(), slot.id());

        let mut flags = SessionFlags::new();
        flags.set_serial_session(true).set_rw_session(true);
        let session = pkcs11.open_session_no_callback(slot, flags)?;
        session.login(UserType::User, server_opt.user_pin.as_deref())?;

        let mut keys = Vec::new();
        for key_handle in session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])? {
            match get_key(&session, key_handle) {
                Ok(key) => keys.push(key),
                Err(err) => eprintln!(
                    "Error retrieving attributes for private key {:?}: {}",
                    key_handle, err
                ),
            }
        }
        for key_handle in session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])? {
            match get_key(&session, key_handle) {
                Ok(key) => keys.push(key),
                Err(err) => eprintln!(
                    "Error retrieving attributes for public key {:?}: {}",
                    key_handle, err
                ),
            }
        }

        keys.sort_by_key(|v| v.id.clone());

        Ok(keys)
    } else {
        bail!("Expected PKCS#11 settings")
    }
}

fn get_key(session: &Session, key_handle: ObjectHandle) -> Result<Key> {
    let mut key = Key {
        id: Default::default(),
        typ: KeyType::Private,
        name: Default::default(),
        alg: Default::default(),
        len: Default::default(),
    };

    let request_attrs = [
        AttributeType::Class,
        AttributeType::Id,
        AttributeType::ModulusBits,
        AttributeType::KeyType,
        AttributeType::Label,
    ];
    let attrs = session.get_attributes(key_handle, &request_attrs)?;

    for attr in attrs {
        match attr {
            Attribute::Class(class) => {
                if class == ObjectClass::PRIVATE_KEY {
                    key.typ = KeyType::Private;
                } else if class == ObjectClass::PUBLIC_KEY {
                    key.typ = KeyType::Public;
                } else {
                    bail!("Unsupported object class");
                }
            }
            Attribute::Id(id) => {
                key.id = hex::encode_upper(&id);
            }
            Attribute::KeyType(typ) => {
                if typ == cryptoki::object::KeyType::RSA {
                    key.alg = "RSA".to_string();
                } else {
                    key.alg = "Non-RSA".to_string();
                }
            }
            Attribute::Label(label) => {
                key.name = String::from_utf8_lossy(&label).to_string();
            }
            Attribute::ModulusBits(bits) => {
                key.len = bits.to_string();
            }
            _ => {
                // ignore unexpected attributes
            }
        }
    }

    Ok(key)
}

fn get_slot(pkcs11: &Pkcs11, server_opt: &Pkcs11ServerOpt) -> Result<Slot> {
    fn has_token_label(pkcs11: &Pkcs11, slot: Slot, slot_label: &str) -> bool {
        pkcs11
            .get_token_info(slot)
            .map(|info| String::from_utf8_lossy(&info.label).trim_end() == slot_label)
            .unwrap_or(false)
    }

    let slot = match (&server_opt.slot_id, &server_opt.slot_label) {
        (Some(id), None) => {
            match pkcs11
                .get_all_slots()?
                .into_iter()
                .find(|&slot| slot.id() == *id)
            {
                Some(slot) => slot,
                None => bail!("Cannot find slot wiht id {}", id),
            }
        }
        (None, Some(label)) => {
            match pkcs11
                .get_slots_with_initialized_token()?
                .into_iter()
                .find(|&slot| has_token_label(pkcs11, slot, label))
            {
                Some(slot) => slot,
                None => bail!("Cannot find slot with label '{}'", label),
            }
        }
        (Some(_), Some(_)) => bail!("Cannot specify both slot id and slot label"),
        (None, None) => bail!("Must specify at least one of slot id or slot label"),
    };

    Ok(slot)
}
