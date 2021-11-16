use std::time::Duration;

use anyhow::{bail, Result};
use kmip::{
    client::{Client, ClientCertificate, ConnectionSettings},
    types::{
        common::{AttributeName, AttributeValue, ObjectType, UniqueIdentifier},
        request::{Attribute, RequestPayload},
        response::{GetResponsePayload, ManagedObject, ResponsePayload},
        traits::ReadWrite,
    },
};

use crate::{
    config::{Opt, ServerOpt},
    key::{Key, KeyType},
    util::load_binary_file,
};

pub(crate) fn get_keys(opt: Opt) -> Result<Vec<Key>> {
    let client = kmip::client::tls::openssl::connect(&opt.try_into()?)?;

    let mut keys = Vec::new();
    for key_id in get_key_ids(&client, ObjectType::PrivateKey)? {
        keys.push(get_key(&client, &key_id)?);
    }
    for key_id in get_key_ids(&client, ObjectType::PublicKey)? {
        keys.push(get_key(&client, &key_id)?);
    }

    keys.sort_by_key(|v| v.id.clone());

    Ok(keys)
}

fn get_key<T: ReadWrite>(client: &Client<T>, key_id: &UniqueIdentifier) -> Result<Key> {
    let key: GetResponsePayload = client.get_key(key_id)?;

    let (typ, alg, len) = match key.cryptographic_object {
        ManagedObject::PublicKey(k) => (
            KeyType::Public,
            k.key_block.cryptographic_algorithm,
            k.key_block.cryptographic_length,
        ),
        ManagedObject::PrivateKey(k) => (
            KeyType::Private,
            k.key_block.cryptographic_algorithm,
            k.key_block.cryptographic_length,
        ),
        _ => bail!("Unsupported type"),
    };

    let payload = RequestPayload::GetAttributes(
        Some(key_id.clone()),
        Some(vec![AttributeName("Name".to_string())]),
    );
    let name = match client.do_request(payload)? {
        ResponsePayload::GetAttributes(res) => match res.attributes {
            Some(attrs) if !attrs.is_empty() => match &attrs[0].value {
                AttributeValue::Name(t, _) => t.to_string(),
                AttributeValue::TextString(t) => t.to_string(),
                _ => "None".to_string(),
            },
            _ => "None".to_string(),
        },
        _ => bail!("Unexpected response payload"),
    };

    let alg = alg
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let len = len
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let id = key_id.to_string();

    Ok(Key {
        id,
        typ,
        name,
        own_id: String::new(),
        alg,
        len,
    })
}

fn get_key_ids<T: ReadWrite>(
    client: &Client<T>,
    object_type: ObjectType,
) -> Result<Vec<UniqueIdentifier>> {
    let payload = RequestPayload::Locate(vec![Attribute::ObjectType(object_type)]);
    match client.do_request(payload)? {
        ResponsePayload::Locate(res) => Ok(res.unique_identifiers),
        _ => bail!("Unexpected response payload"),
    }
}

impl TryFrom<Opt> for ConnectionSettings {
    type Error = anyhow::Error;

    fn try_from(opt: Opt) -> Result<Self> {
        if let ServerOpt::Kmip(server_opt) = &opt.server {
            let client_cert = load_client_cert(&opt)?;

            let server_cert = if let Some(p) = opt.server_cert_path {
                Some(load_binary_file(&p)?)
            } else {
                None
            };
            let ca_cert = if let Some(p) = opt.ca_cert_path {
                Some(load_binary_file(&p)?)
            } else {
                None
            };

            Ok(ConnectionSettings {
                host: server_opt.addr.clone(),
                port: server_opt.port,
                username: server_opt.user.clone(),
                password: server_opt.pass.clone(),
                insecure: opt.insecure,
                client_cert,
                server_cert,
                ca_cert,
                connect_timeout: Some(Duration::from_secs(5)),
                read_timeout: Some(Duration::from_secs(5)),
                write_timeout: Some(Duration::from_secs(5)),
                max_response_bytes: None,
            })
        } else {
            bail!("Expected KMIP settings")
        }
    }
}

fn load_client_cert(opt: &Opt) -> Result<Option<ClientCertificate>> {
    let client_cert = {
        match (
            &opt.client_cert_path,
            &opt.client_key_path,
            &opt.client_pkcs12_path,
        ) {
            (None, None, None) => None,
            (None, None, Some(path)) => Some(ClientCertificate::CombinedPkcs12 {
                cert_bytes: load_binary_file(path)?,
            }),
            (Some(path), None, None) => Some(ClientCertificate::SeparatePem {
                cert_bytes: load_binary_file(path)?,
                key_bytes: None,
            }),
            (None, Some(_), None) => {
                bail!("Client certificate key path requires a client certificate path")
            }
            (_, Some(_), Some(_)) | (Some(_), _, Some(_)) => {
                bail!("Use either but not both of: client certificate and key PEM file paths, or a PCKS#12 certficate file path")
            }
            (Some(cert_path), Some(key_path), None) => Some(ClientCertificate::SeparatePem {
                cert_bytes: load_binary_file(cert_path)?,
                key_bytes: Some(load_binary_file(key_path)?),
            }),
        }
    };
    Ok(client_cert)
}
