use log::info;
use std::time::Duration;

use anyhow::{Result, bail};
use kmip::{
    net::{Client, ConnectionSettings, TlsClientAuth, TlsServerAuth},
    types::{
        common::{
            self, AttributeName,
            AttributeValue::{self},
            ObjectType, Operation, UniqueIdentifier,
        },
        request::{Attribute, BatchItem, Name, RequestPayload},
        response::ResponsePayload,
        traits::ReadWrite,
    },
};

use crate::{
    config::{Opt, ServerOpt},
    key::{Key, KeyType},
};

pub(crate) fn get_keys(opt: Opt) -> Result<Vec<Key>> {
    let mut client = kmip::net::tls::rustls::connect(&opt.try_into()?)?;

    let mut keys = Vec::new();
    let pri_key_ids = get_key_ids(&mut client, ObjectType::PrivateKey)?;
    let pub_key_ids = get_key_ids(&mut client, ObjectType::PublicKey)?;

    let mut batch_items = vec![];
    for (n, key_id) in pri_key_ids.into_iter().chain(pub_key_ids).enumerate() {
        let payload = RequestPayload::GetAttributes(
            Some(key_id),
            Some(vec![
                AttributeName("Name".to_string()),
                AttributeName("Object Type".to_string()),
                AttributeName("Cryptographic Algorithm".to_string()),
                AttributeName("Cryptographic Length".to_string()),
            ]),
        );
        batch_items.push(BatchItem(
            Operation::GetAttributes,
            Some(common::UniqueBatchItemID(n.to_be_bytes().to_vec())),
            payload,
        ));
    }

    info!("Getting information about {} keys..", batch_items.len(),);
    for batch_item in client.do_request_batch(batch_items)? {
        let batch_item = batch_item?;
        match batch_item.payload {
            Some(ResponsePayload::GetAttributes(res)) if res.attributes.is_some() => {
                let mut typ = None;
                let mut name = None;
                let mut alg = None;
                let mut len = None;
                for attr in res.attributes.unwrap() {
                    match attr.value {
                        AttributeValue::Name(Name(t, _)) => name = Some(t.to_string()),
                        AttributeValue::ObjectType(t) => match t {
                            ObjectType::PrivateKey => typ = Some(KeyType::Private),
                            ObjectType::PublicKey => typ = Some(KeyType::Public),
                            _ => {
                                continue;
                            }
                        },
                        AttributeValue::CryptographicAlgorithm(t) => alg = Some(t.to_string()),
                        AttributeValue::CryptographicLength(common::CryptographicLength(t)) => {
                            len = Some(t.to_string())
                        }
                        _ => unreachable!(),
                    }
                }

                keys.push(Key {
                    id: res.unique_identifier.to_string(),
                    typ: typ.unwrap(),
                    name: name.unwrap_or_default(),
                    alg: alg.unwrap_or_default(),
                    len: len.unwrap_or_default(),
                });
            }
            _ => unreachable!(),
        }
    }

    keys.sort_by_key(|v| v.id.clone());

    Ok(keys)
}

fn get_key_ids<T: ReadWrite>(
    client: &mut Client<T>,
    object_type: ObjectType,
) -> Result<Vec<UniqueIdentifier>> {
    let payload = RequestPayload::Locate(vec![Attribute::ObjectType(object_type)]);
    info!("Locating keys of type {object_type}");
    match client.do_request_payload(payload)?.try_into()? {
        ResponsePayload::Locate(res) => Ok(res.unique_identifiers),
        _ => bail!("Unexpected response payload"),
    }
}

impl TryFrom<Opt> for ConnectionSettings {
    type Error = anyhow::Error;

    fn try_from(opt: Opt) -> Result<Self> {
        if let ServerOpt::Kmip(server_opt) = &opt.server {
            let tls_client_auth = load_client_cert(&opt)?;

            let tls_server_auth = match (opt.server_cert_path, opt.ca_cert_path) {
                (None, None) if opt.insecure => TlsServerAuth::None,
                (None, None) => TlsServerAuth::Default,
                (None, Some(ca_cert_path)) => {
                    TlsServerAuth::TrustCertificateAuthority(std::fs::read(ca_cert_path)?)
                }
                (Some(server_cert_path), None) => {
                    TlsServerAuth::TrustCertificate(std::fs::read(server_cert_path)?)
                }
                (Some(_), Some(_)) => {
                    bail!("Only one of server certificate or CA certificate can be specified")
                }
            };

            Ok(ConnectionSettings {
                host: server_opt.addr.clone(),
                port: server_opt.port,
                username: server_opt.user.clone(),
                password: server_opt.pass.clone(),
                connect_timeout: Some(Duration::from_secs(5)),
                read_timeout: Some(Duration::from_secs(5)),
                write_timeout: Some(Duration::from_secs(5)),
                max_response_bytes: None,
                tls_client_auth,
                tls_server_auth,
                tls_server_name: opt.server_name,
            })
        } else {
            bail!("Expected KMIP settings")
        }
    }
}

fn load_client_cert(opt: &Opt) -> Result<Option<TlsClientAuth>> {
    let client_cert = {
        match (&opt.client_cert_path, &opt.client_key_path) {
            (None, None) => None,
            (None, Some(_)) | (Some(_), None) => {
                bail!("Both client certificate and client private key are required")
            }
            (Some(cert_path), Some(key_path)) => Some(TlsClientAuth {
                cert_bytes: std::fs::read(cert_path)?,
                private_key_bytes: std::fs::read(key_path)?,
            }),
        }
    };
    Ok(client_cert)
}
