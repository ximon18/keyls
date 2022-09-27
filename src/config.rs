use std::path::PathBuf;
use std::str::FromStr;

use anyhow::bail;
use anyhow::Result;
use clap::StructOpt;

/// A StructOpt example
#[derive(clap::StructOpt, Debug)]
#[clap(about = "A cryptographic token key lister")]
#[rustfmt::skip]
pub struct Opt {
    #[structopt(parse(try_from_str = parse_server), help = "Server location (e.g. kmip:[user[:pass]@]ip_or_fqdn[:port] or pkcs11:slot_id_or_label[:user_pin]@path/to/lib.so)")]
    pub server: ServerOpt,

    #[structopt(long = "insecure", help = "Disable secure checks (e.g. verification of the server certificate)")]
    pub insecure: bool,

    #[structopt(long = "client-cert", parse(from_os_str), help = "Path to the client certificate file in PEM format")]
    pub client_cert_path: Option<PathBuf>,

    #[structopt(long = "client-key", parse(from_os_str), help = "Path to the client certificate key file in PEM format")]
    pub client_key_path: Option<PathBuf>,

    #[structopt(long = "client-cert-and-key", parse(from_os_str), help = "Path to the client certificate and key file in PKCS#12 format")]
    pub client_pkcs12_path: Option<PathBuf>,

    #[structopt(long = "server-cert", parse(from_os_str), help = "Path to the server certificate file in PEM format")]
    pub server_cert_path: Option<PathBuf>,

    #[structopt(long = "server-ca-cert", parse(from_os_str), help = "Path to the server CA certificate file in PEM format")]
    pub ca_cert_path: Option<PathBuf>,
}

#[derive(Debug)]
pub enum ServerOpt {
    Kmip(KmipServerOpt),
    Pkcs11(Pkcs11ServerOpt),
}

#[derive(StructOpt, Debug)]
pub struct KmipServerOpt {
    pub addr: String,

    pub port: u16,

    pub user: Option<String>,

    pub pass: Option<String>,
}

#[derive(StructOpt, Debug)]
pub struct Pkcs11ServerOpt {
    pub lib_path: PathBuf,

    pub slot_id: Option<u64>,

    pub slot_label: Option<String>,

    pub user_pin: Option<String>,
}

fn parse_server(input: &str) -> Result<ServerOpt> {
    match input.split_once(':') {
        Some(("kmip", settings)) => {
            Ok(ServerOpt::Kmip(parse_kmip_server(settings)?))
        }
        Some(("pkcs11", settings)) => {
            Ok(ServerOpt::Pkcs11(parse_pkcs11_server(settings)?))
        }
        _ => bail!("Expected: kmip:[user[:pass]@]ip_or_fqdn[:port] or pkcs11:slot_id_or_label[:user_pin]@path/to/lib.so")
    }
}

fn parse_kmip_server(input: &str) -> Result<KmipServerOpt> {
    // input should be of the form: [user[:pass]@]ip_or_fqdn[:port]
    let (addr, port, user, pass) = match input.split_once('@') {
        Some((user_pass, rest)) => {
            let (user, pass) = parse_user_pass(user_pass)?;
            let (addr, port) = parse_addr_port(rest)?;
            (addr, port, Some(user), pass)
        }
        None => {
            let (addr, port) = parse_addr_port(input)?;
            (addr, port, None, None)
        }
    };

    Ok(KmipServerOpt {
        addr,
        port,
        user,
        pass,
    })
}

fn parse_user_pass(input: &str) -> Result<(String, Option<String>)> {
    // input should be of the form: user[:pass]
    match input.split_once(':') {
        Some((user, pass)) => Ok((user.to_string(), Some(pass.to_string()))),
        None => Ok((input.to_string(), None)),
    }
}

fn parse_addr_port(input: &str) -> Result<(String, u16)> {
    // input should be of the form: ip_or_fqdn[:port]
    match input.split_once(':') {
        Some((ip_or_fqdn, port)) => Ok((ip_or_fqdn.to_string(), port.parse::<u16>()?)),
        None => Ok((input.to_string(), 5696)),
    }
}

fn parse_pkcs11_server(input: &str) -> Result<Pkcs11ServerOpt> {
    // input should be of the form: slot_id_or_label[:user_pin]@path/to/lib.so
    let (lib_path, slot_id, slot_label, user_pin) = match input.split_once('@') {
        Some((slot_pin, lib_path)) => {
            let (slot_id, slot_label, user_pin) = match slot_pin.split_once(':') {
                Some((slot_id_or_label, user_pin)) => {
                    let (slot_id, slot_label) = parse_slot_id_or_label(slot_id_or_label)?;
                    (slot_id, slot_label, Some(user_pin.to_string()))
                }
                None => {
                    let (slot_id, slot_label) = parse_slot_id_or_label(slot_pin)?;
                    (slot_id, slot_label, None)
                }
            };
            let lib_path = PathBuf::from_str(lib_path)?;
            (lib_path, slot_id, slot_label, user_pin)
        }
        None => bail!("Missing '@' character in PKCS#11 server specification"),
    };

    Ok(Pkcs11ServerOpt {
        lib_path,
        slot_id,
        slot_label,
        user_pin,
    })
}

fn parse_slot_id_or_label(input: &str) -> Result<(Option<u64>, Option<String>)> {
    // input should be of the form: slot_id_or_label
    match input.parse::<u64>() {
        Ok(slot_id) => Ok((Some(slot_id), None)),
        Err(_) => Ok((None, Some(input.to_string()))),
    }
}
