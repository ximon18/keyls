extern crate prettytable;

mod config;
mod key;
mod kmipclient;
mod pkcs11client;
mod util;

use anyhow::Result;
use clap::Parser;
use kmip::net::NetError;
use prettytable::{format, row, Table};

use crate::config::{Opt, ServerOpt};

fn main() -> Result<()> {
    env_logger::init();

    let opt = Opt::parse();

    let keys = match &opt.server {
        ServerOpt::Kmip(_) => kmipclient::get_keys(opt).inspect_err(|err| {
            if let Some(NetError::DeserializeError { err, req, res }) = err.downcast_ref() {
                eprintln!("Err: {err}");
                eprintln!("Req: {}", hex::encode_upper(req));
                eprintln!("Res: {}", hex::encode_upper(res));
            }
        })?,
        ServerOpt::Pkcs11(_) => pkcs11client::get_keys(opt)?,
    };

    if keys.is_empty() {
        println!("No keys found");
    } else {
        println!("Found {} keys", keys.len());
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
        table.set_titles(row!["ID", "Type", "Name", "Algorithm", "Length"]);
        for key in keys {
            table.add_row(row![key.id, key.typ, key.name, key.alg, key.len]);
        }

        table.printstd();
    }

    Ok(())
}
