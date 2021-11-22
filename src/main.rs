#[macro_use]
extern crate prettytable;

mod config;
mod key;
mod kmipclient;
mod pkcs11client;
mod util;

use anyhow::Result;
use prettytable::{format, row, Table};
use structopt::StructOpt;

use crate::config::{Opt, ServerOpt};

fn main() -> Result<()> {
    let opt = Opt::from_args();

    let keys = match &opt.server {
        ServerOpt::Kmip(_) => kmipclient::get_keys(opt)?,
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
