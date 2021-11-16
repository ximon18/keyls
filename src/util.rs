use std::path::Path;

use anyhow::Result;

pub fn load_binary_file(path: &Path) -> Result<Vec<u8>> {
    use std::{fs::File, io::Read};

    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;

    Ok(bytes)
}
