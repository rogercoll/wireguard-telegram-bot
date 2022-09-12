use std::error::Error;
use std::process::Command;

use crate::options::Options;

pub(crate) fn dump(_options: Options) -> Result<String, Box<dyn Error>> {
    let output = Command::new("wg").args(["show", "all", "dump"]).output()?;
    Ok(String::from_utf8(output.stdout)?)
}
