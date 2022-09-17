use std::error::Error;
use std::process::Command;

pub(crate) trait Cmd {
    fn execute_dump(&self) -> Result<String, Box<dyn Error>>;
}

pub(crate) struct UnixCmd {}

impl UnixCmd {
    pub(crate) fn new() -> Self {
        UnixCmd {}
    }
}

impl Cmd for UnixCmd {
    fn execute_dump(&self) -> Result<String, Box<dyn Error>> {
        let output = Command::new("wg").args(["show", "all", "dump"]).output()?;
        Ok(String::from_utf8(output.stdout)?)
    }
}
