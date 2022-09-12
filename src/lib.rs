use command::linux;
use get::WireGuard;
use options::Options;

pub mod command;
pub mod get;
pub mod options;
pub mod parser;
pub mod renderer;

// closures to be used in the Telegram binary
pub fn status() -> String {
    renderer::telegram::TelegramWireguard::new(
        WireGuard::try_from(linux::dump(Options { verbose: true }).unwrap().as_str()).unwrap(),
    )
    .to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
