pub mod command;
pub mod decorator;
pub mod get;
pub mod parser;

// closures to be used in the Telegram binary
// fn status() -> &str

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
