# WireGuard Telegram Bot

[![made-with-rust](https://img.shields.io/badge/Made%20with-Rust-1f425f.svg)](https://www.rust-lang.org/)

Telegram bot that returns the output of the `wg show all dump`. 

## Building

Build using cargo

```sh
git clone git@github.com:rogercoll/wireguard-telegram-bot.git
cd wireguard-telegram-bot
cargo build
```

Set the environment variable `TELEGRAM_TOKEN` which you can get from 
@Botfather then run the target binary. Alternatively you can use cargo run<br>
`TELEGRAM_TOKEN="12345:abcdefghijklmnop" cargo run`
