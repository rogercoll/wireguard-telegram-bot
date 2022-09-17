use command::linux::{Cmd, UnixCmd};
use get::WireGuard;
use renderer::telegram::{SimpleDecorator, WireguardDecorator};
use std::error::Error;
use teloxide::dptree::endpoint;
use teloxide::{prelude::*, utils::command::BotCommands};

pub mod command;
pub mod get;
pub mod parser;
pub mod renderer;

#[derive(BotCommands, Clone)]
#[command(rename = "lowercase", description = "These commands are supported:")]
enum Command {
    #[command(description = "display this text.")]
    Help,
    #[command(description = "Status for all Wireguard interfaces.")]
    Status,
}

fn status<D: WireguardDecorator, C: Cmd>(decorator: D, cmd: C) -> Result<String, Box<dyn Error>> {
    Ok(decorator.decorate(&WireGuard::try_from(cmd.execute_dump()?.as_str())?))
}

async fn answer(bot: AutoSend<Bot>, message: Message) -> Result<(), Box<dyn Error + Send + Sync>> {
    let text = message.text();
    if text.is_none() {
        return Ok(());
    }
    if let Ok(command) = Command::parse(text.unwrap(), "DictionaryBot") {
        match command {
            Command::Help => {
                bot.send_message(message.chat.id, Command::descriptions().to_string())
                    .await?
            }
            Command::Status => {
                let output = match status(SimpleDecorator::new(), UnixCmd::new()) {
                    Ok(def) => def,
                    Err(error) => format!("Error found: {}", error),
                };
                bot.send_message(message.chat.id, output).await?
            }
        };
    }
    Ok(())
}

pub async fn start_unix_bot() {
    let bot = Bot::from_env().auto_send();

    let message_handler = Update::filter_message().branch(endpoint(answer));

    let handler = dptree::entry().branch(message_handler);
    Dispatcher::builder(bot, handler)
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}
