#[tokio::main]
async fn main() {
    wireguard_telegram_bot::start_unix_bot().await;
}
