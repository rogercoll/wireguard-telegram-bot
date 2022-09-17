use std::time::{SystemTime, SystemTimeError};

use crate::get::{Endpoint, WireGuard};

// maximum handshake timeout 15min
// TODO: pass it as option
const MAX_HANDSHAKE: u64 = 900;
const IP_NOT_FOUND: &str = "IP_NOT_FOUND";

pub(crate) trait WireguardDecorator {
    fn new() -> Self;
    fn decorate(&self, _: &WireGuard) -> String;
}

pub(crate) trait Timer {
    //TODO: return Duration
    fn seconds_since_epoch(&self) -> Result<u64, SystemTimeError>;
}

pub(crate) struct SystemTimer;

impl Timer for SystemTimer {
    fn seconds_since_epoch(&self) -> Result<u64, SystemTimeError> {
        let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        Ok(current_time.as_secs())
    }
}

pub(crate) struct SimpleDecorator {
    timer: Box<dyn Timer>,
}

impl WireguardDecorator for SimpleDecorator {
    fn decorate(&self, wg: &WireGuard) -> String {
        wg.interfaces
            .iter()
            .fold("".to_string(), |mut output, (interface, endpoints)| {
                output.push_str(format!("Interface: {}\nEndpoints:\n", interface).as_ref());
                endpoints.iter().enumerate().for_each(|(i, endpoint)| {
                    let endpoint_str = if i < endpoints.len() - 1 {
                        format!("\t{}\n", self.endpoint_str(&endpoint))
                    } else {
                        format!("\t{}", self.endpoint_str(&endpoint))
                    };
                    output.push_str(&endpoint_str)
                });
                output
            })
    }
    fn new() -> Self {
        SimpleDecorator {
            timer: Box::new(SystemTimer {}),
        }
    }
}

impl SimpleDecorator {
    fn endpoint_str(&self, endpoint: &Endpoint) -> String {
        match endpoint {
            Endpoint::Local(local_endpoint) => {
                format!(
                    "Local:\n\t\tPublic key: {}\n\t\tPort: {}",
                    local_endpoint.public_key, local_endpoint.local_port
                )
            }
            Endpoint::Remote(remote_endpoint) => {
                let current_time = self.timer.seconds_since_epoch().unwrap();
                let status = if (current_time - remote_endpoint.latest_handshake) < MAX_HANDSHAKE {
                    "✅"
                } else {
                    "❌"
                };
                let remote_ip = match &remote_endpoint.remote_ip {
                    Some(ip) => ip.clone(),
                    None => IP_NOT_FOUND.to_string(),
                };
                format!(
                    "Remote:\n\t\tIP: {}\n\t\tSend bytes: {}\n\t\tReceived bytes: {}\n\t\tLatest handshake: {}s {}",
                    remote_ip,
                    remote_endpoint.sent_bytes,
                    remote_endpoint.received_bytes,
                    current_time - remote_endpoint.latest_handshake,
                    status
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashMap;

    use super::*;
    use crate::get::tests::new_wireguard;

    fn verify_decorator_trait<D: WireguardDecorator>(wg: &WireGuard, expected_output: String) {
        let d = D::new();
        assert_eq!(d.decorate(wg), expected_output);
    }

    #[test]
    fn verify_dump_empty() {
        verify_decorator_trait::<SimpleDecorator>(
            &WireGuard {
                interfaces: HashMap::new(),
            },
            "".to_string(),
        );
    }

    #[test]
    fn verify_dump_output() {
        struct SystemTimer {}
        impl Timer for SystemTimer {
            fn seconds_since_epoch(&self) -> Result<u64, SystemTimeError> {
                Ok(1662886837)
            }
        }
        let decorator = SimpleDecorator {
            timer: Box::new(SystemTimer {}),
        };
        assert_eq!(
            decorator.decorate(&new_wireguard()),
            "Interface: wg0
Endpoints:
\tLocal:
\t\tPublic key: 4BotR9fetxxxXGxG1/7x400TiMrZMvgCPwR5YFPQAAB=
\t\tPort: 4339
\tRemote:
\t\tIP: 9.8.7.6
\t\tSend bytes: 17808
\t\tReceived bytes: 11536
\t\tLatest handshake: 10s ✅"
                .to_string(),
        );
    }

    #[test]
    fn verify_dump_output_timeout() {
        struct FutureTimer {}
        impl Timer for FutureTimer {
            fn seconds_since_epoch(&self) -> Result<u64, SystemTimeError> {
                Ok(1662889837)
            }
        }
        let decorator = SimpleDecorator {
            timer: Box::new(FutureTimer {}),
        };

        assert_eq!(
            decorator.decorate(&new_wireguard()),
            "Interface: wg0
Endpoints:
\tLocal:
\t\tPublic key: 4BotR9fetxxxXGxG1/7x400TiMrZMvgCPwR5YFPQAAB=
\t\tPort: 4339
\tRemote:
\t\tIP: 9.8.7.6
\t\tSend bytes: 17808
\t\tReceived bytes: 11536
\t\tLatest handshake: 3010s ❌"
        );
    }
}
