use std::collections::HashMap;

use crate::get::{Endpoint, LocalEndpoint, RemoteEndpoint, WireGuard};
use regex::Regex;
use thiserror::Error;

use std::net::SocketAddr;

const EMPTY: &str = "(none)";
const NOT_KEEP_ALIVE: &str = "off";

#[derive(Error, Debug)]
pub enum ParseDumpError {
    #[error("No interfaces found in dump line")]
    NoInterfacesProvided,
    #[error("the data for line `{0}` cannot be encoded to an endpoint")]
    InvalidEndpoint(String),
    #[error("Error parsing parameter `{0}`, err: `{1}`")]
    InvalidEndpointParameter(String, String),
}

fn to_option_string(s: &str) -> Option<String> {
    if s == EMPTY {
        None
    } else {
        Some(s.to_owned())
    }
}

fn keep_alive(s: &str) -> bool {
    s != NOT_KEEP_ALIVE
}

impl TryFrom<&Vec<&str>> for Endpoint {
    type Error = ParseDumpError;
    fn try_from(properties: &Vec<&str>) -> Result<Self, ParseDumpError> {
        match properties.len() {
            5 => Ok(Endpoint::Local(LocalEndpoint {
                public_key: properties[1].to_owned(),
                private_key: properties[2].to_owned(),
                local_port: properties[3].parse::<u16>().unwrap(),
                persistent_keepalive: keep_alive(properties[4]),
            })),
            9 => {
                let public_key = properties[1].to_owned();

                let (remote_ip, remote_port) =
                    if let Some(ip_and_port) = to_option_string(properties[3]) {
                        // this workaround fixes issue #10 (see
                        // https://github.com/MindFlavor/prometheus_wireguard_exporter/issues/10).
                        // Whenever it will be fixed upstream this code will be replaced with a
                        // simple
                        // let addr: SocketAddr = ip_and_port.parse::<SocketAddr>().unwrap();
                        let re = Regex::new(r"^\[(?P<ip>[A-Fa-f0-9:]+)%(.*)\]:(?P<port>[0-9]+)$")
                            .unwrap();
                        let addr: SocketAddr = re
                            .replace_all(&ip_and_port, "[$ip]:$port")
                            .parse::<SocketAddr>()
                            .unwrap();

                        (Some(addr.ip().to_string()), Some(addr.port()))
                    } else {
                        (None, None)
                    };

                let allowed_ips = properties[4].to_owned();

                Ok(Endpoint::Remote(RemoteEndpoint {
                    public_key,
                    remote_ip,
                    remote_port,
                    allowed_ips,
                    latest_handshake: properties[5].parse::<u64>().map_err(|err| {
                        ParseDumpError::InvalidEndpointParameter(
                            "latest_handshake".to_string(),
                            err.to_string(),
                        )
                    })?,
                    received_bytes: properties[6].parse::<u128>().unwrap(),
                    sent_bytes: properties[7].parse::<u128>().unwrap(),
                    persistent_keepalive: keep_alive(properties[8]),
                }))
            }
            _ => return Err(ParseDumpError::InvalidEndpoint(properties.join("\t"))),
        }
    }
}

impl TryFrom<&str> for WireGuard {
    type Error = ParseDumpError;
    fn try_from(value: &str) -> Result<Self, ParseDumpError> {
        match value.is_empty() {
            true => Err(ParseDumpError::NoInterfacesProvided),
            false => value
                .lines()
                .map(|line| {
                    line.split('\t')
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<&str>>()
                })
                .try_fold(
                    WireGuard {
                        interfaces: HashMap::new(),
                    },
                    |mut config, properties| {
                        let endpoint = Endpoint::try_from(&properties)?;
                        if let Some(endpoints) = config.interfaces.get_mut(properties[0]) {
                            endpoints.push(endpoint);
                        } else {
                            let new_vec = vec![endpoint];
                            config.interfaces.insert(properties[0].to_owned(), new_vec);
                        }

                        Ok(config)
                    },
                ),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::get::Endpoint;

    const BASIC_DUMP : &'static str = "wg0\tmDflvnauBzHrIXsLvQO1DZenjg3fOG9WbnKI0f8AB2f=\t\tTUF1fXCrEq0nrbbIFDv3RTxaLf76R+IJ9BK1MVacfkA=\t\t443\t\toff
wg0\t\t8vrzVeNk8rhcra03o4wYGebFzJul5GCdTAmN5aPmF14=\t(none)\t(none)\t10.0.0.2/32\t\t0\t\t0\t\t0\t\t25
wg0\t\tpcSg/lCzggscmdua73uy2k6xFQIKHi/Wdl1zBAQEnl0=\t\t(none)\t88.55.42.162:36518\t\t10.0.0.3/32\t\t1661801925\t1384400\t5605560\t\t25
wg0\t\tFGbKv7F4rkIWl9gcc2P63JFO4zStX0Wk1A1Jr5/9qE8=\t\t(none)\t88.55.42.162:63801\t\t10.0.0.5/32\t\t1661695518\t4823836\t28528792\t\t25
wg0\t\tLFKagB3/g8izSKU4w10otbbsfJMtjI4xSy8mvlXHOik=\t\t(none)\t38.111.111.111:8114\t\t10.0.0.6/32\t\t1661801952\t27229092\t\t55471340\t25
";
    const EMPTY_DUMP: &'static str = "";

    #[test]
    fn try_from_basic() {
        let x = WireGuard::try_from(BASIC_DUMP).unwrap();
        assert!(x.interfaces.len() == 1);
        assert!(x.interfaces["wg0"].len() == 5);

        let local = match &x.interfaces["wg0"][0] {
            Endpoint::Local(end) => end,
            Endpoint::Remote(_) => unreachable!(),
        };

        assert_eq!(
            local.public_key,
            "mDflvnauBzHrIXsLvQO1DZenjg3fOG9WbnKI0f8AB2f=".to_owned()
        );
        assert_eq!(
            local.private_key,
            "TUF1fXCrEq0nrbbIFDv3RTxaLf76R+IJ9BK1MVacfkA=".to_owned()
        );

        assert_eq!(local.local_port, 443);
        assert_eq!(local.persistent_keepalive, false);
    }

    #[test]
    fn try_from_error() {
        let result = WireGuard::try_from(EMPTY_DUMP);
        assert!(matches!(result, Err(ParseDumpError::NoInterfacesProvided)));
    }
}
