use std::collections::HashMap;

pub struct LocalEndpoint {
    pub public_key: String,
    pub private_key: String,
    pub local_port: u16,
    pub persistent_keepalive: bool,
}

pub struct RemoteEndpoint {
    pub public_key: String,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub allowed_ips: String,
    // Unix epoch in seconds
    pub latest_handshake: u64,
    pub sent_bytes: u128,
    pub received_bytes: u128,
    pub persistent_keepalive: bool,
}

pub(crate) enum Endpoint {
    Local(LocalEndpoint),
    Remote(RemoteEndpoint),
}

pub(crate) struct WireGuard {
    pub interfaces: HashMap<String, Vec<Endpoint>>,
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;

    use super::*;

    pub(crate) fn new_local_endpoint() -> Endpoint {
        Endpoint::Local(LocalEndpoint {
            public_key: "4BotR9fetxxxXGxG1/7x400TiMrZMvgCPwR5YFPQAAB=".to_owned(),
            private_key: "8vrzVeNk11111103oqwYGe1111111GCdTAoN5999A99=".to_owned(),
            local_port: 4339,
            persistent_keepalive: true,
        })
    }
    pub(crate) fn new_remote_endpoint() -> Endpoint {
        Endpoint::Remote(RemoteEndpoint {
            public_key: "21189XCAEq0lrbbIFDv2RTxaLf76R+IJ5BAAAAAAAAA=".to_owned(),
            remote_ip: Some("9.8.7.6".to_owned()),
            remote_port: Some(39879),
            allowed_ips: "0.0.0.0".to_owned(),
            latest_handshake: 1662886827,
            sent_bytes: 17808,
            received_bytes: 11536,
            persistent_keepalive: true,
        })
    }

    pub(crate) fn new_wireguard() -> WireGuard {
        WireGuard {
            interfaces: HashMap::from([(
                "wg0".to_owned(),
                Vec::from([new_local_endpoint(), new_remote_endpoint()]),
            )]),
        }
    }
}
